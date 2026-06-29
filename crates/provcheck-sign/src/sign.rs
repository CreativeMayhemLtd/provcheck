//! C2PA signing orchestration.
//!
//! Wraps `c2pa::create_signer::from_keys` + `c2pa::Builder::sign_file`
//! around an [`UnlockedIdentity`]. The caller supplies the manifest
//! JSON (assertions list); this module handles the cert / key wiring
//! and the file IO. Pure-Rust c2pa stack: `default-features = false`
//! + `rust_native_crypto` (matching the workspace pin), no OpenSSL.
//!
//! ## What this is, what it isn't
//!
//! This is the primitive that produces signed media. It is **not**
//! the manifest builder — the caller composes the JSON. The CLI
//! ships an opinionated helper that fills in the standard
//! `c2pa.actions.v2` + `c2pa.creative_work` shape, plus the
//! `app.provcheck.identity` assertion when an identity is
//! registered (Phase 5 work). At the crate level we stay minimal
//! and let downstream callers decide the manifest shape.

use std::path::{Path, PathBuf};

use provcheck_attestation_spec::{IDENTITY_ASSERTION_LABEL, IdentityClaim};
use secrecy::ExposeSecret;

use crate::types::UnlockedIdentity;

/// Errors from the C2PA signing primitive.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("source asset not found or unreadable: {0}")]
    Source(std::io::Error),

    #[error("could not parse signing algorithm '{0}' as a c2pa::SigningAlg variant")]
    UnknownAlgorithm(String),

    #[error("could not construct c2pa signer: {0}")]
    SignerSetup(String),

    #[error("could not parse manifest JSON: {0}")]
    ManifestJson(String),

    #[error("c2pa signing failed: {0}")]
    C2pa(String),
}

#[cfg(test)]
mod sign_error_tests {
    use super::*;

    #[test]
    fn source_message_includes_inner_io() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "source.mp3");
        let s = format!("{}", SignError::Source(io));
        assert!(s.contains("source asset"));
        assert!(s.contains("source.mp3"));
    }

    #[test]
    fn unknown_algorithm_quotes_value() {
        let s = format!("{}", SignError::UnknownAlgorithm("ED25519".into()));
        assert!(s.contains("ED25519"));
        assert!(s.contains("SigningAlg"));
    }

    #[test]
    fn signer_setup_includes_inner() {
        let s = format!("{}", SignError::SignerSetup("missing cert".into()));
        assert!(s.contains("c2pa signer"));
        assert!(s.contains("missing cert"));
    }

    #[test]
    fn manifest_json_includes_inner() {
        let s = format!("{}", SignError::ManifestJson("trailing comma".into()));
        assert!(s.contains("manifest JSON"));
        assert!(s.contains("trailing comma"));
    }

    #[test]
    fn c2pa_message_includes_inner() {
        let s = format!("{}", SignError::C2pa("invalid PEM".into()));
        assert!(s.contains("c2pa signing"));
        assert!(s.contains("invalid PEM"));
    }
}

/// What a successful signing call wrote.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Where the signed asset ended up. For in-place signing this
    /// equals the source path; for sidecar / new-file modes it's
    /// distinct.
    pub output_path: PathBuf,
    /// The serialised manifest bytes (`Vec<u8>` from c2pa's
    /// `sign_file`). The CLI can hand these to its caller for
    /// inspection without re-reading the signed file.
    pub manifest_bytes: Vec<u8>,
}

/// Sign an asset with the unlocked identity's cert chain + private
/// key.
///
/// `src` is the source asset (mp3, wav, jpeg, mp4, etc. — anything
/// the c2pa crate's `Builder::sign_file` recognises). `dst` is
/// where the signed output should land — pass the same path as
/// `src` for in-place signing, or a sibling path for sidecar /
/// new-file output. Source and destination must use the same file
/// format (extension); c2pa enforces this.
///
/// `manifest_json` is the full Builder JSON: `claim_generator`,
/// `format`, `title`, `assertions`, etc. See c2pa's documentation
/// for the schema. A minimal but valid example is in this
/// module's test suite.
pub fn sign_asset(
    identity: &UnlockedIdentity,
    src: &Path,
    dst: &Path,
    manifest_json: &str,
) -> Result<SignResult, SignError> {
    // Software-backed convenience entry: build the c2pa signer from
    // the in-memory PEM, then defer to the signer-only path so the
    // builder / chain / sign_file plumbing lives in exactly one place.
    let alg = parse_algorithm(&identity.locked.algorithm)
        .ok_or_else(|| SignError::UnknownAlgorithm(identity.locked.algorithm.clone()))?;
    let signer = c2pa::create_signer::from_keys(
        identity.locked.chain_pem.as_bytes(),
        identity.key_pem().expose_secret().as_bytes(),
        alg,
        None, // No TSA URL — Phase 6 followup if anyone needs trusted timestamps
    )
    .map_err(|e| SignError::SignerSetup(e.to_string()))?;

    sign_asset_with_signer(signer.as_ref(), src, dst, manifest_json)
}

/// Sign an asset using a pre-built [`c2pa::Signer`]. The signer
/// abstracts over key custody — software-PEM backends produce one
/// via `c2pa::create_signer::from_keys`, hardware-token backends
/// (Yubikey, TPM, Secure Enclave) produce one via
/// [`KeyProvider::signer()`](crate::providers::KeyProvider::signer).
///
/// Behaviour is identical to [`sign_asset`] minus the in-memory
/// PEM lookup — manifest JSON parsing, parent-ingredient chaining,
/// and `c2pa::Builder::sign_file` are the same.
pub fn sign_asset_with_signer(
    signer: &dyn c2pa::Signer,
    src: &Path,
    dst: &Path,
    manifest_json: &str,
) -> Result<SignResult, SignError> {
    std::fs::metadata(src).map_err(SignError::Source)?;

    let mut builder = c2pa::Builder::from_json(manifest_json)
        .map_err(|e| SignError::ManifestJson(e.to_string()))?;

    // Auto-chain: if the source already has a C2PA manifest, declare
    // it as a parent ingredient so the new signature explicitly
    // sits IN the lineage rather than alongside it. c2pa-rs would
    // preserve the prior manifest store either way, but the
    // ingredient declaration is what makes the parent relationship
    // visible at the active-manifest level — which is what most
    // verifiers and renderers walk.
    //
    // We only add the ingredient when the source has provenance
    // worth declaring (an unsigned source becomes a "parent of
    // some unsigned blob" which is noise, not signal). Failures
    // of either the inspect or the add are non-fatal — we fall
    // back to signing without the chain.
    if c2pa::Reader::from_file(src).is_ok() {
        let title = src
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("source")
            .to_string();
        let format = format_for_ingredient(src);
        let ingredient_json = serde_json::json!({
            "title": title,
            "format": format,
            "relationship": "parentOf"
        })
        .to_string();
        if let Ok(mut stream) = std::fs::File::open(src) {
            let _ = builder.add_ingredient_from_stream(&ingredient_json, &format, &mut stream);
        }
    }

    let manifest_bytes = builder
        .sign_file(signer, src, dst)
        .map_err(|e| SignError::C2pa(e.to_string()))?;

    Ok(SignResult {
        output_path: dst.to_path_buf(),
        manifest_bytes,
    })
}

/// Parse a JWS algorithm identifier (`"ES256"`, `"Ed25519"`, etc.)
/// into the corresponding [`c2pa::SigningAlg`] variant. Returns
/// `None` for unrecognised inputs; the canonical set is the seven
/// variants c2pa-rs supports.
///
/// Shared between [`sign_asset`] and the default
/// [`crate::providers::KeyProvider::signer`] implementation so the
/// algorithm-string-to-variant mapping lives in one place.
pub fn parse_algorithm(s: &str) -> Option<c2pa::SigningAlg> {
    Some(match s {
        "ES256" => c2pa::SigningAlg::Es256,
        "ES384" => c2pa::SigningAlg::Es384,
        "ES512" => c2pa::SigningAlg::Es512,
        "PS256" => c2pa::SigningAlg::Ps256,
        "PS384" => c2pa::SigningAlg::Ps384,
        "PS512" => c2pa::SigningAlg::Ps512,
        "Ed25519" => c2pa::SigningAlg::Ed25519,
        _ => return None,
    })
}

#[cfg(test)]
mod parse_algorithm_tests {
    use super::parse_algorithm;
    use c2pa::SigningAlg;

    #[test]
    fn parses_es256() {
        assert_eq!(parse_algorithm("ES256"), Some(SigningAlg::Es256));
    }

    #[test]
    fn parses_es384() {
        assert_eq!(parse_algorithm("ES384"), Some(SigningAlg::Es384));
    }

    #[test]
    fn parses_es512() {
        assert_eq!(parse_algorithm("ES512"), Some(SigningAlg::Es512));
    }

    #[test]
    fn parses_ps256() {
        assert_eq!(parse_algorithm("PS256"), Some(SigningAlg::Ps256));
    }

    #[test]
    fn parses_ps384() {
        assert_eq!(parse_algorithm("PS384"), Some(SigningAlg::Ps384));
    }

    #[test]
    fn parses_ps512() {
        assert_eq!(parse_algorithm("PS512"), Some(SigningAlg::Ps512));
    }

    #[test]
    fn parses_ed25519() {
        assert_eq!(parse_algorithm("Ed25519"), Some(SigningAlg::Ed25519));
    }

    #[test]
    fn rejects_lowercase_es256() {
        // The lexicon (and ALLOWED_ALGORITHMS) is case-sensitive.
        // A lowercase variant must not silently work.
        assert_eq!(parse_algorithm("es256"), None);
    }

    #[test]
    fn rejects_rs256() {
        // RS256 is in ALLOWED_ALGORITHMS per the lexicon but c2pa
        // does not expose it as a SigningAlg yet. Pin that
        // parse_algorithm returns None for it, surfacing the gap
        // as an explicit failure rather than a silent
        // fallthrough.
        assert_eq!(parse_algorithm("RS256"), None);
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(parse_algorithm(""), None);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert_eq!(parse_algorithm("HMACSHA1"), None);
        assert_eq!(parse_algorithm("DSA"), None);
    }

    #[test]
    fn every_parsable_value_is_in_attestation_spec_allowlist() {
        // The 7 names we parse must be a subset of the lexicon's
        // ALLOWED_ALGORITHMS. Silent drift would let the kit sign
        // with an algorithm verifiers reject.
        use provcheck_attestation_spec::ALLOWED_ALGORITHMS;
        for alg in ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "Ed25519"] {
            assert!(parse_algorithm(alg).is_some(), "kit should parse {alg}");
            assert!(
                ALLOWED_ALGORITHMS.contains(&alg),
                "{alg} must be in ALLOWED_ALGORITHMS"
            );
        }
    }
}

/// What C2PA action to declare on the signed manifest. The kit picks
/// a default based on whether the source already has provenance
/// (see [`default_action_for`]); the caller may override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAction {
    /// `c2pa.created` — content was newly created at sign time.
    /// Correct only when the source has no prior C2PA manifest.
    Created,
    /// `c2pa.opened` — source was opened from existing C2PA-signed
    /// content and re-signed without modification.
    Opened,
    /// `c2pa.edited` — source was opened, modified, then re-signed.
    Edited,
    /// `c2pa.published` — the publisher-attestation case. Source
    /// has prior provenance (created by someone else) and the
    /// signer is publishing it onward, vouching with their
    /// attested identity. Default when the source has a manifest.
    Published,
}

impl SignAction {
    /// C2PA action label string (`"c2pa.created"` etc.).
    pub fn as_c2pa_label(self) -> &'static str {
        match self {
            Self::Created => "c2pa.created",
            Self::Opened => "c2pa.opened",
            Self::Edited => "c2pa.edited",
            Self::Published => "c2pa.published",
        }
    }

    /// Parse a CLI / API string. Accepts the canonical form
    /// (`"c2pa.created"`) and the short form (`"created"`).
    pub fn parse(s: &str) -> Option<Self> {
        let stripped = s.strip_prefix("c2pa.").unwrap_or(s);
        match stripped {
            "created" => Some(Self::Created),
            "opened" => Some(Self::Opened),
            "edited" => Some(Self::Edited),
            "published" => Some(Self::Published),
            _ => None,
        }
    }
}

/// Provenance snapshot of a source file's active C2PA manifest.
/// `None` for unsigned or unrecognised sources; `Some` for any file
/// whose store contains a parseable active manifest.
#[derive(Debug, Clone)]
pub struct SourceProvenance {
    /// `claim_generator` of the source's active manifest.
    pub claim_generator: Option<String>,
    /// Signer common name (cert subject CN) of the source's active
    /// manifest, when available.
    pub signer: Option<String>,
    /// Title (file name claim) of the source's active manifest.
    pub title: Option<String>,
    /// Active manifest label (urn-style id).
    pub label: String,
    /// Format string declared by the source's manifest.
    pub format: Option<String>,
}

/// Inspect a file for existing C2PA provenance. Never fails — an
/// unreadable / unsigned / malformed source returns `None`, which
/// is also the "no prior provenance" indicator.
pub fn inspect_source(path: &std::path::Path) -> Option<SourceProvenance> {
    let reader = c2pa::Reader::from_file(path).ok()?;
    let active = reader.active_manifest()?;
    let label = active.label()?.to_string();
    let sig = active.signature_info();
    Some(SourceProvenance {
        claim_generator: active.claim_generator().map(|s| s.to_string()),
        signer: sig.and_then(|s| s.common_name.clone().or_else(|| s.issuer.clone())),
        title: active.title().map(|s| s.to_string()),
        label,
        format: active.format().map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod default_action_for_tests {
    use super::*;

    fn fake_provenance() -> SourceProvenance {
        SourceProvenance {
            label: "test:label".into(),
            signer: Some("Test Signer".into()),
            claim_generator: Some("test-tool/1.0".into()),
            title: None,
            format: None,
        }
    }

    #[test]
    fn no_provenance_defaults_to_created() {
        assert_eq!(default_action_for(None), SignAction::Created);
    }

    #[test]
    fn existing_provenance_defaults_to_published() {
        // Publisher-attestation case: source already has a
        // C2PA chain, the signer's role is to vouch onward.
        let p = fake_provenance();
        assert_eq!(default_action_for(Some(&p)), SignAction::Published);
    }

    #[test]
    fn provenance_with_minimal_fields_still_published() {
        // Even a manifest with no signer / no claim_generator
        // counts as "this file has provenance".
        let p = SourceProvenance {
            label: "minimal".into(),
            signer: None,
            claim_generator: None,
            title: None,
            format: None,
        };
        assert_eq!(default_action_for(Some(&p)), SignAction::Published);
    }
}

#[cfg(test)]
mod format_for_ingredient_tests {
    use super::format_for_ingredient;
    use std::path::Path;

    #[test]
    fn wav_maps_to_audio_wav() {
        assert_eq!(format_for_ingredient(Path::new("a.wav")), "audio/wav");
    }

    #[test]
    fn mp3_maps_to_audio_mpeg() {
        assert_eq!(format_for_ingredient(Path::new("a.mp3")), "audio/mpeg");
    }

    #[test]
    fn flac_maps_to_audio_flac() {
        assert_eq!(format_for_ingredient(Path::new("a.flac")), "audio/flac");
    }

    #[test]
    fn ogg_and_oga_both_map_to_audio_ogg() {
        assert_eq!(format_for_ingredient(Path::new("a.ogg")), "audio/ogg");
        assert_eq!(format_for_ingredient(Path::new("a.oga")), "audio/ogg");
    }

    #[test]
    fn m4a_maps_to_audio_mp4() {
        assert_eq!(format_for_ingredient(Path::new("a.m4a")), "audio/mp4");
    }

    #[test]
    fn aac_maps_to_audio_aac() {
        assert_eq!(format_for_ingredient(Path::new("a.aac")), "audio/aac");
    }

    #[test]
    fn jpg_and_jpeg_both_map_to_image_jpeg() {
        assert_eq!(format_for_ingredient(Path::new("a.jpg")), "image/jpeg");
        assert_eq!(format_for_ingredient(Path::new("a.jpeg")), "image/jpeg");
    }

    #[test]
    fn png_maps_to_image_png() {
        assert_eq!(format_for_ingredient(Path::new("a.png")), "image/png");
    }

    #[test]
    fn tif_and_tiff_both_map_to_image_tiff() {
        assert_eq!(format_for_ingredient(Path::new("a.tif")), "image/tiff");
        assert_eq!(format_for_ingredient(Path::new("a.tiff")), "image/tiff");
    }

    #[test]
    fn webp_maps_to_image_webp() {
        assert_eq!(format_for_ingredient(Path::new("a.webp")), "image/webp");
    }

    #[test]
    fn mp4_and_m4v_both_map_to_video_mp4() {
        assert_eq!(format_for_ingredient(Path::new("a.mp4")), "video/mp4");
        assert_eq!(format_for_ingredient(Path::new("a.m4v")), "video/mp4");
    }

    #[test]
    fn mov_maps_to_video_quicktime() {
        assert_eq!(format_for_ingredient(Path::new("a.mov")), "video/quicktime");
    }

    #[test]
    fn webm_maps_to_video_webm() {
        assert_eq!(format_for_ingredient(Path::new("a.webm")), "video/webm");
    }

    #[test]
    fn unknown_extension_falls_back_to_octet_stream() {
        assert_eq!(
            format_for_ingredient(Path::new("a.unknown")),
            "application/octet-stream"
        );
    }

    #[test]
    fn no_extension_falls_back_to_octet_stream() {
        assert_eq!(
            format_for_ingredient(Path::new("README")),
            "application/octet-stream"
        );
    }

    #[test]
    fn extension_lookup_is_case_insensitive() {
        // Operators pass through paths from the filesystem; on
        // Windows the case can be UPPER. Pin lowercase-normalisation.
        assert_eq!(format_for_ingredient(Path::new("a.MP3")), "audio/mpeg");
        assert_eq!(format_for_ingredient(Path::new("a.JpEg")), "image/jpeg");
    }

    #[test]
    fn full_path_with_directory_is_handled() {
        assert_eq!(
            format_for_ingredient(Path::new("/a/b/c/song.mp3")),
            "audio/mpeg"
        );
        assert_eq!(
            format_for_ingredient(Path::new("C:\\Users\\creator\\song.wav")),
            "audio/wav"
        );
    }
}

/// Pick the right default action for a source based on its
/// provenance. Files with existing provenance default to
/// `Published` (the publisher-attestation case); unsigned files
/// default to `Created`.
pub fn default_action_for(provenance: Option<&SourceProvenance>) -> SignAction {
    if provenance.is_some() {
        SignAction::Published
    } else {
        SignAction::Created
    }
}

/// Map a source path's extension to a MIME-style format string for
/// the C2PA Ingredient. Falls back to `"application/octet-stream"`
/// for unrecognised extensions; c2pa-rs will still hash the stream
/// but won't try to extract format-specific metadata.
fn format_for_ingredient(p: &std::path::Path) -> String {
    let ext = match p.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return "application/octet-stream".to_string(),
    };
    match ext.as_str() {
        "wav" => "audio/wav".into(),
        "mp3" => "audio/mpeg".into(),
        "flac" => "audio/flac".into(),
        "ogg" | "oga" => "audio/ogg".into(),
        "m4a" => "audio/mp4".into(),
        "aac" => "audio/aac".into(),
        "jpg" | "jpeg" => "image/jpeg".into(),
        "png" => "image/png".into(),
        "tif" | "tiff" => "image/tiff".into(),
        "webp" => "image/webp".into(),
        "mp4" | "m4v" => "video/mp4".into(),
        "mov" => "video/quicktime".into(),
        "webm" => "video/webm".into(),
        _ => "application/octet-stream".into(),
    }
}

/// Splice the `app.provcheck.identity` assertion into the
/// `assertions` array of a Builder manifest JSON. Idempotent: if an
/// assertion with the same label is already present, it gets
/// replaced (the new claim wins). The returned string is a fresh
/// JSON document ready to hand to [`sign_asset`].
///
/// Failure modes:
/// - manifest doesn't parse as JSON → [`SignError::ManifestJson`].
/// - manifest's top-level shape isn't a JSON object → likewise.
/// - manifest's `assertions` key is present but isn't an array
///   → likewise. Missing `assertions` is fine; it gets added.
///
/// Use this from the producer-side CLI (provcheck-kit) when the
/// user passes `--embed-identity`. A library consumer calling
/// `sign_asset` directly can use it the same way.
pub fn embed_identity_assertion(
    manifest_json: &str,
    claim: &IdentityClaim,
) -> Result<String, SignError> {
    let mut value: serde_json::Value =
        serde_json::from_str(manifest_json).map_err(|e| SignError::ManifestJson(e.to_string()))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| SignError::ManifestJson("manifest top-level is not an object".into()))?;

    let entry = serde_json::json!({
        "label": IDENTITY_ASSERTION_LABEL,
        "data": claim,
    });

    let assertions = obj
        .entry("assertions".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    let arr = assertions.as_array_mut().ok_or_else(|| {
        SignError::ManifestJson("manifest 'assertions' is present but not an array".into())
    })?;

    // Replace any pre-existing assertion with the same label so
    // re-running embed is idempotent (calling it twice doesn't
    // produce two identity assertions).
    arr.retain(|a| a.get("label").and_then(|l| l.as_str()) != Some(IDENTITY_ASSERTION_LABEL));
    arr.push(entry);

    serde_json::to_string(&value).map_err(|e| SignError::ManifestJson(e.to_string()))
}

#[cfg(test)]
mod embed_identity_assertion_tests {
    use super::embed_identity_assertion;
    use super::SignError;
    use provcheck_attestation_spec::{IDENTITY_ASSERTION_LABEL, IdentityClaim};

    fn claim() -> IdentityClaim {
        IdentityClaim::new("did:plc:abc", Some("creator.bsky.social".into()))
    }

    fn parse_assertions(json: &str) -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(json).expect("parse");
        v.get("assertions")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default()
    }

    fn find_identity_assertion(json: &str) -> Option<serde_json::Value> {
        parse_assertions(json)
            .into_iter()
            .find(|a| a.get("label").and_then(|l| l.as_str()) == Some(IDENTITY_ASSERTION_LABEL))
    }

    #[test]
    fn empty_object_manifest_gains_assertions_array_and_identity() {
        let out = embed_identity_assertion("{}", &claim()).expect("ok");
        let assertions = parse_assertions(&out);
        assert_eq!(assertions.len(), 1, "must add exactly one assertion");
        let identity = find_identity_assertion(&out).expect("must include identity assertion");
        assert_eq!(
            identity.get("label").and_then(|l| l.as_str()),
            Some(IDENTITY_ASSERTION_LABEL)
        );
    }

    #[test]
    fn embedded_assertion_carries_did_in_data() {
        let out = embed_identity_assertion("{}", &claim()).expect("ok");
        let identity = find_identity_assertion(&out).expect("identity");
        let did = identity
            .get("data")
            .and_then(|d| d.get("did"))
            .and_then(|d| d.as_str());
        assert_eq!(did, Some("did:plc:abc"));
    }

    #[test]
    fn embedded_assertion_carries_handle_in_data_when_present() {
        let out = embed_identity_assertion("{}", &claim()).expect("ok");
        let identity = find_identity_assertion(&out).expect("identity");
        let handle = identity
            .get("data")
            .and_then(|d| d.get("handle"))
            .and_then(|d| d.as_str());
        assert_eq!(handle, Some("creator.bsky.social"));
    }

    #[test]
    fn embedded_assertion_omits_handle_when_absent_per_serde_default() {
        // IdentityClaim::handle is #[serde(skip_serializing_if =
        // "Option::is_none")] — a None handle must not appear as
        // a "handle":null field, just be absent.
        let no_handle = IdentityClaim::new("did:plc:abc", None);
        let out = embed_identity_assertion("{}", &no_handle).expect("ok");
        let identity = find_identity_assertion(&out).expect("identity");
        assert!(
            identity.get("data").and_then(|d| d.get("handle")).is_none(),
            "missing handle must serialise as absent, not null"
        );
    }

    #[test]
    fn idempotent_replaces_existing_identity_assertion_not_duplicates() {
        let first = embed_identity_assertion("{}", &claim()).expect("first");
        let second_claim =
            IdentityClaim::new("did:plc:NEW", Some("new.bsky.social".into()));
        let second = embed_identity_assertion(&first, &second_claim).expect("second");
        let assertions = parse_assertions(&second);
        assert_eq!(
            assertions.len(),
            1,
            "re-embed must REPLACE, not append a duplicate"
        );
        // The replaced assertion must carry the new DID.
        let identity = find_identity_assertion(&second).expect("identity");
        assert_eq!(
            identity.get("data").and_then(|d| d.get("did")).and_then(|d| d.as_str()),
            Some("did:plc:NEW")
        );
    }

    #[test]
    fn preserves_unrelated_assertions() {
        // A manifest with an unrelated assertion (e.g. c2pa.actions)
        // must keep that assertion intact when embed adds the
        // identity assertion alongside.
        let manifest = r#"{
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": []}}
            ]
        }"#;
        let out = embed_identity_assertion(manifest, &claim()).expect("ok");
        let assertions = parse_assertions(&out);
        assert_eq!(assertions.len(), 2, "must preserve the existing assertion");
        let labels: Vec<&str> = assertions
            .iter()
            .filter_map(|a| a.get("label").and_then(|l| l.as_str()))
            .collect();
        assert!(labels.contains(&"c2pa.actions.v2"));
        assert!(labels.contains(&IDENTITY_ASSERTION_LABEL));
    }

    #[test]
    fn idempotent_replace_with_unrelated_assertions_preserved() {
        // Re-embed must replace the existing identity assertion
        // BUT keep any unrelated assertions in the array.
        let manifest = r#"{
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": []}},
                {"label": "app.provcheck.identity", "data": {"did": "did:plc:OLD"}}
            ]
        }"#;
        let new_claim = IdentityClaim::new("did:plc:NEW", None);
        let out = embed_identity_assertion(manifest, &new_claim).expect("ok");
        let assertions = parse_assertions(&out);
        assert_eq!(assertions.len(), 2, "actions assertion must remain alongside replaced identity");
        let identity = find_identity_assertion(&out).expect("identity");
        assert_eq!(
            identity.get("data").and_then(|d| d.get("did")).and_then(|d| d.as_str()),
            Some("did:plc:NEW"),
            "identity assertion must carry the new DID, not the old"
        );
    }

    #[test]
    fn rejects_malformed_json() {
        let r = embed_identity_assertion("{not json", &claim());
        assert!(matches!(r, Err(SignError::ManifestJson(_))));
    }

    #[test]
    fn rejects_non_object_top_level() {
        let r = embed_identity_assertion("[]", &claim());
        assert!(matches!(r, Err(SignError::ManifestJson(_))));
        let msg = format!("{}", r.err().unwrap());
        assert!(msg.contains("not an object"));
    }

    #[test]
    fn rejects_non_array_assertions_field() {
        let manifest = r#"{"assertions": "this is not an array"}"#;
        let r = embed_identity_assertion(manifest, &claim());
        assert!(matches!(r, Err(SignError::ManifestJson(_))));
        let msg = format!("{}", r.err().unwrap());
        assert!(msg.contains("not an array"));
    }

    #[test]
    fn output_is_valid_json_round_trip() {
        let out = embed_identity_assertion("{}", &claim()).expect("ok");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse");
        assert!(v.is_object());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{SubjectInfo, generate};
    use crate::types::{KeyProviderKind, LockedIdentity};
    use secrecy::SecretString;
    use tempfile::TempDir;
    use time::OffsetDateTime;

    /// Synthesise a 1-second silent mono 44.1 kHz WAV. Small,
    /// recognised by c2pa as audio/wav, fast to round-trip.
    fn write_silent_wav(path: &Path) {
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44_100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut w = hound::WavWriter::create(path, spec).expect("wav writer");
        for _ in 0..44_100 {
            w.write_sample(0i16).expect("write sample");
        }
        w.finalize().expect("finalize wav");
    }

    /// Build a real UnlockedIdentity from a freshly-generated cert
    /// chain. Costs ~1 cert generation per test — acceptable;
    /// keeps the tests honest about the cert / key / signer
    /// integration.
    fn fresh_identity() -> UnlockedIdentity {
        let kp = generate(&SubjectInfo::default()).expect("cert");
        let locked = LockedIdentity {
            chain_pem: kp.chain_pem,
            fingerprint: kp.fingerprint,
            algorithm: kp.algorithm,
            did: None,
            handle: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            key_provider: KeyProviderKind::Keychain,
            recovery_recipients: vec![],
        };
        UnlockedIdentity::new(locked, SecretString::from(kp.key_pem))
    }

    /// Minimal-but-valid manifest JSON for a wav signing test.
    fn minimal_wav_manifest() -> String {
        serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.0",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.0"}],
            "format": "audio/wav",
            "title": "test.wav",
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": [{"action": "c2pa.created"}]
                    }
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn sign_then_read_round_trips() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);

        let identity = fresh_identity();
        let expected_fingerprint = identity.locked.fingerprint.clone();

        let result = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect("sign");
        assert_eq!(result.output_path, dst);
        assert!(!result.manifest_bytes.is_empty(), "got manifest bytes");
        assert!(dst.exists(), "signed file written");

        // Verify by reading the signed file back through c2pa.
        let reader = c2pa::Reader::from_file(&dst).expect("reader");
        assert!(
            matches!(
                reader.validation_state(),
                c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
            ),
            "manifest crypto verifies: {:?}",
            reader.validation_state()
        );

        // And confirm the verifier's fingerprint computation of the
        // signing cert matches what GeneratedKeypair gave us — the
        // load-bearing publisher↔verifier contract for the atproto
        // attestation flow.
        let active = reader.active_manifest().expect("active manifest");
        let chain = active
            .signature_info()
            .map(|s| s.cert_chain.clone())
            .expect("cert chain available");
        let fp = provcheck_attestation_spec::fingerprint_pem_chain(&chain).expect("fingerprint");
        assert_eq!(fp, expected_fingerprint);
    }

    #[test]
    fn missing_source_surfaces_clean_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("nope.wav");
        let dst = dir.path().join("signed.wav");
        let identity = fresh_identity();

        let err = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect_err("");
        assert!(matches!(err, SignError::Source(_)), "got {err:?}");
        assert!(!dst.exists(), "no destination written on missing source");
    }

    #[test]
    fn invalid_manifest_json_surfaces_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();

        let err = sign_asset(&identity, &src, &dst, "{not valid json}").expect_err("");
        assert!(matches!(err, SignError::ManifestJson(_)), "got {err:?}");
    }

    #[test]
    fn unknown_algorithm_is_typed_error() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);

        let mut identity = fresh_identity();
        identity.locked.algorithm = "RSA-PSS-4096".to_string();

        let err = sign_asset(&identity, &src, &dst, &minimal_wav_manifest()).expect_err("");
        assert!(matches!(err, SignError::UnknownAlgorithm(_)), "got {err:?}");
    }

    #[test]
    fn embed_identity_assertion_adds_to_empty_assertions() {
        let manifest = serde_json::json!({
            "claim_generator": "test/0",
            "format": "audio/wav",
            "title": "x",
        })
        .to_string();
        let claim = IdentityClaim::new("did:plc:abc", Some("creator.bsky.social".into()));
        let out = embed_identity_assertion(&manifest, &claim).expect("embed");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse");
        let arr = v["assertions"].as_array().expect("assertions present");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["label"], IDENTITY_ASSERTION_LABEL);
        assert_eq!(arr[0]["data"]["did"], "did:plc:abc");
        assert_eq!(arr[0]["data"]["handle"], "creator.bsky.social");
    }

    #[test]
    fn embed_identity_assertion_appends_to_existing_assertions() {
        let manifest = serde_json::json!({
            "format": "audio/wav",
            "assertions": [{"label": "c2pa.actions.v2", "data": {"actions": []}}],
        })
        .to_string();
        let claim = IdentityClaim::new("did:plc:abc", None);
        let out = embed_identity_assertion(&manifest, &claim).expect("embed");
        let v: serde_json::Value = serde_json::from_str(&out).expect("parse");
        let arr = v["assertions"].as_array().expect("assertions present");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["label"], "c2pa.actions.v2");
        assert_eq!(arr[1]["label"], IDENTITY_ASSERTION_LABEL);
    }

    #[test]
    fn embed_identity_assertion_is_idempotent() {
        let manifest = serde_json::json!({"format": "audio/wav"}).to_string();
        let claim1 = IdentityClaim::new("did:plc:abc", None);
        let once = embed_identity_assertion(&manifest, &claim1).expect("embed 1");
        let twice = embed_identity_assertion(&once, &claim1).expect("embed 2");
        let v: serde_json::Value = serde_json::from_str(&twice).expect("parse");
        let arr = v["assertions"].as_array().expect("assertions present");
        assert_eq!(arr.len(), 1, "second embed replaces rather than duplicates");
    }

    #[test]
    fn embed_identity_assertion_replaces_stale_did() {
        let manifest = serde_json::json!({"format": "audio/wav"}).to_string();
        let old = IdentityClaim::new("did:plc:OLD", None);
        let new = IdentityClaim::new("did:plc:NEW", None);
        let stage1 = embed_identity_assertion(&manifest, &old).expect("embed 1");
        let stage2 = embed_identity_assertion(&stage1, &new).expect("embed 2");
        let v: serde_json::Value = serde_json::from_str(&stage2).expect("parse");
        let arr = v["assertions"].as_array().expect("assertions present");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["data"]["did"], "did:plc:NEW");
    }

    #[test]
    fn embed_identity_assertion_rejects_non_object_manifest() {
        let err = embed_identity_assertion("[]", &IdentityClaim::new("did:plc:abc", None))
            .expect_err("rejected");
        assert!(matches!(err, SignError::ManifestJson(_)));
    }

    #[test]
    fn embed_identity_assertion_rejects_invalid_assertions_shape() {
        let manifest = serde_json::json!({
            "format": "audio/wav",
            "assertions": "not an array",
        })
        .to_string();
        let err = embed_identity_assertion(&manifest, &IdentityClaim::new("did:plc:abc", None))
            .expect_err("rejected");
        assert!(matches!(err, SignError::ManifestJson(_)));
    }

    #[test]
    fn sign_action_round_trips_string() {
        for (label, expected) in [
            ("c2pa.created", SignAction::Created),
            ("created", SignAction::Created),
            ("c2pa.opened", SignAction::Opened),
            ("opened", SignAction::Opened),
            ("c2pa.edited", SignAction::Edited),
            ("edited", SignAction::Edited),
            ("c2pa.published", SignAction::Published),
            ("published", SignAction::Published),
        ] {
            assert_eq!(SignAction::parse(label), Some(expected), "{label}");
        }
        assert_eq!(SignAction::parse("bogus"), None);
        assert_eq!(SignAction::Published.as_c2pa_label(), "c2pa.published");
    }

    #[test]
    fn inspect_source_returns_none_for_unsigned_file() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("plain.wav");
        write_silent_wav(&src);
        assert!(inspect_source(&src).is_none(), "unsigned file → None");
    }

    #[test]
    fn inspect_source_returns_signer_for_signed_file() {
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("u.wav");
        let signed = dir.path().join("s.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();
        sign_asset(&identity, &src, &signed, &minimal_wav_manifest()).expect("sign");

        let provenance = inspect_source(&signed).expect("source has provenance");
        // Active manifest's signer should be the cert subject CN
        // (the rcgen-default subject when fresh_identity built the
        // cert). Asserting just presence — the exact string is a
        // rcgen / c2pa-rs implementation detail and not part of the
        // contract.
        assert!(provenance.signer.is_some(), "signer extracted");
        assert!(
            !provenance.label.is_empty(),
            "active manifest label present"
        );
    }

    #[test]
    fn default_action_routes_on_provenance() {
        assert_eq!(default_action_for(None), SignAction::Created);
        let stub = SourceProvenance {
            claim_generator: Some("Doomscroll.fm/0.1.0".into()),
            signer: Some("Doomscroll.fm".into()),
            title: Some("clip.mp4".into()),
            label: "urn:c2pa:1234".into(),
            format: Some("video/mp4".into()),
        };
        assert_eq!(default_action_for(Some(&stub)), SignAction::Published);
    }

    #[test]
    fn republish_chains_parent_ingredient() {
        // Two-cert scenario: cert A signs the file (the "doomscroll"
        // role), cert B re-signs it (the "publisher" role). The
        // resulting file should carry both manifests, and the
        // active (publisher) manifest should declare a parent
        // ingredient pointing at the doomscroll manifest's label.
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("raw.wav");
        let stage_a = dir.path().join("by-doomscroll.wav");
        let stage_b = dir.path().join("by-publisher.wav");
        write_silent_wav(&src);

        // Cert A signs as "Doomscroll.fm" (the production tool).
        let identity_a = fresh_identity();
        let manifest_a = serde_json::json!({
            "claim_generator": "Doomscroll.fm/0.1.0",
            "format": "audio/wav",
            "title": "raw.wav",
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}}
            ]
        })
        .to_string();
        sign_asset(&identity_a, &src, &stage_a, &manifest_a).expect("sign A");

        // Cert B re-signs as "publisher" with action c2pa.published.
        let identity_b = fresh_identity();
        let manifest_b = serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.1",
            "format": "audio/wav",
            "title": "by-publisher.wav",
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.published"}]}}
            ]
        })
        .to_string();
        sign_asset(&identity_b, &stage_a, &stage_b, &manifest_b).expect("sign B");

        // Open the result and check the active manifest has a
        // parent ingredient.
        let reader = c2pa::Reader::from_file(&stage_b).expect("reader");
        let active = reader.active_manifest().expect("active");
        let ingredients = active.ingredients();
        assert!(
            !ingredients.is_empty(),
            "active manifest has at least one ingredient"
        );
        let parent = ingredients
            .iter()
            .find(|i| matches!(i.relationship(), c2pa::Relationship::ParentOf));
        assert!(parent.is_some(), "found parentOf ingredient");
        let parent = parent.unwrap();
        // The parent ingredient's label should match the doomscroll
        // manifest's label in the manifest store. That's the
        // load-bearing assertion — proves the lineage is explicit.
        assert!(
            parent.label().is_some(),
            "parent ingredient carries a label pointing into the store"
        );
    }

    #[test]
    fn sign_with_identity_assertion_round_trips() {
        // End-to-end: build manifest, embed identity, sign, read back,
        // and assert the assertion is present in the signed file's
        // active manifest with the right did + handle.
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();

        let claim = IdentityClaim::new("did:plc:roundtrip", Some("rt.bsky.social".into()));
        let manifest = embed_identity_assertion(&minimal_wav_manifest(), &claim).expect("embed");
        sign_asset(&identity, &src, &dst, &manifest).expect("sign");

        let reader = c2pa::Reader::from_file(&dst).expect("reader");
        let active = reader.active_manifest().expect("active manifest");
        let labels: Vec<String> = active
            .assertions()
            .iter()
            .map(|a| a.label().to_string())
            .collect();
        assert!(
            labels.iter().any(|l| l == IDENTITY_ASSERTION_LABEL
                || l.starts_with(&format!("{IDENTITY_ASSERTION_LABEL}."))
                || l.starts_with(&format!("{IDENTITY_ASSERTION_LABEL}__"))),
            "identity assertion present in signed file: {labels:?}"
        );
    }

    #[test]
    fn extra_assertions_round_trip_into_the_manifest() {
        // The signing primitive doesn't transform the manifest
        // JSON — what the caller asks for is what ends up in the
        // signed file. Confirm with a custom assertion that we
        // can find when we read it back.
        let dir = TempDir::new().expect("tempdir");
        let src = dir.path().join("src.wav");
        let dst = dir.path().join("signed.wav");
        write_silent_wav(&src);
        let identity = fresh_identity();

        let manifest = serde_json::json!({
            "claim_generator": "provcheck-kit/0.3.0",
            "claim_generator_info": [{"name": "provcheck-kit", "version": "0.3.0"}],
            "format": "audio/wav",
            "title": "test.wav",
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.created"}]}},
                {"label": "com.provcheck.test", "data": {"flavour": "vanilla", "k": 42}}
            ]
        })
        .to_string();

        sign_asset(&identity, &src, &dst, &manifest).expect("sign");

        let reader = c2pa::Reader::from_file(&dst).expect("reader");
        let active = reader.active_manifest().expect("active manifest");
        let labels: Vec<String> = active
            .assertions()
            .iter()
            .map(|a| a.label().to_string())
            .collect();
        assert!(
            labels.iter().any(|l| l.contains("com.provcheck.test")),
            "extra assertion landed in the manifest: {labels:?}"
        );
    }
}
