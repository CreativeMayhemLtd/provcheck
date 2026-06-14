// Prevents the Windows console from appearing alongside the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

use provcheck::prelude::*;
use provcheck_attestation_spec::{IdentityClaim, SigningKeyRecord};
use provcheck_platform::{AttestationOptions, verify_with_attestation};
use provcheck_publish::AtprotoClient;
use provcheck_sign::backup::resolve_recovery_recipients;
use provcheck_sign::cert::{SubjectInfo, generate};
use provcheck_sign::persist::{default_dir, load_locked, save_public_artefacts};
use provcheck_sign::providers::{
    KeyProvider, KeychainProvider, NewPassphrasePrompt, ProviderError, UnlockPrompt,
};
use provcheck_sign::sign::{embed_identity_assertion, sign_asset};
use provcheck_sign::types::{KeyProviderKind, LockedIdentity, UnlockedIdentity};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ============================================================================
// verify_file — existing CLI-parity verify (UNCHANGED contract)
// ============================================================================

/// JSON-friendly wrapper around provcheck::Report.
#[derive(Serialize)]
struct VerifyResponse {
    ok: bool,
    error: Option<String>,
    report: Option<Report>,
}

/// Verify a file with optional DID-anchored attestation.
#[tauri::command]
fn verify_file(
    path: String,
    handle: Option<String>,
    did: Option<String>,
    require_attested: Option<bool>,
) -> VerifyResponse {
    let path = PathBuf::from(path);
    let want_attestation = handle.is_some() || did.is_some();

    let verify_result = if want_attestation {
        let attest_opts = AttestationOptions {
            bsky_handle: handle,
            did,
            require_attested: require_attested.unwrap_or(false),
            cache_dir: None,
            no_cache: false,
        };
        verify_with_attestation(&path, &VerifyOptions::default(), &attest_opts)
    } else {
        verify(&path)
    };

    match verify_result {
        Ok(mut report) => {
            if let Ok(w) = provcheck_watermark::detect(&path) {
                report.watermarks.push(w);
            }
            if let Ok(w) = provcheck_audioseal::detect(&path) {
                report.watermarks.push(w);
            }
            if let Ok(w) = provcheck_wavmark::detect(&path) {
                report.watermarks.push(w);
            }
            VerifyResponse {
                ok: true,
                error: None,
                report: Some(report),
            }
        }
        Err(e) => VerifyResponse {
            ok: false,
            error: Some(e.to_string()),
            report: None,
        },
    }
}

// ============================================================================
// Sign-tab commands. These compose provcheck-sign + provcheck-publish into the
// same flows the kit binary exposes, but driven by webview UI instead of
// rpassword prompts. Backend selection: OS keychain (KeychainProvider) by
// default — matches `kit init`. The age-file backend is reachable too via
// `kit_init` but not exposed in the GUI's first pass.
// ============================================================================

/// Identity panel data for the Sign tab. Mirrors `kit status`'s identity
/// block, minus the storage-path-display details that the GUI hides.
#[derive(Serialize)]
struct IdentitySnapshot {
    fingerprint: String,
    algorithm: String,
    /// RFC 3339.
    created_at: String,
    /// "keychain" | "encrypted_file".
    backend: String,
    /// Stamped onto identity.json by a successful kit_login. When None
    /// the identity exists but hasn't been attached to atproto yet.
    did: Option<String>,
    handle: Option<String>,
}

/// Session panel data for the Sign tab. None when no session.json on disk.
#[derive(Serialize)]
struct SessionSnapshot {
    did: String,
    handle: String,
    pds: String,
}

/// Top-level state envelope the Sign tab uses to pick which state-screen
/// to render. Computed by kit_status; cheap, no network.
#[derive(Serialize)]
struct KitStatus {
    identity: Option<IdentitySnapshot>,
    session: Option<SessionSnapshot>,
}

/// Wire-friendly version of a single published signingKey record. Mirrors
/// SigningKeyRecord + the at-uri the rkey lives at.
#[derive(Serialize)]
struct RecordSnapshot {
    at_uri: String,
    rkey: Option<String>,
    fingerprint: String,
    algorithm: String,
    /// "active" | "revoked" | "superseded".
    status: &'static str,
    created_at: String,
    label: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    superseded_by: Option<String>,
}

/// Result wrapper — the JS side checks `ok` before consuming `data`.
#[derive(Serialize)]
struct ApiResult<T: Serialize> {
    ok: bool,
    error: Option<String>,
    data: Option<T>,
}

impl<T: Serialize> ApiResult<T> {
    fn ok(data: T) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }
    fn err(msg: String) -> Self {
        Self {
            ok: false,
            error: Some(msg),
            data: None,
        }
    }
}

fn resolve_dir(override_dir: Option<String>) -> Result<PathBuf, String> {
    match override_dir {
        Some(s) => Ok(PathBuf::from(s)),
        None => default_dir().map_err(|e| format!("resolve data dir: {e}")),
    }
}

fn record_status(r: &SigningKeyRecord) -> &'static str {
    if r.superseded_by.is_some() {
        "superseded"
    } else if r.valid_until.is_some() {
        "revoked"
    } else {
        "active"
    }
}

// -------- kit_status -----------------------------------------------------

#[tauri::command]
async fn kit_status(data_dir: Option<String>) -> ApiResult<KitStatus> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };

    let identity = load_locked(&dir).ok().map(|locked| IdentitySnapshot {
        fingerprint: locked.fingerprint.clone(),
        algorithm: locked.algorithm.clone(),
        created_at: locked
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| locked.created_at.to_string()),
        backend: match locked.key_provider {
            KeyProviderKind::Keychain => "keychain".into(),
            KeyProviderKind::EncryptedFile => "encrypted_file".into(),
        },
        did: locked.did.clone(),
        handle: locked.handle.clone(),
    });

    let session = match AtprotoClient::load_session(&dir).await {
        Ok(c) => {
            let snap = c.snapshot();
            Some(SessionSnapshot {
                did: snap.did.clone(),
                handle: snap.handle.clone(),
                pds: snap.pds.clone(),
            })
        }
        Err(_) => None,
    };

    ApiResult::ok(KitStatus { identity, session })
}

// -------- kit_init -------------------------------------------------------

/// Generate a fresh ES256 identity and persist it. Backend defaults to
/// the OS keychain (no passphrase prompt needed — the OS handles its own
/// auth flow on first read).
#[tauri::command]
async fn kit_init(
    data_dir: Option<String>,
    force: Option<bool>,
) -> ApiResult<IdentitySnapshot> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };

    if !force.unwrap_or(false) && load_locked(&dir).is_ok() {
        return ApiResult::err(
            "an identity already exists at this data directory — pass force=true \
             to regenerate (this orphans any previously-published atproto records)"
                .to_string(),
        );
    }

    let kp = match generate(&SubjectInfo::default()) {
        Ok(k) => k,
        Err(e) => return ApiResult::err(format!("generate keypair: {e}")),
    };

    let locked = LockedIdentity {
        chain_pem: kp.chain_pem.clone(),
        fingerprint: kp.fingerprint.clone(),
        algorithm: kp.algorithm.clone(),
        did: None,
        handle: None,
        created_at: OffsetDateTime::now_utc(),
        key_provider: KeyProviderKind::Keychain,
        recovery_recipients: vec![],
    };

    // No passphrase prompt — the keychain provider stashes via the OS
    // backend, which has its own auth surface.
    let mut prompt =
        |_: NewPassphrasePrompt| -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(String::new()))
        };
    if let Err(e) = KeychainProvider::new().store(
        &dir,
        &locked.fingerprint,
        &SecretString::from(kp.key_pem.clone()),
        &mut prompt,
    ) {
        return ApiResult::err(format!("store key in OS keychain: {e}"));
    }
    if let Err(e) = save_public_artefacts(&dir, &locked) {
        return ApiResult::err(format!("save identity.json: {e}"));
    }

    ApiResult::ok(IdentitySnapshot {
        fingerprint: locked.fingerprint,
        algorithm: locked.algorithm,
        created_at: locked
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| locked.created_at.to_string()),
        backend: "keychain".into(),
        did: None,
        handle: None,
    })
}

// -------- kit_login -------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginArgs {
    handle: String,
    app_password: String,
    pds: Option<String>,
    data_dir: Option<String>,
}

#[tauri::command]
async fn kit_login(args: LoginArgs) -> ApiResult<SessionSnapshot> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let pds = args.pds.unwrap_or_else(|| "https://bsky.social".into());

    let client = match AtprotoClient::login(&pds, &args.handle, &args.app_password).await
    {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("atproto login: {e}")),
    };
    if let Err(e) = client.save_session(&dir).await {
        return ApiResult::err(format!("persist session: {e}"));
    }

    // Stamp did + handle on identity.json so subsequent sign --embed-identity
    // has them without round-tripping login. Best-effort: if no identity
    // is present locally, skip silently.
    if let Ok(mut locked) = load_locked(&dir) {
        let snap = client.snapshot();
        locked.did = Some(snap.did.clone());
        locked.handle = Some(snap.handle.clone());
        let _ = save_public_artefacts(&dir, &locked);
    }

    let snap = client.snapshot();
    ApiResult::ok(SessionSnapshot {
        did: snap.did.clone(),
        handle: snap.handle.clone(),
        pds: snap.pds.clone(),
    })
}

// -------- kit_logout ------------------------------------------------------

#[tauri::command]
async fn kit_logout(data_dir: Option<String>) -> ApiResult<()> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    match AtprotoClient::logout(&dir) {
        Ok(()) => ApiResult::ok(()),
        Err(e) => ApiResult::err(format!("delete session.json: {e}")),
    }
}

// -------- kit_publish -----------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishArgs {
    label: Option<String>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct PublishResult {
    at_uri: String,
    fingerprint: String,
}

#[tauri::command]
async fn kit_publish(args: PublishArgs) -> ApiResult<PublishResult> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let locked = match load_locked(&dir) {
        Ok(l) => l,
        Err(e) => return ApiResult::err(format!("load identity: {e}")),
    };
    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session — run kit_login first: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);

    // Guard against duplicates: refuse if a record with this fingerprint
    // is already in the repo (rotate is the path for a fresh fingerprint).
    let existing = match writer.list_signing_keys().await {
        Ok(v) => v,
        Err(e) => return ApiResult::err(format!("atproto list: {e}")),
    };
    if existing
        .iter()
        .any(|(_, r)| r.fingerprint == locked.fingerprint)
    {
        return ApiResult::err(format!(
            "a record with fingerprint {} already exists in your repo",
            locked.fingerprint
        ));
    }

    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    let record = SigningKeyRecord {
        created_at,
        fingerprint: locked.fingerprint.clone(),
        algorithm: locked.algorithm.clone(),
        label: args.label,
        valid_from: None,
        valid_until: None,
        superseded_by: None,
    };
    let at_uri = match writer.publish_signing_key(&record).await {
        Ok(u) => u,
        Err(e) => return ApiResult::err(format!("atproto publish_signing_key: {e}")),
    };
    let _ = client.save_session(&dir).await;

    ApiResult::ok(PublishResult {
        at_uri: at_uri.as_str().to_string(),
        fingerprint: locked.fingerprint,
    })
}

// -------- kit_list --------------------------------------------------------

#[tauri::command]
async fn kit_list(data_dir: Option<String>) -> ApiResult<Vec<RecordSnapshot>> {
    let dir = match resolve_dir(data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let client = match AtprotoClient::load_session(&dir).await {
        Ok(c) => c,
        Err(e) => return ApiResult::err(format!("load session: {e}")),
    };
    let writer = provcheck_publish::RecordWriter::new(&client);
    let records = match writer.list_signing_keys().await {
        Ok(v) => v,
        Err(e) => return ApiResult::err(format!("atproto list: {e}")),
    };

    let snapshots = records
        .into_iter()
        .map(|(uri, r)| RecordSnapshot {
            at_uri: uri.as_str().to_string(),
            rkey: uri.rkey().map(|s| s.to_string()),
            fingerprint: r.fingerprint.clone(),
            algorithm: r.algorithm.clone(),
            status: record_status(&r),
            created_at: r.created_at.clone(),
            label: r.label.clone(),
            valid_from: r.valid_from.clone(),
            valid_until: r.valid_until.clone(),
            superseded_by: r.superseded_by.clone(),
        })
        .collect();

    ApiResult::ok(snapshots)
}

// -------- kit_sign --------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignArgs {
    file: String,
    /// When None → sidecar `<stem>.signed.<ext>` next to source.
    /// When Some → write to this path (must differ from `file` AND share extension).
    out: Option<String>,
    embed_identity: Option<bool>,
    data_dir: Option<String>,
}

#[derive(Serialize)]
struct SignResultDto {
    output_path: String,
    manifest_bytes: usize,
    identity_embedded: Option<String>,
}

#[tauri::command]
async fn kit_sign(args: SignArgs) -> ApiResult<SignResultDto> {
    let dir = match resolve_dir(args.data_dir) {
        Ok(d) => d,
        Err(e) => return ApiResult::err(e),
    };
    let locked = match load_locked(&dir) {
        Ok(l) => l,
        Err(e) => return ApiResult::err(format!("load identity: {e}")),
    };

    // Unlock — keychain backend has no passphrase prompt from our side
    // (OS handles it). EncryptedFile backend would need a passphrase UI
    // which is a follow-up — for v1 we only run the GUI flow against
    // keychain-backed identities.
    let mut prompt =
        |_: UnlockPrompt| -> Result<SecretString, ProviderError> {
            Ok(SecretString::from(String::new()))
        };
    let key_pem = match locked.key_provider {
        KeyProviderKind::Keychain => {
            match KeychainProvider::new().fetch(&dir, &locked.fingerprint, &mut prompt) {
                Ok(k) => k,
                Err(e) => return ApiResult::err(format!("fetch key: {e}")),
            }
        }
        KeyProviderKind::EncryptedFile => {
            return ApiResult::err(
                "GUI signing currently supports OS-keychain identities only. \
                 Use `provcheck-kit sign` from the CLI for age-file identities."
                    .to_string(),
            );
        }
    };
    let unlocked = UnlockedIdentity::new(locked.clone(), key_pem);

    let src = PathBuf::from(&args.file);
    let dst = match args.out.as_ref() {
        Some(p) => PathBuf::from(p),
        None => sidecar_signed_path(&src),
    };

    let base_manifest = match default_manifest(&src) {
        Ok(m) => m,
        Err(e) => return ApiResult::err(e),
    };
    let embed = args.embed_identity.unwrap_or(true);
    let (manifest_json, embedded_did) = if embed {
        match locked.did.as_ref() {
            Some(did) => {
                let claim = IdentityClaim::new(did.clone(), locked.handle.clone());
                match embed_identity_assertion(&base_manifest, &claim) {
                    Ok(m) => (m, Some(did.clone())),
                    Err(e) => {
                        return ApiResult::err(format!("embed identity assertion: {e}"));
                    }
                }
            }
            None => {
                return ApiResult::err(
                    "embed-identity requires a DID — run kit_login first".to_string(),
                );
            }
        }
    } else {
        (base_manifest, None)
    };

    let result = match sign_asset(&unlocked, &src, &dst, &manifest_json) {
        Ok(r) => r,
        Err(e) => return ApiResult::err(format!("c2pa sign: {e}")),
    };

    ApiResult::ok(SignResultDto {
        output_path: result.output_path.to_string_lossy().into_owned(),
        manifest_bytes: result.manifest_bytes.len(),
        identity_embedded: embedded_did,
    })
}

fn sidecar_signed_path(src: &Path) -> PathBuf {
    let parent = src.parent();
    let stem = src
        .file_stem()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("signed"));
    let ext = src.extension();
    let mut name = stem;
    name.push(".signed");
    if let Some(e) = ext {
        name.push(".");
        name.push(e);
    }
    match parent {
        Some(p) if !p.as_os_str().is_empty() => p.join(name),
        _ => PathBuf::from(name),
    }
}

fn default_manifest(asset: &Path) -> Result<String, String> {
    let format = format_from_extension(asset)
        .ok_or_else(|| "unrecognised file extension — custom manifest needed".to_string())?;
    let title = asset
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled");
    let v = serde_json::json!({
        "claim_generator": "provcheck-app/0.3.0",
        "claim_generator_info": [{"name": "provcheck-app", "version": "0.3.0"}],
        "format": format,
        "title": title,
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {"actions": [{"action": "c2pa.created"}]}
            }
        ]
    });
    Ok(v.to_string())
}

fn format_from_extension(p: &Path) -> Option<&'static str> {
    let ext = p.extension().and_then(|s| s.to_str())?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "tif" | "tiff" => "image/tiff",
        "webp" => "image/webp",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        _ => return None,
    })
}

// ============================================================================
// main
// ============================================================================

fn main() {
    // resolve_recovery_recipients is unused in pass 1 but pulled in by the
    // backup module's surface — silence the dead-code warning. Drops naturally
    // when the backup UI lands.
    let _ = resolve_recovery_recipients as fn(&[provcheck_sign::types::RecoveryRecipient]) -> _;
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            verify_file,
            kit_status,
            kit_init,
            kit_login,
            kit_logout,
            kit_publish,
            kit_list,
            kit_sign,
        ])
        .run(tauri::generate_context!())
        .expect("error while running provcheck-app");
}
