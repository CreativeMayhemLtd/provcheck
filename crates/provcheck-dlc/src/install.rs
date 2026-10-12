// SPDX-License-Identifier: Apache-2.0
//! The DLC install surface — the signed-manifest pack pull + the on-disk seat
//! license store/status/unlock. Ported from Lysn.fm's `lysn-desktop-core` DLC
//! module.
//!
//! The Apache binary ships none of a pack's payload. A pack is pulled on demand
//! and gated on an offline-verifiable seat license ([`crate::ProLicense`]) — one
//! more signed record checked against the pinned Creative Mayhem key, no server.
//! The pull reuses SHA-256 verification per file AND adds a signature over the
//! whole manifest, closing the "compromised CDN rewrites file + sum together"
//! gap: a CDN cannot forge the manifest signature without the offline key.
//!
//! This module is behind the default `install` feature (it needs ureq + dirs).
//! The verify-only types ([`crate::ProLicense`], [`crate::catalog`]) are always
//! available.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::license::{self, DLC_MANIFEST_DOMAIN, DlcInfo, LICENSE_ISSUER_DID, ProLicense};
use crate::sign;

// ─────────────────────── on-disk layout ───────────────────────

/// The per-user DLC home. `$PROVCHECK_DLC_HOME` overrides; otherwise
/// `dirs::data_dir()/provcheck/dlc` (durable data, not the weights *cache*):
/// `%APPDATA%\provcheck\dlc` on Windows, `~/.local/share/provcheck/dlc` on Linux,
/// `~/Library/Application Support/provcheck/dlc` on macOS.
pub fn default_home() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("PROVCHECK_DLC_HOME") {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::data_dir()
        .ok_or("could not resolve a data directory on this platform; set PROVCHECK_DLC_HOME")?;
    Ok(base.join("provcheck").join("dlc"))
}

fn dlc_root(home: &Path) -> PathBuf {
    home.join("dlc")
}
/// Where a product's stored seat license lives.
fn dlc_license_path(home: &Path, product: &str) -> PathBuf {
    dlc_root(home)
        .join("licenses")
        .join(format!("{product}.json"))
}
/// Where a product's installed pack payload lives.
pub fn dlc_pack_dir(home: &Path, product: &str) -> PathBuf {
    dlc_root(home).join("packs").join(product)
}

/// The install/license state of one DLC pack, for the app to render.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DlcStatus {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub requires_license: bool,
    /// A valid, holder-bound seat license is stored for this pack.
    pub licensed: bool,
    /// The pack payload is present on disk.
    pub installed: bool,
    pub approx_bytes: u64,
    pub default_source: String,
}

// ─────────────────────── signature + integrity helpers ───────────────────────

/// Verify `sig_b58` is `issuer`'s detached signature over the manifest bytes
/// (domain-separated): the upgrade from same-origin trust to signed trust.
fn verify_signed_sums(issuer: &str, sums_bytes: &[u8], sig_b58: &str) -> Result<(), String> {
    let mut msg = DLC_MANIFEST_DOMAIN.to_vec();
    msg.extend_from_slice(sums_bytes);
    sign::verify_sig(issuer, &msg, sig_b58).map_err(|e| format!("pack manifest signature: {e}"))
}

/// Parse a `SHA256SUMS` file into `name -> lowercase-hex-hash`. Blank lines and
/// `#` comments ignored; a leading `*` (binary marker) on the name is stripped.
fn parse_sha256sums(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        if let (Some(hash), Some(rest)) = (it.next(), it.next()) {
            let name = rest.trim_start().trim_start_matches('*').trim();
            if !hash.is_empty() && !name.is_empty() {
                map.insert(name.to_string(), hash.to_ascii_lowercase());
            }
        }
    }
    map
}

/// SHA-256 of a file as lowercase hex, streamed (never buffered whole).
fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read as _;
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Verify a freshly downloaded `.part` against the manifest BEFORE it is renamed
/// into place. Fail-closed on every path (absent from manifest, unreadable, hash
/// mismatch): delete the `.part` and return Err so nothing bad ever lands.
fn verify_against_manifest(
    part: &Path,
    name: &str,
    sums: &HashMap<String, String>,
) -> Result<(), String> {
    let expected = match sums.get(name) {
        Some(h) => h,
        None => {
            let _ = std::fs::remove_file(part);
            return Err(format!(
                "integrity: {name} is not listed in SHA256SUMS — refusing (fail-closed)"
            ));
        }
    };
    let got = match sha256_file(part) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(part);
            return Err(e);
        }
    };
    if &got != expected {
        let _ = std::fs::remove_file(part);
        return Err(format!(
            "integrity: SHA-256 mismatch for {name} (expected {expected}, got {got}) — refusing (fail-closed)"
        ));
    }
    Ok(())
}

/// Fetch a small text file (the manifest or its signature) over the same
/// transport as the payload.
fn fetch_text(base: &str, name: &str, is_http: bool) -> Result<String, String> {
    if is_http {
        let url = format!("{base}/{name}");
        ureq::get(&url)
            .call()
            .map_err(|e| format!("GET {url}: {e}"))?
            .into_string()
            .map_err(|e| format!("read {name}: {e}"))
    } else {
        let p = Path::new(base).join(name);
        std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
    }
}

// ─────────────────────── license store / status / unlock ───────────────────────

/// A stored license unlocks `product` for `my_did`: signed by `expected_issuer`,
/// unlocks that product, bound to this identity. Any failure → not licensed.
/// (Expiry is not enforced here — v1 issues perpetual licenses.)
fn licensed_for_with(home: &Path, product: &str, my_did: &str, expected_issuer: &str) -> bool {
    let path = dlc_license_path(home, product);
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(lic) = serde_json::from_str::<ProLicense>(&raw) else {
        return false;
    };
    lic.subject == my_did && lic.authorize_with(expected_issuer, product, None).is_ok()
}

/// A pack is installed if its dir holds at least one payload file (ignoring the
/// manifest + signature).
fn pack_installed(home: &Path, product: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(dlc_pack_dir(home, product)) else {
        return false;
    };
    rd.flatten().any(|e| {
        let name = e.file_name();
        let n = name.to_string_lossy();
        n != "SHA256SUMS" && n != "SHA256SUMS.sig" && e.path().is_file()
    })
}

fn status_from(home: &Path, d: DlcInfo, my_did: &str, expected_issuer: &str) -> DlcStatus {
    DlcStatus {
        licensed: licensed_for_with(home, &d.id, my_did, expected_issuer),
        installed: pack_installed(home, &d.id),
        id: d.id,
        name: d.name,
        summary: d.summary,
        requires_license: d.requires_license,
        approx_bytes: d.approx_bytes,
        default_source: d.default_source,
    }
}

/// The status of every known DLC pack for this seat identity.
pub fn dlc_status(home: &Path, my_did: &str) -> Vec<DlcStatus> {
    dlc_status_with(home, my_did, LICENSE_ISSUER_DID)
}
fn dlc_status_with(home: &Path, my_did: &str, expected_issuer: &str) -> Vec<DlcStatus> {
    license::catalog()
        .into_iter()
        .map(|d| status_from(home, d, my_did, expected_issuer))
        .collect()
}

/// Store a seat license after verifying it belongs to this identity and unlocks
/// a known pack. `my_did` is this seat's did; the license subject must match, so
/// it is a per-identity unlock, not a shareable bearer token. Returns the pack's
/// updated status.
pub fn dlc_unlock(home: &Path, license_json: &str, my_did: &str) -> Result<DlcStatus, String> {
    dlc_unlock_with(home, license_json, my_did, LICENSE_ISSUER_DID)
}
fn dlc_unlock_with(
    home: &Path,
    license_json: &str,
    my_did: &str,
    expected_issuer: &str,
) -> Result<DlcStatus, String> {
    let lic: ProLicense =
        serde_json::from_str(license_json).map_err(|e| format!("not a valid license: {e}"))?;
    if !license::catalog().iter().any(|d| d.id == lic.product) {
        return Err(format!("license is for an unknown pack '{}'", lic.product));
    }
    if lic.subject != my_did {
        return Err("this license was issued to a different identity".into());
    }
    lic.authorize_with(expected_issuer, &lic.product, None)
        .map_err(|e| format!("license rejected: {e}"))?;
    let path = dlc_license_path(home, &lic.product);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dlc dir: {e}"))?;
    }
    std::fs::write(&path, license_json).map_err(|e| format!("store license: {e}"))?;
    Ok(status_from(
        home,
        license::catalog()
            .into_iter()
            .find(|d| d.id == lic.product)
            .expect("in catalog"),
        my_did,
        expected_issuer,
    ))
}

/// Install a DLC pack: require a valid license (if the pack needs one), then
/// download every file the pack's SIGNED `SHA256SUMS` lists, verifying each hash
/// and refusing on any mismatch.
pub fn dlc_install(
    home: &Path,
    product: &str,
    source: &str,
    my_did: &str,
) -> Result<String, String> {
    dlc_install_with(home, product, source, my_did, LICENSE_ISSUER_DID)
}
fn dlc_install_with(
    home: &Path,
    product: &str,
    source: &str,
    my_did: &str,
    expected_issuer: &str,
) -> Result<String, String> {
    let info = license::catalog()
        .into_iter()
        .find(|d| d.id == product)
        .ok_or_else(|| format!("unknown pack '{product}'"))?;
    if info.requires_license && !licensed_for_with(home, product, my_did, expected_issuer) {
        return Err("this pack requires a Pro (seat) license — unlock it first".into());
    }
    let dest = dlc_pack_dir(home, product);
    let n = pull_pack(source, &dest, expected_issuer)?;
    Ok(format!(
        "installed {product}: {:.1} MB. Restart to activate.",
        n as f64 / 1e6
    ))
}

/// Offline-verify an already-assembled or already-installed pack directory
/// against `issuer`: the detached `SHA256SUMS.sig` must be `issuer`'s signature
/// over the manifest, and every file the manifest lists must be present with a
/// matching SHA-256. No network. Returns the number of payload files verified.
///
/// This is the same check `pull_pack` runs on download, exposed so a pack can be
/// re-verified after the fact (e.g. before a run, or to prove an offline-signed
/// pack from `dlc-issue pack-sign` is well-formed).
pub fn verify_pack_dir(dir: &Path, issuer: &str) -> Result<usize, String> {
    let sums_text = std::fs::read_to_string(dir.join("SHA256SUMS"))
        .map_err(|e| format!("read SHA256SUMS: {e}"))?;
    let sig = std::fs::read_to_string(dir.join("SHA256SUMS.sig"))
        .map_err(|e| format!("read SHA256SUMS.sig: {e}"))?;
    verify_signed_sums(issuer, sums_text.as_bytes(), sig.trim())?;
    let sums = parse_sha256sums(&sums_text);
    if sums.is_empty() {
        return Err("pack manifest lists no files — refusing (fail-closed)".into());
    }
    let mut verified = 0usize;
    for (name, expected) in &sums {
        if name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
            continue;
        }
        let got = sha256_file(&dir.join(name))?;
        if &got != expected {
            return Err(format!(
                "integrity: SHA-256 mismatch for {name} (expected {expected}, got {got})"
            ));
        }
        verified += 1;
    }
    Ok(verified)
}

/// Download a DLC pack from `source` (an https mirror or a local/UNC folder) into
/// `dest`. The pack serves its files by name plus a `SHA256SUMS` manifest and a
/// `SHA256SUMS.sig` detached signature. Fail-closed: plaintext http is refused;
/// the manifest signature (by `issuer`) is verified FIRST; then every listed file
/// is downloaded and hash-verified before it lands. Files already present are
/// skipped, so a partial pull resumes at file granularity. Returns bytes pulled.
fn pull_pack(source: &str, dest: &Path, issuer: &str) -> Result<u64, String> {
    let source = source.trim();
    if source.is_empty() {
        return Err("no pack source configured — give an https URL or a folder / UNC path".into());
    }
    if source.starts_with("http://") {
        return Err(
            "refusing plaintext http:// pack source — use https:// or a local/UNC folder path"
                .into(),
        );
    }
    std::fs::create_dir_all(dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let is_http = source.starts_with("https://");
    let base = source.trim_end_matches(['/', '\\']);

    // 1) Manifest + detached signature, verified against the pinned issuer before
    //    ANY file is trusted.
    let sums_text = fetch_text(base, "SHA256SUMS", is_http)?;
    let sig = fetch_text(base, "SHA256SUMS.sig", is_http)?;
    verify_signed_sums(issuer, sums_text.as_bytes(), sig.trim())?;
    let sums = parse_sha256sums(&sums_text);
    if sums.is_empty() {
        return Err("pack manifest lists no files — refusing (fail-closed)".into());
    }

    // 2) Every listed payload file: download, hash-verify, land.
    let mut total = 0u64;
    for name in sums.keys() {
        if name == "SHA256SUMS" || name == "SHA256SUMS.sig" {
            continue;
        }
        let out = dest.join(name);
        if out.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            continue; // resume at file granularity
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let tmp = dest.join(format!("{name}.part"));
        let n = if is_http {
            let url = format!("{base}/{name}");
            let resp = ureq::get(&url)
                .call()
                .map_err(|e| format!("GET {url}: {e}"))?;
            let mut w = std::fs::File::create(&tmp)
                .map_err(|e| format!("create {}: {e}", tmp.display()))?;
            std::io::copy(&mut resp.into_reader(), &mut w)
                .map_err(|e| format!("download {name}: {e}"))?
        } else {
            let src = Path::new(base).join(name);
            std::fs::copy(&src, &tmp).map_err(|e| format!("copy {}: {e}", src.display()))?
        };
        verify_against_manifest(&tmp, name, &sums)?;
        std::fs::rename(&tmp, &out).map_err(|e| format!("finalize {name}: {e}"))?;
        total += n;
    }
    // Keep the signed manifest alongside for later re-verification.
    std::fs::write(dest.join("SHA256SUMS"), &sums_text).ok();
    std::fs::write(dest.join("SHA256SUMS.sig"), sig.trim()).ok();
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::DLC_PRO_WATERMARKING;
    use crate::sign::{DomainSigned, did_key_from_verifying, sign_bytes};
    use ed25519_dalek::SigningKey;

    fn issuer() -> (SigningKey, String) {
        let k = SigningKey::from_bytes(&[11u8; 32]);
        let did = did_key_from_verifying(&k.verifying_key());
        (k, did)
    }

    fn signed_license(k: &SigningKey, issuer_did: &str, subject: &str, product: &str) -> String {
        let mut lic = ProLicense {
            issuer: issuer_did.to_string(),
            product: product.to_string(),
            subject: subject.to_string(),
            issued_at: "2026-08-19T12:00:00Z".to_string(),
            expires_at: None,
            sig: None,
        };
        lic.sign(k).unwrap();
        serde_json::to_string(&lic).unwrap()
    }

    /// Sign a `SHA256SUMS` blob the way the offline issuer does (domain-separated).
    fn sign_sums(k: &SigningKey, sums: &str) -> String {
        let mut msg = DLC_MANIFEST_DOMAIN.to_vec();
        msg.extend_from_slice(sums.as_bytes());
        sign_bytes(k, &msg)
    }

    #[test]
    fn unlock_stores_a_valid_license_and_status_reflects_it() {
        let home = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";
        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);

        let st = dlc_unlock_with(home.path(), &lic, me, &iss).unwrap();
        assert!(st.licensed);
        assert!(!st.installed);

        let all = dlc_status_with(home.path(), me, &iss);
        assert!(
            all.iter()
                .find(|d| d.id == DLC_PRO_WATERMARKING)
                .unwrap()
                .licensed
        );
    }

    #[test]
    fn unlock_rejects_a_license_for_another_identity() {
        let home = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let lic = signed_license(&k, &iss, "did:key:z6MkOther", DLC_PRO_WATERMARKING);
        assert!(dlc_unlock_with(home.path(), &lic, "did:key:z6MkMe", &iss).is_err());
    }

    #[test]
    fn unlock_rejects_a_tampered_license() {
        let home = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";
        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);
        let tampered = lic.replace("2026-08-19T12:00:00Z", "2030-01-01T00:00:00Z");
        assert!(dlc_unlock_with(home.path(), &tampered, me, &iss).is_err());
    }

    #[test]
    fn unlock_fails_closed_against_the_unset_production_issuer() {
        let home = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";
        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);
        // Real entrypoint: pinned issuer is still the placeholder → rejected.
        assert!(dlc_unlock(home.path(), &lic, me).is_err());
    }

    #[test]
    fn install_refuses_a_bad_source_but_proves_the_license_gate_opens() {
        let home = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";
        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);
        dlc_unlock_with(home.path(), &lic, me, &iss).unwrap();
        // Licensed, so the gate opens and we fail later on the empty/absent source.
        let err = dlc_install_with(
            home.path(),
            DLC_PRO_WATERMARKING,
            "\\\\nope\\share",
            me,
            &iss,
        )
        .unwrap_err();
        assert!(
            !err.contains("requires a Pro"),
            "gate should be open: {err}"
        );
    }

    #[test]
    fn install_is_blocked_without_a_license() {
        let home = tempfile::tempdir().unwrap();
        let (_k, iss) = issuer();
        let err = dlc_install_with(
            home.path(),
            DLC_PRO_WATERMARKING,
            "\\\\nope\\share",
            "did:key:z6MkMe",
            &iss,
        )
        .unwrap_err();
        assert!(
            err.contains("requires a Pro"),
            "expected the license gate: {err}"
        );
    }

    #[test]
    fn full_pull_verifies_the_signed_manifest_and_installs_from_a_local_folder() {
        // Stand up a local "CDN" folder with a payload file + a signed manifest,
        // then prove the license-gated install pulls + verifies it end to end.
        let home = tempfile::tempdir().unwrap();
        let cdn = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";

        // Payload: a stand-in for the provcheck-mellin binary.
        let payload = b"pretend this is the keyed-tools binary\n";
        std::fs::write(cdn.path().join("tools.bin"), payload).unwrap();
        let hash = sha256_file(&cdn.path().join("tools.bin")).unwrap();
        let sums = format!("{hash}  tools.bin\n");
        std::fs::write(cdn.path().join("SHA256SUMS"), &sums).unwrap();
        std::fs::write(cdn.path().join("SHA256SUMS.sig"), sign_sums(&k, &sums)).unwrap();

        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);
        dlc_unlock_with(home.path(), &lic, me, &iss).unwrap();
        dlc_install_with(
            home.path(),
            DLC_PRO_WATERMARKING,
            cdn.path().to_str().unwrap(),
            me,
            &iss,
        )
        .unwrap();

        // Payload landed + verified; status now reports installed.
        let dest = dlc_pack_dir(home.path(), DLC_PRO_WATERMARKING);
        assert_eq!(std::fs::read(dest.join("tools.bin")).unwrap(), payload);
        assert!(pack_installed(home.path(), DLC_PRO_WATERMARKING));
    }

    #[test]
    fn full_pull_refuses_a_forged_manifest() {
        let home = tempfile::tempdir().unwrap();
        let cdn = tempfile::tempdir().unwrap();
        let (k, iss) = issuer();
        let me = "did:key:z6MkMe";

        let payload = b"payload\n";
        std::fs::write(cdn.path().join("tools.bin"), payload).unwrap();
        let hash = sha256_file(&cdn.path().join("tools.bin")).unwrap();
        let sums = format!("{hash}  tools.bin\n");
        std::fs::write(cdn.path().join("SHA256SUMS"), &sums).unwrap();
        // Signature by an ATTACKER key, not the pinned issuer.
        let attacker = SigningKey::from_bytes(&[99u8; 32]);
        std::fs::write(
            cdn.path().join("SHA256SUMS.sig"),
            sign_sums(&attacker, &sums),
        )
        .unwrap();

        let lic = signed_license(&k, &iss, me, DLC_PRO_WATERMARKING);
        dlc_unlock_with(home.path(), &lic, me, &iss).unwrap();
        let err = dlc_install_with(
            home.path(),
            DLC_PRO_WATERMARKING,
            cdn.path().to_str().unwrap(),
            me,
            &iss,
        )
        .unwrap_err();
        assert!(
            err.contains("manifest signature"),
            "expected a signature refusal: {err}"
        );
    }
}
