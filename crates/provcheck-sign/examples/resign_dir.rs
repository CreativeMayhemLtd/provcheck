//! resign_dir — batch re-sign every .mp3 / .wav in a directory using
//! an external (key.pem, cert.pem) pair. Bypasses provcheck-kit's
//! managed-identity flow so we can sign with an arbitrary key + cert
//! pair without disturbing the local kit identity.
//!
//! Use case: one-shot re-signing of an existing batch of files to fix
//! the visible C2PA signer name (e.g. switch the cert subject CN from
//! "Local Content Signer" to "info@raidio.bot").
//!
//! Run:
//!     cargo run --release -p provcheck-sign --example resign_dir -- \
//!         --key /path/to/key.pem \
//!         --cert /path/to/cert.pem \
//!         --dir /path/to/folder/of/audio \
//!         --claim-generator "rAIdio.bot/1.0" \
//!         --action published
//!
//! Each file is signed in place via a sibling temp file
//! (`<stem>.resigned-tmp.<ext>`); on success the temp file replaces
//! the original. The original's existing C2PA manifest becomes a
//! `parentOf` ingredient of the new signature when the auto-chain
//! path in `sign_asset_with_signer` sees one. A `.orig` backup is
//! taken once per file before the swap so a botched run can be
//! reversed file-by-file.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use provcheck_sign::cert::{generate as generate_keypair, SubjectInfo};
use provcheck_sign::sign::{parse_algorithm, sign_asset_with_signer};

#[derive(Debug)]
struct Args {
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
    dir: PathBuf,
    cn: String,
    org: String,
    ca_cn: String,
    claim_generator: String,
    action: String,
    backup: bool,
    mint_save: Option<PathBuf>,
    identity_did: Option<String>,
    identity_handle: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = env::args().skip(1);
    let mut key = None;
    let mut cert = None;
    let mut dir = None;
    let mut cn = "info@raidio.bot".to_string();
    let mut org = "rAIdio.bot".to_string();
    let mut ca_cn = "rAIdio.bot Local Install CA".to_string();
    let mut claim_generator = "provcheck-resign/0.5.3".to_string();
    let mut action = "c2pa.published".to_string();
    let mut backup = true;
    let mut mint_save = None;
    let mut identity_did: Option<String> = None;
    let mut identity_handle: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => key = args.next().map(PathBuf::from),
            "--cert" => cert = args.next().map(PathBuf::from),
            "--dir" => dir = args.next().map(PathBuf::from),
            "--cn" => cn = args.next().ok_or("--cn needs a value")?,
            "--org" => org = args.next().ok_or("--org needs a value")?,
            "--ca-cn" => ca_cn = args.next().ok_or("--ca-cn needs a value")?,
            "--claim-generator" => {
                claim_generator = args.next().ok_or("--claim-generator needs a value")?
            }
            "--action" => action = normalize_action(&args.next().ok_or("--action needs a value")?),
            "--no-backup" => backup = false,
            "--mint-save" => mint_save = args.next().map(PathBuf::from),
            "--identity-did" => identity_did = args.next(),
            "--identity-handle" => identity_handle = args.next(),
            "-h" | "--help" => {
                eprintln!(
                    "usage: resign_dir [--key key.pem --cert cert.pem | --cn CN --org ORG] \
                     --dir <folder> \
                     [--claim-generator NAME] [--action created|opened|edited|published] \
                     [--no-backup] [--mint-save <dir>]\n\
                     \n\
                     With --key + --cert: reuse an external key + cert chain.\n\
                     Without them: mint a fresh ES256 keypair + cert chain via\n\
                     provcheck-sign::cert::generate using --cn/--org/--ca-cn for\n\
                     the subject info. Pass --mint-save <dir> to persist the\n\
                     minted (key.pem, chain.pem) for future re-signs."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        key,
        cert,
        dir: dir.ok_or("--dir required")?,
        cn,
        org,
        ca_cn,
        claim_generator,
        action,
        backup,
        mint_save,
        identity_did,
        identity_handle,
    })
}

fn normalize_action(s: &str) -> String {
    if s.starts_with("c2pa.") {
        s.to_string()
    } else {
        format!("c2pa.{s}")
    }
}

fn format_from_ext(p: &Path) -> Option<&'static str> {
    let ext = p.extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "ogg" | "oga" => "audio/ogg",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        _ => return None,
    })
}

fn build_manifest(
    asset: &Path,
    claim_generator: &str,
    action: &str,
    identity_did: Option<&str>,
    identity_handle: Option<&str>,
) -> String {
    let title = asset
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("untitled");
    let format = format_from_ext(asset).unwrap_or("application/octet-stream");
    let mut assertions = vec![serde_json::json!({
        "label": "c2pa.actions.v2",
        "data": {"actions": [{"action": action}]}
    })];
    if let Some(did) = identity_did {
        let mut data = serde_json::json!({
            "version": 1,
            "did": did,
        });
        if let Some(h) = identity_handle {
            data["handle"] = serde_json::Value::String(h.to_string());
        }
        assertions.push(serde_json::json!({
            "label": "app.provcheck.identity",
            "data": data
        }));
    }
    serde_json::json!({
        "claim_generator": claim_generator,
        "claim_generator_info": [{"name": claim_generator}],
        "format": format,
        "title": title,
        "assertions": assertions
    })
    .to_string()
}

fn detect_alg_from_cert(cert_pem: &str) -> &'static str {
    // Heuristic: the rAIdio.bot leaf is ES256 and that's what every
    // file we are re-signing started with. A future caller signing
    // with PS256 / Ed25519 should pass --alg explicitly; for now
    // hardcode ES256 since the alternative is parsing the PEM SPKI
    // which is a non-trivial Rust addition for a one-off batch tool.
    let _ = cert_pem; // suppress unused warning
    "ES256"
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    let (key_pem, cert_pem, alg_str) = match (&args.key, &args.cert) {
        (Some(k), Some(c)) => {
            let key_pem = match fs::read_to_string(k) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error reading --key {}: {e}", k.display());
                    std::process::exit(2);
                }
            };
            let cert_pem = match fs::read_to_string(c) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error reading --cert {}: {e}", c.display());
                    std::process::exit(2);
                }
            };
            let alg = detect_alg_from_cert(&cert_pem);
            (key_pem, cert_pem, alg.to_string())
        }
        (None, None) => {
            // Mint a fresh keypair + chain via provcheck-sign so the
            // cert structure matches what c2pa-rs expects.
            let subject = SubjectInfo {
                common_name: args.cn.clone(),
                organisation: args.org.clone(),
                ca_common_name: args.ca_cn.clone(),
            };
            let kp = match generate_keypair(&subject) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("mint keypair failed: {e}");
                    std::process::exit(2);
                }
            };
            println!(
                "minted fresh ES256 chain: CN={} O={} fp={}",
                subject.common_name, subject.organisation, kp.fingerprint
            );
            if let Some(save_dir) = &args.mint_save {
                let _ = fs::create_dir_all(save_dir);
                let key_path = save_dir.join("key.pem");
                let chain_path = save_dir.join("chain.pem");
                let _ = fs::write(&key_path, &kp.key_pem);
                let _ = fs::write(&chain_path, &kp.chain_pem);
                println!(
                    "  saved key={} chain={}",
                    key_path.display(),
                    chain_path.display()
                );
            }
            (kp.key_pem, kp.chain_pem, kp.algorithm)
        }
        _ => {
            eprintln!("error: --key and --cert must be specified together (or both omitted to mint)");
            std::process::exit(2);
        }
    };
    let alg = match parse_algorithm(&alg_str) {
        Some(a) => a,
        None => {
            eprintln!("unsupported algorithm {alg_str}");
            std::process::exit(2);
        }
    };

    let signer = match c2pa::create_signer::from_keys(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        alg,
        None,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("create_signer: {e}");
            std::process::exit(2);
        }
    };

    let mut entries: Vec<PathBuf> = match fs::read_dir(&args.dir) {
        Ok(it) => it
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                let ext = p
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                matches!(ext.as_str(), "mp3" | "wav")
            })
            .collect(),
        Err(e) => {
            eprintln!("read_dir {}: {e}", args.dir.display());
            std::process::exit(2);
        }
    };
    entries.sort();

    let cert_desc = args
        .cert
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| format!("minted CN={} O={}", args.cn, args.org));
    println!(
        "resigning {} files in {} using {} (action={})",
        entries.len(),
        args.dir.display(),
        cert_desc,
        args.action
    );

    let mut ok_count = 0;
    let mut fail_count = 0;
    for src in &entries {
        let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let ext = src.extension().and_then(|s| s.to_str()).unwrap_or("bin");
        let tmp = src.with_file_name(format!("{stem}.resigned-tmp.{ext}"));
        let backup = src.with_file_name(format!("{stem}.{ext}.orig"));

        let manifest = build_manifest(
            src,
            &args.claim_generator,
            &args.action,
            args.identity_did.as_deref(),
            args.identity_handle.as_deref(),
        );

        match sign_asset_with_signer(signer.as_ref(), src, &tmp, &manifest) {
            Ok(_) => {
                if args.backup && !backup.exists() {
                    if let Err(e) = fs::rename(src, &backup) {
                        eprintln!("  {}: backup rename failed: {e}", src.display());
                        let _ = fs::remove_file(&tmp);
                        fail_count += 1;
                        continue;
                    }
                }
                if let Err(e) = fs::rename(&tmp, src) {
                    eprintln!("  {}: tmp -> src rename failed: {e}", src.display());
                    fail_count += 1;
                    continue;
                }
                ok_count += 1;
                println!("  {}: OK", src.file_name().unwrap().to_string_lossy());
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                eprintln!("  {}: sign failed: {e}", src.file_name().unwrap().to_string_lossy());
                fail_count += 1;
            }
        }
    }

    println!("done: {ok_count} OK, {fail_count} FAIL");
    if fail_count > 0 {
        std::process::exit(1);
    }
}
