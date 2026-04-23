//! provcheck-examples — regenerate the branded sample signed media
//! under `<repo>/examples/`.
//!
//! Not part of the public CLI. Run it by hand when the samples need
//! refreshing (new product branding, new manifest fields, new input
//! files). It takes a pair of source paths — an audio file for the
//! rAIdio.bot sample and a video file for the vAIdeo.bot sample —
//! and writes two signed outputs the README references.
//!
//! The cert chain we sign with is synthesised fresh on every run so
//! no private keys ship. Anyone with the source code can reproduce
//! the exact sample by pointing this tool at the same sources.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

#[derive(Debug, Parser)]
#[command(
    name = "provcheck-examples",
    about = "Regenerate branded sample signed media for the examples/ dir."
)]
struct Args {
    /// Source audio file (e.g., a rAIdio.bot MP3).
    #[arg(long)]
    audio_in: PathBuf,

    /// Source video file (e.g., a vAIdeo.bot / DoomscrollFM MP4).
    #[arg(long)]
    video_in: PathBuf,

    /// Examples output directory. Defaults to <repo>/examples.
    #[arg(long, default_value = "examples")]
    out_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    std::fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;

    let audio_out = args.out_dir.join("rAIdio.bot-sample.mp3");
    sign_with_brand(
        &args.audio_in,
        &audio_out,
        Brand::RaidioBot,
        raidio_manifest_json(),
    )
    .context("signing rAIdio.bot audio sample")?;

    let video_out = args.out_dir.join("doomscroll.fm-sample.mp4");
    sign_with_brand(
        &args.video_in,
        &video_out,
        Brand::DoomscrollFm,
        doomscroll_manifest_json(),
    )
    .context("signing Doomscroll.fm video sample")?;

    println!("\nRegenerated:");
    println!("  {}", audio_out.display());
    println!("  {}", video_out.display());
    println!(
        "\nVerify with:\n  provcheck {}\n  provcheck {}",
        audio_out.display(),
        video_out.display()
    );

    Ok(())
}

// ----- Brand wiring ----------------------------------------------------------

#[derive(Copy, Clone)]
enum Brand {
    RaidioBot,
    DoomscrollFm,
}

impl Brand {
    fn common_name(self) -> &'static str {
        match self {
            Brand::RaidioBot => "rAIdio.bot",
            // Doomscroll.fm is a separate workflow / broadcast — not
            // a vAIdeo.bot product. Sibling-product attribution waits
            // for vAIdeo.bot's own pre-release announcement.
            Brand::DoomscrollFm => "Doomscroll.fm",
        }
    }
}

fn raidio_manifest_json() -> String {
    // Mirrors the real rAIdio.bot manifest shape so the sample is a
    // faithful illustration of what verification surfaces in the
    // wild — not a fake. Assertion labels (com.raidio.*) match the
    // production signer's output.
    r#"{
      "claim_generator": "rAIdio.bot/0.1.0",
      "title": "Sample: rAIdio.bot AI-generated music (808 trap tune)",
      "assertions": [
        {
          "label": "c2pa.actions",
          "data": {
            "actions": [{
              "action": "c2pa.created",
              "softwareAgent": "rAIdio.bot/0.1.0",
              "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
            }]
          }
        },
        {
          "label": "com.raidio.model",
          "data": {
            "modelFamily": "ACE-Step",
            "modelVersion": "1.5 XL",
            "modelLicense": "Apache-2.0",
            "modelRepository": "https://github.com/ace-step/ACE-Step",
            "generationMethod": "generation",
            "trainingDataSource": "Licensed and public domain audio",
            "trainingDataLicense": "No copyrighted music in training set",
            "euAiActCompliance": "Transparent AI: model trained on licensed/public domain data only. Not trained on copyrighted recordings."
          }
        },
        {
          "label": "com.raidio.product",
          "data": {
            "productName": "rAIdio.bot",
            "productUrl": "https://store.steampowered.com/app/4600000",
            "productVendor": "Creative Mayhem UG",
            "productType": "Local-first AI music generation studio",
            "privacyPolicy": "Local processing only — no data leaves your machine"
          }
        }
      ]
    }"#
    .to_string()
}

fn doomscroll_manifest_json() -> String {
    // Doomscroll.fm is an autonomous AI-generated satirical news
    // broadcast — its own workflow, not a product under another
    // Creative Mayhem brand. Attribute to the broadcast directly.
    //
    // The `com.doomscroll.distribution` assertion below is doing
    // something important that any C2PA publisher probably wants
    // to copy. C2PA verification is a provenance attestation — it
    // confirms a file's bytes are authentic to what the publisher
    // published. It is NOT a truth claim about the content itself.
    // Some redistribution platforms re-encode media during upload
    // and, in doing so, may strip embedded C2PA manifests. A user
    // who retrieves a clip off such a rebroadcast and verifies it
    // will see "unsigned" and has no way, on its own, to know
    // whether the bytes still match the original publication. The
    // disclaimer + canonical-source pointer gives them the answer:
    // retrieve the signed version from the canonical URL and check
    // against that.
    r#"{
      "claim_generator": "doomscroll.fm/3.0",
      "title": "Sample: Doomscroll.fm AI-generated video (episode bumper)",
      "assertions": [
        {
          "label": "c2pa.actions",
          "data": {
            "actions": [{
              "action": "c2pa.created",
              "softwareAgent": "doomscroll.fm/3.0",
              "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
            }]
          }
        },
        {
          "label": "com.doomscroll.broadcast",
          "data": {
            "broadcast": "Doomscroll.fm",
            "broadcastUrl": "https://doomscroll.fm",
            "broadcastVendor": "Creative Mayhem UG",
            "broadcastDescription": "Autonomous AI-generated satirical news broadcast. Approximately 10–12 episodes per day. All content is C2PA-signed at source."
          }
        },
        {
          "label": "com.doomscroll.distribution",
          "data": {
            "provenanceStatement": "A valid C2PA signature from Doomscroll.fm attests that this file's bytes are authentic to the copy Doomscroll.fm originally published. It is a cryptographic attestation of provenance — not a truth claim about the content itself, and not a judgement on whether the content is accurate or inaccurate.",
            "canonicalSource": "https://doomscroll.fm",
            "canonicalSourceDescription": "The authoritative, always-signed publication of every Doomscroll.fm clip. If you have a copy that fails C2PA verification, retrieve the version here — that one is cryptographically demonstrable as authentic to the original Doomscroll.fm publication.",
            "rebroadcastDisclaimer": "Some redistribution platforms re-encode media during upload and may strip the embedded C2PA manifest in the process. A file that fails verification has not necessarily been altered — it may simply have lost its cryptographic link back to the original publication during re-encoding. To confirm that a clip you encountered elsewhere is authentic to Doomscroll.fm's original publication, retrieve the canonical signed copy and verify that one.",
            "integrityRecommendation": "When ingesting Doomscroll.fm content for archival or republication, pulling from the canonical source preserves the signature chain and keeps provenance verifiable end-to-end."
          }
        },
        {
          "label": "com.doomscroll.episode",
          "data": {
            "contentType": "episode-bumper",
            "note": "Short promo clip used between episode segments."
          }
        }
      ]
    }"#
    .to_string()
}

// ----- Signing ---------------------------------------------------------------

fn sign_with_brand(src: &Path, dest: &Path, brand: Brand, manifest_json: String) -> Result<()> {
    let (cert_pem, key_pem) = generate_chain(brand)?;
    let signer = c2pa::create_signer::from_keys(&cert_pem, &key_pem, c2pa::SigningAlg::Es256, None)
        .context("create_signer")?;

    let mut builder = c2pa::Builder::from_json(&manifest_json).context("builder from json")?;

    // c2pa::Builder::sign_file wants a path for both source and dest
    // and writes the signed bytes to dest. For MP3 it also writes a
    // `.c2pa` sidecar next to dest — caller is responsible for
    // keeping both files together.
    let _manifest_bytes = builder
        .sign_file(signer.as_ref(), src, dest)
        .context("sign_file")?;

    // For MP3 specifically, the manifest bytes are the sidecar
    // contents — write them adjacent so the Reader::from_file path
    // can find the manifest alongside the MP3.
    if let Some(ext) = dest.extension().and_then(|e| e.to_str()) {
        if ext.eq_ignore_ascii_case("mp3") {
            let sidecar = dest.with_extension("c2pa");
            std::fs::write(&sidecar, &_manifest_bytes)
                .with_context(|| format!("write sidecar {}", sidecar.display()))?;
        }
    }

    println!(
        "Signed {} ({} bytes) as {}",
        dest.display(),
        std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0),
        brand.common_name()
    );
    Ok(())
}

fn generate_chain(brand: Brand) -> Result<(Vec<u8>, Vec<u8>)> {
    // Per-run disposable CA + EE. The EE cert's common name is the
    // product brand — which is what `provcheck` surfaces as the
    // `signer` field in its report. That's how the sample carries
    // the product name into the user's verification output.

    let ca_key = KeyPair::generate().context("ca keypair")?;
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Creative Mayhem Sample CA");
    ca_dn.push(DnType::OrganizationName, "Creative Mayhem UG (sample)");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).context("ca self-sign")?;

    let ee_key = KeyPair::generate().context("ee keypair")?;
    let mut ee_params = CertificateParams::default();
    let mut ee_dn = DistinguishedName::new();
    ee_dn.push(DnType::CommonName, brand.common_name());
    ee_dn.push(DnType::OrganizationName, "Creative Mayhem UG");
    ee_params.distinguished_name = ee_dn;
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.use_authority_key_identifier_extension = true;

    let ca_issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).context("ca issuer")?;
    let ee_cert = ee_params
        .signed_by(&ee_key, &ca_issuer)
        .context("ee sign")?;

    let chain_pem = format!("{}{}", ee_cert.pem(), ca_cert.pem());
    let key_pem = ee_key.serialize_pem();
    Ok((chain_pem.into_bytes(), key_pem.into_bytes()))
}
