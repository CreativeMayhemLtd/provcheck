//! Shared fixtures for integration tests. Lives in
//! `tests/common/mod.rs` so each `tests/*.rs` file can `mod common;` it.

#![allow(dead_code)] // each test file uses some but not all helpers

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ---- Media + cert fixtures --------------------------------------------------

/// Write a ~0.1-second mono silent WAV to `dest`.
pub fn write_silent_wav(dest: &Path) {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(dest, spec).expect("wav writer");
    for _ in 0..4_410 {
        writer.write_sample(0_i16).expect("wav sample");
    }
    writer.finalize().expect("wav finalize");
}

/// Generate a throwaway ES256 cert chain (CA + EE) + key, in PEM bytes
/// ready to hand to `c2pa::create_signer::from_keys`. Returns
/// `(chain_pem, key_pem, ca_pem)`.
pub fn generate_test_chain() -> (Vec<u8>, Vec<u8>, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().expect("ca keypair");
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "provcheck Test CA");
    ca_dn.push(DnType::OrganizationName, "provcheck (test only)");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let ee_key = KeyPair::generate().expect("ee keypair");
    let mut ee_params = CertificateParams::default();
    let mut ee_dn = DistinguishedName::new();
    ee_dn.push(DnType::CommonName, "provcheck Test Signer");
    ee_dn.push(DnType::OrganizationName, "provcheck (test only)");
    ee_params.distinguished_name = ee_dn;
    ee_params.is_ca = IsCa::ExplicitNoCa;
    ee_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    ee_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    ee_params.use_authority_key_identifier_extension = true;

    let ca_issuer = rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca_key).expect("ca issuer");
    let ee_cert = ee_params.signed_by(&ee_key, &ca_issuer).expect("ee sign");

    let ca_pem = ca_cert.pem();
    let chain_pem = format!("{}{}", ee_cert.pem(), ca_pem);
    let key_pem = ee_key.serialize_pem();
    (chain_pem.into_bytes(), key_pem.into_bytes(), ca_pem)
}

/// Sign `src` (writing to `dest`) with a freshly generated chain.
/// Returns the CA PEM and the EE cert PEM (so attestation tests can
/// fingerprint the same leaf cert that c2pa just embedded).
pub fn sign_with_fresh_chain(src: &Path, dest: &Path) -> SignedFixture {
    let (cert_pem, key_pem, ca_pem) = generate_test_chain();
    let chain_str = String::from_utf8(cert_pem.clone()).expect("chain is utf8");
    let leaf_pem = first_certificate_pem(&chain_str);

    let signer = c2pa::create_signer::from_keys(&cert_pem, &key_pem, c2pa::SigningAlg::Es256, None)
        .expect("create signer");

    let manifest_json = r#"{
      "claim_generator": "provcheck-test/0.1.0",
      "title": "provcheck attestation test fixture",
      "assertions": [
        {
          "label": "c2pa.actions",
          "data": {
            "actions": [ { "action": "c2pa.created" } ]
          }
        }
      ]
    }"#;

    let mut builder = c2pa::Builder::from_json(manifest_json).expect("builder from json");
    builder
        .sign_file(signer.as_ref(), src, dest)
        .expect("sign file");

    SignedFixture {
        ca_pem,
        leaf_pem,
        chain_pem: chain_str,
    }
}

pub struct SignedFixture {
    pub ca_pem: String,
    pub leaf_pem: String,
    pub chain_pem: String,
}

fn first_certificate_pem(chain: &str) -> String {
    // chain is `EE\n` + `CA\n` (as concatenated by generate_test_chain).
    // Take through the first `END CERTIFICATE` line.
    let end = "-----END CERTIFICATE-----";
    if let Some(idx) = chain.find(end) {
        let until = idx + end.len();
        let mut out = chain[..until].to_string();
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    } else {
        chain.to_string()
    }
}

// ---- Tiny localhost HTTP mock -----------------------------------------------

/// Hand-rolled HTTP/1.1 mock server. We don't use `wiremock` because
/// it's async-only and provcheck-core is sync. Path-based routing,
/// 200-or-404 responses, request log for cache-hit assertions.
pub struct MockServer {
    addr: String,
    routes: Arc<Mutex<HashMap<String, MockResponse>>>,
    request_log: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
struct MockResponse {
    content_type: &'static str,
    body: String,
}

impl MockServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        let port = listener.local_addr().expect("local_addr").port();
        let addr = format!("127.0.0.1:{port}");
        let routes: Arc<Mutex<HashMap<String, MockResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let request_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let routes_thread = routes.clone();
        let log_thread = request_log.clone();

        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 8192];
                let n = match stream.read(&mut buf) {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };
                let request = String::from_utf8_lossy(&buf[..n]);
                let path_with_query = request
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let path_only = path_with_query.split('?').next().unwrap_or("/").to_string();

                log_thread.lock().unwrap().push(path_with_query.clone());

                let response_bytes = {
                    let routes = routes_thread.lock().unwrap();
                    match routes.get(&path_only) {
                        Some(r) => format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: {}\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            r.content_type,
                            r.body.len(),
                            r.body
                        ),
                        None => "HTTP/1.1 404 Not Found\r\n\
                                  Content-Length: 0\r\n\
                                  Connection: close\r\n\
                                  \r\n"
                            .to_string(),
                    }
                };
                let _ = stream.write_all(response_bytes.as_bytes());
                let _ = stream.flush();
            }
        });

        // Tiny pause for the OS to register the listener so the first
        // request doesn't race the accept loop on slow CI.
        thread::sleep(Duration::from_millis(20));

        Self {
            addr,
            routes,
            request_log,
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn route_json(&self, path: &str, body: impl Into<String>) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            MockResponse {
                content_type: "application/json",
                body: body.into(),
            },
        );
    }

    pub fn route_text(&self, path: &str, body: impl Into<String>) {
        self.routes.lock().unwrap().insert(
            path.to_string(),
            MockResponse {
                content_type: "text/plain",
                body: body.into(),
            },
        );
    }

    pub fn request_count(&self) -> usize {
        self.request_log.lock().unwrap().len()
    }

    pub fn requests(&self) -> Vec<String> {
        self.request_log.lock().unwrap().clone()
    }
}
