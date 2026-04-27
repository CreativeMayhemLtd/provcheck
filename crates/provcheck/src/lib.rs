//! # provcheck-core
//!
//! Verify C2PA Content Credentials on any file format supported by
//! the upstream `c2pa` crate (audio, image, video).
//!
//! The library is intentionally thin — it wraps `c2pa::Reader` with a
//! stable [`Report`] type that both the CLI and the GUI render.
//! Behaviour is identical across front-ends because there is exactly
//! one code path through `verify_with_options` (and `verify` wraps
//! that with default options).
//!
//! ```no_run
//! use provcheck::prelude::*;
//! use std::path::Path;
//!
//! let report = verify(Path::new("signed.wav"))?;
//! if report.verified {
//!     println!("Signed by {:?}", report.signer);
//! }
//! # Ok::<(), Error>(())
//! ```

pub mod report;
pub mod verification;

pub mod prelude {
    pub use super::Error;
    pub use crate::report::Report;
    pub use crate::verification::{VerifyOptions, verify, verify_with_options};
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("C2PA read failed: {0}")]
    C2pa(#[from] c2pa::Error),
    #[error("invalid trust-store PEM: {0}")]
    InvalidTrustStore(String),
}

fn sanity_check_pem(pem: &str) -> Result<(), Error> {
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(Error::InvalidTrustStore(
            "no BEGIN CERTIFICATE block found in PEM bundle".into(),
        ));
    }
    if !pem.contains("-----END CERTIFICATE-----") {
        return Err(Error::InvalidTrustStore(
            "no END CERTIFICATE block found in PEM bundle".into(),
        ));
    }
    Ok(())
}

/// c2pa errors that mean "the file is trying to carry a C2PA manifest
/// but it's broken / tampered / unparseable". These should surface as
/// failed-verification reports (exit 1), not as tool-level errors
/// (exit 2) — the user's question has a real answer.
///
/// Variant names tracked against c2pa 0.78.8's Error enum. When
/// bumping c2pa, recheck whether any new variants fit this category.
fn is_manifest_parse_error(err: &c2pa::Error) -> bool {
    use c2pa::Error::*;
    matches!(
        err,
        // JUMBF / manifest structure broken
        JumbfParseError(_)
            | InvalidClaim(_)
            | InvalidAsset(_)
            | ClaimDecoding(_)
            | ClaimEncoding
            | ClaimMissing { .. }
            | ClaimMissingSignatureBox
            | ClaimInvalidContent
            | AssertionMissing { .. }
            | AssertionDecoding(_)
            | AssertionEncoding(_)
            | AssertionInvalidRedaction
            // Cryptographic failure on signature verification
            | HashMismatch(_)
            | CoseSignatureAlgorithmNotSupported
            | CoseMissingKey
            | CoseX5ChainMissing
            | CoseInvalidCert
            | CoseSignature
            | CoseVerifier
            | CoseCertExpiration
            | CoseCertRevoked
            | InvalidCoseSignature { .. }
    )
}

fn unsigned_report(reason: Option<String>) -> prelude::Report {
    prelude::Report {
        verified: false,
        unsigned: true,
        trusted: None,
        failure_reason: reason,
        active_manifest: None,
        signer: None,
        signed_at: None,
        claim_generator: None,
        assertions: serde_json::Value::Null,
        ingredient_count: 0,
        format: None,
        validation_errors: 0,
    }
}

fn format_failure_reason(
    state: c2pa::ValidationState,
    error_count: usize,
    trusted: Option<bool>,
    require_trusted: bool,
) -> String {
    let plural = |n: usize| if n == 1 { "" } else { "s" };

    // Trust-requirement failure: crypto passed but cert isn't trusted.
    if require_trusted
        && matches!(trusted, Some(false) | None)
        && matches!(
            state,
            c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted
        )
        && error_count == 0
    {
        return match trusted {
            Some(false) => "signing certificate is not on the configured trust list".into(),
            None => "trust status could not be established for the signing certificate".into(),
            Some(true) => unreachable!("trusted=true but failure_reason called"),
        };
    }

    // Crypto / manifest failures.
    match state {
        c2pa::ValidationState::Invalid => format!(
            "manifest failed structural or cryptographic validation ({} error{})",
            error_count.max(1),
            plural(error_count.max(1))
        ),
        c2pa::ValidationState::Valid | c2pa::ValidationState::Trusted => {
            if error_count > 0 {
                format!(
                    "content verification failed — {} validation error{} (likely tampered payload under a hash-bound manifest)",
                    error_count,
                    plural(error_count)
                )
            } else {
                "verification failed for an unspecified reason".into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::{VerifyOptions, verify, verify_with_options};
    use std::path::Path;

    #[test]
    fn missing_file_is_io_error() {
        let err = verify(Path::new("does_not_exist_abcxyz.wav")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn exit_code_maps_verified_state() {
        let mut r = unsigned_report(None);
        assert_eq!(r.exit_code(), 1);
        r.verified = true;
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn invalid_trust_store_pem_is_err() {
        let opts = VerifyOptions {
            trust_store_pem: Some("not a pem at all".into()),
            require_trusted: false,
        };
        // Use a fake path — sanity_check should reject the PEM
        // before we even look at the file.
        let err = verify_with_options(Path::new("any.wav"), &opts).unwrap_err();
        assert!(matches!(err, Error::InvalidTrustStore(_)));
    }
}
