//! SHA256 verification of downloaded weight files against the
//! bundled manifest's expected digest.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Error;

/// Returns Ok(true) if the file's SHA256 matches `expected`,
/// Ok(false) otherwise. Errors only on I/O failure reading the
/// file — the verify itself never errors, it just returns
/// match/mismatch.
pub(crate) fn file_sha256_matches(path: &Path, expected: &[u8; 32]) -> Result<bool, Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hasher.finalize();
    Ok(actual.as_slice() == expected.as_slice())
}
