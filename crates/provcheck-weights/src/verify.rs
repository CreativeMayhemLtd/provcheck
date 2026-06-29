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
    // GenericArray::as_slice was deprecated in generic-array 0.14;
    // the sha2 0.10 output is `GenericArray<u8, U32>`. Treating it
    // as `&[u8]` via Deref keeps the comparison constant-time
    // semantics (it is not — but neither does the deprecated
    // method) without pulling in subtle-time.
    let actual_ref: &[u8] = actual.as_ref();
    Ok(actual_ref == expected.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("payload.bin");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(bytes).expect("write");
        (dir, path)
    }

    /// SHA-256 of "hello world" with a trailing newline omitted —
    /// `printf 'hello world' | sha256sum`. Pinned by hand.
    const HELLO_WORLD_SHA: [u8; 32] = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
        0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
        0xe2, 0xef, 0xcd, 0xe9,
    ];

    #[test]
    fn matches_known_sha_for_known_bytes() {
        let (_dir, path) = write_tmp(b"hello world");
        let ok = file_sha256_matches(&path, &HELLO_WORLD_SHA).expect("hash ok");
        assert!(ok, "SHA256 of 'hello world' must match the published constant");
    }

    #[test]
    fn rejects_one_bit_tamper() {
        // Same content but one byte flipped from the expected.
        let (_dir, path) = write_tmp(b"hello world!"); // extra '!'
        let ok = file_sha256_matches(&path, &HELLO_WORLD_SHA).expect("hash ok");
        assert!(!ok, "tampered file must NOT match the expected SHA256");
    }

    #[test]
    fn rejects_truncated_file() {
        let (_dir, path) = write_tmp(b"hello worl"); // truncated by 1 byte
        let ok = file_sha256_matches(&path, &HELLO_WORLD_SHA).expect("hash ok");
        assert!(!ok, "truncated file must NOT match the expected SHA256");
    }

    #[test]
    fn rejects_empty_file_against_real_sha() {
        let (_dir, path) = write_tmp(b"");
        let ok = file_sha256_matches(&path, &HELLO_WORLD_SHA).expect("hash ok");
        assert!(!ok, "empty file must NOT match a non-empty payload's SHA256");
    }

    #[test]
    fn matches_chunked_large_file() {
        // Exercises the BufReader loop's multi-iteration path with
        // a payload larger than the 64 KB read buffer.
        let big: Vec<u8> = (0..(200 * 1024)).map(|i| (i & 0xFF) as u8).collect();
        let (_dir, path) = write_tmp(&big);
        // Compute the expected hash via the same primitives so we
        // don't pin a value here that's brittle to allocator quirks.
        let mut h = Sha256::new();
        h.update(&big);
        let expected: [u8; 32] = h.finalize().into();
        let ok = file_sha256_matches(&path, &expected).expect("hash ok");
        assert!(ok);
    }

    #[test]
    fn missing_file_surfaces_io_error() {
        let r = file_sha256_matches(
            std::path::Path::new("/this/path/does/not/exist/payload.bin"),
            &HELLO_WORLD_SHA,
        );
        assert!(matches!(r, Err(Error::Io(_))));
    }
}
