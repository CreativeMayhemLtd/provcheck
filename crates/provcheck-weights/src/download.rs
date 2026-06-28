//! Blocking HTTPS download via `ureq`. Tiny surface; the rest of
//! the crate handles atomic-rename + verify around this.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::Error;

/// GET the URL and stream the body into `dest`. Caller handles
/// rename-after-verify atomicity.
pub(crate) fn download_to(url: &str, dest: &Path) -> Result<(), Error> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| Error::Download(format!("HTTP error: {e}")))?;
    let mut reader = resp.into_reader();
    let file = File::create(dest)?;
    let mut writer = BufWriter::new(file);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(Error::Io)?;
    }
    writer.flush()?;
    Ok(())
}
