//! Cache directory resolution.

use std::path::PathBuf;

/// Where weight downloads land. Operator can override via the
/// `PROVCHECK_WEIGHTS_CACHE_DIR` env var (useful for read-only
/// filesystems, CI pre-populated mirrors, or shared multi-tenant
/// installs).
pub(crate) fn resolve_cache_dir() -> Option<PathBuf> {
    if let Ok(over) = std::env::var("PROVCHECK_WEIGHTS_CACHE_DIR") {
        let p = PathBuf::from(over);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }
    let base = dirs::cache_dir()?;
    Some(base.join("provcheck").join("weights"))
}
