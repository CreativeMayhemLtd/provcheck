//! Image-watermark embedding — scaffold only.
//!
//! v0.7 phase 7a: the public surface exists for shape parity with
//! the audio sibling crates (`provcheck-watermark`,
//! `provcheck-audioseal`, `provcheck-wavmark`). The actual
//! TrustMark inference lands at phase 7c.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("image embed not yet implemented (v0.7 phase 7a scaffold; 7c wires this)")]
    NotYetImplemented,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Embed config for shape parity with
/// [`provcheck-watermark::encode::EmbedConfig`]. Currently empty;
/// future TrustMark-specific knobs (strength, region masking) will
/// slot in here when 7c lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbedConfig {}

/// Embed a payload into the image at `src` and write the marked
/// output to `dst`.
///
/// v0.7 phase 7a scaffold: always returns
/// [`EncodeError::NotYetImplemented`]. 7c wires the real
/// TrustMark forward pass.
pub fn embed(
    _src: &Path,
    _dst: &Path,
    _payload: &[u8],
) -> Result<(), EncodeError> {
    Err(EncodeError::NotYetImplemented)
}

/// Shape-parity wrapper. Calls [`embed`] and ignores the config.
pub fn embed_with_config(
    src: &Path,
    dst: &Path,
    payload: &[u8],
    _config: EmbedConfig,
) -> Result<(), EncodeError> {
    embed(src, dst, payload)
}
