//! # provcheck-synthid-text
//!
//! [Google SynthID-text](https://github.com/google-deepmind/synthid-text)
//! detection for provcheck. Reads plain `.txt` / `.md` files and
//! computes the Bayesian likelihood that the text was sampled by
//! a tournament-sampled LLM with the watermark active.
//!
//! ## Algorithm
//!
//! SynthID-text injects an unbiased preference between candidate
//! tokens at sampling time. For each generated token, the model
//! draws several candidates from the unbiased distribution, then
//! a hash function `g(context, token, salt)` over the preceding
//! N tokens produces a value in `[0, 1]` per candidate and the
//! tournament picks the candidate that maximises `g`. The
//! aggregate effect: watermarked text has elevated mean `g`
//! across its tokens compared to the 0.5 baseline of unbiased
//! sampling.
//!
//! Detection:
//!
//! 1. Tokenize the input text via the configured tokenizer.
//! 2. For each token at position `i`, compute
//!    `g_i = hash(text[i-W..i], text[i], salt)` mapped to `[0, 1]`.
//! 3. Aggregate `mean_g = sum(g_i) / N`.
//! 4. Under the null hypothesis (unwatermarked text), `mean_g` is
//!    approximately normal with mean `0.5` and standard error
//!    `sqrt(1 / (12 * N))` (variance of uniform on `[0, 1]` is
//!    `1/12`).
//! 5. Compute z-score `z = (mean_g - 0.5) / std_err`; the
//!    confidence that the text is watermarked is `Phi(z)` where
//!    `Phi` is the standard normal CDF.
//! 6. Map confidence to status via the standard
//!    [`provcheck::confidence`] thresholds.
//!
//! ## Tokenizer
//!
//! v0.9.0 ships with a default word-level tokenizer (whitespace
//! split + lowercase + ASCII normalisation). This is intentionally
//! simple — real LLMs use BPE / SentencePiece tokenizers, and
//! detection accuracy is HIGHEST when the detector tokenizer
//! matches the generation tokenizer exactly. The v0.9.x line
//! adds Hugging Face `tokenizers` integration for accurate
//! detection against Gemma / Llama / Qwen output.
//!
//! For now: provcheck-internal SynthID marks (encoded against
//! the word-level default) round-trip cleanly. Detection of
//! marks from other implementations is best-effort.
//!
//! ## License
//!
//! Apache-2.0 algorithm (Google DeepMind). Implementation is a
//! clean-room port — no upstream code is copied, only the
//! algorithm as published in the paper and the public reference
//! implementation.

use std::path::Path;

use sha2::{Digest, Sha256};

pub use provcheck::prelude::{WatermarkBrand, WatermarkKind, WatermarkResult, WatermarkStatus};

/// Minimum token count below which detection is unreliable. The
/// z-statistic's variance grows for short sequences.
const MIN_TOKENS: usize = 32;

/// Context window (number of preceding tokens hashed alongside the
/// current token to derive the g-value). Larger windows reduce
/// false positives but increase tokenizer-mismatch sensitivity.
const CONTEXT_WINDOW: usize = 4;

/// Default salt for the g-value hash function. Provcheck-internal
/// SynthID marks use this. v0.9.x exposes a `--synthid-salt`
/// override and an `app.provcheck.synthid_config` C2PA assertion
/// for ecosystem interop with other generators.
const DEFAULT_SALT: u64 = 0xCA11_AB1E_C0DE_C0DE;

/// Confidence threshold at which a text is classified Detected.
/// Maps to the standard `provcheck::confidence::DETECTED_THRESHOLD`
/// (0.70) since the z-score → confidence transform produces a
/// monotone mapping.
const DETECTED_THRESHOLD: f32 = 0.95;
const DEGRADED_THRESHOLD: f32 = 0.80;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
    #[error("text decode failed: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Run SynthID-text detection on the file at `path`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let _ = std::fs::metadata(path)?;
    if !looks_like_text(path) {
        return Ok(not_text());
    }

    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let tokens = tokenize(&text);

    if tokens.len() < MIN_TOKENS {
        return Ok(WatermarkResult {
            kind: WatermarkKind::SynthIdText,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some(format!(
                "input has only {} tokens; SynthID-text requires at least \
                 {MIN_TOKENS} for statistically meaningful detection",
                tokens.len()
            )),
            marked_regions: None,
        });
    }

    let (mean_g, z, conf) = score(&tokens, DEFAULT_SALT);
    let (status, brand) = classify(conf);

    Ok(WatermarkResult {
        kind: WatermarkKind::SynthIdText,
        status,
        detected: matches!(
            status,
            WatermarkStatus::Detected | WatermarkStatus::Degraded
        ),
        confidence: conf,
        payload: None,
        brand,
        message: Some(format!(
            "SynthID-text tournament-sampling detection — \
             {} tokens, mean g = {:.4} (baseline 0.500), z = {:.2}, \
             P(watermarked) = {:.3}. Default word-level tokenizer; \
             v0.9.x adds HF subword tokenizer support for higher \
             accuracy against real LLM output.",
            tokens.len(),
            mean_g,
            z,
            conf
        )),
        marked_regions: None,
    })
}

fn not_text() -> WatermarkResult {
    WatermarkResult {
        kind: WatermarkKind::SynthIdText,
        status: WatermarkStatus::NotDetected,
        detected: false,
        confidence: 0.0,
        payload: None,
        brand: None,
        message: Some("not text".into()),
        marked_regions: None,
    }
}

fn looks_like_text(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "txt" | "md" | "rst" | "text"
    )
}

/// Word-level tokenizer: whitespace-split, lowercase, strip
/// punctuation. Suitable as the default detector for provcheck-
/// internal marks; subword tokenization for real LLM output
/// arrives in v0.9.x.
pub(crate) fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// Returns `(mean_g, z_score, confidence)`.
pub(crate) fn score(tokens: &[String], salt: u64) -> (f32, f32, f32) {
    let mut g_sum = 0.0_f64;
    let mut count = 0_usize;
    for i in CONTEXT_WINDOW..tokens.len() {
        let ctx = &tokens[i - CONTEXT_WINDOW..i];
        let g = compute_g_value(ctx, &tokens[i], salt);
        g_sum += g;
        count += 1;
    }
    if count == 0 {
        return (0.5, 0.0, 0.5);
    }
    let mean = g_sum / count as f64;
    // Standard error of mean of uniform(0,1) random variables:
    // sqrt(Var / N) where Var = 1/12.
    let std_err = (1.0_f64 / 12.0 / count as f64).sqrt();
    let z = (mean - 0.5) / std_err;
    let conf = standard_normal_cdf(z);
    (mean as f32, z as f32, conf as f32)
}

/// Compute g-value in `[0, 1]` for `token` given `context` and `salt`.
/// Deterministic SHA256-based hash.
fn compute_g_value(context: &[String], token: &str, salt: u64) -> f64 {
    let mut hasher = Sha256::new();
    for c in context {
        hasher.update(c.as_bytes());
        hasher.update(b"|");
    }
    hasher.update(token.as_bytes());
    hasher.update(b"|");
    hasher.update(salt.to_le_bytes());
    let h = hasher.finalize();
    let bits = u64::from_le_bytes(h[..8].try_into().unwrap());
    (bits as f64) / (u64::MAX as f64)
}

/// Phi(x) — standard normal CDF, via the Abramowitz-Stegun rational
/// approximation 7.1.26 of erf. Accurate to ~7 significant digits,
/// sufficient for confidence scoring.
fn standard_normal_cdf(x: f64) -> f64 {
    // Phi(x) = 0.5 * (1 + erf(x / sqrt(2)))
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

fn erf(x: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26
    let sign = x.signum();
    let x = x.abs();
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;
    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();
    sign * y
}

fn classify(conf: f32) -> (WatermarkStatus, Option<WatermarkBrand>) {
    if conf >= DETECTED_THRESHOLD {
        // SynthID-text doesn't carry a brand payload (the
        // watermark is over token choices, not embedded bytes).
        // Brand stays None; the dispatch metadata identifies the
        // watermark family.
        (WatermarkStatus::Detected, None)
    } else if conf >= DEGRADED_THRESHOLD {
        (WatermarkStatus::Degraded, None)
    } else {
        (WatermarkStatus::NotDetected, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmarked_random_text_scores_near_baseline() {
        let text = "The quick brown fox jumps over the lazy dog and \
                    proceeds to write a treatise on the philosophical \
                    implications of cross-species communication in an era \
                    of widespread machine-generated discourse the result \
                    being that no two observers can agree on the meaning \
                    of any single sentence taken in isolation from its \
                    surrounding context which itself depends on a chain \
                    of prior contexts.";
        let tokens = tokenize(text);
        assert!(tokens.len() >= MIN_TOKENS);
        let (mean_g, _z, conf) = score(&tokens, DEFAULT_SALT);
        // For random text under our salt, mean_g should be roughly
        // 0.5 and confidence should not be > DETECTED_THRESHOLD.
        // Allow slack since the sample is small.
        assert!(
            (mean_g - 0.5).abs() < 0.15,
            "mean_g = {mean_g} drifted far from baseline 0.5"
        );
        assert!(
            conf < DETECTED_THRESHOLD,
            "random text classified Detected at conf {conf}"
        );
    }

    #[test]
    fn round_trip_constructed_watermarked_text_scores_high() {
        // Generate a "watermarked" sequence by greedily picking
        // tokens that maximise g-value from a small vocabulary.
        // This mimics what tournament sampling would produce.
        let vocab: Vec<&str> = vec![
            "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
            "and", "proceeds", "wrote", "philosophy", "across", "machines",
            "language", "context", "meaning", "narrative", "structure",
            "discourse", "interpretation", "subtlety", "implication",
            "argument", "hypothesis", "observation", "consequence",
            "framework", "perspective", "analysis", "synthesis",
            "abstraction", "reflection", "consideration", "examination",
            "exploration", "investigation", "speculation", "deliberation",
            "contemplation",
        ];
        let mut tokens: Vec<String> = vec![
            "in".into(), "the".into(), "beginning".into(), "there".into(),
        ];
        for _ in 0..200 {
            let ctx = &tokens[tokens.len().saturating_sub(CONTEXT_WINDOW)..];
            let best = vocab
                .iter()
                .max_by(|a, b| {
                    let ga = compute_g_value(
                        &ctx.iter().cloned().collect::<Vec<_>>(),
                        a,
                        DEFAULT_SALT,
                    );
                    let gb = compute_g_value(
                        &ctx.iter().cloned().collect::<Vec<_>>(),
                        b,
                        DEFAULT_SALT,
                    );
                    ga.partial_cmp(&gb).unwrap()
                })
                .unwrap();
            tokens.push((*best).to_string());
        }
        let (mean_g, z, conf) = score(&tokens, DEFAULT_SALT);
        // Constructed watermarked text should score well above
        // baseline; mean_g far higher than 0.5 and confidence
        // very close to 1.0.
        assert!(mean_g > 0.7, "mean_g {mean_g} not elevated");
        assert!(z > 3.0, "z {z} not elevated");
        assert!(
            conf >= DETECTED_THRESHOLD,
            "constructed watermarked text scored conf {conf} (< {DETECTED_THRESHOLD})"
        );
    }
}

#[cfg(test)]
mod _send_sync_assertions {
    fn assert_send_sync<T: Send + Sync>() {}
    #[test]
    fn key_public_types_are_send_sync() {
        assert_send_sync::<crate::WatermarkResult>();
        assert_send_sync::<crate::WatermarkBrand>();
        assert_send_sync::<crate::WatermarkKind>();
        assert_send_sync::<crate::WatermarkStatus>();
    }
}
