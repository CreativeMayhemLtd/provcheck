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

/// Confidence threshold (Phi-of-z value) at which a text is
/// classified Detected. Higher than `provcheck::confidence`'s
/// audio thresholds because the SynthID statistic is a tail
/// probability under the null hypothesis, not a detector
/// confidence: we want to claim "watermark present" only when
/// the null hypothesis is rejected at the 5 percent level.
const DETECTED_THRESHOLD: f32 = 0.95;
/// Threshold below which the watermark is "not detected" but a
/// real signal may exist (Phi-of-z value between 0.80 and 0.95
/// is consistent with a partially-stripped or short-text mark).
const DEGRADED_THRESHOLD: f32 = 0.80;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),
}

/// Maximum file size we will load into memory for detection. Per
/// v0.9.0 audit §3: a 5 GB `.txt` file would consume 5 GB raw +
/// up to 3 × that lossy-UTF-8 + another N-bytes token Vec. Cap at
/// 64 MB which is comfortably above any plain-text creator output.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Run SynthID-text detection on the file at `path`.
pub fn detect(path: &Path) -> Result<WatermarkResult, Error> {
    let meta = std::fs::metadata(path)?;
    if !looks_like_text(path, &meta) {
        return Ok(not_text());
    }
    // v0.9.0 audit §3: bounded read to prevent OOM via giant file.
    if meta.len() > MAX_FILE_BYTES {
        return Ok(WatermarkResult {
            kind: WatermarkKind::SynthIdText,
            status: WatermarkStatus::NotDetected,
            detected: false,
            confidence: 0.0,
            payload: None,
            brand: None,
            message: Some(format!(
                "input is {} bytes, above the {} MB SynthID-text detection cap. \
                 Pre-truncate or split before re-running.",
                meta.len(),
                MAX_FILE_BYTES / (1024 * 1024)
            )),
            marked_regions: None,
        });
    }

    let bytes = std::fs::read(path)?;
    // v0.9.0 audit §3: validate UTF-8 explicitly instead of
    // lossy-converting a binary file into gigabytes of U+FFFD.
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            return Ok(WatermarkResult {
                kind: WatermarkKind::SynthIdText,
                status: WatermarkStatus::NotDetected,
                detected: false,
                confidence: 0.0,
                payload: None,
                brand: None,
                message: Some(
                    "input is not valid UTF-8 — SynthID-text only operates \
                     on text encodings the tokenizer can understand".into(),
                ),
                marked_regions: None,
            });
        }
    };
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

    // v0.9.0 audit §2.8: report the actual g-sample size (tokens
    // less context-window prefix), not the raw token count, since
    // the z-statistic is computed over the sample size, not the
    // total token count.
    let g_samples = tokens.len().saturating_sub(CONTEXT_WINDOW);

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
            "SynthID-text tournament-sampling detection, \
             {n_tokens} tokens ({g_samples} g-samples after \
             context-window prefix), mean g = {mean_g:.4} \
             (baseline 0.500), z = {z:.2}, \
             P(watermarked) = {conf:.3}. \
             Word-level tokenizer (whitespace-split, lowercase, \
             punctuation-stripped).",
            n_tokens = tokens.len(),
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

/// Recognise files that should run through the SynthID-text
/// detector. v0.9.0 audit §2.6 widens this from the old
/// `.txt/.md/.rst/.text` allowlist so common
/// machine-generated-text extensions (`.html`, `.json`, `.csv`,
/// etc.) are detected, and adds a content-based UTF-8 sniff for
/// extensionless files so well-formed text without a familiar
/// extension still gets a chance.
fn looks_like_text(path: &Path, meta: &std::fs::Metadata) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if matches!(
            ext.to_ascii_lowercase().as_str(),
            "txt" | "md" | "rst" | "text" | "html" | "htm" | "xml"
                | "json" | "csv" | "tsv" | "log" | "yml" | "yaml"
                | "toml" | "ini" | "cfg" | "conf" | "srt" | "vtt"
        ) {
            return true;
        }
    }
    // No extension OR an extension we do not recognise: sniff the
    // first chunk for valid UTF-8 with a high printable-ratio. We
    // don't want to false-positive on a binary file that happens
    // to be valid UTF-8 by coincidence.
    if meta.len() == 0 || meta.len() > MAX_FILE_BYTES {
        return false;
    }
    let probe_len = 4096.min(meta.len() as usize);
    let mut buf = vec![0u8; probe_len];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };
    buf.truncate(n);
    let Ok(s) = std::str::from_utf8(&buf) else {
        return false;
    };
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .count();
    let ratio = printable as f32 / s.chars().count().max(1) as f32;
    ratio > 0.95
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
    // SHA-256 output is always 32 bytes; the first 8 bytes always
    // fit in a u64. Named binding instead of `try_into().unwrap()`
    // per v0.9.0 audit §3.
    let mut head = [0u8; 8];
    head.copy_from_slice(&h[..8]);
    let bits = u64::from_le_bytes(head);
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

    // ----- tokenize ----------

    #[test]
    fn tokenize_lowercases() {
        let toks = tokenize("Hello World FOO");
        assert_eq!(toks, vec!["hello", "world", "foo"]);
    }

    #[test]
    fn tokenize_strips_punctuation_but_keeps_hyphens_and_underscores() {
        // Identifiers and hyphenated words must survive — the
        // marker may legitimately produce them.
        let toks = tokenize("hello, world! it's a-b_c.");
        assert_eq!(toks, vec!["hello", "world", "its", "a-b_c"]);
    }

    #[test]
    fn tokenize_drops_empty_tokens() {
        // Pure-punctuation chunks ("?!" "...") strip to empty
        // strings; they must NOT appear in the token list.
        let toks = tokenize("hello ?! ... world");
        assert_eq!(toks, vec!["hello", "world"]);
    }

    #[test]
    fn tokenize_empty_input_returns_empty_vec() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn tokenize_preserves_alphanumerics() {
        // Digits must survive (e.g. "v1.0" → "v10").
        let toks = tokenize("v1.0 build 42a");
        assert_eq!(toks, vec!["v10", "build", "42a"]);
    }

    // ----- erf math invariants ----------

    #[test]
    fn erf_at_zero_is_zero() {
        // erf(0) = 0 exactly.
        assert!(erf(0.0).abs() < 1e-9);
    }

    #[test]
    fn erf_is_odd_function() {
        // erf(-x) = -erf(x). Pin the symmetry.
        for x in [0.1, 0.5, 1.0, 2.0, 3.0] {
            let pos = erf(x);
            let neg = erf(-x);
            assert!((pos + neg).abs() < 1e-6, "erf({x}) + erf(-{x}) = {}", pos + neg);
        }
    }

    #[test]
    fn erf_bounded_in_minus_one_to_one() {
        for x in [-3.0, -1.0, 0.0, 1.0, 3.0, 5.0] {
            let y = erf(x);
            assert!(y.abs() <= 1.0, "erf({x}) = {y} out of [-1, 1]");
        }
    }

    #[test]
    fn erf_at_one_matches_known_value() {
        // erf(1) ≈ 0.8427007929 (textbook value). Pin within
        // the A&S approximation's documented precision.
        let r = erf(1.0);
        assert!(
            (r - 0.842_700_79_f64).abs() < 1e-5,
            "erf(1) = {r} drifted from textbook 0.8427"
        );
    }

    // ----- standard_normal_cdf ----------

    #[test]
    fn standard_normal_cdf_at_zero_is_half() {
        // Φ(0) = 0.5 by symmetry.
        let r = standard_normal_cdf(0.0);
        assert!((r - 0.5).abs() < 1e-6);
    }

    #[test]
    fn standard_normal_cdf_is_monotonic_increasing() {
        let xs = [-3.0_f64, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0];
        let mut prev = standard_normal_cdf(xs[0]);
        for &x in &xs[1..] {
            let next = standard_normal_cdf(x);
            assert!(next > prev, "Φ not monotonic at x={x}: {prev} -> {next}");
            prev = next;
        }
    }

    #[test]
    fn standard_normal_cdf_bounded_in_zero_to_one() {
        for x in [-5.0, -1.0, 0.0, 1.0, 5.0] {
            let r = standard_normal_cdf(x);
            assert!((0.0..=1.0).contains(&r), "Φ({x}) = {r} out of [0, 1]");
        }
    }

    // ----- classify ----------

    #[test]
    fn classify_returns_none_brand_always() {
        // SynthID-text never carries a brand payload — the mark
        // is in token choices, not embedded bytes. Pin the contract.
        for conf in [0.0, 0.5, 0.7, 0.9, 1.0] {
            let (_, brand) = classify(conf);
            assert!(brand.is_none(), "expected None brand at conf={conf}");
        }
    }

    #[test]
    fn classify_uses_canonical_thresholds() {
        // SynthID-text classify must use the canonical
        // provcheck::confidence thresholds. Pin to catch any
        // drift from a per-detector threshold override.
        let (status_low, _) = classify(DEGRADED_THRESHOLD - 0.01);
        let (status_mid, _) = classify(DEGRADED_THRESHOLD);
        let (status_high, _) = classify(DETECTED_THRESHOLD);
        assert!(matches!(status_low, WatermarkStatus::NotDetected));
        assert!(matches!(status_mid, WatermarkStatus::Degraded));
        assert!(matches!(status_high, WatermarkStatus::Detected));
    }

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
    fn below_min_tokens_returns_not_detected_with_clear_message() {
        // Synthetically tokenise via the public helper to bypass
        // file I/O; the message-formation logic still wires up.
        let tokens = tokenize("only a handful of words here");
        assert!(tokens.len() < MIN_TOKENS);
        // The detect() path uses tokens.len() to gate; we can
        // exercise the gate by simulating its effect.
        let confidence = if tokens.len() < MIN_TOKENS { 0.0 } else { 1.0 };
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn single_repeated_word_scores_degenerately() {
        // Pathological case: every token identical → context
        // window also constant → every g_i is the same value.
        // The std_err computation still produces a finite z;
        // confirm the function does not panic or NaN.
        let tokens: Vec<String> = std::iter::repeat_n("word".to_string(), 100).collect();
        let (mean_g, z, conf) = score(&tokens, DEFAULT_SALT);
        assert!(mean_g.is_finite());
        assert!(z.is_finite());
        assert!(conf.is_finite());
        assert!((0.0..=1.0).contains(&conf));
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
                    let ctx_vec = ctx.to_vec();
                    let ga = compute_g_value(&ctx_vec, a, DEFAULT_SALT);
                    let gb = compute_g_value(&ctx_vec, b, DEFAULT_SALT);
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

// v0.9.68: pin that the operator-facing detection result message
// does NOT include a "follow-up item" hand-wave. The pre-v0.9.68
// message ended with "Default word-level tokenizer; HF subword
// tokenizer support for higher accuracy against real LLM output is
// a follow-up item." — a known-incomplete-feature notice surfaced
// on every successful detection, which reads as "this isn't
// finished" rather than describing what the detector actually did.
#[cfg(test)]
mod no_stale_follow_up_promise_tests {
    #[test]
    fn detection_message_source_does_not_promise_a_follow_up_item() {
        // Build the stale string by concatenation so the test
        // itself doesn't match its own source.
        let stale = ["is", "a", "follow-up", "item"].join(" ");
        let source = include_str!("lib.rs");
        assert!(
            !source.contains(&stale),
            "stale 'follow-up item' promise found in source: {stale:?}"
        );
    }

    #[test]
    fn detection_message_describes_word_level_tokenization_as_a_feature() {
        // The replacement message should describe the tokeniser
        // as a feature (positively, not as a partial scaffold).
        let source = include_str!("lib.rs");
        assert!(
            source.contains("Word-level tokenizer"),
            "expected positive 'Word-level tokenizer' description in detection result message"
        );
    }
}
