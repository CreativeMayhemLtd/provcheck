//! Back-end decode: silentcipher decoder logits → 5-byte
//! payload + confidence + structural-validity flag.
//!
//! Port of the production Python `decode_logits` from
//! silentcipher's `server.py`. All steps are pure integer /
//! float math — no externals.
//!
//! Logits arrive as a flat `Vec<f32>` of length
//! `MESSAGE_DIM * T` representing the tensor `[1, 1, MESSAGE_DIM, T]`
//! (the two leading singletons are stripped by the caller).
//! The layout is row-major: `dim * T + t`.

use crate::hparams::{MESSAGE_DIM, MESSAGE_LEN};

/// Outcome of decoding the decoder logits.
#[derive(Debug, Clone)]
pub struct DecodeResult {
    /// 5 bytes recovered from the 40-bit payload, valid iff
    /// `valid == true`. When `valid == false`, contents are
    /// unspecified; the caller should ignore them.
    pub payload: [u8; 5],
    /// Detector confidence in `[0, 1]`. Fraction of
    /// `(tile, position)` pairs whose argmax-symbol matched
    /// the per-position mode. 0.0 when `valid == false`.
    pub confidence: f32,
    /// True iff the mode-voted message contained the
    /// terminator symbol (value 0) somewhere in its 21
    /// positions. The encoder always appends one terminator;
    /// its absence means the bits are not a silentcipher
    /// message.
    pub valid: bool,
}

/// Run argmax + per-position mode + terminator-find +
/// cyclic-roll + bit-pack on the decoder logits.
///
/// `logits` is row-major `[MESSAGE_DIM][T]` flattened, length
/// `MESSAGE_DIM * t_frames`.
pub fn decode_logits(logits: &[f32], t_frames: usize) -> DecodeResult {
    debug_assert_eq!(logits.len(), MESSAGE_DIM * t_frames);

    // 1. Argmax across the MESSAGE_DIM channels at each time
    //    frame. The python code reads `argmax(logits[0,0], axis=0)`.
    let mut pred_per_frame = Vec::with_capacity(t_frames);
    for t in 0..t_frames {
        let mut best_dim = 0;
        let mut best_val = logits[t];
        for d in 1..MESSAGE_DIM {
            let v = logits[d * t_frames + t];
            if v > best_val {
                best_val = v;
                best_dim = d;
            }
        }
        pred_per_frame.push(best_dim as u8);
    }

    // 2. Truncate to a multiple of MESSAGE_LEN and reshape
    //    into a [n_tiles, MESSAGE_LEN] matrix. Each row is one
    //    decoded copy of the cyclically-tiled message.
    let n_tiles = t_frames / MESSAGE_LEN;
    if n_tiles == 0 {
        return DecodeResult {
            payload: [0; 5],
            confidence: 0.0,
            valid: false,
        };
    }
    let usable = n_tiles * MESSAGE_LEN;
    let pred = &pred_per_frame[..usable];

    // 3. Per-position mode across the n_tiles copies. mode_per_pos[p] is
    //    the symbol most-frequently seen at position p across all tiles.
    let mut mode_per_pos = [0u8; MESSAGE_LEN];
    for p in 0..MESSAGE_LEN {
        // MESSAGE_DIM == 5 so this counter is fine fixed-size.
        let mut counts = [0u32; MESSAGE_DIM];
        for tile in 0..n_tiles {
            let v = pred[tile * MESSAGE_LEN + p] as usize;
            counts[v] += 1;
        }
        // numpy / scipy.stats.mode tiebreaks by returning the
        // smallest value in case of a tie — match that behaviour
        // by scanning low-to-high and only updating on strict >.
        let mut best = 0u8;
        let mut best_count = counts[0];
        for v in 1..MESSAGE_DIM {
            if counts[v] > best_count {
                best_count = counts[v];
                best = v as u8;
            }
        }
        mode_per_pos[p] = best;
    }

    // 4. Confidence = fraction of (tile, position) pairs where
    //    the tile's symbol equals the per-position mode.
    let mut matches = 0u32;
    for tile in 0..n_tiles {
        for p in 0..MESSAGE_LEN {
            if pred[tile * MESSAGE_LEN + p] == mode_per_pos[p] {
                matches += 1;
            }
        }
    }
    let confidence = matches as f32 / (n_tiles * MESSAGE_LEN) as f32;

    // 5. Structural validity: find the terminator (symbol 0) in
    //    the mode-voted message. If none, the bits don't form a
    //    valid silentcipher message → not detected. Pick the
    //    smallest index, matching numpy's `np.nonzero(...)[0].min()`.
    let end_char = match mode_per_pos.iter().position(|&s| s == 0) {
        Some(i) => i,
        None => {
            return DecodeResult {
                payload: [0; 5],
                confidence: 0.0,
                valid: false,
            };
        }
    };

    // 6. Cyclic-roll past the terminator and drop it. The
    //    surviving 20 positions are the payload symbols in
    //    encoder order.
    let mut payload_symbols = [0u8; MESSAGE_LEN - 1]; // 20
    for (out_idx, in_idx) in (end_char + 1..MESSAGE_LEN)
        .chain(0..end_char)
        .enumerate()
    {
        payload_symbols[out_idx] = mode_per_pos[in_idx];
    }

    // 7. Undo the encoder's +1: symbols are now in {0..3}, each
    //    carrying 2 bits.
    for s in payload_symbols.iter_mut() {
        if *s == 0 {
            // Defensive: a second terminator inside the 20-payload
            // window means the decoded structure is inconsistent.
            return DecodeResult {
                payload: [0; 5],
                confidence: 0.0,
                valid: false,
            };
        }
        *s -= 1;
    }

    // 8. Pack 20 base-4 symbols MSB-first into 5 bytes. Each
    //    byte holds 4 consecutive symbols; within each symbol
    //    the 2 bits land MSB-first too. So symbol order
    //    [a, b, c, d] → byte = (a<<6) | (b<<4) | (c<<2) | d.
    let mut payload = [0u8; 5];
    for byte_idx in 0..5 {
        let base = byte_idx * 4;
        let a = payload_symbols[base];
        let b = payload_symbols[base + 1];
        let c = payload_symbols[base + 2];
        let d = payload_symbols[base + 3];
        payload[byte_idx] = (a << 6) | (b << 4) | (c << 2) | d;
    }

    DecodeResult {
        payload,
        confidence,
        valid: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic logits tensor that decodes to a known
    /// payload. Useful for verifying bit-packing direction and
    /// the cyclic-roll logic without the model.
    ///
    /// Encoder convention: each payload byte = 4 base-4 symbols
    /// MSB-first. We invert: take 5 payload bytes, expand to
    /// 20 base-4 symbols, add 1 to each, append a terminator
    /// (0), then tile that 21-symbol sequence across `n_tiles`
    /// time frames, optionally rolled to put the terminator
    /// somewhere other than the end.
    fn synth_logits(payload: [u8; 5], n_tiles: usize, roll: usize) -> (Vec<f32>, usize) {
        let mut symbols = [0u8; MESSAGE_LEN];
        // Expand each byte into 4 base-4 symbols MSB-first.
        for byte_idx in 0..5 {
            let b = payload[byte_idx];
            symbols[byte_idx * 4] = (b >> 6) & 0b11;
            symbols[byte_idx * 4 + 1] = (b >> 4) & 0b11;
            symbols[byte_idx * 4 + 2] = (b >> 2) & 0b11;
            symbols[byte_idx * 4 + 3] = b & 0b11;
        }
        // Encoder adds +1 to payload symbols, terminator is 0.
        for s in &mut symbols[..MESSAGE_LEN - 1] {
            *s += 1;
        }
        // The terminator was appended last in the encoder's
        // tile. Apply the cyclic roll requested by the test
        // (rotates positions, so the terminator can land
        // anywhere from index 0 to MESSAGE_LEN-1).
        let mut rolled = [0u8; MESSAGE_LEN];
        for (i, slot) in rolled.iter_mut().enumerate() {
            *slot = symbols[(i + roll) % MESSAGE_LEN];
        }
        // Tile rolled across the time axis n_tiles times. The
        // logits tensor is [MESSAGE_DIM][T], so for each tile-t
        // we set the "chosen" dim to a strong positive logit
        // and all others to a small negative.
        let t_frames = n_tiles * MESSAGE_LEN;
        let mut logits = vec![-10.0_f32; MESSAGE_DIM * t_frames];
        for tile in 0..n_tiles {
            for p in 0..MESSAGE_LEN {
                let t = tile * MESSAGE_LEN + p;
                let chosen = rolled[p] as usize;
                logits[chosen * t_frames + t] = 10.0;
            }
        }
        (logits, t_frames)
    }

    #[test]
    fn round_trips_rai_payload() {
        let payload = [82, 65, 73, 1, 0]; // RAI + schema=1 + reserved=0
        let (logits, t) = synth_logits(payload, 30, 0);
        let r = decode_logits(&logits, t);
        assert!(r.valid, "structurally valid");
        assert_eq!(r.payload, payload);
        assert!(r.confidence > 0.99, "got {}", r.confidence);
    }

    #[test]
    fn round_trips_dfm_payload() {
        let payload = [68, 70, 77, 1, 0]; // DFM + schema=1 + reserved=0
        let (logits, t) = synth_logits(payload, 30, 0);
        let r = decode_logits(&logits, t);
        assert!(r.valid);
        assert_eq!(r.payload, payload);
    }

    #[test]
    fn handles_cyclic_roll_anywhere() {
        // Terminator must be found at any roll offset.
        let payload = [68, 70, 77, 1, 0];
        for roll in 0..MESSAGE_LEN {
            let (logits, t) = synth_logits(payload, 30, roll);
            let r = decode_logits(&logits, t);
            assert!(r.valid, "valid at roll={roll}");
            assert_eq!(r.payload, payload, "payload at roll={roll}");
        }
    }

    #[test]
    fn rejects_input_with_no_terminator() {
        // Build logits where every position prefers symbol 1
        // (a payload-only message with no terminator). Decoder
        // must reject as not-detected.
        let n_tiles = 30;
        let t_frames = n_tiles * MESSAGE_LEN;
        let mut logits = vec![-10.0_f32; MESSAGE_DIM * t_frames];
        for t in 0..t_frames {
            logits[1 * t_frames + t] = 10.0;
        }
        let r = decode_logits(&logits, t_frames);
        assert!(!r.valid);
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn rejects_too_short_audio() {
        // Only one MESSAGE_LEN's worth of frames — produces
        // exactly 1 tile, which is enough structurally but
        // matches the python behaviour: must have at least 1.
        let payload = [82, 65, 73, 1, 0];
        let (logits, t) = synth_logits(payload, 1, 0);
        let r = decode_logits(&logits, t);
        assert!(r.valid); // 1 tile is the minimum; decoder accepts it
        // Now strictly below MESSAGE_LEN: not enough for any tiles.
        let logits_short = vec![0.0_f32; MESSAGE_DIM * (MESSAGE_LEN - 1)];
        let r2 = decode_logits(&logits_short, MESSAGE_LEN - 1);
        assert!(!r2.valid);
        assert_eq!(r2.confidence, 0.0);
    }

    #[test]
    fn degraded_input_yields_sub_unit_confidence() {
        // Two payloads picked to differ at every payload
        // symbol so 20 of the 21 positions per tile will
        // disagree between the two voting blocs (position 20
        // is the terminator, identical for any valid message).
        //
        // 255 = 0b11111111 → base-4 [3,3,3,3], same in all 3 brand bytes.
        // 0   = 0b00000000 → base-4 [0,0,0,0], same in all 3 brand bytes.
        // So bytes 0..3 differ at every base-4 position (12 positions).
        // Bytes 3 and 4 of the payload are common to both (schema=1, reserved=0),
        // contributing 8 more identical positions. Net: 12 differing positions,
        // 9 matching positions out of 21.
        let majority = [255, 255, 255, 1, 0];
        let minority = [0, 0, 0, 1, 0];
        let n_majority = 15;
        let n_minority = 14;
        let (logits_maj, _) = synth_logits(majority, n_majority, 0);
        let (logits_min, _) = synth_logits(minority, n_minority, 0);
        let total_tiles = n_majority + n_minority;
        let t_frames = total_tiles * MESSAGE_LEN;
        let mut combined = vec![-10.0_f32; MESSAGE_DIM * t_frames];
        let t_a = n_majority * MESSAGE_LEN;
        let t_b = n_minority * MESSAGE_LEN;
        for d in 0..MESSAGE_DIM {
            for t in 0..t_a {
                combined[d * t_frames + t] = logits_maj[d * t_a + t];
            }
            for t in 0..t_b {
                combined[d * t_frames + (t_a + t)] = logits_min[d * t_b + t];
            }
        }
        let r = decode_logits(&combined, t_frames);
        assert!(r.valid);
        assert_eq!(r.payload, majority, "majority bloc should win");
        // Confidence noticeably below 1.0 — split decisions on
        // 12 of 21 positions per tile.
        assert!(
            r.confidence < 0.95,
            "expected sub-unit confidence on split vote, got {}",
            r.confidence
        );
        assert!(
            r.confidence > 0.5,
            "majority bloc dominant — confidence should still be > 0.5, got {}",
            r.confidence
        );
    }
}
