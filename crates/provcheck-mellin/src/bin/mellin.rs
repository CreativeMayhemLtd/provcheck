// SPDX-License-Identifier: BUSL-1.1 OR LicenseRef-provcheck-mellin-Commercial
// Copyright (C) 2026 Creative Mayhem UG (haftungsbeschränkt)
//! `provcheck-mellin` — embed and read a keyed per-copy serial watermark in
//! audio files, using the keyed Fourier-Mellin channel.
//!
//! This binary lives in the opt-in, standalone crate and is never part of the
//! Apache-2.0 provcheck release. Build it with:
//!
//!   cargo build --manifest-path crates/provcheck-mellin/Cargo.toml --release
//!
//! Two watermark modes share the same channel:
//!
//! - `embed` / `read` carry a fixed 64-bit per-copy **serial** for individuation.
//! - `trace-embed` / `accuse` carry a collusion-resistant **Tardos codeword** and
//!   name at least one colluder from a leak (see `tardos.rs` and `trace.rs`).
//!
//! Usage:
//!   provcheck-mellin embed --secret <hex> --work-id <str> --serial <hex>
//!                          [--repeat N] [--strength F] <in.wav> -o <out.wav>
//!   provcheck-mellin read  --secret <hex> --work-id <str>
//!                          [--repeat N] [--strength F] [--expect <hex>] <in.wav>
//!   provcheck-mellin trace-embed --secret <hex> --work-id <str> --buyer <str>
//!                          --positions M --colluders C [--strength F] <in.wav> -o <out.wav>
//!   provcheck-mellin accuse --secret <hex> --work-id <str> --positions M
//!                          --colluders C --buyers <file> [--fp-log10 K] <leak>
//!
//! `--secret` is hex-encoded bytes (or use --secret-file <path> for raw bytes).
//! Detection requires the same secret and work id used to embed.

use std::collections::HashMap;
use std::process::exit;

use provcheck_mellin::MellinChannel;
use provcheck_mellin::audio::{decode_planar_i16le, write_wav_i16le};
use provcheck_mellin::serial::{
    DEFAULT_REPEAT, MIN_SAMPLES_PER_POSITION, embed_serial, positions_for, read_serial_channels,
    samples_per_position,
};

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("provcheck-mellin: {}", msg.as_ref());
    exit(2);
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         provcheck-mellin embed --secret <hex> --work-id <str> --serial <hex> [--repeat N] [--strength F] <in.wav> -o <out.wav>\n  \
         provcheck-mellin read  --secret <hex> --work-id <str> [--repeat N] [--strength F] [--expect <hex>] [--json] <in.wav>\n  \
         provcheck-mellin trace-embed --secret <hex> --work-id <str> --buyer <str> --positions M --colluders C [--strength F] <in.wav> -o <out.wav>\n  \
         provcheck-mellin accuse --secret <hex> --work-id <str> --positions M --colluders C --buyers <file> [--fp-log10 K] [--strength F] [--json] <leak>\n\n\
         embed/read carry a fixed 64-bit per-copy serial; trace-embed/accuse carry a\n  \
         collusion-resistant Tardos codeword and name at least one colluder from a leak."
    );
    exit(2);
}

/// Split argv into (positional, flags). Flags are `--name value`; `-o` aliases `--out`.
fn parse(args: &[String]) -> (Vec<String>, HashMap<String, String>) {
    let mut pos = Vec::new();
    let mut flags = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let name = match a.as_str() {
            "-o" => Some("out"),
            s if s.starts_with("--") => Some(&s[2..]),
            _ => None,
        };
        match name {
            // Boolean flags take no value. `--json` switches stdout to one
            // machine-readable line (the protocol provcheck shells into).
            Some("json") => {
                flags.insert("json".to_string(), "1".to_string());
                i += 1;
            }
            Some(n) => {
                let v = args
                    .get(i + 1)
                    .unwrap_or_else(|| die(format!("--{n} needs a value")));
                flags.insert(n.to_string(), v.clone());
                i += 2;
            }
            None => {
                pos.push(a.clone());
                i += 1;
            }
        }
    }
    (pos, flags)
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        die("hex value must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| die("bad hex digit")))
        .collect()
}

fn u64_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16)
        .unwrap_or_else(|_| die("--serial/--expect must be up to 16 hex digits"))
}

fn secret_bytes(flags: &HashMap<String, String>) -> Vec<u8> {
    if let Some(hex) = flags.get("secret") {
        decode_hex(hex)
    } else if let Some(path) = flags.get("secret-file") {
        std::fs::read(path).unwrap_or_else(|e| die(format!("read secret-file: {e}")))
    } else {
        die("need --secret <hex> or --secret-file <path>");
    }
}

fn repeat_of(flags: &HashMap<String, String>) -> usize {
    flags
        .get("repeat")
        .map(|r| {
            r.parse()
                .unwrap_or_else(|_| die("--repeat must be a positive integer"))
        })
        .unwrap_or(DEFAULT_REPEAT)
}

fn strength_of(flags: &HashMap<String, String>) -> f32 {
    flags
        .get("strength")
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| die("--strength must be a number"))
        })
        .unwrap_or(0.2)
}

fn channel(flags: &HashMap<String, String>) -> MellinChannel {
    let secret = secret_bytes(flags);
    let work_id = flags
        .get("work-id")
        .unwrap_or_else(|| die("need --work-id <str>"));
    MellinChannel::for_work(&secret, work_id.as_bytes(), strength_of(flags))
}

fn usize_flag(flags: &HashMap<String, String>, name: &str) -> usize {
    flags
        .get(name)
        .unwrap_or_else(|| die(format!("need --{name} <n>")))
        .parse()
        .unwrap_or_else(|_| die(format!("--{name} must be a positive integer")))
}

fn fp_log10_of(flags: &HashMap<String, String>) -> u32 {
    flags
        .get("fp-log10")
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| die("--fp-log10 must be a non-negative integer"))
        })
        .unwrap_or(6)
}

/// Read a buyers ledger file: one buyer label per line, blank lines and
/// `#` comments ignored.
fn buyers_from_file(path: &str) -> Vec<String> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("read buyers {path}: {e}")));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Diagnostic logging to stderr; results go to stdout so pipelines stay clean.
fn log(msg: impl AsRef<str>) {
    eprintln!("provcheck-mellin: {}", msg.as_ref());
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        usage();
    }
    let cmd = argv[0].clone();
    let (pos, flags) = parse(&argv[1..]);

    match cmd.as_str() {
        "embed" => {
            let input = pos.first().unwrap_or_else(|| die("need <in.wav>"));
            let out = flags.get("out").unwrap_or_else(|| die("need -o <out.wav>"));
            let serial = u64_hex(
                flags
                    .get("serial")
                    .unwrap_or_else(|| die("need --serial <hex>")),
            );
            let ch = channel(&flags);
            let repeat = repeat_of(&flags);
            let (channels, sr) = decode_planar_i16le(input).unwrap_or_else(|e| die(e));
            let spp = samples_per_position(channels[0].len() / 2, repeat);
            if spp < MIN_SAMPLES_PER_POSITION {
                eprintln!(
                    "provcheck-mellin: warning: only {spp} samples/position (< {MIN_SAMPLES_PER_POSITION} recommended); \
                     detection may erase. Use longer audio, a lower --repeat, or a higher --strength."
                );
            }
            let marked: Vec<Vec<u8>> = channels
                .iter()
                .map(|c| embed_serial(&ch, c, serial, repeat))
                .collect();
            write_wav_i16le(out, &marked, sr).unwrap_or_else(|e| die(e));
            println!(
                "embedded serial 0x{serial:016X} into {out} ({sr} Hz, {} ch, {} positions/ch, {spp} samples/position)",
                channels.len(),
                positions_for(repeat)
            );
        }
        "read" => {
            let input = pos.first().unwrap_or_else(|| die("need <in.wav>"));
            let ch = channel(&flags);
            let json = flags.contains_key("json");
            let (channels, _sr) = decode_planar_i16le(input).unwrap_or_else(|e| die(e));
            let r = read_serial_channels(&ch, &channels, repeat_of(&flags));
            // With --expect: Some(true/false); without: None (surfaced as JSON null).
            let matched = flags
                .get("expect")
                .map(|e| u64_hex(e))
                .map(|want| (want, r.serial == want && r.fully_recovered()));
            if json {
                // EXACTLY one line on stdout: the protocol the provcheck
                // shell-out parses. The serial is a hex STRING because a u64
                // does not survive parsing as a JS/JSON number.
                println!(
                    "{}",
                    serde_json::json!({
                        "channels": channels.len(),
                        "serial": format!("0x{:016X}", r.serial),
                        "bits_recovered": r.bits_recovered,
                        "erasure_rate": r.erasure_rate,
                        "min_bit_votes": r.min_bit_votes,
                        "fully_recovered": r.fully_recovered(),
                        "match": matched.map(|(_, m)| m),
                    })
                );
            } else {
                println!("channels:        {}", channels.len());
                println!("serial:          0x{:016X}", r.serial);
                println!("bits recovered:  {}/{}", r.bits_recovered, 64);
                println!("erasure rate:    {:.1}%", r.erasure_rate * 100.0);
                println!("min bit votes:   {}", r.min_bit_votes);
            }
            // Exit semantics are identical with and without --json.
            if let Some((want, m)) = matched {
                if m {
                    if !json {
                        println!("MATCH 0x{want:016X}");
                    }
                } else {
                    if !json {
                        println!("NO MATCH (expected 0x{want:016X})");
                    }
                    exit(1);
                }
            }
        }
        "trace-embed" => {
            let input = pos.first().unwrap_or_else(|| die("need <in.wav>"));
            let out = flags.get("out").unwrap_or_else(|| die("need -o <out.wav>"));
            let secret = secret_bytes(&flags);
            let work_id = flags
                .get("work-id")
                .unwrap_or_else(|| die("need --work-id <str>"));
            let buyer = flags
                .get("buyer")
                .unwrap_or_else(|| die("need --buyer <str>"));
            let positions = usize_flag(&flags, "positions");
            let colluders = usize_flag(&flags, "colluders");
            let ch = MellinChannel::for_work(&secret, work_id.as_bytes(), strength_of(&flags));
            let (channels, sr) = decode_planar_i16le(input).unwrap_or_else(|e| die(e));
            let spp = channels[0].len() / 2 / positions.max(1);
            log(format!(
                "work '{work_id}', buyer '{buyer}': {positions} positions, {} ch, {spp} samples/position",
                channels.len()
            ));
            if spp < MIN_SAMPLES_PER_POSITION {
                log(format!(
                    "warning: {spp} samples/position (< {MIN_SAMPLES_PER_POSITION}); detection may erase. Use longer audio or fewer --positions."
                ));
            }
            log(format!(
                "indicative collusion capacity here: ~{} colluders (population 1000, eps 1e-6); requested {colluders}",
                provcheck_mellin::trace::capacity(positions, 1000, 6)
            ));
            let codeword = provcheck_mellin::trace::buyer_codeword(
                &secret,
                work_id.as_bytes(),
                buyer,
                positions,
                colluders,
            );
            let ones = codeword.iter().filter(|b| **b).count();
            let marked: Vec<Vec<u8>> = channels
                .iter()
                .map(|c| provcheck_mellin::trace::embed_codeword(&ch, c, &codeword))
                .collect();
            write_wav_i16le(out, &marked, sr).unwrap_or_else(|e| die(e));
            println!(
                "embedded trace codeword for '{buyer}' into {out} ({sr} Hz, {} ch, {positions} positions, {ones} ones)",
                channels.len()
            );
        }
        "accuse" => {
            let input = pos.first().unwrap_or_else(|| die("need <leak>"));
            let secret = secret_bytes(&flags);
            let work_id = flags
                .get("work-id")
                .unwrap_or_else(|| die("need --work-id <str>"));
            let positions = usize_flag(&flags, "positions");
            let colluders = usize_flag(&flags, "colluders");
            let fp_log10 = fp_log10_of(&flags);
            let buyers_path = flags
                .get("buyers")
                .unwrap_or_else(|| die("need --buyers <file>"));
            let buyers = buyers_from_file(buyers_path);
            if buyers.is_empty() {
                die("buyers file has no entries");
            }
            let ch = MellinChannel::for_work(&secret, work_id.as_bytes(), strength_of(&flags));
            let (channels, _sr) = decode_planar_i16le(input).unwrap_or_else(|e| die(e));
            let detected =
                provcheck_mellin::trace::detect_codeword_channels(&ch, &channels, positions);
            let observed = detected.iter().filter(|d| d.is_some()).count();
            let floor = provcheck_mellin::tardos::MIN_OBSERVED_POSITIONS;
            log(format!(
                "{} ch, {positions} positions, {observed} observed ({:.1}% erased), {} enrolled buyers",
                channels.len(),
                100.0 * (1.0 - observed as f64 / positions.max(1) as f64),
                buyers.len()
            ));
            log(format!(
                "threshold {:.2} (fp bound 1e-{fp_log10}, observed floor {floor})",
                provcheck_mellin::tardos::threshold(observed, buyers.len().max(1), fp_log10)
            ));
            let mut ledger = provcheck_mellin::tardos::TraceLedger::new();
            for b in &buyers {
                ledger.enroll(&secret, work_id.as_bytes(), b);
            }
            let suspects = provcheck_mellin::trace::accuse_detected(
                &detected,
                &secret,
                work_id.as_bytes(),
                positions,
                colluders,
                &ledger,
                fp_log10,
            );
            if flags.contains_key("json") {
                // One machine-readable line; exit semantics unchanged below.
                let refused = observed < floor;
                let th = (!refused)
                    .then(|| provcheck_mellin::tardos::threshold(observed, buyers.len().max(1), fp_log10));
                println!(
                    "{}",
                    serde_json::json!({
                        "positions": positions,
                        "observed": observed,
                        "floor": floor,
                        "refused_below_floor": refused,
                        "threshold": th,
                        "accused": suspects
                            .iter()
                            .map(|s| serde_json::json!({
                                "label": s.label,
                                "score": s.score,
                                "threshold": s.threshold,
                            }))
                            .collect::<Vec<_>>(),
                    })
                );
                if suspects.is_empty() {
                    exit(1);
                }
            } else if suspects.is_empty() {
                if observed < floor {
                    println!(
                        "NO ACCUSATION (only {observed} observed positions, below the {floor} floor)"
                    );
                } else {
                    println!("NO ACCUSATION (no buyer scored above threshold)");
                }
                exit(1);
            } else {
                println!("accused (strongest first):");
                for s in &suspects {
                    println!(
                        "  {}  score {:.2}  (threshold {:.2})",
                        s.label, s.score, s.threshold
                    );
                }
            }
        }
        "-h" | "--help" | "help" => usage(),
        other => die(format!(
            "unknown command '{other}' (expected embed, read, trace-embed, or accuse)"
        )),
    }
}
