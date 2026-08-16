//! `provcheck-mellin` — embed and read a keyed per-copy serial watermark in
//! audio files, using the BUSL-1.1 Fourier-Mellin channel.
//!
//! This binary lives in the opt-in, standalone crate and is never part of the
//! Apache-2.0 provcheck release. Build it with:
//!
//!   cargo build --manifest-path crates/provcheck-mellin/Cargo.toml --release
//!
//! Usage:
//!   provcheck-mellin embed --secret <hex> --work-id <str> --serial <hex>
//!                          [--repeat N] [--strength F] <in.wav> -o <out.wav>
//!   provcheck-mellin read  --secret <hex> --work-id <str>
//!                          [--repeat N] [--strength F] [--expect <hex>] <in.wav>
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
         provcheck-mellin read  --secret <hex> --work-id <str> [--repeat N] [--strength F] [--expect <hex>] <in.wav>"
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
            let (channels, _sr) = decode_planar_i16le(input).unwrap_or_else(|e| die(e));
            let r = read_serial_channels(&ch, &channels, repeat_of(&flags));
            println!("channels:        {}", channels.len());
            println!("serial:          0x{:016X}", r.serial);
            println!("bits recovered:  {}/{}", r.bits_recovered, 64);
            println!("erasure rate:    {:.1}%", r.erasure_rate * 100.0);
            println!("min bit votes:   {}", r.min_bit_votes);
            if let Some(expect) = flags.get("expect") {
                let want = u64_hex(expect);
                if r.serial == want && r.fully_recovered() {
                    println!("MATCH 0x{want:016X}");
                } else {
                    println!("NO MATCH (expected 0x{want:016X})");
                    exit(1);
                }
            }
        }
        "-h" | "--help" | "help" => usage(),
        other => die(format!("unknown command '{other}' (expected embed|read)")),
    }
}
