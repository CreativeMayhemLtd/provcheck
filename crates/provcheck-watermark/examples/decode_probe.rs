//! decode_probe — print sample count + first/last samples from our
//! audio decode path. Used to triage public issue #24 (AAC-in-MP4
//! detector regression).

use std::env;
use std::fs::File;
use std::path::Path;

use symphonia::core::codecs::CODEC_TYPE_NULL;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

fn dump_metadata(path: &Path) {
    let Ok(file) = File::open(path) else { return };
    let mss = MediaSourceStream::new(Box::new(file), Default::default());
    let mut hint = Hint::new();
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        hint.with_extension(ext);
    }
    let Ok(probed) = symphonia::default::get_probe().format(
        &hint,
        mss,
        &FormatOptions::default(),
        &MetadataOptions::default(),
    ) else {
        eprintln!("  symphonia: probe failed");
        return;
    };
    let format = probed.format;
    for track in format.tracks() {
        if track.codec_params.codec == CODEC_TYPE_NULL {
            continue;
        }
        let cp = &track.codec_params;
        eprintln!(
            "  symphonia: codec={:?} sr={:?} n_frames={:?} start_ts={} delay={:?} padding={:?} channels={:?}",
            cp.codec, cp.sample_rate, cp.n_frames, cp.start_ts, cp.delay, cp.padding, cp.channels
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: cargo run --release -p provcheck-watermark --example decode_probe -- <file> [<file> ...]");
        std::process::exit(2);
    }

    for p in args {
        let path = Path::new(&p);
        print!("{p}: ");
        dump_metadata(path);
        match provcheck_watermark::audio::decode_to_mono_44k1(path) {
            Ok(samples) => {
                let n = samples.len();
                let dur = n as f32 / 44_100.0;
                let head: Vec<String> = samples.iter().take(4).map(|s| format!("{s:+.6}")).collect();
                let tail: Vec<String> = samples
                    .iter()
                    .rev()
                    .take(4)
                    .map(|s| format!("{s:+.6}"))
                    .collect();
                let sum_sq: f64 = samples.iter().map(|s| (*s as f64) * (*s as f64)).sum();
                let rms = (sum_sq / n.max(1) as f64).sqrt();
                println!(
                    "n={n} ({dur:.4}s @ 44100Hz) rms={rms:.6} head=[{}] tail=[{}]",
                    head.join(", "),
                    tail.join(", ")
                );
            }
            Err(e) => println!("ERR: {e}"),
        }
    }
}
