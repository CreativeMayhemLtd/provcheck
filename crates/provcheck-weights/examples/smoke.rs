fn main() {
    let path = provcheck_weights::load_or_download("trustmark", "b-encoder").expect("load");
    println!("downloaded to {:?}", path);
    println!("size: {} bytes", std::fs::metadata(&path).unwrap().len());
    let s = provcheck_weights::status();
    for w in s {
        println!("  {:30} cached={} valid={}", w.entry.filename, w.cached.exists, w.cached.valid);
    }
}
