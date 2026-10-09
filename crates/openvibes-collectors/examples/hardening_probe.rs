//! Prints what the hardening collector (protocol P19) reads on this host,
//! one `key = value` line per fact and one `error` line per unreadable
//! source. Run as root to see what the root-facts helper sees:
//! `cargo run --example hardening_probe [ROOT]`.

#![forbid(unsafe_code)]

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| "/".to_owned());
    let hardening = openvibes_collectors::collect_hardening(std::path::Path::new(&root));
    for fact in &hardening.facts {
        println!("{} = {:?}", fact.key.as_str(), fact.value);
    }
    for error in &hardening.errors {
        println!(
            "error {} {:?}: {}",
            error.collector.as_str(),
            error.code,
            error.message
        );
    }
}
