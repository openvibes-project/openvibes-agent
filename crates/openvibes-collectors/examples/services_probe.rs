//! One host services scan (P15), printed one fact per line, with its CPU
//! time: for `scripts/services-e2e.sh`, which runs it under the agent's
//! unit with and without the owners drop-in.

fn main() {
    let cpu = || -> u64 {
        std::fs::read_to_string("/proc/thread-self/schedstat")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok())
            .unwrap_or(0)
    };
    let before = cpu();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let scan = match openvibes_collectors::collect_services(deadline) {
        Ok(scan) => scan,
        Err(error) => {
            println!("error {}", error.message);
            std::process::exit(1);
        }
    };
    let cpu_ms = (cpu() - before) as f64 / 1e6;
    println!("owners {:?}", scan.owners);
    for l in &scan.listeners {
        println!(
            "listener {:?} {} {} service={} program={}",
            l.protocol,
            l.address,
            l.port,
            l.service.as_deref().unwrap_or("-"),
            l.program.as_deref().unwrap_or("-"),
        );
    }
    for s in &scan.services {
        println!(
            "service {} processes={} user={} programs={}",
            s.unit,
            s.processes,
            s.user.as_deref().unwrap_or("-"),
            s.programs.join(",")
        );
    }
    println!("cpu_ms {cpu_ms:.2}");
}
