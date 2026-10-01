use std::net::{IpAddr, Ipv4Addr};

use openvibes_core::{HostService, ListenerProtocol, Owners, ServiceListener};
use openvibes_transport::TransportError;

use super::{Delivery, RESEND_MS, Snapshot};

fn listener(port: u16) -> ServiceListener {
    ServiceListener {
        protocol: ListenerProtocol::Tcp,
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        exposed: true,
        service: Some("nginx.service".into()),
        program: None,
    }
}

fn service(unit: &str) -> HostService {
    HostService {
        unit: unit.into(),
        programs: vec!["nginx".into()],
        processes: 1,
        user: Some("root".into()),
    }
}

fn snapshot(at: i64, ports: &[u16]) -> Snapshot {
    Snapshot::new(
        Owners::Partial,
        ports.iter().map(|p| listener(*p)).collect(),
        vec![service("nginx.service")],
        at,
    )
}

/// A fresh directory per test (unit tests have no CARGO_TARGET_TMPDIR).
fn scratch(test: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-services-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn id() -> openvibes_core::Identifier {
    openvibes_core::Identifier::new("agent.1").unwrap()
}

#[test]
fn lists_are_sorted_deduplicated_and_cut_in_digest_order() {
    // Count limit: 2,048 services fit the size limit.
    let s = Snapshot::new(
        Owners::Partial,
        Vec::new(),
        (0..3000)
            .map(|i| service(&format!("u{i}.service")))
            .collect(),
        1,
    );
    assert_eq!(s.services.len(), 2048);
    // Size limit: 4,096 listeners (about 90 bytes each here) do not fit
    // 256 KiB, so fewer are kept, the first in digest order (by JSON text:
    // port 1, 10, 100, 1000, 1001 …), duplicates once.
    let s = Snapshot::new(
        Owners::Partial,
        (0..5000)
            .rev()
            .map(|i| listener(1 + i))
            .chain([listener(1)])
            .collect(),
        vec![service("nginx.service")],
        1,
    );
    assert!(s.listeners.len() < 4096);
    assert_eq!(s.listeners[0].port, 1);
    assert_eq!(s.listeners[1].port, 10);
    assert_eq!(s.listeners.iter().filter(|l| l.port == 1).count(), 1);
    let body = serde_json::to_vec(&(&s.listeners, &s.services)).unwrap();
    assert!(
        body.len() <= openvibes_core::HOST_SERVICES_BYTES - 1024,
        "{}",
        body.len()
    );
    assert_eq!(
        s.sha256,
        openvibes_core::hex(&openvibes_core::services_digest(&s.listeners, &s.services))
    );
}

#[test]
fn sent_when_changed_and_daily_otherwise() {
    let dir = scratch("daily");
    let mut d = Delivery::open(&dir);
    d.pending = Some(snapshot(1_000, &[443]));
    let report = d.due(&id(), 2_000).expect("never acknowledged: due");
    assert_eq!(d.sent(&report, Ok(()), 2_000), None);
    assert!(d.due(&id(), 2_001).is_none(), "acknowledged");
    // Kept across a restart.
    let mut d = Delivery::open(&dir);
    d.pending = Some(snapshot(3_000, &[443]));
    assert!(d.due(&id(), 3_000).is_none(), "same digest after restart");
    assert!(d.due(&id(), 2_000 + RESEND_MS).is_some(), "a day later");
    // A clock stepped backwards does not hold it back forever.
    assert!(d.due(&id(), 1_000).is_some());
    d.pending = Some(snapshot(4_000, &[443, 22]));
    assert!(d.due(&id(), 4_000).is_some(), "changed");
}

#[test]
fn refusals_wait_for_a_change_failures_for_the_next_scan_404_for_restart() {
    let dir = scratch("refusals");
    let mut d = Delivery::open(&dir);
    d.pending = Some(snapshot(1, &[443]));
    let report = d.due(&id(), 1).unwrap();
    assert!(d.sent(&report, Err(TransportError::Rejected), 1).is_some());
    d.pending = Some(snapshot(2, &[443]));
    assert!(d.due(&id(), 2).is_none(), "same lists, refused");
    d.pending = Some(snapshot(3, &[443, 80]));
    let report = d.due(&id(), 3).expect("changed after a refusal");
    assert!(
        d.sent(&report, Err(TransportError::Unavailable), 3)
            .is_some()
    );
    assert!(d.due(&id(), 4).is_none(), "not every tick");
    d.pending = Some(snapshot(5, &[443, 80]));
    let report = d.due(&id(), 5).expect("the next scan retries");
    assert_eq!(d.sent(&report, Err(TransportError::NotFound), 5), None);
    d.pending = Some(snapshot(6, &[1]));
    assert!(d.due(&id(), 6).is_none(), "a platform before P15");
}

#[test]
fn a_damaged_ack_file_means_send_again() {
    let dir = scratch("damaged");
    std::fs::write(dir.join("services.ack"), "nonsense").unwrap();
    let mut d = Delivery::open(&dir);
    d.pending = Some(snapshot(1, &[443]));
    assert!(d.due(&id(), 1).is_some());
}
