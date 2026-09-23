use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use openvibes_core::{CollectorErrorCode, FactValue, ResourceLimits};

use super::{Listener, Protocol, collect_ports, facts};

fn tcp(address: IpAddr, port: u16) -> Listener {
    Listener {
        protocol: Protocol::Tcp,
        address,
        port,
    }
}

fn value<'a>(facts: &'a [openvibes_core::Fact], key: &str) -> &'a FactValue {
    &facts
        .iter()
        .find(|fact| fact.key.as_str() == key)
        .unwrap()
        .value
}

fn strings(values: &[&str]) -> FactValue {
    FactValue::StringList(values.iter().map(|&value| value.to_owned()).collect())
}

#[test]
fn exposed_and_loopback_ports_are_split() {
    let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let local4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let mapped_local = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
    let listeners = [
        tcp(any4, 80),
        tcp(any6, 80),
        tcp(lan, 22),
        tcp(local4, 631),
        tcp(mapped_local, 5432),
        // Bound to loopback and the wildcard: exposed, not local.
        tcp(local4, 443),
        tcp(any6, 443),
        Listener {
            protocol: Protocol::Udp,
            address: any4,
            port: 5353,
        },
    ];
    let facts = facts(&listeners, ResourceLimits::V1).unwrap();
    assert_eq!(
        value(&facts, "port.tcp.exposed"),
        &strings(&["22", "443", "80"])
    );
    assert_eq!(value(&facts, "port.tcp.local"), &strings(&["5432", "631"]));
    assert_eq!(
        value(&facts, "port.tcp.exposed.count"),
        &FactValue::Integer(3)
    );
    assert_eq!(
        value(&facts, "port.tcp.listeners"),
        &strings(&[
            "0.0.0.0:80",
            "127.0.0.1:443",
            "127.0.0.1:631",
            "192.168.1.10:22",
            "[::]:443",
            "[::]:80",
            "[::ffff:127.0.0.1]:5432",
        ])
    );
    assert_eq!(value(&facts, "port.udp.exposed"), &strings(&["5353"]));
    assert!(facts.iter().all(|fact| fact.source.as_str() == "ports"));
    // Every list is sorted and unique, as the evaluator requires.
    for fact in &facts {
        if let FactValue::StringList(values) = &fact.value {
            assert!(
                values.windows(2).all(|pair| pair[0] < pair[1]),
                "{}",
                fact.key.as_str()
            );
        }
    }
}

#[test]
fn too_many_listeners_are_refused() {
    let limits = ResourceLimits {
        fact_list_items: 2,
        ..ResourceLimits::V1
    };
    let listeners: Vec<_> = (1..=3)
        .map(|port| tcp(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        .collect();
    assert_eq!(
        facts(&listeners, limits).unwrap_err().code,
        CollectorErrorCode::InvalidData
    );
}

#[test]
fn a_passed_deadline_emits_nothing() {
    let Some(past) = Instant::now().checked_sub(Duration::from_secs(1)) else {
        return;
    };
    let code = collect_ports(past, ResourceLimits::V1).unwrap_err().code;
    let expected = if cfg!(target_os = "linux") {
        CollectorErrorCode::TimedOut
    } else {
        CollectorErrorCode::Unsupported
    };
    assert_eq!(code, expected);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    use openvibes_core::{CollectorErrorCode, FactValue, ResourceLimits};

    use super::super::{
        Protocol, collect_ports,
        platform::{parse_endpoint, parse_table},
    };

    #[test]
    fn endpoints_decode_native_endian_words() {
        assert_eq!(
            parse_endpoint("0100007F:0016"),
            Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 22))
        );
        assert_eq!(
            parse_endpoint("0A01A8C0:01BB"),
            Some((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 443))
        );
        assert_eq!(
            parse_endpoint("00000000000000000000000001000000:0050"),
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), 80))
        );
        assert_eq!(
            parse_endpoint("0000000000000000FFFF00000100007F:1538"),
            Some((IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 5432))
        );
        for bad in [
            "",
            "0100007F",
            "0100007F:16",
            "0100007:0016",
            "0100007G:0016",
            "ZZ:0016",
        ] {
            assert_eq!(parse_endpoint(bad), None, "{bad}");
        }
    }

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1998 1
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2000 1
   2: 0A01A8C0:D6A2 5DB8D822:01BB 01 00000000:00000000 02:00000A4E 00000000  1000        0 3000 2
";

    #[test]
    fn only_listening_tcp_sockets_are_kept() {
        let listeners = parse_table(TCP, Protocol::Tcp).unwrap();
        let ports: Vec<u16> = listeners.iter().map(|listener| listener.port).collect();
        assert_eq!(ports, [631, 80], "the established connection is skipped");
        let udp = TCP.replace(" 0A ", " 07 ");
        assert_eq!(parse_table(&udp, Protocol::Udp).unwrap().len(), 2);
    }

    #[test]
    fn malformed_tables_are_refused() {
        for (name, table) in [
            ("empty", String::new()),
            (
                "no header",
                TCP.lines().skip(1).collect::<Vec<_>>().join("\n"),
            ),
            ("short row", format!("{TCP}   3: 0100007F:0277\n")),
            ("bad address", TCP.replace("0100007F:0277", "0100007X:0277")),
            ("bad state", TCP.replace(" 0A 0000", " Z 0000")),
        ] {
            let error = parse_table(&table, Protocol::Tcp).unwrap_err();
            assert_eq!(error.code, CollectorErrorCode::InvalidData, "{name}");
        }
    }

    /// Runs on every Linux CI host: something always listens, if only on
    /// loopback, and every value is a valid port.
    #[test]
    fn the_live_host_reports_ports() {
        let facts =
            collect_ports(Instant::now() + Duration::from_secs(30), ResourceLimits::V1).unwrap();
        assert_eq!(facts.len(), 8);
        for fact in &facts {
            let key = fact.key.as_str();
            if let FactValue::StringList(values) = &fact.value
                && (key.ends_with(".exposed") || key.ends_with(".local"))
            {
                assert!(values.iter().all(|port| port.parse::<u16>().is_ok()));
            }
        }
    }
}
