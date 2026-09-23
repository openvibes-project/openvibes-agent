//! Listening sockets: which ports accept connections, and on which addresses.
//!
//! For each protocol (`tcp`, `udp`):
//!
//! - `port.<proto>.exposed` (string list): port numbers, as decimal strings,
//!   bound to any address other than loopback, including the wildcard
//!   (`0.0.0.0`, `::`). A rule reads `'80' in facts['port.tcp.exposed']`.
//! - `port.<proto>.local` (string list): ports bound only to loopback.
//! - `port.<proto>.listeners` (string list): every bound `address:port`, with
//!   IPv6 in brackets, e.g. `0.0.0.0:80`, `[::]:443`, `127.0.0.1:631`.
//! - `port.<proto>.exposed.count` (integer): the number of exposed ports.
//!
//! TCP counts sockets in `LISTEN`. UDP has no listen state, so it counts
//! every bound, unconnected socket, which includes client sockets on
//! ephemeral ports.
//!
//! "Exposed" describes the bind address, not reachability: a host firewall
//! may still block the port, and Docker-published ports bypass firewalld.
//! Only the agent's own network namespace is visible, so listeners inside
//! containers are not seen (Docker's published ports are).
//!
//! All or nothing: an unreadable or malformed socket table, more values than
//! the fact list limit, or a passed deadline yields no facts and one
//! [`CollectorError`].
//!
//! Privileges (Linux): `/proc/net/{tcp,tcp6,udp,udp6}` are world-readable.
//! Windows and macOS report `unsupported`.

use std::{collections::BTreeSet, time::Instant};

use openvibes_core::{
    CollectorError, CollectorErrorCode, Fact, FactValue, Identifier, ResourceLimits,
};

/// Collector identifier reported as the source of every fact and error.
const SOURCE: &str = "ports";

/// Transport protocol of a socket table.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One bound socket: its address and port.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Listener {
    pub(crate) protocol: Protocol,
    pub(crate) address: std::net::IpAddr,
    pub(crate) port: u16,
}

/// Collects the listening-socket facts, or one error if they would be
/// incomplete. Never opens, binds, or probes a socket.
pub fn collect_ports(
    deadline: Instant,
    limits: ResourceLimits,
) -> Result<Vec<Fact>, CollectorError> {
    let listeners = platform::listeners(deadline)?;
    if Instant::now() > deadline {
        return Err(error(
            CollectorErrorCode::TimedOut,
            "port scan exceeded its deadline",
            true,
        ));
    }
    facts(&listeners, limits)
}

pub(crate) fn facts(
    listeners: &[Listener],
    limits: ResourceLimits,
) -> Result<Vec<Fact>, CollectorError> {
    let mut facts = Vec::new();
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let mut exposed = BTreeSet::new();
        let mut loopback = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for listener in listeners
            .iter()
            .filter(|listener| listener.protocol == protocol)
        {
            let port = listener.port.to_string();
            if listener.address.is_loopback() || is_mapped_loopback(listener.address) {
                loopback.insert(port);
            } else {
                exposed.insert(port);
            }
            addresses.insert(match listener.address {
                std::net::IpAddr::V4(address) => format!("{address}:{}", listener.port),
                std::net::IpAddr::V6(address) => format!("[{address}]:{}", listener.port),
            });
        }
        // A port bound to loopback and to an exposed address is exposed.
        let local: BTreeSet<String> = loopback.difference(&exposed).cloned().collect();
        if addresses.len() > limits.fact_list_items {
            return Err(error(
                CollectorErrorCode::InvalidData,
                "more listeners than the fact list limit",
                true,
            ));
        }
        let name = protocol.name();
        let count = i64::try_from(exposed.len()).unwrap_or(i64::MAX);
        facts.push(fact(&format!("port.{name}.exposed"), list(exposed)));
        facts.push(fact(&format!("port.{name}.local"), list(local)));
        facts.push(fact(&format!("port.{name}.listeners"), list(addresses)));
        facts.push(fact(
            &format!("port.{name}.exposed.count"),
            FactValue::Integer(count),
        ));
    }
    Ok(facts)
}

/// Sorted and unique by construction. Port strings sort by byte order
/// (`"1000" < "22"`), which is all binary search needs.
fn list(values: BTreeSet<String>) -> FactValue {
    FactValue::StringList(values.into_iter().collect())
}

fn is_mapped_loopback(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V6(address) => {
            address.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        std::net::IpAddr::V4(_) => false,
    }
}

fn fact(key: &str, value: FactValue) -> Fact {
    Fact {
        key: Identifier::new(key).expect("static fact key"),
        source: Identifier::new(SOURCE).expect("static collector id"),
        value,
    }
}

fn error(code: CollectorErrorCode, message: &str, retryable: bool) -> CollectorError {
    CollectorError {
        collector: Identifier::new(SOURCE).expect("static collector id"),
        code,
        message: message.to_owned(),
        retryable,
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod platform {
    use std::{
        fs::File,
        io::{self, Read},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        path::Path,
        time::Instant,
    };

    use openvibes_core::{CollectorError, CollectorErrorCode};

    use super::{Listener, Protocol, error};

    /// Largest socket table read; a busy server has a few MiB.
    const MAX_TABLE_BYTES: u64 = 64 * 1024 * 1024;
    const TCP_LISTEN: &str = "0A";
    /// `TCP_CLOSE`, which the kernel reports for every unconnected UDP socket.
    const UDP_UNCONNECTED: &str = "07";

    pub(crate) fn listeners(deadline: Instant) -> Result<Vec<Listener>, CollectorError> {
        let tables = [
            ("/proc/net/tcp", Protocol::Tcp, true),
            ("/proc/net/tcp6", Protocol::Tcp, false),
            ("/proc/net/udp", Protocol::Udp, true),
            ("/proc/net/udp6", Protocol::Udp, false),
        ];
        let mut listeners = Vec::new();
        for (path, protocol, required) in tables {
            if Instant::now() > deadline {
                return Err(error(
                    CollectorErrorCode::TimedOut,
                    "port scan exceeded its deadline",
                    true,
                ));
            }
            match read_table(Path::new(path)) {
                Ok(text) => listeners.extend(parse_table(&text, protocol)?),
                // The IPv6 tables are absent when IPv6 is disabled.
                Err(error_) if error_.kind() == io::ErrorKind::NotFound && !required => {}
                Err(error_) => return Err(io_error(&error_)),
            }
        }
        Ok(listeners)
    }

    fn read_table(path: &Path) -> io::Result<String> {
        let mut text = String::new();
        let length = File::open(path)?
            .take(MAX_TABLE_BYTES + 1)
            .read_to_string(&mut text)?;
        if length as u64 > MAX_TABLE_BYTES {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(text)
    }

    /// Bound sockets from one `/proc/net` table. Any malformed row fails the
    /// whole table.
    pub(crate) fn parse_table(
        text: &str,
        protocol: Protocol,
    ) -> Result<Vec<Listener>, CollectorError> {
        let malformed = || {
            error(
                CollectorErrorCode::InvalidData,
                "malformed socket table",
                false,
            )
        };
        let mut lines = text.lines();
        let header = lines.next().ok_or_else(malformed)?;
        if !header.trim_start().starts_with("sl") {
            return Err(malformed());
        }
        let wanted = match protocol {
            Protocol::Tcp => TCP_LISTEN,
            Protocol::Udp => UDP_UNCONNECTED,
        };
        let mut listeners = Vec::new();
        for line in lines.filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split_whitespace();
            let (Some(_slot), Some(local), Some(_remote), Some(state)) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(malformed());
            };
            let (address, port) = parse_endpoint(local).ok_or_else(malformed)?;
            if state.len() != 2 || !state.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(malformed());
            }
            if state.eq_ignore_ascii_case(wanted) {
                listeners.push(Listener {
                    protocol,
                    address,
                    port,
                });
            }
        }
        Ok(listeners)
    }

    /// `HEX_ADDRESS:HEX_PORT`. The address is printed as native-endian 32-bit
    /// words of the network-order bytes; the port is already in host order.
    pub(crate) fn parse_endpoint(field: &str) -> Option<(IpAddr, u16)> {
        let (address, port) = field.split_once(':')?;
        if port.len() != 4 {
            return None;
        }
        let port = u16::from_str_radix(port, 16).ok()?;
        let mut bytes = Vec::with_capacity(16);
        if !(address.len() == 8 || address.len() == 32) {
            return None;
        }
        for word in address.as_bytes().chunks(8) {
            let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        let address = match bytes.len() {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
            _ => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        };
        Some((address, port))
    }

    fn io_error(error_: &io::Error) -> CollectorError {
        match error_.kind() {
            io::ErrorKind::PermissionDenied => error(
                CollectorErrorCode::PermissionDenied,
                "socket tables are not readable by this identity",
                false,
            ),
            io::ErrorKind::NotFound => error(
                CollectorErrorCode::NotFound,
                "/proc/net is not available",
                false,
            ),
            io::ErrorKind::InvalidData => error(
                CollectorErrorCode::InvalidData,
                "socket table is too large or not UTF-8",
                false,
            ),
            _ => error(
                CollectorErrorCode::Internal,
                "cannot read socket tables",
                true,
            ),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) mod platform {
    use std::time::Instant;

    use openvibes_core::{CollectorError, CollectorErrorCode};

    use super::Listener;

    pub(crate) fn listeners(_deadline: Instant) -> Result<Vec<Listener>, CollectorError> {
        Err(super::error(
            CollectorErrorCode::Unsupported,
            "port collection is not supported on this OS yet",
            false,
        ))
    }
}

#[cfg(test)]
mod tests;
