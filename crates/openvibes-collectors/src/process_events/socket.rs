//! The audit multicast socket (Linux): `NETLINK_AUDIT`, group
//! `AUDIT_NLGRP_READLOG`, which needs only `CAP_AUDIT_READ`.

use std::time::Duration;

use openvibes_core::{CollectorError, CollectorErrorCode};

use super::{
    error,
    reader::{Received, Source},
};

/// How long one receive waits, so the reader can expire events.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// Socket buffer asked for; the kernel caps it at `rmem_max`.
const RECV_BUFFER: usize = 1 << 20;

/// A bound audit multicast socket.
pub struct AuditSocket(rustix::fd::OwnedFd);

impl AuditSocket {
    /// The receive buffer the kernel granted, in bytes (capped by
    /// `net.core.rmem_max` for an unprivileged socket).
    #[must_use]
    pub fn recv_buffer(&self) -> Option<usize> {
        rustix::net::sockopt::socket_recv_buffer_size(&self.0).ok()
    }
}

/// Opens and binds the socket: `permission_denied` without
/// `CAP_AUDIT_READ`, `unsupported` without kernel audit.
pub fn open_audit_socket() -> Result<AuditSocket, CollectorError> {
    use rustix::{
        io::Errno,
        net::{
            AddressFamily, SocketFlags, SocketType, bind,
            netlink::{self, SocketAddrNetlink},
            socket_with,
            sockopt::{Timeout, set_socket_recv_buffer_size, set_socket_timeout},
        },
    };
    let failed = |errno: Errno, what: &str| {
        let code = match errno {
            Errno::PERM | Errno::ACCESS => CollectorErrorCode::PermissionDenied,
            Errno::PROTONOSUPPORT | Errno::AFNOSUPPORT | Errno::NOENT => {
                CollectorErrorCode::Unsupported
            }
            _ => CollectorErrorCode::Internal,
        };
        error(code, what)
    };
    let fd = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::AUDIT),
    )
    .map_err(|e| failed(e, "cannot open the audit socket"))?;
    // Group 1 is AUDIT_NLGRP_READLOG, a bit mask.
    bind(&fd, &SocketAddrNetlink::new(0, 1))
        .map_err(|e| failed(e, "cannot join the audit multicast group"))?;
    set_socket_timeout(&fd, Timeout::Recv, Some(RECV_TIMEOUT))
        .map_err(|e| failed(e, "cannot set the audit socket timeout"))?;
    // A larger buffer means fewer ENOBUFS in bursts; best effort.
    let _ = set_socket_recv_buffer_size(&fd, RECV_BUFFER);
    Ok(AuditSocket(fd))
}

/// After a wakeup, how long the reader lets a burst queue up before it
/// drains it without blocking: one wakeup per burst instead of one per
/// message (about seven per exec), which was most of the reader's CPU.
/// Only after the socket ran empty, so sustained load never sleeps; 5 ms of
/// traffic fits the socket buffer (`rmem_max`, ~208 KiB) up to some
/// thousands of execs a second, and an overflow is counted (`ENOBUFS`).
const COALESCE: Duration = Duration::from_millis(5);

impl Source for AuditSocket {
    fn recv(&mut self, buf: &mut [u8]) -> Received {
        use rustix::{
            io::Errno,
            net::{RecvFlags, netlink::SocketAddrNetlink, recvfrom},
        };
        let mut received = recvfrom(&self.0, &mut *buf, RecvFlags::DONTWAIT);
        if matches!(received, Err(Errno::AGAIN)) {
            // Empty: sleep until something arrives (or the timeout), then
            // let the rest of the burst queue up.
            received = recvfrom(&self.0, &mut *buf, RecvFlags::empty());
            if received.is_ok() {
                std::thread::sleep(COALESCE);
            }
        }
        match received {
            // Only the kernel (port 0) sends audit records; anything else
            // is ignored.
            Ok((_, len, Some(from))) => match SocketAddrNetlink::try_from(from) {
                Ok(from) if from.pid() == 0 => Received::Message(len),
                _ => Received::Idle,
            },
            Ok(_) => Received::Idle,
            Err(Errno::NOBUFS) => Received::Lost,
            Err(Errno::AGAIN | Errno::INTR) => Received::Idle,
            Err(_) => Received::Closed,
        }
    }
}
