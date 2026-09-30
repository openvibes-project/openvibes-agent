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

impl Source for AuditSocket {
    fn recv(&mut self, buf: &mut [u8]) -> Received {
        use rustix::{
            io::Errno,
            net::{RecvFlags, netlink::SocketAddrNetlink, recvfrom},
        };
        match recvfrom(&self.0, &mut *buf, RecvFlags::empty()) {
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
