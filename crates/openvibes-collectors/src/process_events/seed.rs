//! A running process read from `/proc`: a parent the agent never saw exec
//! (it started before the agent, or forked without exec like an nginx
//! worker).

use super::{SEEDED_ARG_BYTES, Seeded};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::Path,
};

/// Reads `pid` from `/proc`; `None` when it is gone or unreadable.
#[must_use]
pub fn read_process(pid: u32) -> Option<Seeded> {
    read_from(Path::new("/proc"), pid)
}

pub(crate) fn read_from(proc_root: &Path, pid: u32) -> Option<Seeded> {
    let dir = proc_root.join(pid.to_string());
    let stat = read_bounded(&dir.join("stat"), 1_024)?;
    // `pid (comm) state ppid …`; comm may hold spaces and `)`.
    let close = stat.iter().rposition(|b| *b == b')')?;
    let open = stat.iter().position(|b| *b == b'(')?;
    let name = stat.get(open + 1..close)?.to_vec();
    let mut rest = stat.get(close + 2..)?.split(|b| *b == b' ');
    let ppid = std::str::from_utf8(rest.nth(1)?).ok()?.parse().ok()?;
    let status = read_bounded(&dir.join("status"), 8_192)?;
    let status = String::from_utf8_lossy(&status);
    let mut ids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .map(str::parse::<u32>);
    let (uid, euid) = (ids.next()?.ok()?, ids.next()?.ok()?);
    let mut cmdline = read_bounded(&dir.join("cmdline"), SEEDED_ARG_BYTES + 1)?;
    let args_truncated = cmdline.len() > SEEDED_ARG_BYTES;
    cmdline.truncate(SEEDED_ARG_BYTES);
    if cmdline.last() == Some(&0) {
        cmdline.pop();
    }
    let args = if cmdline.is_empty() {
        Vec::new()
    } else {
        cmdline.split(|b| *b == 0).map(<[u8]>::to_vec).collect()
    };
    let link = |name: &str| {
        fs::read_link(dir.join(name))
            .ok()
            .map(|path| path.as_os_str().as_bytes().to_vec())
    };
    Some(Seeded {
        pid,
        ppid,
        uid,
        euid,
        name,
        exe: link("exe"),
        args,
        args_truncated,
        cwd: link("cwd"),
    })
}

fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path)
        .ok()?
        .take(limit as u64)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}
