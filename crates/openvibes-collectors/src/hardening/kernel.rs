//! `kernel.*`: loaded modules, modules modprobe.d disables, and the
//! kernel command line.

use super::{Out, dir_files};

const MODPROBE: [&str; 3] = ["/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d"];

pub(super) fn collect(out: &mut Out) {
    match out.read("/proc/modules") {
        Ok(text) => out.list(
            "kernel.modules.loaded",
            text.lines()
                .filter_map(|l| l.split_whitespace().next())
                .map(str::to_owned),
        ),
        Err(code) => out.error("modules", code, "cannot read /proc/modules"),
    }
    let mut disabled = Vec::new();
    for dir in MODPROBE {
        for file in dir_files(&out.path(dir), ".conf") {
            if let Ok(text) = super::read_bounded(&file) {
                disabled.extend(text.lines().filter_map(disabling));
            }
        }
    }
    out.list("kernel.modules.disabled", disabled);
    match out.read("/proc/cmdline") {
        Ok(text) => out.list(
            "kernel.cmdline.args",
            text.split_whitespace().map(str::to_owned),
        ),
        Err(code) => out.error("cmdline", code, "cannot read /proc/cmdline"),
    }
}

/// The module a modprobe.d line disables: `blacklist m`, or `install m`
/// running `/bin/false` or `/bin/true` (any `false`/`true` path). Names
/// use `_` as the kernel reports them.
fn disabling(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let module = match words.next()? {
        "blacklist" => words.next()?,
        "install" => {
            let module = words.next()?;
            let command = words.next()?.rsplit('/').next()?;
            if command != "false" && command != "true" {
                return None;
            }
            module
        }
        _ => return None,
    };
    Some(module.replace('-', "_"))
}

#[cfg(test)]
mod tests {
    use super::disabling;

    #[test]
    fn blacklist_and_install_false_disable() {
        assert_eq!(
            disabling("blacklist usb-storage").as_deref(),
            Some("usb_storage")
        );
        assert_eq!(
            disabling("install cramfs /bin/false").as_deref(),
            Some("cramfs")
        );
        assert_eq!(
            disabling("install dccp /usr/bin/true").as_deref(),
            Some("dccp")
        );
        assert_eq!(
            disabling("install foo /sbin/modprobe --ignore-install foo"),
            None
        );
        assert_eq!(disabling("options snd foo=1"), None);
    }
}
