//! The host's operating system from os-release (`ID`, `VERSION_ID`) and
//! the running kernel.

use openvibes_core::OsRelease;

use std::io::Read;

use openvibes_core::Identifier;

/// Largest os-release file read; real ones are well under 1 KiB.
const MAX_BYTES: u64 = 64 * 1024;

/// The host's `ID` and `VERSION_ID` from `/etc/os-release`, falling back to
/// `/usr/lib/os-release`. `None` when neither exists, a key is missing (for
/// example a rolling distribution without `VERSION_ID`), or a value is not
/// an identifier.
#[must_use]
pub fn os_release() -> Option<OsRelease> {
    ["/etc/os-release", "/usr/lib/os-release"]
        .into_iter()
        .find_map(|path| {
            let mut text = String::new();
            std::fs::File::open(path)
                .and_then(|file| file.take(MAX_BYTES).read_to_string(&mut text))
                .ok()?;
            Some(text)
        })
        .and_then(|text| parse(&text))
}

/// The running kernel's release, as `uname -r` prints it (protocol P9).
/// `None` if it is not a valid kernel release.
#[must_use]
pub fn running_kernel() -> Option<String> {
    let release = rustix::system::uname().release().to_str().ok()?.to_owned();
    openvibes_core::is_kernel_release(&release).then_some(release)
}

/// Parses os-release text: `KEY=value` lines, values optionally quoted;
/// a later assignment wins, as in the shell.
pub(crate) fn parse(text: &str) -> Option<OsRelease> {
    let (mut id, mut version_id) = (None, None);
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        match key.trim() {
            "ID" => id = Some(value.to_owned()),
            "VERSION_ID" => version_id = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(OsRelease {
        id: Identifier::new(id?).ok()?,
        version_id: Identifier::new(version_id?).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn reads_the_running_kernel() {
        let release = super::running_kernel().expect("uname works on Linux");
        assert!(openvibes_core::is_kernel_release(&release), "{release}");
    }

    fn pair(text: &str) -> Option<(String, String)> {
        parse(text).map(|os| (os.id.as_str().to_owned(), os.version_id.as_str().to_owned()))
    }

    #[test]
    fn reads_fedora() {
        let text = "NAME=\"Fedora Linux\"\nVERSION=\"44 (Workstation Edition)\"\nID=fedora\nVERSION_ID=44\n";
        assert_eq!(pair(text), Some(("fedora".into(), "44".into())));
    }

    #[test]
    fn handles_quotes_comments_and_blank_lines() {
        let text =
            "# comment\n\nID='debian'\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n";
        assert_eq!(pair(text), Some(("debian".into(), "12".into())));
    }

    #[test]
    fn missing_or_invalid_keys_mean_none() {
        assert_eq!(
            pair("ID=fedora\n"),
            None,
            "no VERSION_ID (e.g. Arch, rolling)"
        );
        assert_eq!(pair("VERSION_ID=44\n"), None);
        assert_eq!(
            pair("ID=\"fe dora\"\nVERSION_ID=44\n"),
            None,
            "not an identifier"
        );
        assert_eq!(pair(""), None);
    }

    #[test]
    fn later_duplicates_win_like_shell() {
        assert_eq!(
            pair("ID=centos\nID=rocky\nVERSION_ID=9.4\n"),
            Some(("rocky".into(), "9.4".into()))
        );
    }
}
