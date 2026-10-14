use super::{DEFAULT_DISTRIBUTION_PORT, DEFAULT_PLATFORM_PORT, with_default_port};

#[test]
fn default_port_is_added_only_when_absent() {
    for (url, expected) in [
        ("https://p.example", Some("https://p.example:18423")),
        ("https://p.example/api", Some("https://p.example:18423/api")),
        ("https://p.example:443", Some("https://p.example:443")),
        ("https://10.0.0.1", Some("https://10.0.0.1:18423")),
        ("https://[::1]", Some("https://[::1]:18423")),
        ("https://[::1]:9", Some("https://[::1]:9")),
        ("http://p.example", None),
        ("https://p.example/", None),
        ("https://user@p.example", None),
        ("https://", None),
    ] {
        assert_eq!(
            with_default_port(url, DEFAULT_PLATFORM_PORT).as_deref(),
            expected,
            "{url}"
        );
    }
    assert_eq!(
        with_default_port("https://p.example", DEFAULT_DISTRIBUTION_PORT).as_deref(),
        Some("https://p.example:18424")
    );
}
