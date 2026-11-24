use super::*;

#[test]
fn hostname_defaults_to_ai_sandbox() {
    assert_eq!(jail_hostname(&Config::default()), "ai-sandbox");
    let named = Config {
        hostname: Some("desktop-k3f9a2".into()),
        ..Config::default()
    };
    assert_eq!(jail_hostname(&named), "desktop-k3f9a2");
}

#[test]
fn hostname_accepts_a_dns_label() {
    for name in ["a", "desktop-k3f9a2", "ws1", &"x".repeat(63)] {
        assert!(validate(name).is_ok(), "{name}");
    }
}

#[test]
fn hostname_refuses_what_is_not_one_label() {
    for name in [
        "",
        "-lead",
        "trail-",
        "Upper",
        "dotted.name",
        "with space",
        "new\nline",
        "tab\t",
        "ünïcode",
        &"x".repeat(64),
    ] {
        let error = validate(name).expect_err(name);
        assert!(error.contains("--hostname"), "{error}");
    }
}

#[test]
fn hostname_files_name_the_jail() {
    let hosts = hosts_contents("desktop-k3f9a2");
    assert_eq!(
        hosts,
        "127.0.0.1 localhost desktop-k3f9a2\n::1       localhost desktop-k3f9a2\n"
    );
    assert_eq!(hostname_contents("desktop-k3f9a2"), "desktop-k3f9a2\n");
}
