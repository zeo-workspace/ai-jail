use super::*;

/// A fake host `/etc` under the temp dir, removed on drop.
struct FakeEtc(PathBuf);

impl FakeEtc {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-minimal-etc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        FakeEtc(dir)
    }

    fn file(&self, name: &str) -> &Self {
        std::fs::write(self.0.join(name), "x\n").unwrap();
        self
    }

    fn dir(&self, name: &str) -> &Self {
        std::fs::create_dir_all(self.0.join(name)).unwrap();
        self
    }

    fn link(&self, name: &str, target: &str) -> &Self {
        std::os::unix::fs::symlink(target, self.0.join(name)).unwrap();
        self
    }
}

impl Drop for FakeEtc {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn files_directories_and_symlinks_keep_their_kind() {
    let etc = FakeEtc::new("kinds");
    etc.file("passwd")
        .dir("ssl")
        .link("localtime", "../usr/share/zoneinfo/UTC")
        .link("resolv.conf", "/run/systemd/resolve/stub-resolv.conf");
    let got = entries(&etc.0);
    assert!(got.contains(&EtcEntry::File {
        src: etc.0.join("passwd"),
        dest: PathBuf::from("/etc/passwd"),
    }));
    assert!(got.contains(&EtcEntry::Dir {
        src: etc.0.join("ssl"),
        dest: PathBuf::from("/etc/ssl"),
    }));
    // The target text is kept verbatim, relative or absolute: it resolves
    // in the sandbox's view, never the host's.
    assert!(got.contains(&EtcEntry::Symlink {
        target: "../usr/share/zoneinfo/UTC".into(),
        dest: PathBuf::from("/etc/localtime"),
    }));
    assert!(got.contains(&EtcEntry::Symlink {
        target: "/run/systemd/resolve/stub-resolv.conf".into(),
        dest: PathBuf::from("/etc/resolv.conf"),
    }));
    assert_eq!(got.len(), 4);
}

#[test]
fn an_entry_off_the_list_or_missing_is_left_out() {
    let etc = FakeEtc::new("unlisted");
    etc.file("hostname")
        .file("shadow")
        .file("gshadow")
        .file("sudoers")
        .file("fstab")
        .file("crypttab")
        .file("machine-id")
        .dir("ssh")
        .dir("portage")
        .file("group");
    let got = entries(&etc.0);
    assert_eq!(
        got,
        vec![EtcEntry::File {
            src: etc.0.join("group"),
            dest: PathBuf::from("/etc/group"),
        }]
    );
}

#[test]
fn a_dangling_symlink_is_recreated_not_followed() {
    let etc = FakeEtc::new("dangling");
    etc.link("mtab", "../proc/self/mounts");
    assert_eq!(
        entries(&etc.0),
        vec![EtcEntry::Symlink {
            target: "../proc/self/mounts".into(),
            dest: PathBuf::from("/etc/mtab"),
        }]
    );
}

#[test]
fn a_special_file_is_skipped() {
    let etc = FakeEtc::new("special");
    let fifo = std::ffi::CString::new(
        etc.0.join("hosts").as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    // SAFETY: a valid NUL-terminated path; mkfifo only creates a node.
    assert_eq!(unsafe { nix::libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(entries(&etc.0).is_empty());
}

#[test]
fn the_list_never_names_secrets_or_the_host() {
    for name in [
        "shadow",
        "gshadow",
        "sudoers",
        "sudoers.d",
        "hostname",
        "machine-id",
        "ssh",
        "crypttab",
        "fstab",
        "portage",
        "NetworkManager",
    ] {
        assert!(!ALLOWLIST.contains(&name), "{name} must stay out");
    }
    let mut sorted = ALLOWLIST.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ALLOWLIST.len(), "duplicate entry");
}

#[test]
fn host_view_masks_of_absent_entries_are_dropped() {
    for kept in [
        "/etc/machine-id",
        "/etc/os-release",
        "/etc/ssl/certs/x.pem",
        "/proc/cpuinfo",
        "/usr/lib/os-release",
        "/etcetera",
    ] {
        assert!(keeps_host_view_mount(Path::new(kept)), "{kept}");
    }
    for dropped in [
        "/etc/crypttab",
        "/etc/gentoo-release",
        "/etc/lsb-release",
        "/etc/portage",
    ] {
        assert!(!keeps_host_view_mount(Path::new(dropped)), "{dropped}");
    }
}
