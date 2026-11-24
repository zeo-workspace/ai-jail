//! `--minimal-etc`: `/etc` as a tmpfs holding only what programs read at
//! run time.
//!
//! The base mounts bind the host's whole `/etc` read-only. Most of it is
//! configuration for services the sandbox never runs, and much of it names
//! the host: `hostname`, `fstab`, `crypttab`, `ssh/` (the host keys' public
//! halves), `NetworkManager/`, `libvirt/`, `portage/`, the package manager's
//! world. `--mask-host` masks a handful of those; this replaces the tree
//! with an allowlist, so an entry nobody listed is simply absent.
//!
//! Each listed entry the host has is carried over as what it is: a
//! directory or a regular file is bound read-only, a symlink is recreated
//! with its target text, so it resolves inside the sandbox's own view
//! (`localtime` into `/usr/share/zoneinfo`, `os-release` into the
//! `/usr/lib/os-release` `--mask-host` rewrites, a systemd-resolved
//! `resolv.conf` into the `/run` copy the base mounts make). Anything else
//! (a socket, a FIFO, a device, a target that is not UTF-8) is skipped.
//!
//! The list was measured on a Gentoo desktop, not guessed: git, Node and
//! Python TLS, cargo, rustc, java, Claude Code and a bash login shell each
//! ran inside `--mask-host --minimal-etc`.

use std::path::{Path, PathBuf};

/// The host's `/etc` entries the sandbox keeps, by name. Why each one:
pub(super) const ALLOWLIST: &[&str] = &[
    // Accounts: getpwuid(3) for `~`, `id`, git's author fallback, ssh.
    "passwd",
    "group",
    "shells",
    // Name service: glibc's resolver reads all four.
    "nsswitch.conf",
    "host.conf",
    "gai.conf",
    "hosts",
    "resolv.conf",
    // getservbyname(3) / getprotobyname(3): curl, Python's socket, Java.
    "protocols",
    "services",
    // Time zone: Debian keeps the name in `timezone`, glibc reads
    // `localtime`.
    "localtime",
    "timezone",
    // The default locale for shells (Gentoo, systemd).
    "locale.conf",
    // The dynamic linker's cache; ld.so.conf(.d) for `ldconfig -p` and
    // build tools that read the search path.
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    // TLS roots: OpenSSL's `ssl/certs` (a symlink farm into
    // /usr/share/ca-certificates on Gentoo and Debian), the Fedora/Arch
    // `pki/` trust store, and the bundle's configuration.
    "ssl",
    "pki",
    "ca-certificates",
    "ca-certificates.conf",
    // Shell startup: login shells source profile, profile.env (Gentoo's
    // generated environment, from env.d) and profile.d; bash reads its
    // own directory (Gentoo) or bash.bashrc (Debian); readline reads
    // inputrc.
    "profile",
    "profile.d",
    "profile.env",
    "env.d",
    "environment",
    "bash",
    "bash.bashrc",
    "inputrc",
    // Debian's terminfo overrides; file(1)'s and Python's mimetypes table.
    "terminfo",
    "mime.types",
    // System-wide git and npm configuration.
    "gitconfig",
    "npmrc",
    // Gentoo's interpreter selection: python-exec picks the python3
    // behind /usr/bin/python3, java-config the JVM behind /usr/bin/java,
    // eselect the rest. Debian's alternatives are symlinks into /etc.
    "python-exec",
    "java-config-2",
    "eselect",
    "alternatives",
    // Claude Code's managed settings (`claude-code/managed-settings.json`):
    // without them an organisation's policy silently stops applying.
    "claude-code",
    // A symlink to /proc/self/mounts that df(1) and mount(8) read.
    "mtab",
    // A symlink into /usr/lib on most distributions, where `--mask-host`
    // puts a generic one; a regular file is rewritten by `--mask-host`.
    "os-release",
];

/// `--mask-host` binds its own `machine-id` (a fresh id per launch); it is
/// not on the list, so the host's never reaches the sandbox first.
const MASK_HOST_OWN: &[&str] = &["machine-id"];

/// One entry of the minimal `/etc`, its destination under the sandbox's
/// `/etc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EtcEntry {
    Dir { src: PathBuf, dest: PathBuf },
    File { src: PathBuf, dest: PathBuf },
    Symlink { target: String, dest: PathBuf },
}

/// The entries of `host_etc` on the allowlist, in its order, with
/// destinations under `/etc`. `host_etc` is a parameter so tests can lay
/// out a fake tree.
pub(super) fn entries(host_etc: &Path) -> Vec<EtcEntry> {
    let etc = Path::new("/etc");
    ALLOWLIST
        .iter()
        .filter_map(|name| {
            let src = host_etc.join(name);
            let dest = etc.join(name);
            let meta = std::fs::symlink_metadata(&src).ok()?;
            let kind = meta.file_type();
            if kind.is_symlink() {
                let target = std::fs::read_link(&src).ok()?;
                Some(EtcEntry::Symlink {
                    target: target.to_str()?.to_string(),
                    dest,
                })
            } else if kind.is_dir() {
                Some(EtcEntry::Dir { src, dest })
            } else if kind.is_file() {
                Some(EtcEntry::File { src, dest })
            } else {
                None
            }
        })
        .collect()
}

/// Whether a mount `--mask-host` makes at `dest` still belongs on top of
/// the minimal `/etc`. Its masks of entries the list leaves out
/// (`crypttab`, `portage`, the release files) would create them, empty,
/// in the tmpfs: the name alone tells which distribution this is.
pub(super) fn keeps_host_view_mount(dest: &Path) -> bool {
    let Ok(rest) = dest.strip_prefix("/etc") else {
        return true;
    };
    let Some(first) = rest.components().next() else {
        return true;
    };
    let name = first.as_os_str();
    ALLOWLIST.iter().chain(MASK_HOST_OWN).any(|n| name == *n)
}

#[cfg(test)]
#[path = "minimal_etc_tests.rs"]
mod tests;
