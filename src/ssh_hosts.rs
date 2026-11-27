//! Host keys for SSH through filtered egress (§6.9 of Zeo's proposal).
//!
//! The sandbox's home is its own, so `ssh` inside it has no `known_hosts`
//! and would refuse every server it is allowed to reach. Copying the user's
//! whole file in would tell the sandbox every host the user ever visited.
//! Instead the supervisor asks `ssh-keygen -F` -- which also matches hashed
//! entries -- for the keys of exactly the hosts whose port 22 is allowlisted,
//! writes those lines to a file beside the proxy socket (mode 0600, created
//! fresh), and the sandbox mounts it read-only with strict checking. A host
//! with no known key stays unreachable until the user trusts it outside.

use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Where the sandbox finds the filtered file.
pub(crate) const IN_SANDBOX_KNOWN_HOSTS: &str = "/tmp/.ai-jail-known-hosts";

/// The hosts whose port 22 an allowlist opens, lowercase, once each.
pub(crate) fn ssh_hosts(entries: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = entries
        .iter()
        .filter_map(|entry| crate::proxy::split_allow_entry(entry).ok())
        .filter(|(_, port)| *port == Some(22))
        .map(|(host, _)| host.trim_end_matches('.').to_lowercase())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The host-side path of the filtered file, beside the proxy socket.
pub(crate) fn known_hosts_path(proxy_socket: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.known_hosts",
        proxy_socket.as_os_str().to_string_lossy()
    ))
}

/// The lines of `known_hosts` that name `hosts`, as `ssh-keygen -F` finds
/// them (comment lines dropped). A missing file or `ssh-keygen` finds none.
pub(crate) fn matching_lines(known_hosts: &Path, hosts: &[String]) -> String {
    let mut out = String::new();
    for host in hosts {
        let Ok(output) = Command::new("ssh-keygen")
            .arg("-F")
            .arg(host)
            .arg("-f")
            .arg(known_hosts)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            continue;
        };
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if !line.starts_with('#') && !line.trim().is_empty() {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Writes the filtered file for `hosts` beside the proxy socket, refusing
/// to follow or reuse an existing path. Returns its path.
pub(crate) fn write_known_hosts(
    proxy_socket: &Path,
    user_known_hosts: &Path,
    hosts: &[String],
) -> Result<PathBuf, String> {
    let path = known_hosts_path(proxy_socket);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(matching_lines(user_known_hosts, hosts).as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// Removes the filtered file; quiet, it runs on teardown.
pub(crate) fn remove_known_hosts(proxy_socket: &Path) {
    let _ = std::fs::remove_file(known_hosts_path(proxy_socket));
}

/// The ssh options that make the sandbox use only the filtered file. `-F
/// /dev/null` too: inside the user namespace the host's `/etc/ssh` files
/// belong to an unmapped owner, which ssh refuses as "bad owner", and the
/// sandbox's home has no `~/.ssh/config` to lose.
pub(crate) fn ssh_options() -> String {
    format!(
        "-F /dev/null -o UserKnownHostsFile={IN_SANDBOX_KNOWN_HOSTS} -o StrictHostKeyChecking=yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_port_22_entries_are_ssh_hosts() {
        let entries = [
            "github.com".to_string(),
            "GitHub.com:22".to_string(),
            "gitlab.com:22".to_string(),
            "example.com:2222".to_string(),
            "github.com:22".to_string(),
        ];
        assert_eq!(ssh_hosts(&entries), ["github.com", "gitlab.com"]);
    }

    #[test]
    fn the_file_holds_only_the_allowed_hosts_keys() {
        if Command::new("ssh-keygen").arg("-?").output().is_err() {
            return;
        }
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-known-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let user = dir.join("known_hosts");
        std::fs::write(
            &user,
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n\
             secret-host.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKZ6TQTTMDNk2r2Ga9h3j9VdPF8CXa6nrw0Dt2tSF1wJ\n",
        )
        .unwrap();
        let socket = dir.join("proxy.sock");
        let path =
            write_known_hosts(&socket, &user, &["github.com".into()]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("github.com ssh-ed25519"), "{text}");
        assert!(!text.contains("secret-host"), "{text}");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Never reused.
        assert!(write_known_hosts(&socket, &user, &[]).is_err());
        remove_known_hosts(&socket);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
