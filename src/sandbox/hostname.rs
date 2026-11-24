//! The jail's host name: `--hostname NAME`, or `ai-sandbox` without it.
//!
//! One name everywhere the jail can read one: the UTS namespace bwrap
//! creates (`--hostname`), the sandbox's `/etc/hosts`, an `/etc/hostname`
//! over the host's (which, bound with the rest of `/etc`, named this
//! machine), and `uname(2)` under `--syscall-view`. A caller that wants
//! each project to look like a different machine passes a name per project.

use crate::config::Config;

/// The name a jail gets when none is asked for.
pub(crate) const DEFAULT_HOSTNAME: &str = "ai-sandbox";

/// The longest label DNS allows, and what `new_utsname` can hold (64).
const MAX_LEN: usize = 63;

/// The jail's host name for `config`.
pub(crate) fn jail_hostname(config: &Config) -> &str {
    config.hostname.as_deref().unwrap_or(DEFAULT_HOSTNAME)
}

/// A single DNS label (RFC 1123): 1 to 63 lowercase ASCII letters, digits
/// and hyphens, not starting or ending with a hyphen. Anything else could
/// break `/etc/hosts` or name a domain, so it is refused, not cleaned.
pub(crate) fn validate(name: &str) -> Result<(), String> {
    let well_formed = !name.is_empty()
        && name.len() <= MAX_LEN
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if well_formed {
        Ok(())
    } else {
        Err(format!(
            "--hostname {name:?}: a host name is 1 to {MAX_LEN} lowercase letters, \
             digits and hyphens, not starting or ending with a hyphen"
        ))
    }
}

/// The sandbox's `/etc/hosts`: loopback for localhost and the jail's name.
pub(crate) fn hosts_contents(name: &str) -> String {
    format!("127.0.0.1 localhost {name}\n::1       localhost {name}\n")
}

/// The sandbox's `/etc/hostname`.
pub(crate) fn hostname_contents(name: &str) -> String {
    format!("{name}\n")
}

#[cfg(test)]
#[path = "hostname_tests.rs"]
mod tests;
