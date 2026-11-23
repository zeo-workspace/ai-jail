//! `--mask-host`'s time namespace: `CLOCK_BOOTTIME`, `CLOCK_MONOTONIC`
//! and `sysinfo().uptime` count from the jail's start, not the host's boot.
//!
//! A time namespace can only be created by a process holding
//! `CAP_SYS_ADMIN` in its user namespace, and its offsets only written
//! before any process has entered it. The launcher computes the offsets
//! (`prepare`) and hands them to the supervisor process that execs bwrap
//! (`signals::run_supervised_exec`) in the internal variable `ENV`, since
//! the supervision wrapper replaces bwrap's `Command` and a `pre_exec` hook
//! set on it would be dropped. Just before the exec, the supervisor
//! (`enter`) makes a user namespace mapping the caller's
//! own uid and gid (nothing else, so bwrap still runs as that user and
//! creates its own namespaces inside), then the time namespace, then
//! writes the offsets. `execve` moves the process into its
//! `time_for_children` namespace (Linux 5.11+), so bwrap and everything it
//! starts see the shifted clocks. Everything is prepared in the parent: the
//! hook itself only calls `unshare`, `open`, `write` and `close`, which are
//! async-signal-safe.
//!
//! A kernel without `CONFIG_TIME_NS` has no `/proc/self/ns/time`; the
//! launch then skips this with a warning, as `--mask-host` does for any
//! piece the host lacks.

use std::io;

/// The internal variable carrying the offsets from the launcher to the
/// supervisor; removed before bwrap runs.
pub(crate) const ENV: &str = "AI_JAIL_TIME_NS";

/// What `enter` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TimeNamespace {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    offsets: Vec<u8>,
}

impl TimeNamespace {
    /// The namespace for a jail starting now, or `None` when the kernel
    /// lacks time namespaces.
    pub fn prepare() -> Option<Self> {
        if !super::host_view_extra::time_namespaces_available() {
            return None;
        }
        let now = |clock| {
            let mut ts = nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `ts` is a valid out-pointer.
            if unsafe { nix::libc::clock_gettime(clock, &mut ts) } != 0 {
                return None;
            }
            Some(std::time::Duration::new(
                u64::try_from(ts.tv_sec).ok()?,
                u32::try_from(ts.tv_nsec).ok()?,
            ))
        };
        let offsets = super::host_view_extra::timens_offsets(
            now(nix::libc::CLOCK_MONOTONIC)?,
            now(nix::libc::CLOCK_BOOTTIME)?,
        );
        Self::from_offsets(&offsets)
    }

    /// The offsets, as `ENV` carries them.
    pub fn offsets(&self) -> String {
        String::from_utf8_lossy(&self.offsets).into_owned()
    }

    /// Rebuild from `ENV`'s value, for this process's own uid and gid.
    /// Anything but `monotonic`/`boottime` lines of two integers is
    /// refused: the text is written to a procfs file.
    pub fn from_offsets(text: &str) -> Option<Self> {
        let valid = |line: &str| {
            let mut parts = line.split(' ');
            matches!(parts.next(), Some("monotonic" | "boottime"))
                && parts.next().is_some_and(|s| s.parse::<i64>().is_ok())
                && parts.next().is_some_and(|n| {
                    n.parse::<u32>().is_ok_and(|n| n < 1_000_000_000)
                })
                && parts.next().is_none()
        };
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() || !lines.iter().all(|l| valid(l)) {
            return None;
        }
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        Some(TimeNamespace {
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
            offsets: format!("{}\n", lines.join("\n")).into_bytes(),
        })
    }

    /// Run in the process about to exec bwrap. Async-signal-safe, so it
    /// may also run in a `pre_exec` hook.
    pub fn enter(&self) -> io::Result<()> {
        use nix::libc;
        // SAFETY: plain syscalls on values owned by `self`.
        unsafe {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                return Err(io::Error::last_os_error());
            }
            write_proc(c"/proc/self/setgroups", b"deny")?;
            write_proc(c"/proc/self/uid_map", &self.uid_map)?;
            write_proc(c"/proc/self/gid_map", &self.gid_map)?;
            if libc::unshare(libc::CLONE_NEWTIME) != 0 {
                return Err(io::Error::last_os_error());
            }
            write_proc(c"/proc/self/timens_offsets", &self.offsets)?;
        }
        Ok(())
    }
}

/// Write `data` to a procfs file in one `write`, as these files require.
///
/// # Safety
/// Calls libc directly; async-signal-safe.
unsafe fn write_proc(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    use nix::libc;
    // SAFETY: `path` is NUL-terminated; `data` outlives the call.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = libc::write(fd, data.as_ptr().cast(), data.len());
        let err = io::Error::last_os_error();
        libc::close(fd);
        if n < 0 || n as usize != data.len() {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_round_trip_through_the_variable() {
        let text = "monotonic -4999 0\nboottime -7000 750000000\n";
        let ns = TimeNamespace::from_offsets(text).unwrap();
        assert_eq!(ns.offsets(), text);
        let uid = nix::unistd::getuid().as_raw();
        assert_eq!(ns.uid_map, format!("{uid} {uid} 1\n").into_bytes());
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "",
            "realtime 1 0",
            "monotonic 1",
            "monotonic x 0",
            "monotonic 1 1000000000",
            "monotonic 1 0 extra",
            "monotonic 1 0\n0 0 0",
        ] {
            assert!(TimeNamespace::from_offsets(bad).is_none(), "{bad:?}");
        }
    }
}
