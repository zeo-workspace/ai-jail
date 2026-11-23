//! `--syscall-view` (with `--mask-host`): `uname(2)` and `sysinfo(2)`
//! answered by ai-jail, so the kernel release and the machine's memory,
//! swap, load and uptime the jail reads through them agree with the host
//! view's files.
//!
//! Nothing unprivileged rewrites what these two system calls return: the
//! UTS namespace lets a process set only its host and domain names, and
//! `sysinfo` reads the whole machine. So the in-jail helper installs, right
//! before its deny filter, a seccomp filter whose answer to `uname` and
//! `sysinfo` is `SECCOMP_RET_USER_NOTIF`, created with
//! `SECCOMP_FILTER_FLAG_NEW_LISTENER`, and hands the listener descriptor out
//! over a socket pair the launcher made (`--syscall-view-fd`). A thread of
//! the launcher -- outside the jail, where its seccomp denies neither
//! `process_vm_writev` nor the listener's ioctls -- then answers each call:
//! it checks the notification is still live (`SECCOMP_IOCTL_NOTIF_ID_VALID`,
//! so a recycled pid cannot be written), writes a `new_utsname` or a
//! `struct sysinfo` into the caller's buffer and returns 0. The launcher is
//! the jail's ancestor, which is what Yama's `ptrace_scope = 1` asks of a
//! process writing another's memory.
//!
//! If the launcher dies, the trapped calls fail with `ENOSYS`; bwrap's
//! `--die-with-parent` ends the jail with it. Only the native architecture
//! is trapped: a 32-bit or x32 call passes through unchanged.
//!
//! It hides, it does not isolate: `cpuid`, timing and the vDSO stay.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::libc;

/// The internal flag that carries the helper's end of the socket pair.
pub(crate) const FD_FLAG: &str = "--syscall-view-fd";

/// The jail's host name, as bwrap's `--hostname` sets it.
pub(crate) const JAIL_HOSTNAME: &str = "ai-sandbox";

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const NATIVE_ARCH: u32 = 0; // matches nothing: the filter traps nothing

/// Bytes of one `new_utsname` field (`__NEW_UTS_LEN + 1`).
const UTS_FIELD: usize = 65;
/// `struct new_utsname`: six fields.
pub(super) const UTSNAME_LEN: usize = 6 * UTS_FIELD;

/// How often the supervisor thread looks at its stop flag.
const POLL: Duration = Duration::from_millis(200);

/// What the jail is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answers {
    pub release: String,
    pub version: String,
    pub machine: String,
    /// The jail's cgroup, for `memory.current` and `pids.current`.
    pub cgroup_dir: Option<PathBuf>,
    pub memory_max: Option<u64>,
    pub swap_max: Option<u64>,
}

/// `struct new_utsname` as the jail should read it: `Linux`, the jail's
/// host name, the cleaned release and version, the host's machine, no
/// domain. A value longer than 64 bytes is cut.
pub(super) fn utsname_bytes(a: &Answers) -> [u8; UTSNAME_LEN] {
    let mut out = [0u8; UTSNAME_LEN];
    for (i, value) in [
        "Linux",
        JAIL_HOSTNAME,
        a.release.as_str(),
        a.version.as_str(),
        a.machine.as_str(),
        "(none)",
    ]
    .iter()
    .enumerate()
    {
        let bytes = value.as_bytes();
        let n = bytes.len().min(UTS_FIELD - 1);
        out[i * UTS_FIELD..i * UTS_FIELD + n].copy_from_slice(&bytes[..n]);
    }
    out
}

/// `struct sysinfo` for the jail: the host's, with the jail's age as
/// uptime, no load, memory sized to the limit (free = limit - used), swap
/// to the swap limit, and the jail's own task count. `mem_unit` 1, so the
/// sizes are bytes.
pub(super) fn sysinfo_for(
    host: &libc::sysinfo,
    age: Duration,
    a: &Answers,
    memory_current: Option<u64>,
    tasks: Option<u64>,
) -> libc::sysinfo {
    let mut out = *host;
    let unit = u64::from(host.mem_unit.max(1));
    // c_ulong is u64 on every 64-bit Linux target ai-jail builds for.
    let bytes = |v: libc::c_ulong| v.saturating_mul(unit);
    let long =
        |v: u64| libc::c_ulong::try_from(v).unwrap_or(libc::c_ulong::MAX);
    out.uptime = libc::c_long::try_from(age.as_secs()).unwrap_or(0);
    out.loads = [0; 3];
    out.mem_unit = 1;
    match a.memory_max {
        Some(max) => {
            let used = memory_current.unwrap_or(0).min(max);
            out.totalram = long(max);
            out.freeram = long(max - used);
            out.sharedram = 0;
            out.bufferram = 0;
        }
        None => {
            out.totalram = long(bytes(host.totalram));
            out.freeram = long(bytes(host.freeram));
            out.sharedram = long(bytes(host.sharedram));
            out.bufferram = long(bytes(host.bufferram));
        }
    }
    match a.swap_max {
        Some(max) => {
            out.totalswap = long(max);
            out.freeswap = long(max);
        }
        None => {
            out.totalswap = long(bytes(host.totalswap));
            out.freeswap = long(bytes(host.freeswap));
        }
    }
    out.totalhigh = 0;
    out.freehigh = 0;
    if let Some(n) = tasks {
        out.procs = u16::try_from(n).unwrap_or(u16::MAX);
    }
    out
}

/// The notify filter: `uname` and `sysinfo` of the native architecture go
/// to the listener, everything else is allowed (the deny filter installed
/// after it still applies to the rest).
pub(super) fn notify_program() -> Vec<libc::sock_filter> {
    const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let op = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    // seccomp_data: nr at 0, arch at 4.
    vec![
        op(LD_W_ABS, 0, 0, 4),
        op(JEQ_K, 0, 4, NATIVE_ARCH), // foreign arch -> allow (6)
        op(LD_W_ABS, 0, 0, 0),
        op(JEQ_K, 1, 0, libc::SYS_uname as u32), // -> notify (5)
        op(JEQ_K, 0, 1, libc::SYS_sysinfo as u32), // -> notify / allow
        op(RET_K, 0, 0, libc::SECCOMP_RET_USER_NOTIF),
        op(RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

/// In the helper: install the notify filter and send its listener over
/// `fd`, then close both. Must run before the deny filter (which may deny
/// `seccomp(2)` itself) and before the final exec.
pub(crate) fn install_in_jail(fd: RawFd) -> Result<(), String> {
    // SAFETY: `fd` is the inherited socket end this process now owns.
    let socket = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let program = notify_program();
    let prog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_ptr().cast_mut(),
    };
    // SAFETY: plain syscalls; `prog` points at `program`, alive here.
    let listener = unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(format!(
                "--syscall-view: no_new_privs: {}",
                std::io::Error::last_os_error()
            ));
        }
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        return Err(format!(
            "--syscall-view: cannot install the notify filter: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the kernel just returned this descriptor to this process.
    let listener = unsafe { OwnedFd::from_raw_fd(listener as RawFd) };
    crate::proxy::send_fd(&socket, &listener).map_err(|e| {
        format!("--syscall-view: cannot hand out the listener: {e}")
    })
}

/// The launcher's side: the socket end it keeps, the one the helper
/// inherits, and the thread answering the calls. Stopped and joined on
/// drop, which the sandbox guard does after the jail ended.
#[derive(Debug)]
pub(crate) struct Supervisor {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    child_end: OwnedFd,
}

impl Supervisor {
    pub fn start(answers: Answers, start: Instant) -> Result<Self, String> {
        let (ours, theirs) = UnixStream::pair()
            .map_err(|e| format!("--syscall-view: socket pair: {e}"))?;
        let child_end = OwnedFd::from(theirs);
        // The helper inherits it through the supervisor and bwrap.
        // SAFETY: fcntl on a descriptor this process owns.
        unsafe {
            let flags = libc::fcntl(child_end.as_raw_fd(), libc::F_GETFD);
            if flags < 0
                || libc::fcntl(
                    child_end.as_raw_fd(),
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
            {
                return Err(format!(
                    "--syscall-view: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("ai-jail-syscall-view".into())
            .spawn(move || run(ours, &answers, start, &flag))
            .map_err(|e| format!("--syscall-view: cannot start: {e}"))?;
        Ok(Supervisor {
            stop,
            thread: Some(thread),
            child_end,
        })
    }

    /// The descriptor number to pass as `--syscall-view-fd`.
    pub fn child_fd(&self) -> RawFd {
        self.child_end.as_raw_fd()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Wait until `fd` is readable or the stop flag is set; `false` on stop
/// or on a hang-up with nothing to read.
fn wait_readable(fd: RawFd, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(POLL.as_millis()).unwrap_or(200);
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n > 0 {
            if pfd.revents & libc::POLLIN != 0 {
                return true;
            }
            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
            {
                return false;
            }
        }
    }
}

fn run(socket: UnixStream, a: &Answers, start: Instant, stop: &AtomicBool) {
    if !wait_readable(socket.as_raw_fd(), stop) {
        return;
    }
    let Ok(Some(listener)) = crate::proxy::recv_fd(&socket) else {
        return;
    };
    drop(socket);
    let sizes = notif_sizes();
    while wait_readable(listener.as_raw_fd(), stop) {
        // An error here is a notification whose caller already went away.
        let _ = answer_one(listener.as_raw_fd(), sizes, a, start);
    }
}

fn notif_sizes() -> libc::seccomp_notif_sizes {
    let mut sizes = libc::seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };
    // SAFETY: the kernel fills `sizes`.
    unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut libc::seccomp_notif_sizes,
        );
    }
    sizes
}

fn read_u64(path: Option<PathBuf>) -> Option<u64> {
    std::fs::read_to_string(path?).ok()?.trim().parse().ok()
}

fn answer_one(
    listener: RawFd,
    sizes: libc::seccomp_notif_sizes,
    a: &Answers,
    start: Instant,
) -> std::io::Result<()> {
    let req_len = usize::from(sizes.seccomp_notif)
        .max(std::mem::size_of::<libc::seccomp_notif>());
    let resp_len = usize::from(sizes.seccomp_notif_resp)
        .max(std::mem::size_of::<libc::seccomp_notif_resp>());
    // u64 storage: aligned for both structs; zeroed, as RECV requires.
    let mut req = vec![0u64; req_len.div_ceil(8)];
    // SAFETY: `req` is zeroed and at least as large as the kernel's struct.
    if unsafe {
        libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_RECV, req.as_mut_ptr())
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the buffer holds an initialised seccomp_notif prefix.
    let notif = unsafe { &*req.as_ptr().cast::<libc::seccomp_notif>() };
    let addr = notif.data.args[0];
    let payload: Vec<u8> = if i64::from(notif.data.nr) == libc::SYS_uname {
        utsname_bytes(a).to_vec()
    } else {
        // SAFETY: zeroed is a valid sysinfo; the call fills it.
        let mut host: libc::sysinfo = unsafe { std::mem::zeroed() };
        unsafe { libc::sysinfo(&mut host) };
        let dir = a.cgroup_dir.clone();
        let info = sysinfo_for(
            &host,
            start.elapsed(),
            a,
            read_u64(dir.as_ref().map(|d| d.join("memory.current"))),
            read_u64(dir.map(|d| d.join("pids.current"))),
        );
        // SAFETY: plain-old-data viewed as bytes.
        unsafe {
            std::slice::from_raw_parts(
                (&info as *const libc::sysinfo).cast::<u8>(),
                std::mem::size_of::<libc::sysinfo>(),
            )
        }
        .to_vec()
    };
    let mut id = notif.id;
    // The caller may have died and its pid been reused since RECV.
    // SAFETY: `id` is a u64 the ioctl reads.
    let live = unsafe {
        libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id)
    } == 0;
    if !live {
        return Ok(());
    }
    let local = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: payload.len(),
    };
    // SAFETY: one local and one remote iovec, both sized to `payload`.
    let written = unsafe {
        libc::process_vm_writev(
            notif.pid as libc::pid_t,
            &local,
            1,
            &remote,
            1,
            0,
        )
    };
    let mut resp = vec![0u64; resp_len.div_ceil(8)];
    // SAFETY: `resp` is zeroed and large enough for the kernel's struct.
    let r =
        unsafe { &mut *resp.as_mut_ptr().cast::<libc::seccomp_notif_resp>() };
    r.id = notif.id;
    if written == payload.len() as isize {
        r.val = 0;
        r.error = 0;
    } else {
        r.val = -1;
        r.error = -libc::EFAULT;
    }
    // SAFETY: `resp` holds an initialised response.
    if unsafe {
        libc::ioctl(listener, libc::SECCOMP_IOCTL_NOTIF_SEND, resp.as_mut_ptr())
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The answers for this host, from the same cleaning as the host view's
/// files and the jail's cgroup limits.
pub(crate) fn answers_for_host() -> Answers {
    let identity = super::host_view_extra::HostIdentity::read(String::new());
    let snap = super::host_view::HostSnapshot::read();
    // SAFETY: zeroed utsname is valid; uname fills it.
    let machine = unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            std::ffi::CStr::from_ptr(u.machine.as_ptr())
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        }
    };
    Answers {
        release: super::host_view_extra::kernel_release(&identity.osrelease),
        version: super::host_view_extra::kernel_version(&identity.version),
        machine,
        cgroup_dir: snap.cgroup_dir,
        memory_max: snap.memory_max,
        swap_max: snap.swap_max,
    }
}

#[cfg(test)]
#[path = "syscall_view_tests.rs"]
mod tests;
