//! `--mask-host`: replace the host's system-wide view with one sized to
//! the jail.
//!
//! ai-jail binds `/sys` and `/etc` read-only whole and gives the sandbox a
//! fresh `/proc`, whose system-wide files still describe the host: its CPU
//! model and count, its RAM and swap, its load, its board (DMI) and every
//! sibling cgroup. Under `--mask-host` the launch writes synthetic
//! `/proc/cpuinfo`, `/proc/stat`, `/proc/loadavg`, a live `/proc/uptime`
//! counted from the jail's start, `/proc/meminfo` (when a
//! memory limit applies) and `/sys/devices/system/cpu` into a private temp
//! directory and binds them over the real ones, shows only the jail's own
//! cgroup at `/sys/fs/cgroup` (with `--unshare-cgroup`, so
//! `/proc/self/cgroup` reads `0::/`), hides DMI, and gives `/etc/machine-id`
//! a per-jail id.
//!
//! The sizes come from what the jail really gets when its arguments are
//! built: the cgroup's `cpu.max` (rounded up to whole CPUs), `memory.max`
//! and `memory.swap.max` -- the smallest along the path to the root -- and
//! the process's CPU affinity. Without a limit a file keeps the host's
//! numbers; the CPU model is generic either way.
//!
//! Cost: a procfs with files mounted over it is not "fully visible" to the
//! kernel (`mnt_already_visible`), so a nested `--proc /proc` mount inside
//! the jail fails with EPERM: Claude Code's own Bash sandbox, rootless
//! podman and nested bwrap stop working. That is why this is opt-in.
//!
//! It hides, it does not isolate: the `cpuid` instruction, timing,
//! `uname(2)`, the CPU numbers `sched_getaffinity` returns and the sources
//! in `/proc/self/mountinfo` stay the host's, short of a VM.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::host_view_synth as synth;
use super::host_view_uptime::UptimeTicker;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYS_CPU: &str = "/sys/devices/system/cpu";
/// DMI/SMBIOS: board vendor and model. `class/dmi/id` links into
/// `devices/virtual/dmi`, so both are hidden.
const DMI_PATHS: &[&str] = &["/sys/class/dmi", "/sys/devices/virtual/dmi"];
const MACHINE_ID: &str = "/etc/machine-id";

/// What a launch tells the host view beyond what ai-jail reads from its
/// own environment.
#[derive(Debug, Default, Clone)]
pub(crate) struct HostViewRequest {
    /// CPUs the sandbox will be pinned to, for a caller that pins it after
    /// the bwrap arguments are built.
    pub cpus: Option<BTreeSet<usize>>,
    /// Where the jail's machine id is kept between launches. `None` gives
    /// every launch a fresh id.
    pub machine_id_file: Option<PathBuf>,
}

/// The host as the jail's limits frame it, read once per launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HostSnapshot {
    pub host_cpus: BTreeSet<usize>,
    pub affinity: Option<BTreeSet<usize>>,
    pub cgroup_dir: Option<PathBuf>,
    pub quota_cpus: Option<usize>,
    pub memory_max: Option<u64>,
    pub memory_current: u64,
    pub swap_max: Option<u64>,
    pub cpuinfo: String,
    pub meminfo: String,
    pub btime: u64,
}

impl HostSnapshot {
    pub fn read() -> Self {
        let cgroup_dir = own_cgroup_dir();
        let walk = |file: &str| {
            cgroup_dir
                .as_deref()
                .map(|dir| cgroup_ancestry(dir, file))
                .unwrap_or_default()
        };
        let read = |path: &str| std::fs::read_to_string(path).ok();
        let host_cpus = read("/sys/devices/system/cpu/online")
            .and_then(|t| synth::parse_id_list(&t))
            .unwrap_or_else(|| {
                let n = std::thread::available_parallelism()
                    .map_or(1, std::num::NonZeroUsize::get);
                (0..n).collect()
            });
        let affinity = read("/proc/self/status").and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Cpus_allowed_list:")
                    .and_then(synth::parse_id_list)
            })
        });
        HostSnapshot {
            host_cpus,
            affinity,
            quota_cpus: walk("cpu.max")
                .iter()
                .filter_map(|v| synth::quota_cpus(v))
                .min(),
            memory_max: walk("memory.max")
                .iter()
                .filter_map(|v| v.trim().parse().ok())
                .min(),
            memory_current: cgroup_dir
                .as_deref()
                .and_then(|d| {
                    std::fs::read_to_string(d.join("memory.current")).ok()
                })
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0),
            swap_max: walk("memory.swap.max")
                .iter()
                .filter_map(|v| v.trim().parse().ok())
                .min(),
            cgroup_dir,
            cpuinfo: read("/proc/cpuinfo").unwrap_or_default(),
            meminfo: read("/proc/meminfo").unwrap_or_default(),
            btime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }
}

/// The cgroup v2 directory of this process: the sandbox's, since bwrap
/// and its child are forked into the same one.
fn own_cgroup_dir() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    let dir = Path::new(CGROUP_ROOT).join(rel.trim().trim_start_matches('/'));
    dir.is_dir().then_some(dir)
}

/// `file` in `dir` and in each parent up to the cgroup root: a limit on
/// an enclosing slice binds the jail as much as one on its own scope.
fn cgroup_ancestry(dir: &Path, file: &str) -> Vec<String> {
    dir.ancestors()
        .take_while(|d| d.starts_with(CGROUP_ROOT))
        .filter_map(|d| std::fs::read_to_string(d.join(file)).ok())
        .collect()
}

/// One mount of the host view; `bwrap.rs` turns it into arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HostViewMount {
    File { src: PathBuf, dest: PathBuf },
    Dir { src: PathBuf, dest: PathBuf },
    Tmpfs { dest: PathBuf },
}

/// What to write (relative to the view's directory) and what to mount.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct HostViewPlan {
    pub files: Vec<(PathBuf, String)>,
    pub mounts: Vec<HostViewMount>,
    /// CPUs the live `/proc/uptime` counts as idle.
    pub uptime_cpus: usize,
}

/// Lay out the view for `snap`. Pure: `exists` answers for host paths, so
/// a mount point the host lacks (no DMI on a VM, no machine-id in a
/// container) is skipped instead of failing bwrap.
pub(super) fn plan(
    snap: &HostSnapshot,
    request: &HostViewRequest,
    machine_id: &str,
    dir: &Path,
    exists: &dyn Fn(&Path) -> bool,
) -> HostViewPlan {
    let base = request
        .cpus
        .clone()
        .or_else(|| snap.affinity.clone())
        .unwrap_or_else(|| snap.host_cpus.clone());
    let ids = synth::jail_cpu_ids(&base, snap.quota_cpus);
    let mut out = HostViewPlan {
        uptime_cpus: ids.len(),
        ..HostViewPlan::default()
    };
    let mut file = |name: &str, text: String, dest: Option<&str>| {
        out.files.push((PathBuf::from(name), text));
        if let Some(dest) = dest {
            out.mounts.push(HostViewMount::File {
                src: dir.join(name),
                dest: dest.into(),
            });
        }
    };
    file(
        "cpuinfo",
        synth::cpuinfo(&ids, &snap.cpuinfo),
        Some("/proc/cpuinfo"),
    );
    file("stat", synth::stat(&ids, snap.btime), Some("/proc/stat"));
    file("loadavg", synth::loadavg(), Some("/proc/loadavg"));
    file(
        "uptime",
        synth::uptime(0.0, ids.len()),
        Some("/proc/uptime"),
    );
    if let Some(memory) = snap.memory_max {
        let text = synth::meminfo(
            memory,
            snap.memory_current,
            snap.swap_max,
            &snap.meminfo,
        );
        file("meminfo", text, Some("/proc/meminfo"));
    }
    let list = format!("{}\n", synth::format_id_list(&ids));
    for name in ["online", "possible", "present"] {
        file(&format!("cpu/{name}"), list.clone(), None);
    }
    file("cpu/offline", "\n".into(), None);
    for id in &ids {
        file(&format!("cpu/cpu{id}/online"), "1\n".into(), None);
    }
    if exists(Path::new(MACHINE_ID)) {
        file("machine-id", format!("{machine_id}\n"), Some(MACHINE_ID));
    }

    if exists(Path::new(SYS_CPU)) {
        out.mounts.push(HostViewMount::Dir {
            src: dir.join("cpu"),
            dest: SYS_CPU.into(),
        });
    }
    match &snap.cgroup_dir {
        Some(own) => out.mounts.push(HostViewMount::Dir {
            src: own.clone(),
            dest: CGROUP_ROOT.into(),
        }),
        None if exists(Path::new(CGROUP_ROOT)) => {
            out.mounts.push(HostViewMount::Tmpfs {
                dest: CGROUP_ROOT.into(),
            });
        }
        None => {}
    }
    for path in DMI_PATHS {
        if exists(Path::new(path)) {
            out.mounts.push(HostViewMount::Tmpfs { dest: path.into() });
        }
    }
    out
}

/// The view of one launch: its temp directory (removed on drop) and the
/// mounts that put it in place.
#[derive(Debug)]
pub(crate) struct HostView {
    dir: PathBuf,
    written: bool,
    mounts: Vec<HostViewMount>,
    /// Keeps `/proc/uptime` live; stopped first when the view is dropped.
    uptime: Option<UptimeTicker>,
}

impl HostView {
    /// Read the host and lay out the view. With `write` false (dry run)
    /// nothing is created on disk and a persisted machine id is not made.
    pub fn create(
        request: HostViewRequest,
        write: bool,
    ) -> Result<Self, String> {
        // The jail's clock starts here, just before bwrap is spawned.
        let start = std::time::Instant::now();
        let snap = HostSnapshot::read();
        let machine_id = machine_id(request.machine_id_file.as_deref(), write)?;
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-host.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let exists = |p: &Path| match std::fs::symlink_metadata(p) {
            // A symlinked machine-id points into /var, which the jail
            // does not have: binding over the link would follow it.
            Ok(meta) if p == Path::new(MACHINE_ID) => meta.is_file(),
            Ok(_) => true,
            Err(_) => false,
        };
        let plan = plan(&snap, &request, &machine_id, &dir, &exists);
        let mut view = HostView {
            dir,
            written: false,
            mounts: plan.mounts,
            uptime: None,
        };
        if write && let Some(file) = view.write(&plan.files)? {
            view.uptime =
                Some(UptimeTicker::start(file, start, plan.uptime_cpus)?);
        }
        Ok(view)
    }

    pub(super) fn mounts(&self) -> &[HostViewMount] {
        &self.mounts
    }

    /// Write the files; returns `uptime` still open for writing, since the
    /// ticker could not reopen it once it is read-only.
    fn write(
        &mut self,
        files: &[(PathBuf, String)],
    ) -> Result<Option<std::fs::File>, String> {
        let fail = |what: &Path, e: std::io::Error| {
            format!("--mask-host: cannot write {}: {e}", what.display())
        };
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| fail(&self.dir, e))?;
        self.written = true;
        let mut uptime = None;
        for (rel, text) in files {
            let path = self.dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| fail(parent, e))?;
            }
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| fail(&path, e))?;
            f.write_all(text.as_bytes()).map_err(|e| fail(&path, e))?;
            // Read-only, like the procfs files it stands in for; the 0700
            // directory already keeps other host users out.
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(0o444),
            )
            .map_err(|e| fail(&path, e))?;
            if rel == Path::new("uptime") {
                uptime = Some(f);
            }
        }
        Ok(uptime)
    }
}

impl Drop for HostView {
    fn drop(&mut self) {
        drop(self.uptime.take());
        if self.written {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// A machine id in systemd's format (32 lowercase hex digits).
pub(super) fn valid_machine_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && text.bytes().any(|b| b != b'0')
}

fn random_machine_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("--mask-host: cannot read /dev/urandom: {e}"))?;
    // UUID v4 bits, as systemd-machine-id-setup writes them.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The jail's machine id: the one kept at `store` when it is valid, else
/// a new one, saved there (0600) when `write` is set. A symlink or a
/// non-file at `store` is refused rather than followed.
pub(super) fn machine_id(
    store: Option<&Path>,
    write: bool,
) -> Result<String, String> {
    let Some(path) = store else {
        return random_machine_id();
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(format!(
                "--mask-host: {} is not a regular file",
                path.display()
            ));
        }
        Ok(_) => {
            let text = std::fs::read_to_string(path).map_err(|e| {
                format!("--mask-host: cannot read {}: {e}", path.display())
            })?;
            if valid_machine_id(text.trim()) {
                return Ok(text.trim().to_string());
            }
        }
        Err(_) => {}
    }
    let id = random_machine_id()?;
    if write {
        crate::fsutil::write_atomic(
            path,
            &format!("{id}\n"),
            false,
            "machine-id",
        )?;
    }
    Ok(id)
}

#[cfg(test)]
#[path = "host_view_tests.rs"]
mod tests;
