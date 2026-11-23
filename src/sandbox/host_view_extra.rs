//! The second layer of `--mask-host`: what names the host rather than
//! sizing it.
//!
//! `host_view` replaces what describes the machine's capacity (CPUs, RAM,
//! load). This module adds what *identifies* it: the kernel's build
//! strings, the distribution's release files, the disks (`/proc/swaps`,
//! partitions, block devices, `/etc/crypttab`), the NUMA and memory-block
//! layout, the installed kernels and a stable boot id. Each is either a
//! generic stand-in written into the view's directory or a mask (an empty
//! file, a tmpfs for a directory). A path the host lacks is skipped, so a
//! distribution without `/etc/portage` or `/proc/pressure` launches the
//! same.
//!
//! The kernel release keeps its numeric part (`7.3.5`): feature probes
//! compare versions, so a fake number would break them. `uname(2)` itself
//! still answers with the full string -- nothing unprivileged rewrites it.
//!
//! It also builds the time namespace's offsets, so `CLOCK_BOOTTIME`,
//! `CLOCK_MONOTONIC` and `sysinfo().uptime` count from the jail's start
//! (see `bwrap::time_namespace_hook`), and, under `--overlay-system`, the
//! read-only overlays that keep `/usr`, `/etc` and `/opt`'s mount sources
//! (device mapper names, subvolumes) out of `/proc/self/mountinfo`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::host_view::{HostViewMount, HostViewPlan};
use super::host_view_synth as synth;

/// Files emptied under `--mask-host`. `/etc/crypttab` is world-readable
/// and names the encrypted volumes.
pub(super) const FILE_MASKS: &[&str] = &[
    "/etc/crypttab",
    "/etc/gentoo-release",
    "/etc/lsb-release",
    "/proc/partitions",
    "/proc/diskstats",
    "/proc/zoneinfo",
    "/proc/interrupts",
    "/proc/schedstat",
];

/// Directories hidden by a tmpfs under `--mask-host`.
pub(super) const DIR_MASKS: &[&str] = &[
    "/etc/portage",
    "/proc/pressure",
    "/sys/block",
    "/sys/class/block",
    "/sys/devices/system/node",
    "/sys/devices/system/memory",
    "/usr/lib/modules",
    "/usr/src",
];

/// `/etc/os-release` is a symlink to this on systemd-era distributions,
/// and bwrap refuses to mount over a symlink.
const OS_RELEASE: &str = "/usr/lib/os-release";
const ETC_OS_RELEASE: &str = "/etc/os-release";
const PROC_VERSION: &str = "/proc/version";
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const KERNEL_VERSION: &str = "/proc/sys/kernel/version";
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const SWAPS: &str = "/proc/swaps";

/// A distribution-neutral `os-release`.
pub(super) const GENERIC_OS_RELEASE: &str =
    "NAME=\"Linux\"\nID=linux\nPRETTY_NAME=\"Linux\"\n";

/// `/proc/swaps` with no swap device: the header line only, which
/// `swapon --show` and `free` read as "no swap".
pub(super) const EMPTY_SWAPS: &str =
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

/// The trees `--overlay-system` serves through a read-only overlay.
pub(super) const OVERLAY_TREES: &[&str] = &["/usr", "/etc", "/opt"];

/// The host's identity strings, read once per launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HostIdentity {
    /// `/proc/sys/kernel/osrelease`, e.g. `7.3.5-bentoo-dist`.
    pub osrelease: String,
    /// `/proc/sys/kernel/version`, e.g. `#1 SMP PREEMPT_DYNAMIC <date>`.
    pub version: String,
    /// A fresh boot id for this jail, in the kernel's format.
    pub boot_id: String,
    /// `/etc/os-release` is a regular file rather than the usual symlink
    /// into `/usr/lib`, so it needs a bind of its own.
    pub etc_os_release_is_file: bool,
}

impl HostIdentity {
    pub fn read(boot_id: String) -> Self {
        let read = |p: &str| {
            std::fs::read_to_string(p)
                .map(|t| t.trim().to_string())
                .unwrap_or_default()
        };
        HostIdentity {
            osrelease: read(OSRELEASE),
            version: read(KERNEL_VERSION),
            boot_id,
            etc_os_release_is_file: std::fs::symlink_metadata(ETC_OS_RELEASE)
                .is_ok_and(|m| m.file_type().is_file()),
        }
    }
}

/// The numeric part of a kernel release: `7.3.5-bentoo-dist` -> `7.3.5`,
/// `6.1.0-13-amd64` -> `6.1.0`. The local suffix names the distribution or
/// the builder; the number is what feature probes compare.
pub(super) fn kernel_release(raw: &str) -> String {
    let numeric: String = raw
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let numeric = numeric.trim_end_matches('.');
    if numeric.is_empty() {
        "0.0.0".into()
    } else {
        numeric.into()
    }
}

/// The kernel version string without its build date: `#1 SMP
/// PREEMPT_DYNAMIC Tue Nov 17 ...` -> `#1 SMP PREEMPT_DYNAMIC`. Keeps the
/// build number and the all-caps feature words, stops at the first other
/// word (the weekday).
pub(super) fn kernel_version(raw: &str) -> String {
    let mut words = raw.split_whitespace();
    let mut out = match words.next() {
        Some(first) if first.starts_with('#') => first.to_string(),
        _ => return "#1 SMP".into(),
    };
    for word in words {
        let feature = !word.is_empty()
            && word
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c == '-');
        if !feature {
            break;
        }
        out.push(' ');
        out.push_str(word);
    }
    out
}

/// `/proc/version` built from the cleaned strings: no builder, compiler
/// or date.
pub(super) fn proc_version(release: &str, version: &str) -> String {
    format!("Linux version {release} {version}\n")
}

/// A random boot id in the kernel's format (a v4 UUID, lowercase).
pub(super) fn format_boot_id(bytes: [u8; 16]) -> String {
    let mut b = bytes;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    )
}

/// A CPU set in the kernel's bitmap format: 32-bit hex words, most
/// significant first, comma-separated (`cpu/cpuN/topology/*_siblings`).
pub(super) fn cpu_mask(ids: &BTreeSet<usize>) -> String {
    let top = ids.iter().next_back().copied().unwrap_or(0);
    let mut words = vec![0u32; top / 32 + 1];
    for id in ids {
        words[id / 32] |= 1 << (id % 32);
    }
    let text: Vec<String> =
        words.iter().rev().map(|w| format!("{w:08x}")).collect();
    format!("{}\n", text.join(","))
}

/// `topology/` files for each CPU stub: every CPU its own core in one
/// package, so `lscpu` reads one thread per core instead of zero. Both the
/// list and the bitmap forms, since tools read either.
pub(super) fn topology_files(ids: &BTreeSet<usize>) -> Vec<(String, String)> {
    let all = format!("{}\n", synth::format_id_list(ids));
    let all_mask = cpu_mask(ids);
    let mut out = Vec::new();
    for (core, id) in ids.iter().enumerate() {
        let own = format!("{id}\n");
        let own_mask = cpu_mask(&BTreeSet::from([*id]));
        let base = format!("cpu/cpu{id}/topology");
        for (name, text) in [
            ("core_id", format!("{core}\n")),
            ("physical_package_id", "0\n".to_string()),
            ("die_id", "0\n".to_string()),
            ("thread_siblings_list", own.clone()),
            ("core_cpus_list", own.clone()),
            ("core_siblings_list", all.clone()),
            ("package_cpus_list", all.clone()),
            ("thread_siblings", own_mask.clone()),
            ("core_cpus", own_mask.clone()),
            ("core_siblings", all_mask.clone()),
            ("package_cpus", all_mask.clone()),
        ] {
            out.push((format!("{base}/{name}"), text));
        }
    }
    out
}

/// Add the identity layer to `out`. Pure, like `host_view::plan`.
pub(super) fn extend_plan(
    out: &mut HostViewPlan,
    identity: &HostIdentity,
    ids: &BTreeSet<usize>,
    dir: &Path,
    exists: &dyn Fn(&Path) -> bool,
) {
    let mut file = |name: &str, text: String, dest: &str| {
        if !exists(Path::new(dest)) {
            return;
        }
        out.files.push((PathBuf::from(name), text));
        out.mounts.push(HostViewMount::File {
            src: dir.join(name),
            dest: dest.into(),
        });
    };
    let release = kernel_release(&identity.osrelease);
    let version = kernel_version(&identity.version);
    file("version", proc_version(&release, &version), PROC_VERSION);
    file("osrelease", format!("{release}\n"), OSRELEASE);
    file("kernel-version", format!("{version}\n"), KERNEL_VERSION);
    file("boot_id", format!("{}\n", identity.boot_id), BOOT_ID);
    file("swaps", EMPTY_SWAPS.into(), SWAPS);
    file("os-release", GENERIC_OS_RELEASE.into(), OS_RELEASE);
    // A distribution whose /etc/os-release is a regular file, not the
    // usual symlink, needs its own bind.
    if identity.etc_os_release_is_file {
        file("etc-os-release", GENERIC_OS_RELEASE.into(), ETC_OS_RELEASE);
    }
    if FILE_MASKS.iter().any(|p| exists(Path::new(p))) {
        out.files.push((PathBuf::from("empty"), String::new()));
    }
    for path in FILE_MASKS {
        if exists(Path::new(path)) {
            out.mounts.push(HostViewMount::File {
                src: dir.join("empty"),
                dest: path.into(),
            });
        }
    }
    for path in DIR_MASKS {
        if exists(Path::new(path)) {
            out.mounts.push(HostViewMount::Tmpfs { dest: path.into() });
        }
    }
    for (rel, text) in topology_files(ids) {
        out.files.push((PathBuf::from(rel), text));
    }
}

/// `--overlay-system`: each read-only tree that exists, served through a
/// read-only overlay over an empty bottom layer (overlayfs wants two
/// layers when none is writable), so the mount table names `overlay` and
/// two `/proc/self/fd` paths instead of the host's device and subvolume.
/// The real tree is the top layer, so its root keeps the host's owner and
/// mode.
pub(super) fn overlay_mounts(
    dir: &Path,
    exists: &dyn Fn(&Path) -> bool,
) -> Vec<HostViewMount> {
    OVERLAY_TREES
        .iter()
        .filter(|tree| exists(Path::new(tree)))
        .map(|tree| HostViewMount::RoOverlay {
            lower: PathBuf::from(tree),
            empty: dir.join("overlay-empty"),
            dest: PathBuf::from(tree),
        })
        .collect()
}

/// `/proc/self/timens_offsets` text that starts the jail's
/// `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` at one second, given their host
/// values now. The kernel refuses an offset that makes a clock negative,
/// hence the second.
pub(super) fn timens_offsets(
    monotonic: Duration,
    boottime: Duration,
) -> String {
    let line = |name: &str, now: Duration| {
        // Offset = 1 s - now, as (seconds, nanoseconds in [0, 1e9)).
        let nanos = now.subsec_nanos();
        let mut secs = 1 - i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let mut ns = 0u32;
        if nanos > 0 {
            secs -= 1;
            ns = 1_000_000_000 - nanos;
        }
        format!("{name} {secs} {ns}\n")
    };
    line("monotonic", monotonic) + &line("boottime", boottime)
}

/// Whether the kernel has time namespaces (`CONFIG_TIME_NS`).
pub(super) fn time_namespaces_available() -> bool {
    Path::new("/proc/self/ns/time").exists()
}

#[cfg(test)]
#[path = "host_view_extra_tests.rs"]
mod tests;
