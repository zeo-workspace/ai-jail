//! Pure generators for `--mask-host`: the synthetic `/proc` and
//! `/sys/devices/system/cpu` contents a jail sees instead of the host's.
//!
//! Kept free of I/O so every rule can be unit-tested against fixed host
//! text; `host_view` reads the host and writes these to disk.

use std::collections::BTreeSet;

/// The model name every synthetic CPU reports. The real one (and its
/// family/model/stepping numbers) is what identifies the host's hardware.
pub(super) const VIRTUAL_CPU_MODEL: &str = "Virtual CPU";

/// cpuinfo keys copied from the host's first CPU. Feature flags stay real
/// because software picks code paths by them (`avx2`, `sse4_2`, `neon`):
/// hiding them breaks builds and runtimes while `cpuid` reveals them anyway.
/// Everything else -- model, stepping, microcode, frequency, cache size,
/// `bugs` (the vulnerability list) and the topology -- is replaced or dropped.
const CPUINFO_COPIED_KEYS: &[&str] = &[
    "vendor_id",
    "cpu family",
    "fpu",
    "fpu_exception",
    "cpuid level",
    "wp",
    "flags",
    "clflush size",
    "cache_alignment",
    "address sizes",
    "Features",
    "CPU architecture",
];

/// Parse a kernel CPU list (`0-3,8,10-11`) into ids.
pub(super) fn parse_id_list(text: &str) -> Option<BTreeSet<usize>> {
    let mut ids = BTreeSet::new();
    for part in text.trim().split(',') {
        let (lo, hi): (usize, usize) = match part.split_once('-') {
            Some((lo, hi)) => {
                (lo.trim().parse().ok()?, hi.trim().parse().ok()?)
            }
            None => {
                let id = part.trim().parse().ok()?;
                (id, id)
            }
        };
        if lo > hi {
            return None;
        }
        ids.extend(lo..=hi);
    }
    Some(ids)
}

/// Render ids in the kernel's list syntax (`0-3,8`).
pub(super) fn format_id_list(ids: &BTreeSet<usize>) -> String {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &id in ids {
        match runs.last_mut() {
            Some((_, hi)) if *hi + 1 == id => *hi = id,
            _ => runs.push((id, id)),
        }
    }
    runs.iter()
        .map(|&(lo, hi)| {
            if lo == hi {
                lo.to_string()
            } else {
                format!("{lo}-{hi}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The CPU ids the jail is shown.
///
/// `base` is the explicit `--cpus` set when there is one, else the
/// process's affinity, else every host CPU. A CPU quota smaller than the
/// base keeps its first `quota_cpus` ids, so a quota-only jail on a
/// 32-CPU host reads `0-3` rather than `0-31`.
pub(super) fn jail_cpu_ids(
    base: &BTreeSet<usize>,
    quota_cpus: Option<usize>,
) -> BTreeSet<usize> {
    match quota_cpus {
        Some(n) if n < base.len() => base.iter().copied().take(n).collect(),
        _ => base.clone(),
    }
}

/// CPUs a cgroup v2 `cpu.max` line allows, rounded up: `400000 100000`
/// is 4, `150000 100000` is 2, `max 100000` is no limit.
pub(super) fn quota_cpus(cpu_max: &str) -> Option<usize> {
    let mut it = cpu_max.split_whitespace();
    let quota: u64 = it.next()?.parse().ok()?;
    let period: u64 = it.next()?.parse().ok()?;
    if period == 0 {
        return None;
    }
    usize::try_from(quota.div_ceil(period).max(1)).ok()
}

/// `/proc/cpuinfo` with one generic block per id.
pub(super) fn cpuinfo(ids: &BTreeSet<usize>, host: &str) -> String {
    // The host's first block, key text kept verbatim (tabs included) so
    // the copied lines read exactly as the kernel prints them.
    let copied: Vec<&str> = host
        .split("\n\n")
        .next()
        .unwrap_or("")
        .lines()
        .filter(|line| {
            line.split_once(':').is_some_and(|(key, _)| {
                CPUINFO_COPIED_KEYS.contains(&key.trim())
            })
        })
        .collect();
    let n = ids.len();
    let mut out = String::new();
    for (index, id) in ids.iter().enumerate() {
        out.push_str(&format!("processor\t: {id}\n"));
        out.push_str(&format!("model name\t: {VIRTUAL_CPU_MODEL}\n"));
        out.push_str(&format!(
            "physical id\t: 0\nsiblings\t: {n}\ncore id\t\t: {index}\n\
             cpu cores\t: {n}\napicid\t\t: {index}\n"
        ));
        for line in &copied {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// `/proc/meminfo` sized to `memory` bytes, with `used` already taken.
///
/// Every key of the host's file is kept, in order, so parsers that expect
/// one find it; the sizes the jail can know are computed and every other
/// counter reads 0. Swap follows `swap` when the cgroup caps it (`Some`),
/// else stays the host's.
pub(super) fn meminfo(
    memory: u64,
    used: u64,
    swap: Option<u64>,
    host: &str,
) -> String {
    let kib = |bytes: u64| bytes / 1024;
    let free = kib(memory.saturating_sub(used));
    let host_value = |key: &str| {
        host.lines().find_map(|line| {
            let (k, rest) = line.split_once(':')?;
            (k == key).then(|| {
                rest.trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse::<u64>()
                    .ok()
            })?
        })
    };
    let (swap_total, swap_free) = match swap {
        Some(bytes) => (kib(bytes), kib(bytes)),
        None => (
            host_value("SwapTotal").unwrap_or(0),
            host_value("SwapFree").unwrap_or(0),
        ),
    };
    let mut keys: Vec<(&str, bool)> = host
        .lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            Some((key, rest.trim_end().ends_with("kB")))
        })
        .collect();
    if keys.is_empty() {
        keys = [
            "MemTotal",
            "MemFree",
            "MemAvailable",
            "SwapTotal",
            "SwapFree",
        ]
        .iter()
        .map(|k| (*k, true))
        .collect();
    }
    let mut out = String::new();
    for (key, in_kb) in keys {
        let value = match key {
            "MemTotal" => kib(memory),
            "MemFree" | "MemAvailable" => free,
            "SwapTotal" => swap_total,
            "SwapFree" => swap_free,
            // The page size of huge pages is the architecture's, not a
            // measure of the host.
            "Hugepagesize" => host_value(key).unwrap_or(0),
            _ => 0,
        };
        let label = format!("{key}:");
        if in_kb {
            out.push_str(&format!("{label:<16}{value:>8} kB\n"));
        } else {
            out.push_str(&format!("{label:<16}{value:>8}\n"));
        }
    }
    out
}

/// `/proc/stat` with one zeroed line per id: static, so a tool that
/// computes usage from deltas reads an idle machine, not the host's load.
pub(super) fn stat(ids: &BTreeSet<usize>, btime: u64) -> String {
    const ZEROS: &str = "0 0 0 0 0 0 0 0 0 0";
    let mut out = format!("cpu  {ZEROS}\n");
    for id in ids {
        out.push_str(&format!("cpu{id} {ZEROS}\n"));
    }
    out.push_str(&format!(
        "intr 0\nctxt 0\nbtime {btime}\nprocesses 0\nprocs_running 1\n\
         procs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n"
    ));
    out
}

/// `/proc/loadavg` for an idle machine: one running task, the reader.
pub(super) fn loadavg() -> String {
    "0.00 0.00 0.00 1/1 1\n".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[usize]) -> BTreeSet<usize> {
        list.iter().copied().collect()
    }

    const HOST_CPUINFO: &str = "\
processor\t: 0
vendor_id\t: AuthenticAMD
cpu family\t: 26
model\t\t: 68
model name\t: AMD Ryzen 9 9950X 16-Core Processor
stepping\t: 0
microcode\t: 0xb404023
cpu MHz\t\t: 3000.000
cache size\t: 1024 KB
physical id\t: 0
siblings\t: 32
core id\t\t: 0
cpu cores\t: 16
apicid\t\t: 0
fpu\t\t: yes
flags\t\t: fpu vme avx2 sse4_2
bugs\t\t: sysret_ss_attrs spectre_v1
bogomips\t: 8600.00
address sizes\t: 48 bits physical, 48 bits virtual

processor\t: 1
vendor_id\t: AuthenticAMD
model name\t: AMD Ryzen 9 9950X 16-Core Processor
flags\t\t: fpu vme avx2 sse4_2
";

    const HOST_MEMINFO: &str = "\
MemTotal:       63421728 kB
MemFree:        12345678 kB
MemAvailable:   40000000 kB
Buffers:          123456 kB
Cached:         20000000 kB
SwapTotal:      100663288 kB
SwapFree:       100000000 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
";

    #[test]
    fn id_lists_round_trip_through_kernel_syntax() {
        assert_eq!(
            parse_id_list("0-3,8,10-11\n"),
            Some(ids(&[0, 1, 2, 3, 8, 10, 11]))
        );
        assert_eq!(parse_id_list("5"), Some(ids(&[5])));
        assert_eq!(parse_id_list(""), None);
        assert_eq!(parse_id_list("3-1"), None);
        assert_eq!(parse_id_list("a-b"), None);
        assert_eq!(
            format_id_list(&ids(&[0, 1, 2, 3, 8, 10, 11])),
            "0-3,8,10-11"
        );
        assert_eq!(format_id_list(&ids(&[28, 29, 30, 31])), "28-31");
        assert_eq!(format_id_list(&ids(&[7])), "7");
    }

    #[test]
    fn cpu_quota_rounds_up_to_whole_cpus() {
        assert_eq!(quota_cpus("400000 100000\n"), Some(4));
        assert_eq!(quota_cpus("150000 100000"), Some(2));
        assert_eq!(quota_cpus("50000 100000"), Some(1));
        assert_eq!(quota_cpus("max 100000"), None);
        assert_eq!(quota_cpus("garbage"), None);
        assert_eq!(quota_cpus("100000 0"), None);
    }

    #[test]
    fn quota_trims_the_base_set_to_its_first_ids() {
        let host: BTreeSet<usize> = (0..32).collect();
        assert_eq!(jail_cpu_ids(&host, Some(4)), ids(&[0, 1, 2, 3]));
        assert_eq!(jail_cpu_ids(&host, None), host);
        let pinned = ids(&[28, 29, 30, 31]);
        assert_eq!(jail_cpu_ids(&pinned, Some(2)), ids(&[28, 29]));
        // A quota larger than the set never invents CPUs.
        assert_eq!(jail_cpu_ids(&pinned, Some(8)), pinned);
    }

    #[test]
    fn cpuinfo_hides_the_model_and_keeps_the_flags() {
        let text = cpuinfo(&ids(&[0, 1, 2, 3]), HOST_CPUINFO);
        assert_eq!(text.matches("processor\t: ").count(), 4);
        assert_eq!(
            text.matches(&format!("model name\t: {VIRTUAL_CPU_MODEL}"))
                .count(),
            4
        );
        assert!(text.contains("flags\t\t: fpu vme avx2 sse4_2"));
        assert!(text.contains("vendor_id\t: AuthenticAMD"));
        assert!(text.contains("siblings\t: 4"));
        assert!(text.contains("cpu cores\t: 4"));
        for leak in [
            "Ryzen",
            "microcode",
            "bugs",
            "cpu MHz",
            "cache size",
            "stepping",
            "bogomips",
            "spectre",
        ] {
            assert!(!text.contains(leak), "{leak} leaked into:\n{text}");
        }
    }

    #[test]
    fn cpuinfo_numbers_processors_by_their_real_ids() {
        let text = cpuinfo(&ids(&[28, 29]), HOST_CPUINFO);
        assert!(text.contains("processor\t: 28\n"));
        assert!(text.contains("processor\t: 29\n"));
        assert!(!text.contains("processor\t: 0\n"));
    }

    #[test]
    fn meminfo_reports_the_limit_and_zeroes_host_counters() {
        let gib = 1024 * 1024 * 1024;
        let text = meminfo(8 * gib, gib, Some(0), HOST_MEMINFO);
        assert!(text.contains("MemTotal:        8388608 kB\n"), "{text}");
        assert!(text.contains("MemFree:         7340032 kB\n"), "{text}");
        assert!(text.contains("MemAvailable:    7340032 kB\n"), "{text}");
        assert!(text.contains("Buffers:               0 kB\n"), "{text}");
        assert!(text.contains("Cached:                0 kB\n"), "{text}");
        assert!(text.contains("SwapTotal:             0 kB\n"), "{text}");
        assert!(text.contains("SwapFree:              0 kB\n"), "{text}");
        assert!(text.contains("HugePages_Total:       0\n"), "{text}");
        assert!(text.contains("Hugepagesize:       2048 kB\n"), "{text}");
        assert!(!text.contains("63421728"));
    }

    #[test]
    fn meminfo_keeps_host_swap_when_the_cgroup_does_not_cap_it() {
        let gib = 1024 * 1024 * 1024;
        let text = meminfo(8 * gib, 0, None, HOST_MEMINFO);
        assert!(text.contains("SwapTotal:      100663288 kB\n"), "{text}");
        assert!(text.contains("SwapFree:       100000000 kB\n"), "{text}");
    }

    #[test]
    fn meminfo_never_reports_more_used_than_total() {
        let text = meminfo(1024 * 1024, 4 * 1024 * 1024, Some(0), HOST_MEMINFO);
        assert!(text.contains("MemFree:               0 kB\n"), "{text}");
    }

    #[test]
    fn stat_lists_one_zeroed_line_per_cpu() {
        let text = stat(&ids(&[0, 1, 2, 3]), 1_700_000_000);
        assert!(text.starts_with("cpu  0 0 0 0 0 0 0 0 0 0\n"), "{text}");
        for id in 0..4 {
            assert!(text.contains(&format!("\ncpu{id} 0 0 0 0 0 0 0 0 0 0\n")));
        }
        assert!(!text.contains("cpu4 "));
        assert!(text.contains("\nbtime 1700000000\n"));
        assert!(text.contains("\nprocs_running 1\n"));
    }

    #[test]
    fn loadavg_reads_idle() {
        assert_eq!(loadavg(), "0.00 0.00 0.00 1/1 1\n");
    }
}
