//! `--cpus`: CPU affinity for the sandbox, locked by seccomp.
//!
//! Moved from `feat/resource-limits` d3187c5 (`src/limits.rs`), without
//! the systemd scope code: affinity needs no privilege, and the seccomp
//! rule in `seccomp.rs` is what stops the sandbox from widening it again.

use std::collections::BTreeSet;

/// Upper bound on a CPU number, matching glibc's `CPU_SETSIZE`.
const MAX_CPU: usize = 1024;

/// `8,24`, `0-3`, `0-3,8`: the `taskset -c` / cpuset list syntax.
pub fn parse_cpu_list(text: &str) -> Result<BTreeSet<usize>, String> {
    let mut set = BTreeSet::new();
    for part in text.split(',') {
        let part = part.trim();
        let cpu = |s: &str| -> Result<usize, String> {
            let n: usize = s
                .trim()
                .parse()
                .map_err(|_| format!("invalid CPU list {text:?}"))?;
            if n >= MAX_CPU {
                return Err(format!("CPU {n} is out of range"));
            }
            Ok(n)
        };
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (cpu(lo)?, cpu(hi)?);
                if lo > hi {
                    return Err(format!("invalid CPU range {part:?}"));
                }
                set.extend(lo..=hi);
            }
            None => {
                set.insert(cpu(part)?);
            }
        }
    }
    if set.is_empty() {
        return Err("empty CPU list".into());
    }
    Ok(set)
}

pub fn format_cpu_list(cpus: &BTreeSet<usize>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut iter = cpus.iter().copied().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end += 1;
            iter.next();
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    out.join(",")
}

/// Project CPUs narrow the baseline to their intersection. Returns the
/// value to keep and whether the project value was (partly) dropped.
///
/// Unlike the `feat/resource-limits` version, an empty intersection is
/// kept as the empty list rather than falling back to the baseline: the
/// project asked for CPUs the trusted layers never allow, so nothing is
/// left to run on, and the launch refuses it (`check_launch`) instead of
/// quietly running on CPUs the project excluded.
pub fn tighten_cpus(
    base: Option<String>,
    local: Option<String>,
) -> (Option<String>, bool) {
    match (base, local) {
        (base, None) => (base, false),
        (None, local) => (local, false),
        (Some(b), Some(l)) => match (parse_cpu_list(&b), parse_cpu_list(&l)) {
            (Ok(bs), Ok(ls)) => {
                let both: BTreeSet<usize> =
                    bs.intersection(&ls).copied().collect();
                let dropped = both != ls;
                (Some(format_cpu_list(&both)), dropped)
            }
            // A trusted value that does not parse is kept so the launch
            // fails closed at `check_launch`: a valid project value must
            // never stand in for it.
            // Not the project's fault: `check_launch` names the trusted
            // value when it refuses.
            (Err(_), _) => (Some(b), false),
            // A project value that does not parse is kept for the same
            // reason: dropping it would silently widen its own policy.
            (Ok(_), Err(_)) => (Some(l), false),
        },
    }
}

/// CPUs the calling process may run on right now.
#[cfg(target_os = "linux")]
fn allowed_cpus() -> Result<BTreeSet<usize>, String> {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;
    let set = sched_getaffinity(Pid::from_raw(0))
        .map_err(|e| format!("cannot read CPU affinity: {e}"))?;
    Ok((0..CpuSet::count())
        .filter(|&i| set.is_set(i).unwrap_or(false))
        .collect())
}

/// Refuse CPUs this process cannot use: the kernel would silently drop
/// them, and `--cpus 40` on a 32-CPU host must not mean "any CPU".
#[cfg(target_os = "linux")]
pub fn validate_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    let allowed = allowed_cpus()?;
    let missing: BTreeSet<usize> = cpus.difference(&allowed).copied().collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--cpus {} names CPUs this process cannot use: {} (available: {})",
            format_cpu_list(cpus),
            format_cpu_list(&missing),
            format_cpu_list(&allowed)
        ))
    }
}

/// Every refusal `--cpus` can produce, checked before anything starts.
pub fn check_launch(
    cpus: Option<&str>,
    seccomp_enabled: bool,
) -> Result<(), String> {
    let Some(text) = cpus else {
        return Ok(());
    };
    if text.is_empty() {
        return Err("--cpus: the project .ai-jail CPU set shares no CPU \
                    with the trusted set, so nothing is left to run on"
            .into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = seccomp_enabled;
        Err("--cpus is Linux only".into())
    }
    #[cfg(target_os = "linux")]
    {
        // Affinity alone is advisory: any process may widen its own.
        // Seccomp is what makes --cpus a limit rather than a hint.
        if !seccomp_enabled {
            return Err("--cpus needs seccomp, which stops the sandbox \
                        from widening its own CPU set; drop --no-seccomp"
                .into());
        }
        let set = parse_cpu_list(text).map_err(|e| format!("--cpus: {e}"))?;
        validate_cpus(&set)
    }
}

/// Pin the calling thread -- and everything it later execs or forks --
/// to `cpus`. Must run before seccomp refuses `sched_setaffinity`.
#[cfg(target_os = "linux")]
pub fn apply_cpus(cpus: &BTreeSet<usize>) -> Result<(), String> {
    use nix::sched::{CpuSet, sched_setaffinity};
    use nix::unistd::Pid;
    validate_cpus(cpus)?;
    let mut set = CpuSet::new();
    for &cpu in cpus {
        set.set(cpu)
            .map_err(|e| format!("cannot select CPU {cpu}: {e}"))?;
    }
    sched_setaffinity(Pid::from_raw(0), &set)
        .map_err(|e| format!("cannot set CPU affinity: {e}"))
}

// `--cpus`: parsing, formatting, validation and project narrowing.
//
// The signatures are shared with `feat/resource-limits`' `src/limits.rs`:
// `parse_cpu_list(&str) -> Result<BTreeSet<usize>, String>`,
// `format_cpu_list(&BTreeSet<usize>) -> String`,
// `validate_cpus(&BTreeSet<usize>) -> Result<(), String>`,
// `tighten_cpus(Option<String>, Option<String>) -> (Option<String>, bool)`.
// The empty-intersection refusal is asserted at launch level in
// `tests/rlimit_values.rs`, not here.
#[cfg(test)]
mod affinity_tests {
    use std::collections::BTreeSet;

    use super::*;

    fn set(cpus: &[usize]) -> BTreeSet<usize> {
        cpus.iter().copied().collect()
    }

    /// The kernel's own view of this process's CPUs, as `0-31` text.
    /// Reads `/proc`, so Linux only, like `validate_cpus`.
    #[cfg(target_os = "linux")]
    fn kernel_allowed_list() -> String {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
            .map(|v| v.trim().to_string())
            .expect("Cpus_allowed_list in /proc/self/status")
    }

    #[test]
    fn cpu_lists_parse_single_cpus_and_ranges() {
        assert_eq!(parse_cpu_list("8,24").unwrap(), set(&[8, 24]));
        assert_eq!(parse_cpu_list("0-3,8").unwrap(), set(&[0, 1, 2, 3, 8]));
        assert_eq!(parse_cpu_list("5").unwrap(), set(&[5]));
        assert_eq!(parse_cpu_list("2-2").unwrap(), set(&[2]));
    }

    #[test]
    fn malformed_cpu_lists_are_refused() {
        for text in ["", "a", "3-1", "0,,1", "-1", "1024", "0-1024", "1.5"] {
            assert!(parse_cpu_list(text).is_err(), "{text:?} must be refused");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpus_outside_the_supervisors_set_are_refused_naming_entry_and_set() {
        let allowed = kernel_allowed_list();
        let allowed_set = parse_cpu_list(&allowed).unwrap();
        let outside = (0..1024)
            .rev()
            .find(|c| !allowed_set.contains(c))
            .expect("some CPU number below 1024 is not allowed here");
        let err = validate_cpus(&set(&[outside])).unwrap_err();
        assert!(err.contains(&outside.to_string()), "names the entry: {err}");
        assert!(
            err.contains(&format_cpu_list(&allowed_set)),
            "names the allowed set {allowed}: {err}"
        );
        let first = *allowed_set.iter().next().unwrap();
        assert!(validate_cpus(&set(&[first])).is_ok());
    }

    #[test]
    fn project_cpus_narrow_the_trusted_set_to_the_intersection() {
        let (got, _) = tighten_cpus(Some("0-3".into()), Some("2-5".into()));
        assert_eq!(got.as_deref(), Some("2-3"));
        let (got, _) = tighten_cpus(Some("0-3".into()), None);
        assert_eq!(got.as_deref(), Some("0-3"));
    }

    #[test]
    fn affinity_code_carries_no_privileged_path() {
        // no systemd-run, sudo, setuid helper or cgroup write.
        let src = include_str!("affinity.rs");
        let code: String = src
            .lines()
            .take_while(|l| !l.contains("mod affinity_tests"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in ["systemd-run", "\"sudo\"", "/sys/fs/cgroup", "setuid("] {
            assert!(!code.contains(needle), "affinity.rs mentions {needle}");
        }
    }
}
