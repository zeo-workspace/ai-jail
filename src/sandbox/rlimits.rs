use crate::config::Config;
use crate::output;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use std::collections::BTreeMap;

// Normal mode: generous limits that prevent abuse
// without breaking build tools or AI agents.
#[cfg(target_os = "linux")]
const NPROC_NORMAL: u64 = 4096;
const NOFILE_NORMAL: u64 = 65536;

// Lockdown mode: tighter limits for untrusted workloads.
#[cfg(target_os = "linux")]
const NPROC_LOCKDOWN: u64 = 1024;
const NOFILE_LOCKDOWN: u64 = 4096;
const FSIZE_LOCKDOWN: u64 = 1024 * 1024 * 1024;

/// A per-process limit the operator may set with `--rlimit NAME=VALUE`.
///
/// The set is deliberately small: these are the rlimits that bound a
/// runaway agent without privilege. Anything needing a cgroup
/// (memory.max, cpu.max, io.max) is out of reach for an unprivileged
/// process and is documented as such instead of half-offered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RlimitName {
    Nproc,
    Nofile,
    Core,
    Cpu,
    Fsize,
    Data,
    As,
}

impl RlimitName {
    pub const ALL: [RlimitName; 7] = [
        RlimitName::Nproc,
        RlimitName::Nofile,
        RlimitName::Core,
        RlimitName::Cpu,
        RlimitName::Fsize,
        RlimitName::Data,
        RlimitName::As,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RlimitName::Nproc => "nproc",
            RlimitName::Nofile => "nofile",
            RlimitName::Core => "core",
            RlimitName::Cpu => "cpu",
            RlimitName::Fsize => "fsize",
            RlimitName::Data => "data",
            RlimitName::As => "as",
        }
    }

    pub fn resource(self) -> Resource {
        match self {
            RlimitName::Nproc => Resource::RLIMIT_NPROC,
            RlimitName::Nofile => Resource::RLIMIT_NOFILE,
            RlimitName::Core => Resource::RLIMIT_CORE,
            RlimitName::Cpu => Resource::RLIMIT_CPU,
            RlimitName::Fsize => Resource::RLIMIT_FSIZE,
            RlimitName::Data => Resource::RLIMIT_DATA,
            RlimitName::As => Resource::RLIMIT_AS,
        }
    }

    /// Byte-sized limits accept the K/M/G/T suffixes; counts and CPU
    /// seconds do not, because "4K processes" reads as 4000 to most
    /// people and 4096 to this parser.
    fn is_bytes(self) -> bool {
        matches!(self, RlimitName::Fsize | RlimitName::Data | RlimitName::As)
    }

    fn accepted_forms(self) -> &'static str {
        if self.is_bytes() {
            "a decimal integer, an integer with a K/M/G/T suffix (powers of 1024), or unlimited"
        } else {
            "a decimal integer or unlimited"
        }
    }
}

impl std::str::FromStr for RlimitName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        RlimitName::ALL
            .into_iter()
            .find(|name| name.as_str() == text)
            .ok_or_else(|| {
                let known: Vec<&str> =
                    RlimitName::ALL.iter().map(|n| n.as_str()).collect();
                format!(
                    "unknown rlimit name {text:?}; expected one of {}",
                    known.join(", ")
                )
            })
    }
}

/// A parsed limit value. `Unlimited` maps to `RLIM_INFINITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlimitValue {
    Finite(u64),
    Unlimited,
}

impl RlimitValue {
    pub fn parse(name: RlimitName, text: &str) -> Result<RlimitValue, String> {
        let refuse = || {
            format!(
                "invalid value {text:?} for rlimit {}: expected {}",
                name.as_str(),
                name.accepted_forms()
            )
        };
        if text == "unlimited" {
            return Ok(RlimitValue::Unlimited);
        }
        let (digits, multiplier) = match text.as_bytes().last() {
            Some(b'K') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 10)
            }
            Some(b'M') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 20)
            }
            Some(b'G') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 30)
            }
            Some(b'T') if name.is_bytes() => {
                (&text[..text.len() - 1], 1u64 << 40)
            }
            _ => (text, 1),
        };
        // `u64::from_str` would accept a leading '+'; the grammar is
        // decimal digits only.
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(refuse());
        }
        let base: u64 = digits.parse().map_err(|_| refuse())?;
        base.checked_mul(multiplier)
            .map(RlimitValue::Finite)
            .ok_or_else(refuse)
    }

    /// The raw `rlim_t` value, with `Unlimited` as `RLIM_INFINITY`.
    pub fn as_raw(self) -> u64 {
        match self {
            RlimitValue::Finite(n) => n,
            RlimitValue::Unlimited => nix::libc::RLIM_INFINITY,
        }
    }
}

/// Which layer supplied an effective limit. Recorded for `--dry-run` and
/// the audit record; it never changes what is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitSource {
    Default,
    Cli,
    Global,
    Project,
}

impl LimitSource {
    pub fn as_str(self) -> &'static str {
        match self {
            LimitSource::Default => "default",
            LimitSource::Cli => "cli",
            LimitSource::Global => "global",
            LimitSource::Project => "project",
        }
    }
}

/// One limit as it will be applied inside the sandbox.
pub struct EffectiveLimit {
    pub name: RlimitName,
    pub soft: u64,
    pub hard: u64,
    pub source: LimitSource,
}

/// The defaults ai-jail has always applied. `nproc` is applied only
/// inside the sandbox (see `apply_sandbox`).
fn default_limits(config: &Config) -> Vec<(RlimitName, u64)> {
    let lockdown = config.lockdown_enabled();
    let mut limits = vec![
        (
            RlimitName::Nofile,
            if lockdown {
                NOFILE_LOCKDOWN
            } else {
                NOFILE_NORMAL
            },
        ),
        (RlimitName::Core, 0),
    ];
    if lockdown {
        limits.push((RlimitName::Fsize, FSIZE_LOCKDOWN));
    }
    #[cfg(target_os = "linux")]
    limits.push((
        RlimitName::Nproc,
        if lockdown {
            NPROC_LOCKDOWN
        } else {
            NPROC_NORMAL
        },
    ));

    // RLIMIT_AS is intentionally not a default: JVMs and Chromium reserve
    // large virtual address spaces even when their physical use is
    // modest. An operator may still set it explicitly.

    limits
}

/// The ceiling `--lockdown` puts on an explicit value. Lockdown exists to
/// tighten, so an explicit value may only match or tighten its defaults.
fn lockdown_ceiling(name: RlimitName) -> Option<u64> {
    match name {
        RlimitName::Nofile => Some(NOFILE_LOCKDOWN),
        RlimitName::Core => Some(0),
        RlimitName::Fsize => Some(FSIZE_LOCKDOWN),
        #[cfg(target_os = "linux")]
        RlimitName::Nproc => Some(NPROC_LOCKDOWN),
        _ => None,
    }
}

/// Every limit that applies inside the sandbox: the defaults (unless
/// `--no-rlimits`), each replaced by an explicit value of the same name,
/// plus the explicit values that have no default.
pub fn effective(config: &Config) -> Result<Vec<EffectiveLimit>, String> {
    let mut chosen: BTreeMap<RlimitName, (u64, LimitSource)> = BTreeMap::new();
    if config.rlimits_enabled() {
        for (name, soft) in default_limits(config) {
            chosen.insert(name, (soft, LimitSource::Default));
        }
    }
    for (key, text) in &config.rlimit {
        let name: RlimitName = key.parse()?;
        let value = RlimitValue::parse(name, text)?.as_raw();
        if config.lockdown_enabled()
            && let Some(ceiling) = lockdown_ceiling(name)
            && value > ceiling
        {
            return Err(format!(
                "rlimit {}={text} is above the --lockdown limit {ceiling}; \
                 lockdown only allows tightening it",
                name.as_str()
            ));
        }
        let source = config
            .rlimit_source
            .get(key)
            .copied()
            .unwrap_or(LimitSource::Cli);
        chosen.insert(name, (value, source));
    }
    Ok(chosen
        .into_iter()
        .map(|(name, (soft, source))| EffectiveLimit {
            name,
            soft,
            // RLIMIT_CPU: at the soft limit the kernel sends SIGXCPU, at
            // the hard limit SIGKILL. With soft == hard the process gets
            // SIGKILL straight away and no chance to report; five seconds
            // of grace keep the catchable signal first.
            hard: if name == RlimitName::Cpu {
                soft.saturating_add(5)
            } else {
                soft
            },
            source,
        })
        .collect())
}

/// The value a layer holds for one limit: its explicit entry, else the
/// default, else `RLIM_INFINITY` (no limit). An entry that does not parse
/// counts as `RLIM_INFINITY`, so a comparison against it fails closed:
/// a malformed value never reads as a tightening.
pub fn value_in(config: &Config, name: RlimitName) -> u64 {
    if let Some(text) = config.rlimit.get(name.as_str()) {
        return RlimitValue::parse(name, text)
            .map(RlimitValue::as_raw)
            .unwrap_or(nix::libc::RLIM_INFINITY);
    }
    if !config.rlimits_enabled() {
        return nix::libc::RLIM_INFINITY;
    }
    default_limits(config)
        .into_iter()
        .find(|(n, _)| *n == name)
        .map_or(nix::libc::RLIM_INFINITY, |(_, v)| v)
}

/// Whether `candidate` holds any `rlimit` entry looser than `baseline`
/// (higher, `unlimited`, malformed, or an unknown name).
pub fn widens(candidate: &Config, baseline: &Config) -> bool {
    candidate
        .rlimit
        .keys()
        .any(|key| match key.parse::<RlimitName>() {
            Ok(name) => {
                candidate
                    .rlimit
                    .get(key)
                    .is_some_and(|text| RlimitValue::parse(name, text).is_err())
                    || value_in(candidate, name) > value_in(baseline, name)
            }
            Err(_) => true,
        })
}

/// Apply one limit. A default limit that cannot be read or set keeps
/// upstream's warn-and-skip; an explicit one is an error, because the
/// operator asked for it and silently running without it fails open.
fn apply_one(limit: &EffectiveLimit, verbose: bool) -> Result<(), String> {
    let explicit = limit.source != LimitSource::Default;
    let label = format!("RLIMIT_{}", limit.name.as_str().to_uppercase());
    let fail = |msg: String| {
        if explicit {
            Err(msg)
        } else {
            output::warn(&format!("{msg}, skipping"));
            Ok(())
        }
    };
    let current_hard = match getrlimit(limit.name.resource()) {
        Ok((_, hard)) => hard,
        Err(e) => return fail(format!("Failed to read {label}: {e}")),
    };
    // An unprivileged process cannot raise its hard limit: clamp, but
    // say so, since the operator asked for a different number.
    let soft = limit.soft.min(current_hard);
    let hard = limit.hard.min(current_hard);
    if soft < limit.soft {
        output::warn(&format!(
            "{label}: requested {}, hard limit {current_hard}, applied {soft}",
            limit.soft
        ));
    }
    if let Err(e) = setrlimit(limit.name.resource(), soft, hard) {
        return fail(format!("Failed to set {label}: {e}"));
    }
    if verbose {
        output::verbose(&format!("{label}: {soft} (hard: {hard})"));
    }
    Ok(())
}

/// Apply the supervisor's limits before spawning the sandbox. Limits are
/// inherited across fork+exec.
///
/// Only today's defaults (NOFILE, CORE, lockdown FSIZE) are applied here,
/// and only those no explicit value replaces. An explicit `cpu`, `fsize`,
/// `data` or `as` on the supervisor would kill or cap the PTY loop, the
/// proxy and the audit writer and orphan the sandbox; explicit values are
/// applied inside the sandbox by `apply_sandbox` instead.
pub fn apply(config: &Config, verbose: bool) -> Result<(), String> {
    if !config.rlimits_enabled() {
        if verbose {
            output::verbose("Resource limits: disabled");
        }
        return Ok(());
    }
    for (name, soft) in default_limits(config) {
        // NPROC counts against bwrap's own clone(); see `apply_sandbox`.
        if name == RlimitName::Nproc
            || config.rlimit.contains_key(name.as_str())
        {
            continue;
        }
        let limit = EffectiveLimit {
            name,
            soft,
            hard: soft,
            source: LimitSource::Default,
        };
        apply_one(&limit, verbose)?;
    }
    Ok(())
}

/// Apply the full effective set — defaults and explicit values, NPROC
/// included — in the current process. Must be called inside the bwrap
/// sandbox (from --landlock-exec), after the bridges are spawned, not on
/// the bwrap parent: bwrap uses clone() for namespace creation, which
/// counts against RLIMIT_NPROC system-wide, and applying the limit before
/// that clone() causes EAGAIN when other user processes are running.
///
/// Hard is pinned to soft (soft + 5 for CPU) so the sandboxed process
/// cannot raise a limit back: lowering a hard limit is irreversible for
/// an unprivileged process.
#[cfg(target_os = "linux")]
pub fn apply_sandbox(config: &Config, verbose: bool) -> Result<(), String> {
    for limit in effective(config)? {
        apply_one(&limit, verbose)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_sets_core_to_zero() {
        let config = Config::default();
        apply(&config, false).unwrap();

        let (soft, _) = getrlimit(Resource::RLIMIT_CORE).unwrap();
        assert_eq!(soft, 0);
    }

    #[test]
    fn apply_respects_disabled() {
        let config = Config {
            no_rlimits: Some(true),
            ..Config::default()
        };
        // Should be a no-op — just verify it doesn't fail
        apply(&config, true).unwrap();
    }

    #[test]
    fn limits_lockdown_tighter_than_normal() {
        let normal = Config::default();
        let lockdown = Config {
            lockdown: Some(true),
            ..Config::default()
        };

        let normal_limits = effective(&normal).unwrap();
        let lockdown_limits = effective(&lockdown).unwrap();

        for n in &normal_limits {
            let l = lockdown_limits
                .iter()
                .find(|l| l.name == n.name)
                .expect("lockdown keeps every normal default");
            assert!(
                l.soft <= n.soft,
                "Lockdown {} ({}) should be <= normal ({})",
                n.name.as_str(),
                l.soft,
                n.soft
            );
        }
    }

    /// `apply_sandbox` carries the post-#21/#22 fix that moves NPROC
    /// enforcement inside the sandbox. The key invariant is that
    /// the hard limit is pinned equal to the soft limit so a
    /// compromised child can't raise NPROC back up. Verify that
    /// invariant directly.
    ///
    /// Run the assertion in a child test process so the lowered hard
    /// limit cannot leak into the rest of the test suite.
    #[cfg(target_os = "linux")]
    #[test]
    fn apply_nproc_pins_hard_equal_to_soft() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "sandbox::rlimits::tests::apply_nproc_pins_hard_equal_to_soft_child",
            )
            .arg("--ignored")
            .env("AI_JAIL_RLIMIT_CHILD", "1")
            .output()
            .expect("spawn child rlimit test");
        assert!(
            output.status.success(),
            "child rlimit test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn apply_pins_nofile_and_core_hard_equal_to_soft() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "sandbox::rlimits::tests::apply_pins_nofile_and_core_hard_equal_to_soft_child",
            )
            .arg("--ignored")
            .env("AI_JAIL_RLIMIT_CHILD", "1")
            .output()
            .expect("spawn child rlimit test");
        assert!(output.status.success(), "child rlimit test failed");
    }

    #[test]
    #[ignore]
    fn apply_pins_nofile_and_core_hard_equal_to_soft_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        apply(&Config::default(), false).unwrap();
        for resource in [Resource::RLIMIT_NOFILE, Resource::RLIMIT_CORE] {
            let (soft, hard) = getrlimit(resource).expect("getrlimit");
            assert_eq!(soft, hard, "{resource:?} hard limit must be pinned");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn apply_nproc_pins_hard_equal_to_soft_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        // Skip if the current hard limit is already below
        // NPROC_NORMAL — apply_sandbox would clamp to whatever's
        // currently in effect, so the post-condition is then
        // soft == hard == previous-hard. Still asserts the
        // pin invariant.
        let (_, hard_before) =
            getrlimit(Resource::RLIMIT_NPROC).expect("getrlimit");

        let config = Config::default();
        apply_sandbox(&config, false).unwrap();

        let (soft_after, hard_after) =
            getrlimit(Resource::RLIMIT_NPROC).expect("getrlimit");
        assert_eq!(
            soft_after, hard_after,
            "apply_sandbox must pin hard == soft so the sandbox can't raise it"
        );
        let expected = NPROC_NORMAL.min(hard_before);
        assert_eq!(
            soft_after, expected,
            "soft limit should match NPROC_NORMAL clamped to current hard"
        );
    }
}

// Story 047, Task 1.1 — the limit grammar (R3.2, R3.3).
//
// Materialization: append this whole file to the end of
// `src/sandbox/rlimits.rs` on `feat/adjustable-rlimits`
// (or `include!("rlimits_story047_grammar.rs");` from it).
//
// Contract (design.md §C6): `RlimitName` implements `FromStr` and
// `as_str`; `RlimitValue::{Finite(u64), Unlimited}` has
// `parse(name: RlimitName, text: &str) -> Result<RlimitValue, String>`.
// K/M/G/T are powers of 1024 and are accepted only for fsize, data, as.
// No `Debug`/`PartialEq` derive is assumed on the new types.
#[cfg(test)]
mod story047_grammar_tests {
    use super::*;

    const ALL: [&str; 7] =
        ["nproc", "nofile", "core", "cpu", "fsize", "data", "as"];

    fn name(text: &str) -> RlimitName {
        text.parse::<RlimitName>()
            .ok()
            .unwrap_or_else(|| panic!("{text} must be a known limit name"))
    }

    fn parsed(limit: &str, text: &str) -> RlimitValue {
        match RlimitValue::parse(name(limit), text) {
            Ok(v) => v,
            Err(e) => panic!("{limit}={text} must parse, got Err({e})"),
        }
    }

    fn refused(limit: &str, text: &str) -> String {
        match RlimitValue::parse(name(limit), text) {
            Ok(_) => panic!("{limit}={text} must be refused"),
            Err(e) => e,
        }
    }

    fn finite(limit: &str, text: &str) -> u64 {
        match parsed(limit, text) {
            RlimitValue::Finite(n) => n,
            RlimitValue::Unlimited => {
                panic!("{limit}={text} must be finite, got Unlimited")
            }
        }
    }

    #[test]
    fn every_documented_name_parses_and_round_trips_through_as_str() {
        for text in ALL {
            assert_eq!(name(text).as_str(), text);
        }
    }

    #[test]
    fn names_outside_the_set_are_refused() {
        // Near misses first: each looks like a limit but is not one of
        // the seven the story offers.
        for text in ["nprocs", "rss", "stack", "memlock", "nice", "", " nofile"]
        {
            assert!(
                text.parse::<RlimitName>().is_err(),
                "{text:?} must not be a limit name"
            );
        }
    }

    #[test]
    fn binary_suffix_is_refused_for_count_and_time_limits() {
        // Hostile half first: a suffix that would wrongly be accepted on a
        // limit that is not measured in bytes.
        for limit in ["nofile", "nproc", "cpu", "core"] {
            let err = refused(limit, "4K");
            assert!(err.contains("4K"), "error must name the value: {err}");
        }
    }

    #[test]
    fn binary_suffixes_are_powers_of_1024_for_byte_limits() {
        for limit in ["fsize", "data", "as"] {
            assert_eq!(finite(limit, "4K"), 4 * 1024);
            assert_eq!(finite(limit, "3M"), 3 * 1024 * 1024);
            assert_eq!(finite(limit, "8G"), 8 * 1024 * 1024 * 1024);
            assert_eq!(finite(limit, "2T"), 2 * 1024_u64.pow(4));
        }
    }

    #[test]
    fn decimal_integers_parse_for_every_name() {
        for limit in ALL {
            assert_eq!(finite(limit, "0"), 0);
            assert_eq!(finite(limit, "4096"), 4096);
        }
        assert_eq!(finite("nofile", "18446744073709551614"), u64::MAX - 1);
    }

    #[test]
    fn unlimited_is_accepted_for_every_name() {
        for limit in ALL {
            assert!(
                matches!(parsed(limit, "unlimited"), RlimitValue::Unlimited),
                "{limit}=unlimited"
            );
        }
    }

    #[test]
    fn overflowing_values_are_refused_not_wrapped() {
        // u64::MAX + 1 as a decimal.
        let err = refused("nofile", "18446744073709551616");
        assert!(err.contains("18446744073709551616"), "{err}");
        // 2^24 * 2^40 = 2^64: one past u64::MAX through the suffix.
        let err = refused("fsize", "16777216T");
        assert!(err.contains("16777216T"), "{err}");
        // The largest suffixed value that still fits is accepted.
        assert_eq!(finite("fsize", "16777215T"), 16_777_215 * 1024_u64.pow(4));
    }

    #[test]
    fn malformed_values_are_refused() {
        for text in ["", "-1", "1.5G", "1 G", "1KB", "0x10", "ten"] {
            refused("data", text);
        }
    }

    #[test]
    fn errors_name_the_limit_the_value_and_the_accepted_forms() {
        let err = refused("data", "12X");
        assert!(err.contains("data"), "must name the limit: {err}");
        assert!(err.contains("12X"), "must name the value: {err}");
        assert!(
            err.contains("unlimited"),
            "must list the accepted forms (decimal, K/M/G/T, unlimited): {err}"
        );
    }
}

// Story 047, Task 1.2 — effective limits and their application
// (R3.1, R3.4, R3.5, R3.6, R3.7, R3.8, R3.10).
//
// Materialization: append this whole file to the end of
// `src/sandbox/rlimits.rs` on `feat/adjustable-rlimits`
// (or `include!("rlimits_story047_effective.rs");` from it).
//
// Contract (design.md §C6):
// - `Config.rlimit: BTreeMap<String, String>` (values in the CLI grammar)
//   and `Config.rlimit_source: BTreeMap<String, LimitSource>` (serde skip);
// - `pub fn effective(config: &Config) -> Result<Vec<EffectiveLimit>, String>`;
// - `EffectiveLimit { name: RlimitName, soft: u64, hard: u64,
//   source: LimitSource }`, `LimitSource::{Default, Cli, Global, Profile,
//   Project}`, `RlimitName::as_str`;
// - the supervisor's `apply(config, verbose) -> Result<(), String>` applies
//   only today's defaults (NOFILE, CORE, lockdown FSIZE) and warns, naming
//   the requested and the applied value, when it clamps to the hard limit
//   instead of clamping silently (R3.4).
// `unlimited` is RLIM_INFINITY, which is u64::MAX on Linux.
#[cfg(test)]
mod story047_effective_tests {
    use std::collections::BTreeMap;

    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let rlimit: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let rlimit_source: BTreeMap<String, LimitSource> = pairs
            .iter()
            .map(|(k, _)| (k.to_string(), LimitSource::Cli))
            .collect();
        Config {
            rlimit,
            rlimit_source,
            ..Config::default()
        }
    }

    fn limits(config: &Config) -> Vec<EffectiveLimit> {
        match effective(config) {
            Ok(v) => v,
            Err(e) => panic!("effective() must succeed, got Err({e})"),
        }
    }

    fn find<'a>(
        limits: &'a [EffectiveLimit],
        name: &str,
    ) -> &'a EffectiveLimit {
        limits
            .iter()
            .find(|l| l.name.as_str() == name)
            .unwrap_or_else(|| panic!("no effective limit named {name}"))
    }

    fn names(limits: &[EffectiveLimit]) -> Vec<&'static str> {
        let mut v: Vec<&'static str> =
            limits.iter().map(|l| l.name.as_str()).collect();
        v.sort_unstable();
        v
    }

    fn pair(limits: &[EffectiveLimit], name: &str) -> (u64, u64) {
        let l = find(limits, name);
        (l.soft, l.hard)
    }

    #[test]
    fn defaults_are_unchanged_when_no_value_is_given() {
        let normal = limits(&Config::default());
        assert_eq!(names(&normal), vec!["core", "nofile", "nproc"]);
        assert_eq!(pair(&normal, "nofile"), (65536, 65536));
        assert_eq!(pair(&normal, "core"), (0, 0));
        assert_eq!(pair(&normal, "nproc"), (4096, 4096));
        for l in &normal {
            assert!(matches!(l.source, LimitSource::Default));
        }

        let lockdown = limits(&Config {
            lockdown: Some(true),
            ..Config::default()
        });
        assert_eq!(names(&lockdown), vec!["core", "fsize", "nofile", "nproc"]);
        assert_eq!(pair(&lockdown, "nofile"), (4096, 4096));
        assert_eq!(pair(&lockdown, "fsize"), (GIB, GIB));
        assert_eq!(pair(&lockdown, "nproc"), (1024, 1024));
    }

    #[test]
    fn explicit_value_replaces_only_that_default() {
        let got = limits(&config(&[("nofile", "1024")]));
        assert_eq!(pair(&got, "nofile"), (1024, 1024));
        assert!(matches!(find(&got, "nofile").source, LimitSource::Cli));
        // The other defaults stay, still labelled as defaults (R3.5).
        assert_eq!(pair(&got, "core"), (0, 0));
        assert!(matches!(find(&got, "core").source, LimitSource::Default));
        assert_eq!(pair(&got, "nproc"), (4096, 4096));
    }

    #[test]
    fn explicit_value_adds_a_limit_with_no_default() {
        let got = limits(&config(&[("data", "8G"), ("as", "unlimited")]));
        assert_eq!(pair(&got, "data"), (8 * GIB, 8 * GIB));
        assert_eq!(pair(&got, "as"), (u64::MAX, u64::MAX));
        assert_eq!(pair(&got, "nofile"), (65536, 65536));
    }

    #[test]
    fn no_rlimits_applies_only_the_explicit_values() {
        let mut only = config(&[("nofile", "1024")]);
        only.no_rlimits = Some(true);
        let got = limits(&only);
        assert_eq!(names(&got), vec!["nofile"], "no default may remain");
        assert_eq!(pair(&got, "nofile"), (1024, 1024));

        let none = Config {
            no_rlimits: Some(true),
            ..Config::default()
        };
        assert!(limits(&none).is_empty());
    }

    #[test]
    fn lockdown_accepts_values_at_or_below_its_defaults() {
        // Hostile half first: the refusal must not fire on a value that
        // only matches or tightens the lockdown default.
        for (name, value) in
            [("nofile", "4096"), ("nofile", "1024"), ("nproc", "512")]
        {
            let mut c = config(&[(name, value)]);
            c.lockdown = Some(true);
            assert!(effective(&c).is_ok(), "lockdown {name}={value}");
        }
        // A limit lockdown has no default for is not capped by it.
        let mut c = config(&[("cpu", "600")]);
        c.lockdown = Some(true);
        assert!(effective(&c).is_ok());
    }

    #[test]
    fn lockdown_refuses_a_value_above_its_default_naming_both() {
        for (name, value, default) in [
            ("nofile", "8192", "4096"),
            ("nofile", "unlimited", "4096"),
            ("nproc", "2048", "1024"),
            ("fsize", "2G", "1073741824"),
            ("core", "1", "0"),
        ] {
            let mut c = config(&[(name, value)]);
            c.lockdown = Some(true);
            let err = match effective(&c) {
                Ok(_) => panic!("lockdown {name}={value} must be refused"),
                Err(e) => e,
            };
            assert!(err.contains(name), "must name the limit: {err}");
            assert!(
                err.contains(default) || err.contains("1G"),
                "must name the lockdown default {default}: {err}"
            );
        }
    }

    #[test]
    fn cpu_hard_limit_is_five_seconds_above_soft() {
        assert_eq!(pair(&limits(&config(&[("cpu", "60")])), "cpu"), (60, 65));
        assert_eq!(pair(&limits(&config(&[("cpu", "0")])), "cpu"), (0, 5));
        // Saturating, never wrapping to a tiny hard limit.
        let near = (u64::MAX - 2).to_string();
        assert_eq!(
            pair(&limits(&config(&[("cpu", &near)])), "cpu"),
            (u64::MAX - 2, u64::MAX)
        );
        assert_eq!(
            pair(&limits(&config(&[("cpu", "unlimited")])), "cpu"),
            (u64::MAX, u64::MAX)
        );
    }

    #[test]
    fn every_limit_but_cpu_pins_hard_to_soft() {
        let got = limits(&config(&[
            ("nproc", "100"),
            ("nofile", "200"),
            ("core", "0"),
            ("fsize", "1M"),
            ("data", "1G"),
            ("as", "2G"),
        ]));
        for l in &got {
            assert_eq!(
                l.soft,
                l.hard,
                "{} must have soft == hard",
                l.name.as_str()
            );
        }
    }

    #[test]
    fn invalid_entries_are_errors_not_silently_skipped() {
        for (name, value) in [
            ("rss", "1"),
            ("nofile", "12X"),
            ("nofile", "4K"),
            ("data", ""),
        ] {
            assert!(
                effective(&config(&[(name, value)])).is_err(),
                "{name}={value} must be an error"
            );
        }
    }

    /// R3.4: clamping to the current hard limit is never silent. The hard
    /// limit is lowered irreversibly, so the check runs in a child test
    /// process (the pattern of `apply_nproc_pins_hard_equal_to_soft`).
    #[test]
    fn clamping_to_the_hard_limit_warns_with_requested_and_applied() {
        let output = std::process::Command::new(
            std::env::current_exe().unwrap(),
        )
        .arg("--exact")
        .arg("sandbox::rlimits::story047_effective_tests::clamping_child")
        .arg("--ignored")
        .arg("--nocapture")
        .env("AI_JAIL_RLIMIT_CHILD", "1")
        .output()
        .expect("spawn child rlimit test");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child failed\nstdout:\n{}\nstderr:\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        let warning = stderr
            .lines()
            .find(|l| l.contains("65536") && l.contains("2000"))
            .unwrap_or_else(|| {
                panic!("no warning naming requested 65536 and applied 2000: {stderr}")
            });
        assert!(
            warning.to_ascii_lowercase().contains("nofile"),
            "the warning must name the limit: {warning}"
        );
    }

    #[test]
    #[ignore]
    fn clamping_child() {
        if std::env::var_os("AI_JAIL_RLIMIT_CHILD").is_none() {
            return;
        }
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
        assert!(hard >= 2000, "test needs a NOFILE hard limit >= 2000");
        setrlimit(Resource::RLIMIT_NOFILE, 2000, 2000).expect("lower hard");
        // The default NOFILE (65536) is above the new hard limit.
        apply(&Config::default(), false).expect("apply defaults");
        let (soft, hard) =
            getrlimit(Resource::RLIMIT_NOFILE).expect("getrlimit");
        assert_eq!(
            (soft, hard),
            (2000, 2000),
            "applied value is the hard limit"
        );
    }
}
