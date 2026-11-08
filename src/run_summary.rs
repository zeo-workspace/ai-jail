//! `--run-summary`: one versioned JSON document per launch.
//!
//! The document gathers what the other three producers already know —
//! the exit reason, the egress totals and the teardown report — plus the
//! resource usage of the children, and writes it atomically so a reader
//! never sees a torn file. Its shape is `docs/run-summary.schema.json`;
//! `tests::summary_shape_matches_schema` fails when either side moves alone.

use crate::egress_log::EgressTotals;
use crate::exit_reason::{self, ChildStatus, ExitReason, StatusSource};
use crate::teardown::ChildStatusWire;
use serde_json::{Value, json};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::teardown::TeardownSection;

pub const SCHEMA_ID: &str = "ai-jail.run-summary";
pub const SCHEMA_VERSION: u32 = 1;

/// What the peak RSS figure covers: `getrusage` sees only the largest
/// single process it waited for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeakScope {
    LargestProcess,
}

/// Where the figures come from. On Linux every process the command
/// starts is a descendant of the in-sandbox wrapper, not of this
/// supervisor, so only the wrapper's own `getrusage` sees them; this
/// process's would measure bwrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageSource {
    #[cfg(any(test, target_os = "linux"))]
    SandboxWrapper,
    /// macOS: no wrapper; this process's own `getrusage(RUSAGE_CHILDREN)`,
    /// which covers every child it waited for (the command and ai-jail's
    /// own helpers), not what the command left behind.
    #[cfg(any(test, target_os = "macos"))]
    Getrusage,
    Unavailable,
}

/// `None` figures are unknown, never zero: they are written as `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUsage {
    pub cpu_user_ms: Option<u64>,
    pub cpu_system_ms: Option<u64>,
    pub peak_rss_kib: Option<u64>,
    pub scope: PeakScope,
    pub source: UsageSource,
}

/// Counts exist only where a proxy saw every connection: filtered mode.
/// Off and full have no observer, so their counts are `null`, never 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSection {
    Counted {
        mode: &'static str,
        totals: EgressTotals,
    },
    NotCounted {
        mode: &'static str,
    },
}

/// Everything one summary is built from. `program` is the command's
/// basename, empty when there is none (written as `null`).
pub struct RunFacts<'a> {
    pub run_id: &'a str,
    pub started: SystemTime,
    pub ended: SystemTime,
    pub program: &'a str,
    pub exit: &'a ExitReason,
    pub usage: ResourceUsage,
    pub network: NetworkSection,
    pub teardown: TeardownSection,
}

/// The wrapper's report is the command's own status, so it carries
/// `reported` and no 128+N decode is applied to it.
impl From<&ChildStatusWire> for ChildStatus {
    fn from(wire: &ChildStatusWire) -> Self {
        let termination = match *wire {
            ChildStatusWire::Exited(code) => {
                exit_reason::Termination::Exited(code)
            }
            ChildStatusWire::Signaled { signal, core } => {
                exit_reason::Termination::Signaled { signal, core }
            }
        };
        ChildStatus {
            termination,
            source: StatusSource::Reported,
        }
    }
}

/// The basename of the command's first word, empty when there is none:
/// a full path could name the user's home.
pub fn program_name(command: &[String]) -> &str {
    command
        .first()
        .and_then(|c| Path::new(c).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("")
}

/// The version-1 document, as `docs/run-summary.schema.json` describes it.
pub fn build(f: &RunFacts) -> Value {
    // `ended` is `started` plus a monotonic elapsed time in production
    // (see `SummaryGuard::finish`), so this never goes negative; a test's
    // hand-made pair that does yields 0 rather than a panic.
    let duration_ms = f
        .ended
        .duration_since(f.started)
        .map_or(0, |d| d.as_millis() as u64);
    json!({
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "run_id": f.run_id,
        "ai_jail_version": env!("CARGO_PKG_VERSION"),
        "started_at": crate::audit::rfc3339(f.started),
        "ended_at": crate::audit::rfc3339(f.ended),
        "duration_ms": duration_ms,
        "program": (!f.program.is_empty()).then_some(f.program),
        "exit": f.exit.to_json(),
        "resources": resources_json(&f.usage),
        "network": network_json(&f.network),
        "filesystem": {
            // Reserved: nothing counts Landlock denials yet.
            "denied_accesses": Value::Null,
            "denied_accesses_source": "unavailable",
        },
        "teardown": teardown_json(&f.teardown),
    })
}

fn resources_json(u: &ResourceUsage) -> Value {
    json!({
        "cpu_user_ms": u.cpu_user_ms,
        "cpu_system_ms": u.cpu_system_ms,
        "peak_rss_kib": u.peak_rss_kib,
        "peak_rss_scope": match u.scope {
            PeakScope::LargestProcess => "largest-process",
        },
        "source": match u.source {
            #[cfg(any(test, target_os = "linux"))]
            UsageSource::SandboxWrapper => "sandbox-wrapper",
            #[cfg(any(test, target_os = "macos"))]
            UsageSource::Getrusage => "getrusage",
            UsageSource::Unavailable => "unavailable",
        },
    })
}

fn network_json(n: &NetworkSection) -> Value {
    match n {
        NetworkSection::Counted { mode, totals } => json!({
            "mode": mode,
            "connections_allowed": totals.allowed,
            "connections_denied": totals.denied,
            "connections_errored": totals.errored,
            "bytes_up": totals.bytes_up,
            "bytes_down": totals.bytes_down,
        }),
        NetworkSection::NotCounted { mode } => json!({
            "mode": mode,
            "connections_allowed": Value::Null,
            "connections_denied": Value::Null,
            "connections_errored": Value::Null,
            "bytes_up": Value::Null,
            "bytes_down": Value::Null,
        }),
    }
}

fn teardown_json(t: &TeardownSection) -> Value {
    let idle = |supported: bool| {
        json!({
            "supported": supported,
            "active": false,
            "complete": Value::Null,
            "incomplete_reason": Value::Null,
            "grace_ms": Value::Null,
            "survivors": [],
        })
    };
    match t {
        #[cfg(any(test, not(target_os = "linux")))]
        TeardownSection::Unsupported => idle(false),
        TeardownSection::Inactive => idle(cfg!(target_os = "linux")),
        TeardownSection::Reported(r) => json!({
            "supported": true,
            "active": true,
            "complete": r.complete,
            "incomplete_reason": r.incomplete_reason,
            "grace_ms": r.grace_ms,
            // Survivor serialises to exactly the schema's item shape.
            "survivors": serde_json::to_value(&r.survivors)
                .unwrap_or_else(|_| json!([])),
        }),
        TeardownSection::Missing { reason } => json!({
            "supported": true,
            "active": true,
            "complete": false,
            "incomplete_reason": reason,
            "grace_ms": crate::teardown::GRACE.as_millis() as u64,
            "survivors": [],
        }),
    }
}

#[cfg(any(test, target_os = "linux"))]
/// The figures the in-sandbox wrapper measured after its last reap (the
/// command and every survivor it stopped), or `unavailable` when there
/// is no report or the report has no figures.
pub fn usage_from_report(
    usage: Option<&crate::teardown::WireUsage>,
) -> ResourceUsage {
    match usage {
        Some(u) => ResourceUsage {
            cpu_user_ms: Some(u.cpu_user_ms),
            cpu_system_ms: Some(u.cpu_system_ms),
            peak_rss_kib: Some(u.peak_rss_kib),
            scope: PeakScope::LargestProcess,
            source: UsageSource::SandboxWrapper,
        },
        None => unavailable_usage(),
    }
}

pub fn unavailable_usage() -> ResourceUsage {
    ResourceUsage {
        cpu_user_ms: None,
        cpu_system_ms: None,
        peak_rss_kib: None,
        scope: PeakScope::LargestProcess,
        source: UsageSource::Unavailable,
    }
}

/// macOS: `getrusage(RUSAGE_CHILDREN)` of this process: every child it
/// waited for (the command and ai-jail's own helpers), not what the
/// command left behind. On error the figures are unknown.
#[cfg(target_os = "macos")]
pub fn resource_usage() -> ResourceUsage {
    use nix::sys::resource::{UsageWho, getrusage};
    let Ok(usage) = getrusage(UsageWho::RUSAGE_CHILDREN) else {
        return unavailable_usage();
    };
    let ms = |tv: nix::sys::time::TimeVal| {
        // tv_usec is i32 on Apple targets.
        let ms =
            tv.tv_sec().saturating_mul(1000) + i64::from(tv.tv_usec()) / 1000;
        u64::try_from(ms).unwrap_or(0)
    };
    // ru_maxrss is bytes on macOS.
    let max_rss = u64::try_from(usage.max_rss()).unwrap_or(0) / 1024;
    ResourceUsage {
        cpu_user_ms: Some(ms(usage.user_time())),
        cpu_system_ms: Some(ms(usage.system_time())),
        peak_rss_kib: Some(max_rss),
        scope: PeakScope::LargestProcess,
        source: UsageSource::Getrusage,
    }
}

/// The summary's destination, checked once at startup. The parent
/// directory is opened here and every later step goes through that handle
/// (`openat`/`renameat`): when the target sits in the writable project,
/// the sandboxed command cannot swap the directory for a symlink between
/// startup and the write and steer the supervisor's file elsewhere.
#[derive(Debug)]
pub struct RunSummaryTarget {
    path: PathBuf,
    dir: File,
    name: CString,
}

impl RunSummaryTarget {
    /// Absolutise against the invocation cwd (the command may `cd`, ai-jail
    /// does not), refuse a symlink at the path, and require the parent
    /// directory to exist. Each error names the path it is about.
    pub fn prepare(path: &Path, cwd: &Path) -> Result<Self, String> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
        let shown = path.display();
        let name = path
            .file_name()
            .ok_or_else(|| format!("--run-summary {shown}: names no file"))
            .and_then(|n| {
                CString::new(n.as_bytes()).map_err(|_| {
                    format!("--run-summary {shown}: contains a NUL byte")
                })
            })?;
        // The temporary sibling is the name plus a suffix, and both must
        // fit in one directory entry: refuse now rather than fail the write
        // at the end of the run.
        if name.as_bytes().len() > NAME_MAX - TEMP_NAME_OVERHEAD {
            return Err(format!(
                "--run-summary {shown}: the file name is too long (at most \
                 {} bytes, to leave room for the temporary file)",
                NAME_MAX - TEMP_NAME_OVERHEAD
            ));
        }
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!(
                    "--run-summary {shown}: is a symlink; refusing to follow it"
                ));
            }
            Ok(m) if m.is_dir() => {
                return Err(format!("--run-summary {shown}: is a directory"));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("--run-summary {shown}: {e}")),
        }
        let parent = path.parent().unwrap_or(Path::new("/"));
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
            .open(parent)
            .map_err(|e| {
                format!(
                    "--run-summary {shown}: directory {} is not usable: {e}",
                    parent.display()
                )
            })?;
        Ok(RunSummaryTarget { path, dir, name })
    }
}

/// What the end of a run hands to [`SummaryGuard::finish`].
pub struct RunEnd {
    pub exit: ExitReason,
    pub usage: ResourceUsage,
    pub network: NetworkSection,
    pub teardown: TeardownSection,
}

/// Holds what is known at the start of a launch, so the one `finish`
/// call at the end of `run()` can write the summary on every exit path.
pub struct SummaryGuard {
    target: RunSummaryTarget,
    run_id: String,
    program: String,
    started: SystemTime,
    clock: std::time::Instant,
}

impl SummaryGuard {
    pub fn start(
        target: RunSummaryTarget,
        run_id: &str,
        program: &str,
    ) -> Self {
        SummaryGuard {
            target,
            run_id: run_id.to_string(),
            program: program.to_string(),
            started: SystemTime::now(),
            clock: std::time::Instant::now(),
        }
    }

    /// Build and write the summary. A write failure is an error message
    /// naming the path; the run's exit code is the caller's and is never
    /// changed by it.
    pub fn finish(self, end: RunEnd) {
        // `ended` is derived from the monotonic clock, so a wall-clock step
        // during the run never yields a negative duration.
        let ended = self.started + self.clock.elapsed();
        let doc = build(&RunFacts {
            run_id: &self.run_id,
            started: self.started,
            ended,
            program: &self.program,
            exit: &end.exit,
            usage: end.usage,
            network: end.network,
            teardown: end.teardown,
        });
        if let Err(e) = write_atomic(&self.target, &doc) {
            crate::output::error(&format!("run summary not written: {e}"));
        }
    }
}

/// The longest directory entry Linux and macOS accept.
const NAME_MAX: usize = 255;

/// What `create_temp` adds around the target's name: `.`, `.`, a pid of
/// at most 10 digits, `.`, 8 hex digits of nanoseconds, a counter of at
/// most 16 hex digits and `.tmp`.
const TEMP_NAME_OVERHEAD: usize = 1 + 1 + 10 + 1 + 8 + 16 + 4;

/// Distinguishes temporary names within one process; `O_EXCL` is what
/// guarantees no two writers share a file.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `doc` to a fresh 0600 temporary file beside the target, `fsync`
/// it, rename it over the target and `fsync` the directory. A symlink
/// planted at the target after `prepare` is replaced, never followed,
/// because `renameat` acts on the name. On any error before the rename the
/// temporary file is unlinked and the error names the path. The directory
/// `fsync` after a successful rename is best effort, as in `fsutil`: the
/// complete document is already in place.
pub fn write_atomic(target: &RunSummaryTarget, doc: &Value) -> io::Result<()> {
    let with_path = |e: io::Error| {
        io::Error::new(e.kind(), format!("{}: {e}", target.path.display()))
    };
    let mut bytes = serde_json::to_vec_pretty(doc)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');

    let dir_fd = target.dir.as_raw_fd();
    let (tmp, mut file) =
        create_temp(dir_fd, &target.name).map_err(with_path)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(feature = "test-hooks")]
        test_delay();
        // SAFETY: both names are valid NUL-terminated strings and `dir_fd`
        // is an open directory owned by `target` for the whole call.
        let rc = unsafe {
            nix::libc::renameat(
                dir_fd,
                tmp.as_ptr(),
                dir_fd,
                target.name.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    if let Err(e) = result {
        // SAFETY: as above. Ignored: the temporary may already be gone.
        let _ = unsafe { nix::libc::unlinkat(dir_fd, tmp.as_ptr(), 0) };
        return Err(with_path(e));
    }
    // Ignored on purpose (see the doc comment).
    let _ = target.dir.sync_all();
    Ok(())
}

fn create_temp(dir_fd: RawFd, name: &CStr) -> io::Result<(CString, File)> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mut last = None;
    for _ in 0..8 {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        // Built from the name's bytes: a lossy decode would grow each
        // invalid UTF-8 byte to three and break the NAME_MAX bound.
        let mut bytes = b".".to_vec();
        bytes.extend_from_slice(name.to_bytes());
        bytes.extend_from_slice(
            format!(".{}.{nanos:08x}{n:x}.tmp", std::process::id()).as_bytes(),
        );
        let tmp = CString::new(bytes)
            .map_err(|_| io::Error::other("temporary name holds a NUL byte"))?;
        let flags = nix::libc::O_WRONLY
            | nix::libc::O_CREAT
            | nix::libc::O_EXCL
            | nix::libc::O_NOFOLLOW
            | nix::libc::O_CLOEXEC;
        // SAFETY: `tmp` is NUL-terminated and `dir_fd` is an open
        // directory; a non-negative return is a new descriptor we own.
        let fd = unsafe {
            nix::libc::openat(
                dir_fd,
                tmp.as_ptr(),
                flags,
                0o600 as nix::libc::c_uint,
            )
        };
        if fd >= 0 {
            // SAFETY: `fd` was just returned by openat and is owned here.
            return Ok((tmp, File::from(unsafe { OwnedFd::from_raw_fd(fd) })));
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
        last = Some(e);
    }
    Err(last.unwrap_or_else(|| io::Error::other("no temporary name")))
}

/// Lets the atomicity test watch the target while a write is in
/// flight. Compiled only under the `test-hooks` feature.
#[cfg(feature = "test-hooks")]
fn test_delay() {
    if let Some(ms) = std::env::var("AI_JAIL_TEST_SUMMARY_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[cfg(test)]
mod tests {
    // The schema walker below implements only
    // properties/type/enum/required/items, the subset the schema file is kept
    // to.

    use super::*;
    use crate::egress_log::EgressTotals;
    use crate::exit_reason::{
        ChildStatus, LimitsInForce, StatusSource, Termination, classify,
    };
    use crate::teardown::{ChildStatusWire, EndedBy, Survivor, TeardownReport};
    use serde_json::Value;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// A host that folds signals into `128 + N` and has a kernel log,
    /// spelled out so the cases hold on a macOS test run too.
    const LINUX_HOST: crate::exit_reason::HostTraits =
        crate::exit_reason::HostTraits {
            folds_signals: true,
            kernel_log_hint: true,
        };

    const SCHEMA_PATH: &str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/docs/run-summary.schema.json");

    fn schema() -> Value {
        let text = std::fs::read_to_string(SCHEMA_PATH)
            .expect("docs/run-summary.schema.json ships with the crate");
        serde_json::from_str(&text).expect("schema is JSON")
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-summary-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn json_type(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_u64() || n.is_i64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    /// Validate `doc` against `schema`, collecting every mismatch. Object
    /// key sets must match `properties` EXACTLY, so a field that moves on
    /// one side only is a failure.
    fn validate(
        doc: &Value,
        schema: &Value,
        at: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(types) = schema.get("type") {
            let allowed: Vec<&str> = match types {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let t = json_type(doc);
            let ok = allowed.contains(&t)
                || (t == "integer" && allowed.contains(&"number"));
            if !ok {
                errors.push(format!("{at}: type {t} not in {allowed:?}"));
                return;
            }
        }
        if let Some(Value::Array(options)) = schema.get("enum")
            && !options.contains(doc)
        {
            errors.push(format!("{at}: {doc} not in enum {options:?}"));
        }
        if let (Value::Object(obj), Some(Value::Object(props))) =
            (doc, schema.get("properties"))
        {
            for key in obj.keys() {
                if !props.contains_key(key) {
                    errors.push(format!("{at}.{key}: not in the schema"));
                }
            }
            for (key, sub) in props {
                match obj.get(key) {
                    Some(v) => validate(v, sub, &format!("{at}.{key}"), errors),
                    None => errors.push(format!("{at}.{key}: missing")),
                }
            }
            if let Some(Value::Array(req)) = schema.get("required") {
                for k in req.iter().filter_map(Value::as_str) {
                    if !obj.contains_key(k) {
                        errors.push(format!("{at}.{k}: required"));
                    }
                }
            }
        }
        if let (Value::Array(items), Some(sub)) = (doc, schema.get("items")) {
            for (i, item) in items.iter().enumerate() {
                validate(item, sub, &format!("{at}[{i}]"), errors);
            }
        }
    }

    fn errors_of(doc: &Value) -> Vec<String> {
        let mut errors = Vec::new();
        validate(doc, &schema(), "$", &mut errors);
        errors
    }

    fn exit_clean() -> crate::exit_reason::ExitReason {
        classify(
            &ChildStatus {
                termination: Termination::Exited(0),
                source: StatusSource::Reported,
            },
            &LimitsInForce { file_size: None },
        )
    }

    fn exit_killed() -> crate::exit_reason::ExitReason {
        classify(
            &crate::exit_reason::from_exit_code(137, LINUX_HOST),
            &LimitsInForce { file_size: None },
        )
    }

    fn usage() -> ResourceUsage {
        ResourceUsage {
            cpu_user_ms: Some(12),
            cpu_system_ms: Some(3),
            peak_rss_kib: Some(2048),
            scope: PeakScope::LargestProcess,
            source: UsageSource::Getrusage,
        }
    }

    fn report() -> TeardownReport {
        TeardownReport {
            v: 1,
            child: ChildStatusWire::Exited(0),
            survivors: vec![
                Survivor {
                    pid: 7,
                    ppid: 1,
                    comm: "sleep".into(),
                    age_s: 0,
                    ended_by: EndedBy::Sigterm,
                },
                Survivor {
                    pid: 9,
                    ppid: 7,
                    comm: "stuck".into(),
                    age_s: 2,
                    ended_by: EndedBy::Sigkill,
                },
            ],
            grace_ms: 2000,
            usage: None,
            complete: true,
            incomplete_reason: None,
        }
    }

    const RUN_ID: &str = "0123456789abcdef0123456789abcdef";

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn facts<'a>(
        exit: &'a crate::exit_reason::ExitReason,
        network: NetworkSection,
        teardown: TeardownSection,
    ) -> RunFacts<'a> {
        RunFacts {
            run_id: RUN_ID,
            started: t0(),
            ended: t0() + Duration::from_millis(1500),
            program: "claude-agent-acp-plus",
            exit,
            usage: usage(),
            network,
            teardown,
        }
    }

    fn filtered() -> NetworkSection {
        NetworkSection::Counted {
            mode: "filtered",
            totals: EgressTotals {
                allowed: 3,
                denied: 2,
                errored: 1,
                bytes_up: 100,
                bytes_down: 5000,
            },
        }
    }

    // ── build ──────────────────────────────────────────

    #[test]
    fn build_carries_identity_times_and_exit() {
        let exit = exit_clean();
        let doc = build(&facts(&exit, filtered(), TeardownSection::Inactive));
        assert_eq!(doc["schema"], SCHEMA_ID);
        assert_eq!(SCHEMA_ID, "ai-jail.run-summary");
        assert_eq!(doc["schema_version"], 1);
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(doc["run_id"], RUN_ID);
        assert_eq!(doc["ai_jail_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(doc["started_at"], "2023-11-14T22:13:20Z");
        assert_eq!(doc["ended_at"], "2023-11-14T22:13:21Z");
        assert_eq!(doc["duration_ms"], 1500);
        assert_eq!(doc["program"], "claude-agent-acp-plus");
        assert_eq!(doc["exit"], exit.to_json());
        assert_eq!(doc["resources"]["cpu_user_ms"], 12);
        assert_eq!(doc["resources"]["cpu_system_ms"], 3);
        assert_eq!(doc["resources"]["peak_rss_kib"], 2048);
        assert_eq!(doc["resources"]["peak_rss_scope"], "largest-process");
        assert_eq!(doc["resources"]["source"], "getrusage");
    }

    #[test]
    fn network_counts_are_null_outside_filtered_and_zero_is_not_null() {
        let exit = exit_clean();
        // Off/full must be null, never 0.
        for mode in ["off", "full"] {
            let doc = build(&facts(
                &exit,
                NetworkSection::NotCounted { mode },
                TeardownSection::Inactive,
            ));
            let net = &doc["network"];
            assert_eq!(net["mode"], mode);
            for k in [
                "connections_allowed",
                "connections_denied",
                "connections_errored",
                "bytes_up",
                "bytes_down",
            ] {
                assert!(net[k].is_null(), "{mode}: {k} must be null: {net}");
            }
        }
        // Filtered with no traffic is 0, never null.
        let zero = NetworkSection::Counted {
            mode: "filtered",
            totals: EgressTotals {
                allowed: 0,
                denied: 0,
                errored: 0,
                bytes_up: 0,
                bytes_down: 0,
            },
        };
        let doc = build(&facts(&exit, zero, TeardownSection::Inactive));
        assert_eq!(doc["network"]["connections_denied"], 0);
        let doc = build(&facts(&exit, filtered(), TeardownSection::Inactive));
        let net = &doc["network"];
        assert_eq!(net["mode"], "filtered");
        assert_eq!(net["connections_allowed"], 3);
        assert_eq!(net["connections_denied"], 2);
        assert_eq!(net["connections_errored"], 1);
        assert_eq!(net["bytes_up"], 100);
        assert_eq!(net["bytes_down"], 5000);
    }

    #[test]
    fn denied_file_accesses_are_reserved_null() {
        let exit = exit_clean();
        let doc = build(&facts(&exit, filtered(), TeardownSection::Inactive));
        assert!(doc["filesystem"]["denied_accesses"].is_null());
        assert_eq!(doc["filesystem"]["denied_accesses_source"], "unavailable");
    }

    #[test]
    fn teardown_section_variants() {
        let exit = exit_clean();
        let inactive =
            build(&facts(&exit, filtered(), TeardownSection::Inactive));
        let t = &inactive["teardown"];
        assert_eq!(t["active"], false);
        assert_eq!(t["survivors"], serde_json::json!([]));
        assert!(t["complete"].is_null());

        let unsupported =
            build(&facts(&exit, filtered(), TeardownSection::Unsupported));
        assert_eq!(unsupported["teardown"]["supported"], false);

        let reported = build(&facts(
            &exit,
            filtered(),
            TeardownSection::Reported(report()),
        ));
        let t = &reported["teardown"];
        assert_eq!(t["supported"], true);
        assert_eq!(t["active"], true);
        assert_eq!(t["complete"], true);
        assert_eq!(t["grace_ms"], 2000);
        assert_eq!(t["survivors"][0]["comm"], "sleep");
        assert_eq!(t["survivors"][0]["ended_by"], "sigterm");
        assert_eq!(t["survivors"][1]["ended_by"], "sigkill");
        assert_eq!(t["survivors"][1]["age_s"], 2);
        assert_eq!(t["survivors"][1]["ppid"], 7);

        let missing = build(&facts(
            &exit_killed(),
            filtered(),
            TeardownSection::Missing {
                reason: "report missing: EOF".into(),
            },
        ));
        let t = &missing["teardown"];
        assert_eq!(t["complete"], false);
        assert_eq!(t["incomplete_reason"], "report missing: EOF");
        assert_eq!(missing["exit"]["status_source"], "inferred");
    }

    // ── schema contract ────────────────────────

    #[test]
    fn summary_shape_matches_schema() {
        let s = schema();
        assert!(
            s["$id"].as_str().is_some_and(|id| id
                .ends_with(&format!("run-summary/v{SCHEMA_VERSION}.json"))),
            "$id names the version: {}",
            s["$id"]
        );
        assert_eq!(
            s["properties"]["schema_version"]["enum"],
            serde_json::json!([SCHEMA_VERSION]),
            "the schema document and SCHEMA_VERSION move together"
        );
        assert_eq!(
            s["properties"]["schema"]["enum"],
            serde_json::json!([SCHEMA_ID])
        );

        let clean = exit_clean();
        let killed = exit_killed();
        let failed =
            crate::exit_reason::start_failed("Failed to start sandbox");
        let variants = [
            facts(&clean, filtered(), TeardownSection::Reported(report())),
            facts(
                &clean,
                NetworkSection::NotCounted { mode: "off" },
                TeardownSection::Inactive,
            ),
            facts(
                &killed,
                NetworkSection::NotCounted { mode: "full" },
                TeardownSection::Unsupported,
            ),
            facts(
                &killed,
                filtered(),
                TeardownSection::Missing {
                    reason: "malformed".into(),
                },
            ),
            facts(
                &failed,
                NetworkSection::NotCounted { mode: "off" },
                TeardownSection::Inactive,
            ),
        ];
        for f in &variants {
            let doc = build(f);
            let errors = errors_of(&doc);
            assert!(errors.is_empty(), "{errors:#?}\n{doc:#}");
        }
    }

    #[test]
    fn the_schema_walker_catches_a_field_moving_on_one_side() {
        // The failure case for the contract test: a walker that accepts
        // anything would keep summary_shape_matches_schema green forever.
        let exit = exit_clean();
        let good = build(&facts(
            &exit,
            filtered(),
            TeardownSection::Reported(report()),
        ));
        assert!(errors_of(&good).is_empty());

        let mut removed = good.clone();
        removed["exit"]
            .as_object_mut()
            .unwrap()
            .remove("status_source");
        assert!(!errors_of(&removed).is_empty(), "a removed field passed");

        let mut added = good.clone();
        added["resources"]["peak_rss_bytes"] = serde_json::json!(1);
        assert!(!errors_of(&added).is_empty(), "an added field passed");

        let mut retyped = good.clone();
        retyped["duration_ms"] = serde_json::json!("1500");
        assert!(!errors_of(&retyped).is_empty(), "a retyped field passed");

        let mut out_of_enum = good;
        out_of_enum["exit"]["reason"] = serde_json::json!("crashed");
        assert!(
            !errors_of(&out_of_enum).is_empty(),
            "a new enum value passed"
        );
    }

    // ── resource_usage ─────────────────────────────────────────────

    // macOS only: Linux takes the figures from the wrapper's report.
    #[cfg(target_os = "macos")]
    #[test]
    fn resource_usage_reports_largest_process_in_kib() {
        std::process::Command::new("true").status().unwrap();
        let u = resource_usage();
        assert!(matches!(u.scope, PeakScope::LargestProcess));
        assert!(matches!(u.source, UsageSource::Getrusage));
        // ru_maxrss is bytes on macOS and resource_usage converts it: a
        // waited child is well above 100 KiB and far below 10 GiB. Bytes
        // (x1024) or MiB (/1024) both fall outside.
        assert!(
            (100..10_000_000).contains(&u.peak_rss_kib.unwrap_or(0)),
            "peak_rss_kib {:?} is not a KiB figure",
            u.peak_rss_kib
        );
    }

    // ── target preparation ──────────────────────────────────

    #[test]
    fn prepare_refuses_a_symlink_and_a_missing_directory() {
        let dir = temp_dir("prepare");
        let victim = dir.join("victim.json");
        std::fs::write(&victim, b"untouched").unwrap();
        let link = dir.join("summary.json");
        symlink(&victim, &link).unwrap();
        let err = match RunSummaryTarget::prepare(&link, &dir) {
            Ok(_) => panic!("a symlinked summary path was accepted"),
            Err(e) => e,
        };
        assert!(err.contains("summary.json"), "names the path: {err}");

        let err = match RunSummaryTarget::prepare(
            Path::new("nope/summary.json"),
            &dir,
        ) {
            Ok(_) => panic!("a missing directory was accepted"),
            Err(e) => e,
        };
        assert!(err.contains("nope"), "names the directory: {err}");

        // A target that does not exist yet, in an existing
        // directory, is the normal case and must be accepted.
        assert!(RunSummaryTarget::prepare(Path::new("new.json"), &dir).is_ok());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_target_is_resolved_against_the_invocation_cwd() {
        let dir = temp_dir("relative");
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let target =
            RunSummaryTarget::prepare(Path::new("out/s.json"), &dir).unwrap();
        write_atomic(&target, &serde_json::json!({"k": 1})).unwrap();
        let back: Value = serde_json::from_slice(
            &std::fs::read(dir.join("out/s.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(back["k"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── atomic write ────────────────────────────

    #[test]
    fn write_is_atomic() {
        let dir = temp_dir("atomic");
        let path = dir.join("summary.json");
        let old = serde_json::json!({"generation": "old"});
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        let target = RunSummaryTarget::prepare(&path, &dir).unwrap();
        let big = serde_json::json!({
            "generation": "new",
            "pad": "p".repeat(4 << 20),
        });

        let _env_lock = crate::test_utils::ENV_LOCK.lock().unwrap();
        let _delay = crate::test_utils::EnvVarGuard::set(
            "AI_JAIL_TEST_SUMMARY_DELAY_MS",
            "300",
        );
        let writer = {
            let big = big.clone();
            std::thread::spawn(move || write_atomic(&target, &big))
        };
        let mut saw_tmp = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !writer.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "write never finished"
            );
            // The target is always a whole document: old or new, never torn.
            let bytes = std::fs::read(&path).expect("target never disappears");
            let doc: Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                    panic!("partial file visible at target: {e}")
                });
            assert!(doc["generation"] == "old" || doc["generation"] == "new");
            for entry in std::fs::read_dir(&dir).unwrap().map_while(Result::ok)
            {
                if entry.path() != path {
                    saw_tmp = true;
                    let mode = entry.metadata().unwrap().permissions().mode();
                    assert_eq!(mode & 0o777, 0o600, "temporary file mode");
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        writer.join().unwrap().unwrap();
        if cfg!(feature = "test-hooks") {
            assert!(
                saw_tmp,
                "the temporary file lives in the target's directory"
            );
        }
        let doc: Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(doc, big);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(left.len(), 1, "no temporary file left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_planted_after_prepare_is_replaced_not_followed() {
        let dir = temp_dir("planted");
        let path = dir.join("summary.json");
        let target = RunSummaryTarget::prepare(&path, &dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &path).unwrap();
        write_atomic(&target, &serde_json::json!({"k": 1})).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_file()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file() {
        let dir = temp_dir("failed");
        let path = dir.join("summary.json");
        let target = RunSummaryTarget::prepare(&path, &dir).unwrap();
        // A non-empty directory planted at the target makes the rename fail
        // after the temporary file exists.
        std::fs::create_dir_all(path.join("occupied")).unwrap();
        let err = write_atomic(&target, &serde_json::json!({"k": 1}));
        assert!(err.is_err(), "rename over a directory must fail");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map_while(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["summary.json".to_string()], "tmp unlinked");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── wire status -> exit_reason ──────────────────────────

    #[test]
    fn wire_child_status_becomes_reported() {
        let no_limits = LimitsInForce { file_size: None };
        // A reported exit(137) is a normal exit, not a
        // SIGKILL; the 128+N decode must not be applied to it.
        let status = ChildStatus::from(&ChildStatusWire::Exited(137));
        assert!(matches!(status.termination, Termination::Exited(137)));
        assert!(matches!(status.source, StatusSource::Reported));
        let reason = classify(&status, &no_limits);
        assert!(
            reason.explanation(LINUX_HOST).is_none(),
            "a reported exit 137 prints nothing: {:?}",
            reason.explanation(LINUX_HOST)
        );
        assert_eq!(reason.to_json()["reason"], "exited");
        assert!(reason.to_json()["signal"].is_null());
        assert_eq!(reason.code, 137);

        let status = ChildStatus::from(&ChildStatusWire::Signaled {
            signal: 11,
            core: true,
        });
        assert!(matches!(
            status.termination,
            Termination::Signaled {
                signal: 11,
                core: true
            }
        ));
        assert!(matches!(status.source, StatusSource::Reported));
        let reason = classify(&status, &no_limits);
        let json = reason.to_json();
        assert_eq!(json["status_source"], "reported");
        assert_eq!(json["signal"], "SIGSEGV");
        assert_eq!(json["core_dumped"], true);
        // A signal the wrapper reported is a fact, never qualified as
        // inferred.
        let line = reason.explanation(LINUX_HOST).expect("SIGSEGV explained");
        assert!(!line.contains("inferred"), "{line}");
    }

    #[test]
    fn summary_marks_a_plain_exit_code_exit_code() {
        let no_limits = LimitsInForce { file_size: None };
        let summary_of = |status: &ChildStatus| -> Value {
            let exit = classify(status, &no_limits);
            build(&facts(
                &exit,
                NetworkSection::NotCounted { mode: "off" },
                TeardownSection::Inactive,
            ))
        };
        const NO_FOLDING: crate::exit_reason::HostTraits =
            crate::exit_reason::HostTraits {
                folds_signals: false,
                kernel_log_hint: false,
            };

        // Where it would collapse wrongly: the same exit code, once from the
        // wrapper's report and once taken as it is, must not read alike.
        for code in [0, 137] {
            let wire =
                summary_of(&ChildStatus::from(&ChildStatusWire::Exited(code)));
            let plain = summary_of(&crate::exit_reason::from_exit_code(
                code, NO_FOLDING,
            ));
            assert_eq!(
                wire["exit"]["status_source"], "reported",
                "the wrapper's exit {code} is its report"
            );
            assert_ne!(
                wire["exit"]["status_source"], plain["exit"]["status_source"],
                "exit {code}: a report and a plain code are told apart"
            );
        }

        // Where it would split wrongly: every code taken as it is reads the
        // one value, on a folding host outside the window and on a host
        // that does not fold anywhere.
        let mut plain = Vec::new();
        for code in [0, 1, 128, 193] {
            plain.push((
                code,
                summary_of(&crate::exit_reason::from_exit_code(
                    code, LINUX_HOST,
                )),
            ));
        }
        for code in [0, 129, 137, 192, 255] {
            plain.push((
                code,
                summary_of(&crate::exit_reason::from_exit_code(
                    code, NO_FOLDING,
                )),
            ));
        }
        for (code, doc) in &plain {
            assert_eq!(
                doc["exit"]["status_source"], "exit-code",
                "exit {code} taken as it is"
            );
            assert_eq!(doc["exit"]["code"], *code, "code unchanged");
            let errors = errors_of(doc);
            assert!(
                errors.is_empty(),
                "the schema lists `exit-code`: {errors:#?}"
            );
        }

        // A third value must not land on `exit-code` either: each way of
        // learning a status keeps its own string, five in all.
        let direct = ChildStatus {
            termination: Termination::Signaled {
                signal: 9,
                core: false,
            },
            source: StatusSource::Direct,
        };
        let sources: Vec<Value> = [
            summary_of(&ChildStatus::from(&ChildStatusWire::Exited(1))),
            summary_of(&crate::exit_reason::from_exit_code(137, LINUX_HOST)),
            summary_of(&direct),
            summary_of(&crate::exit_reason::from_exit_code(1, LINUX_HOST)),
            build(&facts(
                &crate::exit_reason::start_failed("Failed to start sandbox"),
                NetworkSection::NotCounted { mode: "off" },
                TeardownSection::Inactive,
            )),
        ]
        .iter()
        .map(|doc| doc["exit"]["status_source"].clone())
        .collect();
        assert_eq!(
            sources,
            ["reported", "inferred", "direct", "exit-code", "none"],
            "one string per way a status is learned"
        );
    }

    // ── resources of the command ──────────

    fn assert_resources(doc: &Value, figures: [Option<u64>; 3], source: &str) {
        let r = &doc["resources"];
        for (key, want) in ["cpu_user_ms", "cpu_system_ms", "peak_rss_kib"]
            .iter()
            .zip(figures)
        {
            match want {
                Some(n) => assert_eq!(r[*key], n, "{key}: {r}"),
                None => assert!(r[*key].is_null(), "{key} must be null: {r}"),
            }
        }
        assert_eq!(r["source"], source, "{r}");
        let errors = errors_of(doc);
        assert!(errors.is_empty(), "{errors:#?}\n{doc:#}");
    }

    #[test]
    fn resources_come_from_the_wrapper_report() {
        let exit = exit_clean();
        let mut f =
            facts(&exit, filtered(), TeardownSection::Reported(report()));

        // Zero figures are measurements (a command that
        // ended at once), never collapsed into "unavailable".
        let zero = usage_from_report(Some(&crate::teardown::WireUsage {
            cpu_user_ms: 0,
            cpu_system_ms: 0,
            peak_rss_kib: 0,
        }));
        assert_eq!(zero.peak_rss_kib, Some(0));
        assert!(matches!(zero.source, UsageSource::SandboxWrapper));
        f.usage = zero;
        assert_resources(
            &build(&f),
            [Some(0), Some(0), Some(0)],
            "sandbox-wrapper",
        );

        let wire = crate::teardown::WireUsage {
            cpu_user_ms: 412,
            cpu_system_ms: 96,
            peak_rss_kib: 183_204,
        };
        let u = usage_from_report(Some(&wire));
        assert_eq!(
            (u.cpu_user_ms, u.cpu_system_ms, u.peak_rss_kib),
            (Some(412), Some(96), Some(183_204)),
            "the wrapper's figures, unchanged and in the same units"
        );
        assert!(matches!(u.scope, PeakScope::LargestProcess));
        assert!(matches!(u.source, UsageSource::SandboxWrapper));
        f.usage = u;
        let doc = build(&f);
        assert_resources(
            &doc,
            [Some(412), Some(96), Some(183_204)],
            "sandbox-wrapper",
        );
        assert_eq!(doc["resources"]["peak_rss_scope"], "largest-process");
    }

    #[test]
    fn resources_null_without_a_report() {
        // No report at all.
        let missing = usage_from_report(None);
        assert_eq!(
            (
                missing.cpu_user_ms,
                missing.cpu_system_ms,
                missing.peak_rss_kib
            ),
            (None, None, None)
        );
        assert!(matches!(missing.source, UsageSource::Unavailable));

        // A report that carries no usage figures (the wrapper's getrusage
        // failed) gives the same answer by another route.
        let mut without = report();
        without.usage = None;
        let unfigured = usage_from_report(without.usage.as_ref());
        assert_eq!(
            (
                unfigured.cpu_user_ms,
                unfigured.cpu_system_ms,
                unfigured.peak_rss_kib
            ),
            (None, None, None)
        );
        assert!(matches!(unfigured.source, UsageSource::Unavailable));

        // Both are written as null with source `unavailable`: never 0, and
        // never the launcher's own figures.
        let exit = exit_killed();
        let cases = [
            (
                TeardownSection::Missing {
                    reason: "missing: no report before EOF".into(),
                },
                missing,
            ),
            (TeardownSection::Reported(without), unfigured),
        ];
        for (teardown, usage) in cases {
            let mut f = facts(&exit, filtered(), teardown);
            f.usage = usage;
            assert_resources(&build(&f), [None, None, None], "unavailable");
        }
    }

    #[test]
    fn start_failed_status_source_is_none() {
        let failed =
            crate::exit_reason::start_failed("Failed to start sandbox");
        let json = failed.to_json();
        assert_eq!(json["reason"], "start-failed");
        assert_eq!(
            json["status_source"], "none",
            "nothing observed the command's end: it never ran"
        );
        // An end that was observed keeps its own source.
        assert_eq!(exit_clean().to_json()["status_source"], "reported");
        assert_eq!(exit_killed().to_json()["status_source"], "inferred");

        let doc = build(&facts(
            &failed,
            NetworkSection::NotCounted { mode: "off" },
            TeardownSection::Inactive,
        ));
        assert_eq!(doc["exit"]["status_source"], "none");
        let errors = errors_of(&doc);
        assert!(errors.is_empty(), "the schema lists `none`: {errors:#?}");
    }

    #[test]
    fn prepare_refuses_a_basename_too_long_for_the_temporary_name() {
        let dir = temp_dir("name-max");
        // A `len`-byte basename ending in `.json`, relative to `dir`.
        let named = |len: usize| {
            let name = format!("{}.json", "s".repeat(len - 5));
            (RunSummaryTarget::prepare(Path::new(&name), &dir), name)
        };

        // 255 bytes is a name the kernel takes for the
        // target, but its temporary sibling (the name plus a suffix) cannot
        // exist, so the write would fail only at the end of the run.
        let (refused, name) = named(255);
        let err = match refused {
            Ok(_) => panic!("a {}-byte basename was accepted", name.len()),
            Err(e) => e,
        };
        assert!(err.contains(&name), "names the path: {err}");
        assert!(err.contains("long"), "names the cause: {err}");

        // The accepted lengths are one range, from short names up to a bound
        // below NAME_MAX that leaves room for ordinary names.
        let accepted: Vec<usize> =
            (6..=255).filter(|&n| named(n).0.is_ok()).collect();
        let longest = *accepted.last().expect("short names are accepted");
        assert_eq!(accepted, (6..=longest).collect::<Vec<_>>(), "no gaps");
        assert!(longest < 255, "{longest}");
        assert!(longest >= 128, "the bound is not over-cautious: {longest}");

        // The opposite (no false acceptance at the bound): the longest accepted
        // name really is written, temporary file and all.
        let (target, name) = named(longest);
        let target = target.unwrap();
        write_atomic(&target, &serde_json::json!({"k": 1}))
            .expect("a basename prepare accepts can be written");
        assert!(dir.join(&name).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn schema_id_is_a_urn() {
        let s = schema();
        let id = s["$id"].as_str().expect("the schema has an $id");
        assert_eq!(id, "urn:ai-jail:run-summary/v1.json");
        assert!(id.ends_with(&format!("v{SCHEMA_VERSION}.json")), "{id}");
        // A URL would promise a document at an address nobody serves.
        assert!(!id.contains("://"), "{id}");
    }

    // ── the parent directory is held from prepare ───────────────

    #[test]
    fn a_parent_swapped_for_a_symlink_after_prepare_is_not_followed() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-summary-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (out, elsewhere) = (root.join("out"), root.join("elsewhere"));
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let target =
            RunSummaryTarget::prepare(&out.join("s.json"), &root).unwrap();
        std::fs::rename(&out, root.join("out.old")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &out).unwrap();
        write_atomic(&target, &json!({"k": 1})).unwrap();
        assert!(!elsewhere.join("s.json").exists(), "followed the swap");
        assert!(root.join("out.old/s.json").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    // Linux only: APFS refuses a name that is not valid UTF-8 (EILSEQ), and
    // the byte-built temporary name this guards is the same everywhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_utf8_name_prepare_accepts_is_written() {
        use std::os::unix::ffi::OsStrExt;
        let dir = temp_dir("non-utf8");
        // 200 invalid UTF-8 bytes: a lossy decode would triple them past
        // NAME_MAX in the temporary name.
        let name = std::ffi::OsStr::from_bytes(&[0xff; 200]);
        let target =
            RunSummaryTarget::prepare(Path::new(name), &dir).expect("accepted");
        write_atomic(&target, &serde_json::json!({"k": 1}))
            .expect("a name prepare accepts can be written");
        assert!(dir.join(name).is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
