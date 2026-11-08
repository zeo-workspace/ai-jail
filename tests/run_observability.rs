// End-to-end tests for run observability, driven through the real
// binary and bwrap.
//
// Linux-only; every test skips (does not fail) when bwrap cannot create
// the namespaces it needs, like tests/filtered_egress.rs. The egress
// cases use the test-only proxy hatch (AI_JAIL_TEST_PROXY_ALLOW_PRIVATE),
// so the file needs `cargo test --features test-hooks`.
#![cfg(feature = "test-hooks")]
#![cfg(target_os = "linux")]

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, http_fixture};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// ── shared helpers ─────────────────────────────────────────────

/// A fresh project dir + HOME under the cargo test tmpdir.
fn tree(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("run-observability-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // The mandatory `.ai-jail` mask warns (even under --exec) when the file
    // is absent, so give it one to mask.
    std::fs::write(project.join(".ai-jail"), "").unwrap();
    (project, home)
}

fn command(project: &Path, home: &Path) -> Command {
    let mut c = Command::new(ai_jail());
    c.args(["--clean", "--no-save-config", "--no-status-bar"])
        .current_dir(project)
        .env("HOME", home)
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .stdin(Stdio::null());
    for k in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        c.env_remove(k);
    }
    c
}

/// Run `ai-jail <args>` in a fresh tree.
fn run(name: &str, args: &[&str]) -> Output {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    command(&project, &home).args(args).output().unwrap()
}

/// Run `ai-jail <args>` in a fresh tree; returns output and elapsed time.
fn timed_run(name: &str, args: &[&str]) -> (Output, Duration) {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let started = Instant::now();
    let out = command(&project, &home).args(args).output().unwrap();
    (out, started.elapsed())
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("egress line is JSON"))
        .collect()
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        panic!("summary {} not written: {e}", path.display())
    });
    serde_json::from_slice(&bytes).expect("summary is JSON")
}

const CURL_UP: &str =
    "--retry 20 --retry-delay 0 --retry-connrefused --max-time 20";

fn is_hex32(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn is_rfc3339_utc(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| {
        let b = s.as_bytes();
        b.len() == 20 && b[4] == b'-' && b[10] == b'T' && b[19] == b'Z'
    })
}

/// Minimal validator for docs/run-summary.schema.json: the
/// properties/type/enum/required/items subset the schema file keeps to. Key
/// sets must match `properties` exactly.
fn schema_errors(doc: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    fn ty(v: &Value) -> &'static str {
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
    fn walk(d: &Value, s: &Value, at: &str, e: &mut Vec<String>) {
        if let Some(t) = s.get("type") {
            let allowed: Vec<&str> = match t {
                Value::String(x) => vec![x.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            let got = ty(d);
            if !(allowed.contains(&got)
                || (got == "integer" && allowed.contains(&"number")))
            {
                e.push(format!("{at}: {got} not in {allowed:?}"));
                return;
            }
        }
        if let Some(Value::Array(opts)) = s.get("enum")
            && !opts.contains(d)
        {
            e.push(format!("{at}: {d} not in enum"));
        }
        if let (Value::Object(o), Some(Value::Object(p))) =
            (d, s.get("properties"))
        {
            for k in o.keys() {
                if !p.contains_key(k) {
                    e.push(format!("{at}.{k}: not in schema"));
                }
            }
            for (k, sub) in p {
                match o.get(k) {
                    Some(v) => walk(v, sub, &format!("{at}.{k}"), e),
                    None => e.push(format!("{at}.{k}: missing")),
                }
            }
        }
        if let (Value::Array(items), Some(sub)) = (d, s.get("items")) {
            for (i, it) in items.iter().enumerate() {
                walk(it, sub, &format!("{at}[{i}]"), e);
            }
        }
    }
    let schema_path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/docs/run-summary.schema.json");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(schema_path).expect("schema document ships"),
    )
    .expect("schema is JSON");
    let mut e = Vec::new();
    walk(doc, &schema, "$", &mut e);
    e
}

// ── egress log: "egress_" ──────────────────────────────────────

const EGRESS_FIELDS: [&str; 10] = [
    "bytes_down",
    "bytes_up",
    "duration_ms",
    "host",
    "port",
    "reason",
    "run_id",
    "ts",
    "v",
    "verdict",
];

/// Filtered run (allowlist 127.0.0.1) writing the egress log to `log`.
fn egress_run(name: &str, log: &Path, script: &str) -> Output {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
        .arg(log)
        .args(["bash", "-c", script])
        .output()
        .unwrap()
}

/// Opens exactly three proxy connections: one allowed tunnel, one
/// non-allowlisted CONNECT, one malformed request.
fn three_connections(fixture: u16) -> String {
    // The sandbox exports loopback in no_proxy
    // (proxy.rs, b7a5358), so force the loopback fixture through the proxy
    // as tests/filtered_egress.rs does.
    format!(
        "curl --noproxy '' -p -sS {CURL_UP} \
           http://127.0.0.1:{fixture}/ >/dev/null; \
         curl -p -sS --max-time 10 http://not-allowed.example:80/ \
           >/dev/null 2>&1; \
         exec 3<>/dev/tcp/127.0.0.1/15919; \
         printf 'GARBAGE\\r\\n\\r\\n' >&3; cat <&3 >/dev/null; exec 3>&-; \
         exit 0"
    )
}

#[test]
fn egress_log_has_one_line_per_connection() {
    require_bwrap_net!();
    require_curl!();
    let fixture = http_fixture();
    let dir = tree("egress-count").0;
    let log = dir.join("egress.jsonl");
    let out = egress_run("egress-count-run", &log, &three_connections(fixture));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 3, "one line per connection: {lines:#?}");
    for l in &lines {
        let mut keys: Vec<&str> =
            l.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, EGRESS_FIELDS, "{l}");
        assert_eq!(l["v"], 1);
        assert!(is_hex32(&l["run_id"]), "{l}");
        assert!(is_rfc3339_utc(&l["ts"]), "{l}");
        assert_eq!(l["run_id"], lines[0]["run_id"], "one run id per run");
    }
    let by = |v: &str| lines.iter().find(|l| l["verdict"] == v).unwrap();
    let allow = by("allow");
    assert_eq!(allow["reason"], "in-allowlist");
    assert_eq!(allow["host"], "127.0.0.1");
    assert_eq!(allow["port"], fixture);
    assert!(allow["bytes_up"].as_u64().unwrap() > 0);
    assert!(allow["bytes_down"].as_u64().unwrap() > 0);
    let deny = by("deny");
    assert_eq!(deny["reason"], "not-in-allowlist");
    assert_eq!(deny["host"], "not-allowed.example");
    assert_eq!(deny["bytes_up"], 0);
    assert_eq!(deny["bytes_down"], 0);
    let error = by("error");
    assert_eq!(error["reason"], "malformed-request");
    assert!(error["host"].is_null());
}

#[test]
fn egress_log_file_is_private_and_appended_across_runs() {
    require_bwrap_net!();
    require_curl!();
    let dir = tree("egress-append").0;
    let log = dir.join("egress.jsonl");
    let script = "curl -p -sS --retry 20 --retry-delay 0 --retry-connrefused \
                  --max-time 10 http://not-allowed.example:80/ \
                  >/dev/null 2>&1; exit 0";
    egress_run("egress-append-1", &log, script);
    egress_run("egress-append-2", &log, script);
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 2, "append, never truncate: {lines:#?}");
    assert_ne!(lines[0]["run_id"], lines[1]["run_id"], "run ids differ");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&log).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn egress_log_unopenable_path_warns_and_launches() {
    require_bwrap_net!();
    let dir = tree("egress-unopenable").0;
    // A missing directory, then a symlink: both warn with the path and
    // the launch goes on.
    let missing = dir.join("no-such-dir").join("egress.jsonl");
    let out = egress_run("egress-unopenable-1", &missing, "exit 7");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "launch continued: {stderr}");
    assert!(
        stderr.contains("no-such-dir"),
        "warns with the path: {stderr}"
    );

    let victim = dir.join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let out = egress_run("egress-unopenable-2", &link, "exit 5");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("link.jsonl"), "{stderr}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

#[test]
fn egress_log_refused_without_filtered_network() {
    require_bwrap_net!();
    let dir = tree("egress-refused").0;
    let log = dir.join("egress.jsonl");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    // The refusal must not fire in filtered mode.
    let (project, home) = tree("egress-refused-filtered");
    let ok = command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
        .arg(&log)
        .args(["sh", "-c", "exit 0"])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "filtered + --egress-log starts: {}",
        text(&ok.stderr)
    );
    for (name, flag) in [("off", "--no-network"), ("full", "--network")] {
        let (project, home) = tree(&format!("egress-refused-{name}"));
        let out = command(&project, &home)
            .args(["--exec", flag, "--egress-log"])
            .arg(&log)
            .args(["sh", "-c", &touch])
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert!(!out.status.success(), "{name}: must refuse to start");
        assert!(stderr.contains("--egress-log"), "{name}: {stderr}");
        assert!(stderr.contains("filtered"), "{name}: {stderr}");
        assert!(!marker.exists(), "{name}: the command ran");
    }
}

/// A loopback port whose accept queue is already full: the kernel drops
/// every further SYN, so a dial to it waits in SYN_SENT until the dialer
/// gives up. The proxy's dial then holds the connection open past the
/// command's exit, and no socket shutdown can end it early.
fn blackhole_port() -> (TcpListener, std::net::TcpStream, u16) {
    use std::os::fd::AsRawFd;
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    // SAFETY: `l` is an open listening socket; listen() on it again only
    // lowers its backlog.
    assert_eq!(unsafe { nix::libc::listen(l.as_raw_fd(), 0) }, 0);
    let port = l.local_addr().unwrap().port();
    let filler =
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    (l, filler, port)
}

/// True while some socket of this host's netns (the supervisor's proxy
/// lives there) is dialing 127.0.0.1:`port`.
fn dialing(port: u16) -> bool {
    let remote = format!("0100007F:{port:04X}");
    std::fs::read_to_string("/proc/net/tcp")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3 && f[2] == remote && f[3] == "02"
        })
}

/// A filtered launch whose command starts a tunnel to `port` in the
/// background and exits. Returns the output, whether the proxy was seen
/// dialing, and how long the run lasted after that was first seen.
fn held_open_run(
    name: &str,
    extra: &[&str],
    port: u16,
) -> (Output, bool, Duration) {
    let (project, home) = tree(name);
    let script = format!(
        "curl --noproxy '' -p -sS --max-time 30 http://127.0.0.1:{port}/ \
           >/dev/null 2>&1 & sleep 0.5; exit 0"
    );
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut child = command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1"])
        .args(extra)
        .args(["bash", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = None;
    while child.try_wait().unwrap().is_none() {
        if seen.is_none() && dialing(port) {
            seen = Some(Instant::now());
        }
        assert!(Instant::now() < deadline, "{name}: the run never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
    let ended = Instant::now();
    let out = child.wait_with_output().unwrap();
    (
        out,
        seen.is_some(),
        seen.map_or(Duration::ZERO, |t| ended - t),
    )
}

#[test]
fn filtered_launch_without_egress_log_does_not_drain() {
    require_bwrap_net!();
    require_curl!();
    let (_listener, _filler, port) = blackhole_port();

    // The passing case first, so the fixture is proved to hold a connection the
    // drain must wait for: with --egress-log the run waits the grace and
    // says what it could not close.
    let dir = tree("egress-held-logged").0;
    let log = dir.join("egress.jsonl");
    let log_arg = log.display().to_string();
    let (out, seen, after) = held_open_run(
        "egress-held-logged-run",
        &["--egress-log", &log_arg],
        port,
    );
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(seen, "setup: the proxy never dialed the held port");
    assert!(stderr.contains("still open"), "drain warned: {stderr}");
    assert!(
        after >= Duration::from_millis(1900),
        "the drain waited its grace: {after:?}"
    );

    // Without --egress-log the proxy ends as it did before the flag
    // existed: no drain wait after the command, no drain warning.
    let (out, seen, after) = held_open_run("egress-held-plain", &[], port);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(seen, "setup: the proxy never dialed the held port");
    assert!(
        !stderr.contains("still open") && !stderr.contains("drain"),
        "no drain warning without --egress-log: {stderr}"
    );
    assert!(
        after < Duration::from_millis(1500),
        "no drain wait without --egress-log: {after:?}"
    );
}

// ── exit reason: "exit_" ───────────────────────────────────────

#[test]
fn exit_file_size_limit_is_named_under_lockdown() {
    require_bwrap_net!();
    // A 1 MiB write at offset 2 GiB crosses the 1 GiB lockdown FSIZE
    // without writing a gigabyte (sparse file on the sandbox tmpfs).
    let out = run(
        "xfsz",
        &[
            "--lockdown",
            "--exec",
            "sh",
            "-c",
            "exec dd if=/dev/zero of=/tmp/big bs=1M count=1 seek=2048 2>/dev/null",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(153), "{stderr}");
    assert!(stderr.contains("SIGXFSZ"), "{stderr}");
    assert!(
        stderr.contains("file-size") || stderr.contains("file size"),
        "{stderr}"
    );
    assert!(
        stderr.contains("1 GiB")
            || stderr.contains("1.0 GiB")
            || stderr.contains("1073741824"),
        "the value in force: {stderr}"
    );
}

#[test]
fn exit_cpu_time_limit_is_named() {
    require_bwrap_net!();
    // Soft limit only: with soft == hard (`ulimit -t 1`) the kernel
    // sends SIGKILL, not SIGXCPU (measured: exit 137).
    let out = run(
        "xcpu",
        &["--exec", "sh", "-c", "ulimit -S -t 1; while :; do :; done"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(152), "{stderr}");
    assert!(stderr.contains("SIGXCPU"), "{stderr}");
    assert!(stderr.to_lowercase().contains("cpu"), "{stderr}");
}

#[test]
fn exit_unattributed_sigkill_points_at_the_host_oom_killer() {
    require_bwrap_net!();
    let out = run("kill9", &["--exec", "sh", "-c", "kill -9 $$"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(137), "{stderr}");
    assert!(stderr.contains("SIGKILL"), "{stderr}");
    assert!(stderr.to_lowercase().contains("oom"), "{stderr}");
    assert!(
        stderr.contains("journalctl -k"),
        "kernel-log hint: {stderr}"
    );
    assert_eq!(stderr.matches("journalctl").count(), 1, "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
}

#[test]
fn exit_only_unexplained_signals_speak() {
    require_bwrap_net!();
    // Clean exits and deliberate signals must stay silent, with their codes
    // unchanged ...
    for (name, script, code) in [
        ("clean", "exit 0", 0),
        ("exit3", "exit 3", 3),
        ("term", "kill -TERM $$", 143),
        ("int", "kill -INT $$", 130),
        ("hup", "kill -HUP $$", 129),
        ("pipe", "kill -PIPE $$", 141),
    ] {
        let out = run(name, &["--exec", "sh", "-c", script]);
        assert_eq!(out.status.code(), Some(code), "{name}");
        assert_eq!(text(&out.stderr), "", "{name} must print nothing");
    }
    // ... and an unexplained signal must say which one, on one line.
    let out = run("segv", &["--exec", "sh", "-c", "kill -SEGV $$"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(139), "{stderr}");
    assert!(stderr.contains("SIGSEGV"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

// ── teardown report: "teardown_" ───────────────────────────────

#[test]
fn teardown_survivor_is_named_and_stopped_gracefully() {
    require_bwrap_net!();
    // No survivors -> no line and no grace delay.
    let (out, took) = timed_run(
        "td-none",
        &["--teardown-report", "--exec", "sh", "-c", "exit 0"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "", "nothing printed");
    // The claim is "no grace", not a launch speed.
    assert!(took < Duration::from_millis(2000), "no delay ({took:?})");

    let (out, took) = timed_run(
        "td-sleep",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(took < Duration::from_secs(3), "SIGTERM ends it: {took:?}");
    assert!(stderr.contains("sleep"), "names it: {stderr}");
    assert!(stderr.contains('1'), "counts it: {stderr}");
    assert!(
        !stderr.contains("ai-jail"),
        "no phantom wrapper/bridge: {stderr}"
    );
}

#[test]
fn teardown_sigterm_ignoring_survivor_is_killed_after_the_grace() {
    require_bwrap_net!();
    let (out, took) = timed_run(
        "td-stubborn",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sh -c 'trap \"\" TERM; exec sleep 300' & sleep 0.2; exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        took >= Duration::from_millis(1900),
        "grace honoured: {took:?}"
    );
    assert!(took < Duration::from_secs(5), "then SIGKILL: {took:?}");
    assert!(stderr.contains("sleep"), "{stderr}");
}

#[test]
fn teardown_works_under_lockdown() {
    require_bwrap_net!();
    let (out, took) = timed_run(
        "td-lockdown",
        &[
            "--lockdown",
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert!(stderr.contains("sleep"), "{stderr}");
}

#[test]
fn teardown_report_fd_is_not_visible_to_the_command() {
    require_bwrap_net!();
    // The shell lists its own descriptors with a
    // glob and a builtin, so no pipeline adds pipe ends to the listing.
    let script = "cd /proc/$$/fd && echo *";
    let (plain, _) = timed_run("td-fd-plain", &["--exec", "sh", "-c", script]);
    let (with, _) = timed_run(
        "td-fd-report",
        &["--teardown-report", "--exec", "sh", "-c", script],
    );
    assert!(with.status.success(), "{}", text(&with.stderr));
    assert_eq!(
        text(&with.stdout),
        text(&plain.stdout),
        "the command holds no extra descriptor"
    );
}

#[test]
fn teardown_keeps_the_exit_code_of_every_end() {
    require_bwrap_net!();
    for (name, script, code) in [
        ("exit7", "exit 7", 7),
        ("term", "kill -TERM $$", 143),
        ("segv", "kill -SEGV $$", 139),
        ("kill", "kill -9 $$", 137),
    ] {
        let (out, _) = timed_run(
            &format!("td-code-{name}"),
            &["--teardown-report", "--exec", "sh", "-c", script],
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "exit code unchanged, {name}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn teardown_wrapper_forwards_term_and_hup_and_ignores_int() {
    require_bwrap_net!();
    // With the report active the command's parent is the wrapper.
    for sig in ["TERM", "HUP"] {
        let script = format!(
            "trap 'echo got-{sig}; exit 42' {sig}; w=$PPID; \
             (sleep 0.3; kill -{sig} $w) & \
             i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; exit 1"
        );
        let (out, _) = timed_run(
            &format!("td-fwd-{sig}"),
            &["--teardown-report", "--exec", "sh", "-c", &script],
        );
        assert_eq!(out.status.code(), Some(42), "{sig}: {}", text(&out.stderr));
        assert!(text(&out.stdout).contains(&format!("got-{sig}")));
    }
    let (out, _) = timed_run(
        "td-int",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "kill -INT $PPID; sleep 0.3; echo alive; exit 5",
        ],
    );
    assert_eq!(out.status.code(), Some(5), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("alive"),
        "the wrapper ignored SIGINT"
    );
}

/// The stderr lines that announce an incomplete teardown report.
fn incomplete_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| l.contains("Teardown report incomplete"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn teardown_incomplete_report_prints_one_line() {
    require_bwrap_net!();
    // A complete report with a survivor names it and
    // says nothing about being incomplete.
    let (out, _) = timed_run(
        "td-complete",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("sleep"),
        "setup: the survivor line: {stderr}"
    );
    assert!(
        incomplete_lines(&stderr).is_empty(),
        "a complete report is announced as incomplete: {stderr}"
    );

    // More survivors than one report lists: it arrives marked incomplete
    // (survivor-list-truncated), and that is said once. --no-rlimits:
    // RLIMIT_NPROC counts the user's processes host-wide, so on a busy
    // desktop it could refuse the forks this setup needs.
    let (out, _) = timed_run(
        "td-truncated",
        &[
            "--no-rlimits",
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "i=0; while [ $i -lt 300 ]; do sleep 300 & i=$((i+1)); done; exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let lines = incomplete_lines(&stderr);
    assert_eq!(lines.len(), 1, "exactly one incomplete line: {stderr}");
    assert!(
        lines[0].contains("Teardown report incomplete: ")
            && lines[0].contains("survivor-list-truncated"),
        "the line names the reason: {}",
        lines[0]
    );
}

/// The words of a dry run's printed argv, shell quotes removed.
fn dry_run_words(out: &Output) -> Vec<String> {
    text(&out.stdout)
        .split_whitespace()
        .map(|w| w.trim_matches(|c| c == '\'' || c == '"').to_string())
        .collect()
}

#[test]
fn teardown_dry_run_shows_the_wrapper_and_a_placeholder_fd() {
    require_bwrap_net!();
    // Every other reason for the wrapper is off, so only the teardown
    // report can put it on the argv.
    let controls_off = [
        "--no-landlock",
        "--no-seccomp",
        "--no-rlimits",
        "--no-network",
    ];
    let dry = |name: &str, extra: &[&str]| {
        let mut args: Vec<&str> = controls_off.to_vec();
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--dry-run", "sh", "-c", "exit 0"]);
        let (out, _) = timed_run(name, &args);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        dry_run_words(&out)
    };

    // Without the report, the dry run shows neither
    // the wrapper nor a report descriptor, as the launch uses neither.
    let plain = dry("td-dry-plain", &[]);
    assert!(
        plain.iter().any(|w| w.ends_with("bwrap")),
        "setup: a dry run prints the bwrap argv: {plain:?}"
    );
    assert!(
        !plain.iter().any(|w| w == "--teardown-report-fd"),
        "{plain:?}"
    );
    assert!(!plain.iter().any(|w| w == "--landlock-exec"), "{plain:?}");

    // With it: the argv the real launch runs, wrapper included, with the
    // descriptor a dry run never opens shown as a placeholder.
    let with = dry("td-dry-report", &["--teardown-report"]);
    let exec_at = with
        .iter()
        .position(|w| w == "--landlock-exec")
        .unwrap_or_else(|| panic!("the wrapper is missing: {with:?}"));
    let fd_at = with
        .iter()
        .position(|w| w == "--teardown-report-fd")
        .unwrap_or_else(|| panic!("the report flag is missing: {with:?}"));
    assert!(
        fd_at > exec_at,
        "the wrapper takes the flag only after --landlock-exec: {with:?}"
    );
    let fd = with.get(fd_at + 1).map(String::as_str).unwrap_or("");
    assert!(
        !fd.is_empty()
            && !fd.starts_with("--")
            && !fd.bytes().all(|b| b.is_ascii_digit()),
        "the fd is a placeholder, not a number no dry run opened: {fd:?}"
    );
}

// ── run summary: "summary_" ────────────────────────────────────

fn summary_run(
    name: &str,
    extra: &[&str],
    cmd: &[&str],
) -> (Output, serde_json::Value) {
    let (project, home) = tree(name);
    let path = project.join("summary.json");
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let out = command(&project, &home)
        .arg("--run-summary")
        .arg(&path)
        .args(extra)
        .arg("--exec")
        .args(cmd)
        .output()
        .unwrap();
    let doc = read_json(&path);
    let errors = schema_errors(&doc);
    assert!(errors.is_empty(), "schema, {name}: {errors:#?}\n{doc:#}");
    (out, doc)
}

#[test]
fn summary_clean_run_is_schema_v1() {
    require_bwrap_net!();
    // With no network flag, v3 default-allows the
    // package registries (filtered mode), so ask for "off" explicitly.
    let (out, doc) =
        summary_run("sum-clean", &["--no-network"], &["sh", "-c", "exit 3"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(doc["schema"], "ai-jail.run-summary");
    assert_eq!(doc["schema_version"], 1);
    assert!(is_hex32(&doc["run_id"]), "{doc}");
    assert_eq!(doc["ai_jail_version"], env!("CARGO_PKG_VERSION"));
    assert!(is_rfc3339_utc(&doc["started_at"]));
    assert!(is_rfc3339_utc(&doc["ended_at"]));
    assert!(doc["duration_ms"].is_u64());
    assert_eq!(doc["program"], "sh");
    assert_eq!(doc["exit"]["code"], 3);
    assert_eq!(doc["exit"]["reason"], "exited");
    assert_eq!(
        doc["exit"]["status_source"], "reported",
        "the wrapper's report"
    );
    assert_eq!(doc["resources"]["peak_rss_scope"], "largest-process");
    // On Linux the figures are measured inside the
    // sandbox, by the wrapper.
    assert_eq!(doc["resources"]["source"], "sandbox-wrapper");
    assert!(doc["resources"]["peak_rss_kib"].as_u64().unwrap() > 0);
    assert_eq!(doc["network"]["mode"], "off");
    assert!(
        doc["network"]["connections_denied"].is_null(),
        "no proxy, no count"
    );
    assert!(doc["filesystem"]["denied_accesses"].is_null());
    assert_eq!(doc["filesystem"]["denied_accesses_source"], "unavailable");
    assert_eq!(doc["teardown"]["active"], true, "implied by --run-summary");
    assert_eq!(doc["teardown"]["complete"], true);
    assert_eq!(doc["teardown"]["survivors"], serde_json::json!([]));
}

#[test]
fn summary_records_the_program_basename_only() {
    require_bwrap_net!();
    let (project, home) = tree("sum-basename");
    let path = project.join("summary.json");
    let out = command(&project, &home)
        .env("AI_JAIL_SECRET_PROBE", "hunter2-env")
        .arg("--run-summary")
        .arg(&path)
        .args(["--exec", "/bin/sh", "-c", "exit 0", "argv-hunter2"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let raw = std::fs::read_to_string(&path).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["program"], "sh");
    for needle in ["hunter2", "/bin/sh", "exit 0"] {
        assert!(!raw.contains(needle), "{needle:?} leaked: {raw}");
    }
}

#[test]
fn summary_network_counts_follow_the_mode() {
    require_bwrap_net!();
    // Off/full are null, not 0 ...
    for (name, flag, mode) in [
        ("off", "--no-network", "off"),
        ("full", "--network", "full"),
    ] {
        let (_, doc) =
            summary_run(&format!("sum-net-{name}"), &[flag], &["true"]);
        assert_eq!(doc["network"]["mode"], mode);
        for k in [
            "connections_allowed",
            "connections_denied",
            "connections_errored",
            "bytes_up",
            "bytes_down",
        ] {
            assert!(
                doc["network"][k].is_null(),
                "{mode}.{k}: {}",
                doc["network"]
            );
        }
    }
    // ... and filtered with no traffic is 0, not null.
    let (_, doc) = summary_run(
        "sum-net-filtered",
        &["--allow-host", "127.0.0.1"],
        &["true"],
    );
    assert_eq!(doc["network"]["mode"], "filtered");
    assert_eq!(doc["network"]["connections_denied"], 0);
    assert_eq!(doc["network"]["connections_allowed"], 0);
}

#[test]
fn summary_matches_egress_log() {
    require_bwrap_net!();
    require_curl!();
    let fixture = http_fixture();
    let (project, home) = tree("sum-egress");
    let log = project.join("egress.jsonl");
    // An earlier run already left a deny line in the same
    // append-only log. The summary must count THIS run's lines only.
    // Loopback is in no_proxy (see
    // three_connections), so force the fixture through the proxy.
    let earlier = format!(
        "curl --noproxy '' -p -sS {CURL_UP} http://127.0.0.1:{fixture}/ >/dev/null; \
         curl -p -sS --max-time 10 http://earlier.example:80/ >/dev/null 2>&1; exit 0"
    );
    egress_run("sum-egress-earlier", &log, &earlier);
    let before = read_jsonl(&log).len();
    assert_eq!(before, 2, "earlier run wrote its lines");

    let script = format!(
        // Three_connections already ends in "; ", so a
        // second ";" was a bash syntax error.
        "{} curl -p -sS --max-time 10 http://second.example:80/ >/dev/null 2>&1; \
         sleep 300 & exit 0",
        three_connections(fixture).trim_end_matches("exit 0")
    );
    let summary = project.join("summary.json");
    let out = {
        let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        command(&project, &home)
            .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
            .arg(&log)
            .arg("--run-summary")
            .arg(&summary)
            .args(["bash", "-c", &script])
            .output()
            .unwrap()
    };
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc = read_json(&summary);
    assert!(schema_errors(&doc).is_empty(), "{:#?}", schema_errors(&doc));
    let all = read_jsonl(&log);
    let mine: Vec<_> = all
        .iter()
        .filter(|l| l["run_id"] == doc["run_id"])
        .collect();
    assert_eq!(mine.len(), 4, "this run opened four connections: {mine:#?}");
    assert_ne!(all[0]["run_id"], doc["run_id"], "run ids never repeat");
    let count =
        |v: &str| mine.iter().filter(|l| l["verdict"] == v).count() as u64;
    let sum =
        |k: &str| mine.iter().map(|l| l[k].as_u64().unwrap()).sum::<u64>();
    let net = &doc["network"];
    assert_eq!(
        net["connections_denied"],
        count("deny"),
        "denied = deny lines"
    );
    assert_eq!(net["connections_denied"], 2);
    assert_eq!(net["connections_allowed"], count("allow"));
    assert_eq!(net["connections_errored"], count("error"));
    assert_eq!(net["bytes_up"], sum("bytes_up"));
    assert_eq!(net["bytes_down"], sum("bytes_down"));
    assert_eq!(doc["exit"]["status_source"], "reported");
    let survivors = doc["teardown"]["survivors"].as_array().unwrap();
    let sleep = survivors
        .iter()
        .find(|s| s["comm"] == "sleep")
        .expect("sleep survivor");
    assert_eq!(sleep["ended_by"], "sigterm");
    for k in ["pid", "ppid", "age_s"] {
        assert!(sleep[k].is_u64() || sleep[k].is_i64(), "{k}: {sleep}");
    }
    assert!(
        survivors.iter().all(|s| s["comm"] != "ai-jail"),
        "no phantom bridge survivor: {survivors:?}"
    );
}

#[test]
fn summary_names_the_sigkill_ending_of_a_stubborn_survivor() {
    require_bwrap_net!();
    let (_, doc) = summary_run(
        "sum-stubborn",
        &[],
        &[
            "sh",
            "-c",
            "sh -c 'trap \"\" TERM; exec sleep 300' & sleep 0.2; exit 0",
        ],
    );
    let survivors = doc["teardown"]["survivors"].as_array().unwrap();
    assert!(
        survivors
            .iter()
            .any(|s| s["comm"] == "sleep" && s["ended_by"] == "sigkill"),
        "{survivors:?}"
    );
    assert_eq!(doc["teardown"]["grace_ms"], 2000);
}

#[test]
fn summary_teardown_incomplete_when_the_wrapper_dies() {
    require_bwrap_net!();
    // The command kills its parent (the wrapper): no report arrives.
    let (out, doc) = summary_run(
        "sum-wrapper-killed",
        &[],
        &["sh", "-c", "kill -9 $PPID; sleep 5"],
    );
    assert_eq!(doc["teardown"]["complete"], false, "{doc:#}");
    assert!(doc["teardown"]["incomplete_reason"].is_string(), "{doc:#}");
    assert_eq!(doc["exit"]["status_source"], "inferred", "falls back");
    assert_eq!(
        doc["exit"]["code"].as_i64(),
        out.status.code().map(i64::from)
    );
}

#[test]
fn summary_invalid_target_warns_and_launches() {
    require_bwrap_net!();
    let (project, home) = tree("sum-invalid");
    let victim = project.join("victim.json");
    std::fs::write(&victim, b"untouched").unwrap();
    let link = project.join("link.json");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let missing = project.join("no-such-dir").join("s.json");
    for (target, needle, code) in
        [(&link, "link.json", "6"), (&missing, "no-such-dir", "4")]
    {
        let out = command(&project, &home)
            .arg("--run-summary")
            .arg(target)
            .args(["--exec", "sh", "-c", &format!("exit {code}")])
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(code.parse().unwrap()), "{stderr}");
        assert!(stderr.contains(needle), "warns with the path: {stderr}");
    }
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

#[test]
fn summary_write_failure_keeps_the_exit_code() {
    require_bwrap_net!();
    // The target directory sits in the project, which the command can
    // write: it removes the directory, so the final write must fail.
    let (project, home) = tree("sum-write-fail");
    std::fs::create_dir_all(project.join("out")).unwrap();
    let target = project.join("out").join("s.json");
    let out = command(&project, &home)
        .arg("--run-summary")
        .arg(&target)
        .args(["--exec", "sh", "-c", "rm -rf out; exit 9"])
        .output()
        .unwrap();
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(9), "{stderr}");
    assert!(
        stderr.contains("s.json") || stderr.contains("out"),
        "error names the path: {stderr}"
    );
}

#[test]
fn summary_reported_exit_137_is_silent() {
    require_bwrap_net!();
    // The fallback first: with no report, bwrap's 137 is indistinguishable
    // from SIGKILL, so it is decoded (inferred) and explained.
    let plain = run("sum-137-plain", &["--exec", "sh", "-c", "exit 137"]);
    assert_eq!(plain.status.code(), Some(137));
    assert!(text(&plain.stderr).contains("SIGKILL"), "inferred decode");
    // With the wrapper's report, exit(137) is a normal exit: no line.
    let (out, doc) = summary_run("sum-137", &[], &["sh", "-c", "exit 137"]);
    assert_eq!(out.status.code(), Some(137), "code unchanged");
    assert_eq!(text(&out.stderr), "", "a reported exit 137 is silent");
    assert_eq!(doc["exit"]["reason"], "exited", "{doc:#}");
    assert!(doc["exit"]["signal"].is_null(), "{doc:#}");
    assert_eq!(doc["exit"]["status_source"], "reported");
    assert_eq!(doc["exit"]["code"], 137);
}

#[test]
fn summary_start_failed_is_recorded() {
    require_bwrap_net!();
    // TMPDIR names a missing directory: sandbox::prepare() cannot create
    // its temporary hosts file, after the summary guard exists.
    let (project, home) = tree("sum-start-failed");
    let path = project.join("summary.json");
    let out = command(&project, &home)
        .env("TMPDIR", project.join("no-such-tmp"))
        .arg("--run-summary")
        .arg(&path)
        .args(["--exec", "true"])
        .output()
        .unwrap();
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "start failure: {stderr}");
    let doc = read_json(&path);
    let errors = schema_errors(&doc);
    assert!(errors.is_empty(), "{errors:#?}");
    assert_eq!(doc["exit"]["reason"], "start-failed", "{doc:#}");
    assert!(
        doc["exit"]["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the startup error is recorded: {doc:#}"
    );
}

#[test]
fn summary_resources_measure_the_command() {
    require_bwrap_net!();
    // The failure case first (units): a command that holds almost nothing
    // reports a peak far below 64 MiB. A peak in bytes, or a fixed or
    // summed figure, would not be.
    let (out, doc) = summary_run(
        "sum-res-small",
        &["--no-network"],
        &["sh", "-c", "exit 0"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let r = &doc["resources"];
    assert_eq!(r["source"], "sandbox-wrapper", "{r}");
    let small = r["peak_rss_kib"]
        .as_u64()
        .unwrap_or_else(|| panic!("the peak is a figure: {r}"));
    assert!(small < 65_536, "a trivial command's peak: {small} KiB");

    // The command itself holds 64 MiB: bash reads it into one variable.
    // Its peak must be the command's, not the launcher's (bwrap alone
    // stays at a few MiB).
    let script = "x=$(head -c 67108864 /dev/zero | tr '\\0' a); echo ${#x}";
    let (out, doc) =
        summary_run("sum-res-64m", &["--no-network"], &["bash", "-c", script]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout).trim(),
        "67108864",
        "setup: the command held 64 MiB"
    );
    let r = &doc["resources"];
    assert_eq!(r["source"], "sandbox-wrapper", "{r}");
    assert_eq!(r["peak_rss_scope"], "largest-process", "{r}");
    let peak = r["peak_rss_kib"]
        .as_u64()
        .unwrap_or_else(|| panic!("the peak is a figure: {r}"));
    assert!(
        peak >= 65_536,
        "the command's 64 MiB, not the launcher's: {peak} KiB"
    );
    assert!(
        r["cpu_user_ms"].is_u64() && r["cpu_system_ms"].is_u64(),
        "{r}"
    );
}

#[test]
fn summary_dry_run_shows_the_teardown_wrapper_it_implies() {
    require_bwrap_net!();
    // --run-summary implies --teardown-report, so the argv a dry run prints
    // must carry the wrapper and its descriptor as the launch would. Every
    // other reason for the wrapper is off.
    let target = std::env::temp_dir()
        .join(format!("ai-jail-summary-dry-{}.json", std::process::id()));
    let target = target.to_str().unwrap();
    let out = run(
        "summary-dry",
        &[
            "--no-landlock",
            "--no-seccomp",
            "--no-rlimits",
            "--no-network",
            "--run-summary",
            target,
            "--dry-run",
            "sh",
            "-c",
            "exit 0",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let words = dry_run_words(&out);
    assert!(words.iter().any(|w| w == "--landlock-exec"), "{words:?}");
    let fd = words.iter().position(|w| w == "--teardown-report-fd");
    assert!(fd.is_some(), "the report descriptor is shown: {words:?}");
    assert!(
        !std::path::Path::new(target).exists(),
        "a dry run writes no summary"
    );
}
