// End-to-end tests for run observability, driven through the real
// binary and bwrap.
//
// Linux-only; every test skips (does not fail) when bwrap cannot create
// the namespaces it needs, like tests/filtered_egress.rs.
#![cfg(target_os = "linux")]

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail};
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
