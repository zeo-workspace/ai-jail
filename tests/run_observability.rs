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

/// Run `ai-jail <args>` in a fresh tree.
fn run(name: &str, args: &[&str]) -> Output {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    command(&project, &home).args(args).output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
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
