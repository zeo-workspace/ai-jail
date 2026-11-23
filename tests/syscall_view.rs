// `--syscall-view` end to end: uname(2) and sysinfo(2) answered by
// ai-jail inside a real jail. Linux-only; skipped when bwrap cannot create
// namespaces or python3 is missing.
#![cfg(target_os = "linux")]

use std::process::{Command, Output};

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, bwrap_available};

const JAIL_FLAGS: &[&str] = &[
    "--clean",
    "--no-save-config",
    "--no-ssh",
    "--no-gpu",
    "--no-docker",
    "--no-display",
    "--no-status-bar",
    "--mask-host",
];

fn ready() -> bool {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create namespaces here");
        return false;
    }
    if !Command::new("python3")
        .arg("-c")
        .arg("0")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("SKIPPED: no python3");
        return false;
    }
    true
}

const PROBE: &str = r#"
echo "release=$(uname -r)"
echo "nodename=$(uname -n)"
echo "version=$(uname -v)"
python3 - <<'PY'
import ctypes, os
buf = (ctypes.c_long * 64)()
ctypes.CDLL(None).sysinfo(buf)
print("sysuptime=%d" % buf[0])
print("pyrelease=%s" % os.uname().release)
PY
"#;

fn jail(prefix: &[&str], extra: &[&str], script: &str) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = if prefix.is_empty() {
        Command::new(ai_jail())
    } else {
        let mut c = Command::new(prefix[0]);
        c.args(&prefix[1..]).arg(ai_jail());
        c
    };
    cmd.args(JAIL_FLAGS)
        .args(extra)
        .args(["sh", "-c", script])
        .output()
        .expect("failed to spawn ai-jail")
}

fn stdout(out: &Output) -> String {
    assert!(
        out.status.success(),
        "jail failed: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("{key} missing:\n{text}"))
}

fn host_release() -> String {
    String::from_utf8_lossy(
        &Command::new("uname").arg("-r").output().unwrap().stdout,
    )
    .trim()
    .to_string()
}

#[test]
fn syscall_view_answers_uname_and_sysinfo() {
    if !ready() {
        return;
    }
    let out = stdout(&jail(&[], &["--syscall-view"], PROBE));
    let release = field(&out, "release");
    assert!(
        release.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "uname -r still the host's: {out}"
    );
    assert_eq!(field(&out, "pyrelease"), release, "{out}");
    assert_eq!(field(&out, "nodename"), "ai-sandbox");
    assert!(!field(&out, "version").contains(':'), "date in {out}");
    let uptime: i64 = field(&out, "sysuptime").parse().unwrap();
    assert!((0..60).contains(&uptime), "sysinfo uptime: {out}");
}

#[test]
fn without_syscall_view_uname_is_the_kernels() {
    if !ready() {
        return;
    }
    let out = stdout(&jail(&[], &[], PROBE));
    assert_eq!(field(&out, "release"), host_release());
}

#[test]
fn syscall_view_sizes_phys_pages_to_a_memory_limit() {
    if !ready() {
        return;
    }
    let scope = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "MemoryMax=512M",
            "true",
        ])
        .output();
    if !scope.is_ok_and(|o| o.status.success()) {
        eprintln!("SKIPPED: no systemd user scope available");
        return;
    }
    let out = stdout(&jail(
        &[
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "MemoryMax=512M",
        ],
        &["--syscall-view"],
        "echo bytes=$(( $(getconf _PHYS_PAGES) * $(getconf PAGESIZE) ))",
    ));
    assert_eq!(field(&out, "bytes"), (512u64 << 20).to_string(), "{out}");
}

#[test]
fn syscall_view_alone_is_refused() {
    let out = Command::new(ai_jail())
        .args(["--clean", "--no-save-config", "--syscall-view", "true"])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--mask-host"));
}
