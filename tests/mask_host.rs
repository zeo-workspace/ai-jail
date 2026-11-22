// `--mask-host` end to end: a real jail must read the synthetic host view.
//
// Linux-only and skipped when bwrap cannot create user namespaces (most
// CI containers). The CPU count is pinned with taskset so the expected
// value does not depend on the machine running the test.
#![cfg(target_os = "linux")]

use std::process::{Command, Output};

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, bwrap_available};

macro_rules! require_bwrap {
    () => {
        if !bwrap_available() {
            eprintln!("SKIPPED: bwrap cannot create namespaces here");
            return;
        }
    };
}

fn taskset_available() -> bool {
    Command::new("taskset")
        .args(["-c", "0", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run `script` in a jail, pinned to CPU 0 when taskset exists.
fn jail(mask_host: bool, script: &str) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = if taskset_available() {
        let mut c = Command::new("taskset");
        c.args(["-c", "0"]).arg(ai_jail());
        c
    } else {
        Command::new(ai_jail())
    };
    cmd.args([
        "--clean",
        "--no-save-config",
        "--no-ssh",
        "--no-gpu",
        "--no-docker",
        "--no-display",
        "--no-status-bar",
    ]);
    if mask_host {
        cmd.arg("--mask-host");
    }
    cmd.args(["sh", "-c", script])
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

/// `key=value` lines printed by the probe script.
fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("{key} missing from probe output:\n{text}"))
}

const PROBE: &str = r#"
echo "nproc=$(nproc)"
echo "processors=$(grep -c '^processor' /proc/cpuinfo)"
echo "model=$(grep -m1 '^model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
echo "online=$(cat /sys/devices/system/cpu/online)"
echo "statcpus=$(grep -c '^cpu[0-9]' /proc/stat)"
echo "loadavg=$(cat /proc/loadavg)"
echo "memtotal=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
echo "cgroup=$(cat /proc/self/cgroup)"
echo "cgroupfs=$(ls /sys/fs/cgroup | tr '\n' ' ')"
echo "dmi=$(ls /sys/class/dmi/id 2>/dev/null | wc -l)"
echo "machineid=$(cat /etc/machine-id 2>/dev/null)"
"#;

fn host_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("model name"))
        .and_then(|rest| rest.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

#[test]
fn mask_host_shows_a_host_sized_to_the_jail() {
    require_bwrap!();
    let masked = stdout(&jail(true, PROBE));

    // CPUs: every tool agrees, and the model is generic.
    let n = field(&masked, "nproc");
    if taskset_available() {
        assert_eq!(n, "1", "pinned to CPU 0:\n{masked}");
        assert_eq!(field(&masked, "online"), "0");
    }
    assert_eq!(field(&masked, "processors"), n, "{masked}");
    assert_eq!(field(&masked, "statcpus"), n, "{masked}");
    assert_eq!(field(&masked, "model"), "Virtual CPU");
    let host = host_model();
    if !host.is_empty() {
        assert!(!masked.contains(&host), "host CPU model leaked:\n{masked}");
    }
    assert_eq!(field(&masked, "loadavg"), "0.00 0.00 0.00 1/1 1");

    // cgroup: its own namespace, and none of the host's units.
    assert_eq!(field(&masked, "cgroup"), "0::/");
    let fs = field(&masked, "cgroupfs");
    for unit in [".slice", ".scope", ".service"] {
        assert!(!fs.contains(unit), "host cgroup units visible: {fs}");
    }

    // DMI hidden; machine-id is the jail's, not the host's.
    assert_eq!(field(&masked, "dmi"), "0");
    if let Ok(host_id) = std::fs::read_to_string("/etc/machine-id") {
        let id = field(&masked, "machineid");
        assert_eq!(id.len(), 32, "{masked}");
        assert_ne!(id, host_id.trim(), "host machine-id leaked");
    }
}

#[test]
fn without_mask_host_the_jail_reads_the_real_host() {
    require_bwrap!();
    let plain = stdout(&jail(false, PROBE));
    let host = host_model();
    if !host.is_empty() {
        assert_eq!(field(&plain, "model"), host);
    }
    assert_ne!(field(&plain, "cgroup"), "0::/");
}

#[test]
fn mask_host_sizes_meminfo_to_a_memory_limit() {
    require_bwrap!();
    // A transient user scope stands in for any memory cap the jail is
    // launched under; skip where there is no systemd user manager.
    let probe = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "MemoryMax=512M",
            "true",
        ])
        .output();
    if !probe.is_ok_and(|o| o.status.success()) {
        eprintln!("SKIPPED: no systemd user scope available");
        return;
    }
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let out = Command::new("systemd-run")
        .args(["--user", "--scope", "--quiet", "-p", "MemoryMax=512M"])
        .arg(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--no-ssh",
            "--no-gpu",
            "--no-docker",
            "--no-display",
            "--no-status-bar",
            "--mask-host",
            "sh",
            "-c",
            "awk '/^MemTotal:/ {print \"memtotal=\" $2}' /proc/meminfo",
        ])
        .output()
        .expect("failed to spawn ai-jail");
    let text = stdout(&out);
    assert_eq!(field(&text, "memtotal"), "524288", "{text}");
}

/// `/proc/uptime` inside a masked jail: "SECONDS IDLE".
fn uptime_pair(text: &str) -> (f64, f64) {
    let mut it = text.split_whitespace().map(|v| v.parse::<f64>().unwrap());
    (it.next().unwrap(), it.next().unwrap())
}

#[test]
fn mask_host_uptime_counts_from_the_jail_start() {
    require_bwrap!();
    let host = std::fs::read_to_string("/proc/uptime").unwrap();
    let (host_up, _) = uptime_pair(&host);
    let out = stdout(&jail(
        true,
        "cat /proc/uptime; sleep 2.2; cat /proc/uptime; uptime >/dev/null && echo uptime_rc=0",
    ));
    let lines: Vec<&str> = out.lines().collect();
    let (first, first_idle) = uptime_pair(lines[0]);
    let (second, second_idle) = uptime_pair(lines[1]);
    // The jail's own age, not the host's: a few seconds at most.
    assert!(first < 10.0, "uptime is the host's ({host_up}):\n{out}");
    assert!(host_up > 30.0 || first < host_up, "{out}");
    // Live: it advances while the jail runs.
    assert!(second >= first + 1.0, "uptime did not advance:\n{out}");
    // Idle counts every jail CPU as idle (pinned to one CPU here).
    if taskset_available() {
        assert!((first_idle - first).abs() < 0.02, "{out}");
        assert!((second_idle - second).abs() < 0.02, "{out}");
    }
    assert_eq!(field(&out, "uptime_rc"), "0");
}
