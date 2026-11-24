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

#[test]
fn mask_host_follows_the_stack_limits_and_keeps_the_id_per_state_root() {
    require_bwrap!();
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
    if std::thread::available_parallelism().map_or(1, |n| n.get()) < 4 {
        eprintln!("SKIPPED: needs CPUs 2-3");
        return;
    }
    let root = std::env::temp_dir()
        .join(format!("ai-jail-mask-host-state.{}", std::process::id()));
    let run = || {
        let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        Command::new(ai_jail())
            .args([
                "--clean",
                "--no-save-config",
                "--no-ssh",
                "--no-gpu",
                "--no-docker",
                "--no-display",
                "--no-status-bar",
                "--memory",
                "512M",
                "--cpu-quota",
                "100%",
                "--cpus",
                "2-3",
                "--mask-host",
                "--state-root",
            ])
            .arg(&root)
            .args(["sh", "-c", PROBE])
            .output()
            .expect("failed to spawn ai-jail")
    };
    let first = stdout(&run());
    // --cpus 2-3 trimmed to a 100% quota: one CPU, keeping its number.
    assert_eq!(field(&first, "online"), "2", "{first}");
    assert_eq!(field(&first, "processors"), "1", "{first}");
    assert_eq!(field(&first, "memtotal"), "524288", "{first}");
    assert_eq!(field(&first, "cgroup"), "0::/");
    let id = field(&first, "machineid").to_string();
    assert_eq!(id.len(), 32, "{first}");
    let second = stdout(&run());
    assert_eq!(field(&second, "machineid"), id, "one id per state root");
    let _ = std::fs::remove_dir_all(&root);
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

const IDENTITY_PROBE: &str = r#"
echo "version=$(cat /proc/version)"
echo "osrelease=$(cat /proc/sys/kernel/osrelease)"
echo "osid=$(. /etc/os-release; echo "$ID")"
echo "swaps=$(wc -l < /proc/swaps)"
echo "crypttab=$(wc -c < /etc/crypttab 2>/dev/null || echo absent)"
echo "partitions=$(wc -c < /proc/partitions)"
echo "sysblock=$(ls /sys/block | wc -l)"
echo "modules=$(ls /usr/lib/modules 2>/dev/null | wc -l)"
echo "bootid=$(cat /proc/sys/kernel/random/boot_id)"
echo "lscpu_threads=$(lscpu 2>/dev/null | awk -F: '/^Thread\(s\) per core/ {gsub(/ /,"",$2); print $2}')"
echo "quiet_env=${AI_JAIL_QUIET:-unset}"
echo "procstart=$(awk '{print $22}' /proc/self/stat)"
echo "clk_tck=$(getconf CLK_TCK)"
"#;

#[test]
fn mask_host_hides_the_kernel_build_distribution_and_disks() {
    require_bwrap!();
    let out = stdout(&jail(true, IDENTITY_PROBE));
    let release = field(&out, "osrelease");
    assert!(
        release.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "kernel suffix leaked: {release}"
    );
    let version = field(&out, "version");
    assert!(
        version.starts_with(&format!("Linux version {release} #")),
        "{version:?}"
    );
    for leak in ["(", "@", "gcc", "clang", ":"] {
        assert!(!version.contains(leak), "build detail in {version:?}");
    }
    assert_eq!(field(&out, "osid"), "linux");
    assert_eq!(field(&out, "swaps"), "1", "{out}");
    let crypttab = field(&out, "crypttab");
    assert!(crypttab == "0" || crypttab == "absent", "{out}");
    assert_eq!(field(&out, "partitions"), "0", "{out}");
    assert_eq!(field(&out, "sysblock"), "0", "{out}");
    assert_eq!(field(&out, "modules"), "0", "{out}");
    let host_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default();
    assert_ne!(field(&out, "bootid"), host_boot.trim());
    let threads = field(&out, "lscpu_threads");
    assert!(threads.is_empty() || threads == "1", "{out}");
}

#[test]
fn mask_host_starts_the_boot_clock_at_the_jail() {
    require_bwrap!();
    if !std::path::Path::new("/proc/self/ns/time").exists() {
        eprintln!("SKIPPED: no time namespaces in this kernel");
        return;
    }
    let out = stdout(&jail(true, IDENTITY_PROBE));
    // A process's start time is counted in ticks since boot, in the time
    // namespace's own boot clock.
    let start: f64 = field(&out, "procstart").parse().unwrap();
    let tck: f64 = field(&out, "clk_tck").parse().unwrap();
    assert!(start / tck < 60.0, "boot clock is the host's:\n{out}");
}

#[test]
fn the_agent_does_not_inherit_the_quiet_marker() {
    require_bwrap!();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let out = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--no-ssh",
            "--no-gpu",
            "--no-docker",
            "--no-display",
            "--no-status-bar",
            "--exec",
            "sh",
            "-c",
            "echo quiet_env=${AI_JAIL_QUIET:-unset}",
        ])
        .output()
        .expect("failed to spawn ai-jail");
    assert_eq!(field(&stdout(&out), "quiet_env"), "unset");
}

#[test]
fn overlay_system_hides_the_disk_behind_the_system_trees() {
    require_bwrap!();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let script = r#"
awk '$5=="/usr" || $5=="/etc" {print "src" $5 "=" $(NF-1)}' /proc/self/mountinfo
echo "hosts=$(wc -c < /etc/hosts)"
echo "crypttab=$(wc -c < /etc/crypttab 2>/dev/null || echo absent)"
echo "usrmode=$(stat -c %a /usr)"
git --version >/dev/null && echo git=ok
"#;
    let out = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--no-ssh",
            "--no-gpu",
            "--no-docker",
            "--no-display",
            "--no-status-bar",
            "--mask-host",
            "--overlay-system",
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("failed to spawn ai-jail");
    let text = stdout(&out);
    assert_eq!(field(&text, "src/usr"), "overlay", "{text}");
    assert_eq!(field(&text, "src/etc"), "overlay", "{text}");
    // Binds made inside /etc after the base mounts still land on top.
    assert_ne!(field(&text, "hosts"), "0", "{text}");
    let crypttab = field(&text, "crypttab");
    assert!(crypttab == "0" || crypttab == "absent", "{text}");
    assert_eq!(field(&text, "usrmode"), "755", "{text}");
    assert_eq!(field(&text, "git"), "ok", "{text}");
}

#[test]
fn overlay_system_alone_is_refused() {
    let out = Command::new(ai_jail())
        .args(["--clean", "--no-save-config", "--overlay-system", "true"])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--mask-host"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn minimal_etc_keeps_only_the_allowlist_and_the_tools_working() {
    require_bwrap!();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let script = r#"
echo "count=$(ls -A /etc | wc -l)"
for f in passwd hosts fstab crypttab portage shadow; do
  if [ -e /etc/$f ] || [ -L /etc/$f ]; then echo "$f=present"; else echo "$f=absent"; fi
done
echo "hosts_size=$(wc -c < /etc/hosts)"
echo "etc_hostname=$(cat /etc/hostname 2>/dev/null || echo none)"
echo "user=$(id -un 2>/dev/null || echo none)"
echo "src=$(awk '$5=="/etc" {print $(NF-2)}' /proc/self/mountinfo | tail -1)"
touch /etc/probe 2>/dev/null && echo writable=yes || echo writable=no
if [ -L /etc/localtime ]; then [ -e /etc/localtime ] && echo tz=ok || echo tz=dangling; else echo tz=ok; fi
git --version >/dev/null && echo git=ok
sh -lc 'echo login=ok'
"#;
    let out = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--no-ssh",
            "--no-gpu",
            "--no-docker",
            "--no-display",
            "--no-status-bar",
            "--mask-host",
            "--minimal-etc",
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("failed to spawn ai-jail");
    let text = stdout(&out);
    let host_count = std::fs::read_dir("/etc").map_or(0, Iterator::count);
    let count: usize = field(&text, "count").parse().unwrap();
    assert!(count < host_count || host_count < 40, "{count}: {text}");
    for absent in ["fstab", "crypttab", "portage", "shadow"] {
        assert_eq!(field(&text, absent), "absent", "{absent}: {text}");
    }
    // Not the host's: the sandbox's own, bound over the tmpfs.
    if std::path::Path::new("/etc/hostname").exists() {
        assert_eq!(field(&text, "etc_hostname"), "ai-sandbox", "{text}");
    }
    if std::path::Path::new("/etc/passwd").exists() {
        assert_eq!(field(&text, "passwd"), "present", "{text}");
        assert_ne!(field(&text, "user"), "none", "{text}");
    }
    // Binds made inside /etc after the tmpfs still land on it.
    assert_eq!(field(&text, "hosts"), "present", "{text}");
    assert_ne!(field(&text, "hosts_size"), "0", "{text}");
    assert_eq!(field(&text, "src"), "tmpfs", "{text}");
    assert_eq!(field(&text, "writable"), "no", "{text}");
    assert_eq!(field(&text, "tz"), "ok", "{text}");
    assert_eq!(field(&text, "git"), "ok", "{text}");
    assert_eq!(field(&text, "login"), "ok", "{text}");
}

#[test]
fn minimal_etc_alone_is_refused() {
    let out = Command::new(ai_jail())
        .args(["--clean", "--no-save-config", "--minimal-etc", "true"])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--minimal-etc requires --mask-host"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn hostname_names_the_jail_everywhere_it_reads_one() {
    require_bwrap!();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let script = r#"
echo "uts=$(uname -n)"
echo "etc_hostname=$(cat /etc/hostname 2>/dev/null || echo none)"
grep -q ' desktop-k3f9a2$' /etc/hosts && echo hosts=named || echo hosts=other
"#;
    let out = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--no-ssh",
            "--no-gpu",
            "--no-docker",
            "--no-display",
            "--no-status-bar",
            "--mask-host",
            "--syscall-view",
            "--hostname",
            "desktop-k3f9a2",
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("failed to spawn ai-jail");
    let text = stdout(&out);
    // uname(2) here is answered by --syscall-view, so both halves agree.
    assert_eq!(field(&text, "uts"), "desktop-k3f9a2", "{text}");
    assert_eq!(field(&text, "hosts"), "named", "{text}");
    if std::path::Path::new("/etc/hostname").exists() {
        assert_eq!(field(&text, "etc_hostname"), "desktop-k3f9a2", "{text}");
    }
}

#[test]
fn hostname_that_is_not_one_label_is_refused() {
    let out = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-save-config",
            "--hostname",
            "evil.example",
            "true",
        ])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--hostname"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
