// Story 047, Task 4.3 — behaviour that exists only where the story's
// branches meet the fork's others on `integration`: a profile widening a
// field another branch added, and an explicit `--rlimit fsize` reaching
// story 046's exit explanation. Kept in its own file so the upstream
// candidates' suites (`tests/profiles.rs`, `tests/rlimit_values.rs`)
// stay byte-identical to their branches.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// A temporary HOME and XDG_CONFIG_HOME whose trusted global config is
/// `global`, plus an empty project directory to launch from.
struct GlobalTree {
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
}

impl GlobalTree {
    fn new(name: &str, global: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("aj047-int-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        let store = xdg.join("ai-jail");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let config = store.join("config.toml");
        std::fs::write(&config, global).unwrap();
        std::fs::set_permissions(
            &config,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    fn dry_run(&self, flags: &[&str]) -> Output {
        Command::new(ai_jail())
            .args(["--no-status-bar", "--no-save-config"])
            .args(flags)
            .args(["--dry-run", "bash"])
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run ai-jail")
    }
}

impl Drop for GlobalTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A loopback port nothing listens on right now: `--publish-port` binds
/// it even under `--dry-run`.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn profile_widening_lines_name_every_new_field() {
    let port = free_port();
    // The trusted base pins CPU 0; the profile asks for more CPUs, a
    // looser nofile and a published port. Each is a widening the
    // operator must see, named with the profile and its field.
    let global = format!(
        "cpus = \"0\"\n\n\
         [profiles.agent-test]\n\
         profile_version = 1\n\
         cpus = \"0-1\"\n\
         publish_ports = [{port}]\n\
         [profiles.agent-test.rlimit]\n\
         nofile = \"unlimited\"\n"
    );
    let tree = GlobalTree::new("widen", &global);
    let out = tree.dry_run(&["--profile", "agent-test"]);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "stderr: {stderr}\nstdout: {stdout}");
    let lines: Vec<&str> =
        stderr.lines().filter(|l| l.contains("widens=")).collect();
    for field in ["rlimit", "publish_ports", "cpus"] {
        let needle = format!("profile=agent-test widens={field} ");
        assert!(
            lines.iter().any(|l| l.contains(&needle)),
            "no widening line for {field}: {lines:?}"
        );
    }
    assert!(
        lines.iter().all(|l| l.contains("profile=agent-test ")),
        "a widening line without its profile: {lines:?}"
    );
    // The profile's limit is labelled as the profile's, not as global.
    let all = format!("{stdout}{stderr}");
    let nofile = all
        .lines()
        .find(|l| l.starts_with("rlimit name=nofile "))
        .unwrap_or_else(|| panic!("no nofile dry-run line: {all}"));
    // `unlimited` sits above the supervisor's own `nofile`, so the line
    // also carries `ceiling=supervisor` after the source.
    assert!(nofile.contains(" source=profile"), "{nofile}");
    assert!(nofile.ends_with(" ceiling=supervisor"), "{nofile}");
}

#[test]
fn rlimit_fsize_death_names_the_limit_in_the_exit_explanation() {
    require_bwrap_net!();
    // `exec` so the sandboxed command itself dies of SIGXFSZ (153).
    let out = common::run_in(
        None,
        &["--no-network", "--rlimit", "fsize=1M"],
        "exec head -c 2097152 /dev/zero > /tmp/aj047.big",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(153), "{stderr}");
    assert!(
        stderr.contains("the file-size rlimit was reached (1.0 MiB)"),
        "the explanation must quote the explicit limit: {stderr}"
    );
}
