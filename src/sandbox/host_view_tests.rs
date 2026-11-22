use super::*;

fn ids(list: &[usize]) -> BTreeSet<usize> {
    list.iter().copied().collect()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ai-jail-host-view-test.{tag}.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A 32-CPU host with a 4-CPU / 8 GiB scope, as Zeo's jail runs.
fn limited_host() -> HostSnapshot {
    HostSnapshot {
        host_cpus: (0..32).collect(),
        affinity: Some((0..32).collect()),
        cgroup_dir: Some("/sys/fs/cgroup/app.slice/ai-jail-1.scope".into()),
        quota_cpus: Some(4),
        memory_max: Some(8 << 30),
        memory_current: 1 << 30,
        swap_max: Some(0),
        cpuinfo: "processor\t: 0\nmodel name\t: Big Host CPU\nflags\t\t: fpu avx2\n".into(),
        meminfo: "MemTotal:       63421728 kB\nMemFree:        1 kB\nSwapTotal:      2 kB\n".into(),
        btime: 1_700_000_000,
    }
}

fn everything_exists(_: &Path) -> bool {
    true
}

fn file<'a>(plan: &'a HostViewPlan, name: &str) -> &'a str {
    plan.files
        .iter()
        .find(|(rel, _)| rel == Path::new(name))
        .map(|(_, text)| text.as_str())
        .unwrap_or_else(|| panic!("{name} not planned: {:?}", plan.files))
}

fn dests(plan: &HostViewPlan) -> Vec<String> {
    plan.mounts
        .iter()
        .map(|m| match m {
            HostViewMount::File { dest, .. }
            | HostViewMount::Dir { dest, .. }
            | HostViewMount::Tmpfs { dest } => dest.display().to_string(),
        })
        .collect()
}

#[test]
fn plan_sizes_every_file_to_the_cgroup_limits() {
    let dir = Path::new("/tmp/view");
    let plan = plan(
        &limited_host(),
        &HostViewRequest::default(),
        "0123456789abcdef0123456789abcdef",
        dir,
        &everything_exists,
    );
    assert_eq!(file(&plan, "cpu/online"), "0-3\n");
    assert_eq!(file(&plan, "cpu/possible"), "0-3\n");
    assert_eq!(file(&plan, "cpu/present"), "0-3\n");
    assert_eq!(file(&plan, "cpu/cpu3/online"), "1\n");
    assert!(
        !plan
            .files
            .iter()
            .any(|(r, _)| r == Path::new("cpu/cpu4/online"))
    );
    assert_eq!(file(&plan, "cpuinfo").matches("processor\t: ").count(), 4);
    assert!(!file(&plan, "cpuinfo").contains("Big Host"));
    assert!(file(&plan, "meminfo").contains("MemTotal:        8388608 kB"));
    assert_eq!(
        file(&plan, "stat")
            .lines()
            .filter(|l| l.starts_with("cpu"))
            .count(),
        5
    );
    assert_eq!(
        file(&plan, "machine-id"),
        "0123456789abcdef0123456789abcdef\n"
    );
    assert!(plan.mounts.contains(&HostViewMount::File {
        src: dir.join("cpuinfo"),
        dest: "/proc/cpuinfo".into(),
    }));
    assert!(plan.mounts.contains(&HostViewMount::Dir {
        src: dir.join("cpu"),
        dest: "/sys/devices/system/cpu".into(),
    }));
    assert!(plan.mounts.contains(&HostViewMount::Dir {
        src: "/sys/fs/cgroup/app.slice/ai-jail-1.scope".into(),
        dest: "/sys/fs/cgroup".into(),
    }));
    let all = dests(&plan);
    for dest in [
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/stat",
        "/proc/loadavg",
        "/sys/devices/system/cpu",
        "/sys/fs/cgroup",
        "/sys/class/dmi",
        "/sys/devices/virtual/dmi",
        "/etc/machine-id",
    ] {
        assert!(
            all.contains(&dest.to_string()),
            "{dest} missing from {all:?}"
        );
    }
}

#[test]
fn explicit_cpus_win_over_affinity_and_keep_their_numbers() {
    let pinned = ids(&[28, 29, 30, 31]);
    let request = HostViewRequest {
        cpus: Some(pinned),
        machine_id_file: None,
    };
    let plan = plan(
        &limited_host(),
        &request,
        "1",
        Path::new("/v"),
        &everything_exists,
    );
    assert_eq!(file(&plan, "cpu/online"), "28-31\n");
    assert!(file(&plan, "cpuinfo").contains("processor\t: 28\n"));
}

#[test]
fn affinity_sizes_the_view_when_no_quota_applies() {
    let snap = HostSnapshot {
        quota_cpus: None,
        affinity: Some(ids(&[2, 3])),
        ..limited_host()
    };
    let plan = plan(
        &snap,
        &HostViewRequest::default(),
        "1",
        Path::new("/v"),
        &everything_exists,
    );
    assert_eq!(file(&plan, "cpu/online"), "2-3\n");
}

#[test]
fn without_a_memory_limit_meminfo_stays_the_hosts() {
    let snap = HostSnapshot {
        memory_max: None,
        ..limited_host()
    };
    let plan = plan(
        &snap,
        &HostViewRequest::default(),
        "1",
        Path::new("/v"),
        &everything_exists,
    );
    assert!(!plan.files.iter().any(|(r, _)| r == Path::new("meminfo")));
    assert!(!dests(&plan).contains(&"/proc/meminfo".to_string()));
    // The CPU model is generic with or without limits.
    assert!(!file(&plan, "cpuinfo").contains("Big Host"));
}

#[test]
fn no_readable_cgroup_hides_the_tree_with_a_tmpfs() {
    let snap = HostSnapshot {
        cgroup_dir: None,
        ..limited_host()
    };
    let plan = plan(
        &snap,
        &HostViewRequest::default(),
        "1",
        Path::new("/v"),
        &everything_exists,
    );
    assert!(plan.mounts.contains(&HostViewMount::Tmpfs {
        dest: "/sys/fs/cgroup".into()
    }));
}

#[test]
fn mount_points_the_host_lacks_are_skipped() {
    let only_proc = |p: &Path| p.starts_with("/proc");
    let snap = HostSnapshot {
        cgroup_dir: None,
        ..limited_host()
    };
    let plan = plan(
        &snap,
        &HostViewRequest::default(),
        "1",
        Path::new("/v"),
        &only_proc,
    );
    let all = dests(&plan);
    for absent in [
        "/sys/devices/system/cpu",
        "/sys/fs/cgroup",
        "/sys/class/dmi",
        "/sys/devices/virtual/dmi",
        "/etc/machine-id",
    ] {
        assert!(!all.contains(&absent.to_string()), "{absent} in {all:?}");
    }
    assert!(all.contains(&"/proc/cpuinfo".to_string()));
}

#[test]
fn machine_ids_are_systemd_shaped() {
    let id = machine_id(None, false).unwrap();
    assert!(valid_machine_id(&id), "{id}");
    assert_ne!(id, machine_id(None, false).unwrap());
    assert!(!valid_machine_id("0".repeat(32).as_str()));
    assert!(!valid_machine_id("ABCDEF0123456789abcdef0123456789"));
    assert!(!valid_machine_id("abc"));
}

#[test]
fn a_stored_machine_id_is_created_once_then_reused() {
    let dir = scratch("store");
    let store = dir.join("machine-id");
    let dry = machine_id(Some(&store), false).unwrap();
    assert!(valid_machine_id(&dry));
    assert!(!store.exists(), "a dry run must not create the store");
    let first = machine_id(Some(&store), true).unwrap();
    let second = machine_id(Some(&store), true).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        std::fs::read_to_string(&store).unwrap(),
        format!("{first}\n")
    );
    let mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::write(&store, "not an id\n").unwrap();
    let third = machine_id(Some(&store), true).unwrap();
    assert_ne!(third, first);
    assert!(valid_machine_id(&third));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_symlinked_machine_id_store_is_refused() {
    let dir = scratch("symlink");
    let target = dir.join("elsewhere");
    std::fs::write(&target, "0123456789abcdef0123456789abcdef\n").unwrap();
    let link = dir.join("machine-id");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = machine_id(Some(&link), true).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_written_view_is_read_only_and_removed_on_drop() {
    let view = HostView::create(HostViewRequest::default(), true).unwrap();
    let dir = view.dir.clone();
    let cpuinfo = dir.join("cpuinfo");
    let text = std::fs::read_to_string(&cpuinfo).unwrap();
    assert!(text.contains(synth::VIRTUAL_CPU_MODEL));
    let mode =
        std::fs::metadata(&cpuinfo).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o444);
    let dir_mode =
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    drop(view);
    assert!(!dir.exists());
}

#[test]
fn a_dry_run_view_writes_nothing() {
    let view = HostView::create(HostViewRequest::default(), false).unwrap();
    assert!(!view.dir.exists());
    assert!(!view.mounts().is_empty());
}
