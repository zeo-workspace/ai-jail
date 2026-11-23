use super::*;

fn ids(list: &[usize]) -> BTreeSet<usize> {
    list.iter().copied().collect()
}

fn identity() -> HostIdentity {
    HostIdentity {
        osrelease: "7.3.5-bentoo-dist".into(),
        version: "#1 SMP PREEMPT_DYNAMIC Tue Nov 17 20:32:13 -03 2026".into(),
        boot_id: "0f0e0d0c-0b0a-4908-8706-050403020100".into(),
        etc_os_release_is_file: false,
    }
}

fn planned(exists: &dyn Fn(&Path) -> bool) -> HostViewPlan {
    let mut plan = HostViewPlan::default();
    extend_plan(
        &mut plan,
        &identity(),
        &ids(&[28, 29]),
        Path::new("/v"),
        exists,
    );
    plan
}

fn file<'a>(plan: &'a HostViewPlan, name: &str) -> Option<&'a str> {
    plan.files
        .iter()
        .find(|(rel, _)| rel == Path::new(name))
        .map(|(_, text)| text.as_str())
}

fn bound_from(plan: &HostViewPlan, dest: &str) -> Option<PathBuf> {
    plan.mounts.iter().find_map(|m| match m {
        HostViewMount::File { src, dest: d } if d == Path::new(dest) => {
            Some(src.clone())
        }
        _ => None,
    })
}

fn tmpfs_at(plan: &HostViewPlan, dest: &str) -> bool {
    plan.mounts.iter().any(
        |m| matches!(m, HostViewMount::Tmpfs { dest: d } if d == Path::new(dest)),
    )
}

#[test]
fn kernel_release_keeps_only_the_number() {
    assert_eq!(kernel_release("7.3.5-bentoo-dist"), "7.3.5");
    assert_eq!(kernel_release("6.1.0-13-amd64"), "6.1.0");
    assert_eq!(kernel_release("6.8.0\n"), "6.8.0");
    assert_eq!(kernel_release("6.9.rc1-foo"), "6.9");
    assert_eq!(kernel_release(""), "0.0.0");
}

#[test]
fn kernel_version_drops_the_build_date() {
    assert_eq!(
        kernel_version("#1 SMP PREEMPT_DYNAMIC Tue Nov 17 20:32:13 -03 2026"),
        "#1 SMP PREEMPT_DYNAMIC"
    );
    assert_eq!(
        kernel_version("#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)"),
        "#1 SMP PREEMPT_DYNAMIC"
    );
    assert_eq!(kernel_version("garbage"), "#1 SMP");
}

#[test]
fn proc_version_names_no_builder_compiler_or_date() {
    let plan = planned(&|_| true);
    let text = file(&plan, "version").expect("version planned");
    assert_eq!(text, "Linux version 7.3.5 #1 SMP PREEMPT_DYNAMIC\n");
    assert_eq!(file(&plan, "osrelease"), Some("7.3.5\n"));
    assert_eq!(
        file(&plan, "kernel-version"),
        Some("#1 SMP PREEMPT_DYNAMIC\n")
    );
    assert_eq!(
        bound_from(&plan, "/proc/version"),
        Some(PathBuf::from("/v/version"))
    );
    assert_eq!(
        bound_from(&plan, "/proc/sys/kernel/osrelease"),
        Some(PathBuf::from("/v/osrelease"))
    );
}

#[test]
fn os_release_is_generic_and_bound_in_usr_lib() {
    let plan = planned(&|_| true);
    let text = file(&plan, "os-release").unwrap();
    assert!(text.contains("ID=linux\n"), "{text}");
    assert!(!text.to_lowercase().contains("gentoo"));
    assert_eq!(
        bound_from(&plan, "/usr/lib/os-release"),
        Some(PathBuf::from("/v/os-release"))
    );
    // The usual symlink is followed through /usr/lib, never bound.
    assert_eq!(bound_from(&plan, "/etc/os-release"), None);

    let mut regular = HostViewPlan::default();
    let id = HostIdentity {
        etc_os_release_is_file: true,
        ..identity()
    };
    extend_plan(&mut regular, &id, &ids(&[0]), Path::new("/v"), &|_| true);
    assert!(bound_from(&regular, "/etc/os-release").is_some());
}

#[test]
fn swaps_has_the_header_only() {
    let plan = planned(&|_| true);
    assert_eq!(file(&plan, "swaps").unwrap().lines().count(), 1);
    assert!(bound_from(&plan, "/proc/swaps").is_some());
}

#[test]
fn every_mask_is_planned_and_crypttab_is_emptied() {
    let plan = planned(&|_| true);
    assert_eq!(file(&plan, "empty"), Some(""));
    for path in FILE_MASKS {
        assert_eq!(
            bound_from(&plan, path),
            Some(PathBuf::from("/v/empty")),
            "{path}"
        );
    }
    for path in DIR_MASKS {
        assert!(tmpfs_at(&plan, path), "{path}");
    }
    assert!(FILE_MASKS.contains(&"/etc/crypttab"));
}

#[test]
fn a_path_the_host_lacks_is_skipped() {
    let missing = |p: &Path| {
        !matches!(
            p.to_str(),
            Some(
                "/etc/crypttab"
                    | "/proc/pressure"
                    | "/proc/sys/kernel/random/boot_id"
            )
        )
    };
    let plan = planned(&missing);
    assert_eq!(bound_from(&plan, "/etc/crypttab"), None);
    assert!(!tmpfs_at(&plan, "/proc/pressure"));
    assert_eq!(bound_from(&plan, "/proc/sys/kernel/random/boot_id"), None);
    assert!(bound_from(&plan, "/proc/partitions").is_some());

    let nothing = planned(&|_| false);
    assert!(nothing.mounts.is_empty(), "{:?}", nothing.mounts);
    assert_eq!(file(&nothing, "empty"), None);
}

#[test]
fn boot_id_is_a_v4_uuid() {
    let id = format_boot_id([0xff; 16]);
    assert_eq!(id.len(), 36);
    assert_eq!(&id[14..15], "4");
    assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    assert_eq!(id.matches('-').count(), 4);
    let plan = planned(&|_| true);
    assert_eq!(
        file(&plan, "boot_id"),
        Some("0f0e0d0c-0b0a-4908-8706-050403020100\n")
    );
}

#[test]
fn topology_gives_each_cpu_its_own_core_in_one_package() {
    let files = topology_files(&ids(&[28, 29]));
    let get = |name: &str| {
        files
            .iter()
            .find(|(rel, _)| rel == name)
            .map(|(_, t)| t.as_str())
            .unwrap_or_else(|| panic!("{name} missing"))
    };
    assert_eq!(get("cpu/cpu28/topology/core_id"), "0\n");
    assert_eq!(get("cpu/cpu29/topology/core_id"), "1\n");
    assert_eq!(get("cpu/cpu29/topology/thread_siblings_list"), "29\n");
    assert_eq!(get("cpu/cpu28/topology/core_siblings_list"), "28-29\n");
    assert_eq!(get("cpu/cpu28/topology/physical_package_id"), "0\n");
    assert_eq!(get("cpu/cpu29/topology/thread_siblings"), "20000000\n");
    assert_eq!(get("cpu/cpu28/topology/core_siblings"), "30000000\n");
    let plan = planned(&|_| true);
    assert!(file(&plan, "cpu/cpu29/topology/package_cpus_list").is_some());
}

#[test]
fn overlay_puts_the_real_tree_above_an_empty_layer() {
    let only_usr = |p: &Path| p == Path::new("/usr");
    let mounts = overlay_mounts(Path::new("/v"), &only_usr);
    assert_eq!(
        mounts,
        vec![HostViewMount::RoOverlay {
            lower: "/usr".into(),
            empty: "/v/overlay-empty".into(),
            dest: "/usr".into(),
        }]
    );
    assert_eq!(overlay_mounts(Path::new("/v"), &|_| true).len(), 3);
}

#[test]
fn timens_offsets_start_both_clocks_at_one_second() {
    let text = timens_offsets(
        Duration::new(5000, 0),
        Duration::new(7000, 250_000_000),
    );
    assert_eq!(
        text, "monotonic -4999 0\nboottime -7000 750000000\n",
        "offset + now must be 1 s"
    );
    // A fresh clock (under a second) still yields a valid offset.
    assert_eq!(
        timens_offsets(Duration::ZERO, Duration::from_millis(500)),
        "monotonic 1 0\nboottime 0 500000000\n"
    );
}

#[test]
fn live_meminfo_keeps_one_length_as_usage_moves() {
    let host = "MemTotal: 1 kB\nMemFree: 1 kB\nMemAvailable: 1 kB\n";
    for memory in [8u64 << 30, 512 << 30, 3 << 20] {
        let len = synth::meminfo(memory, 0, Some(0), host).len();
        for used in [1u64, 1 << 20, memory / 2, memory, memory * 2] {
            assert_eq!(
                synth::meminfo(memory, used, Some(0), host).len(),
                len,
                "memory {memory} used {used}"
            );
        }
    }
}

#[test]
fn cpu_mask_is_the_kernels_bitmap_format() {
    assert_eq!(cpu_mask(&ids(&[0])), "00000001\n");
    assert_eq!(cpu_mask(&ids(&[0, 1, 31])), "80000003\n");
    assert_eq!(cpu_mask(&ids(&[32, 33])), "00000003,00000000\n");
}
