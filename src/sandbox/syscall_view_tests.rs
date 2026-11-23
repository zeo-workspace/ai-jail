use super::*;

fn answers() -> Answers {
    Answers {
        release: "7.3.5".into(),
        version: "#1 SMP PREEMPT_DYNAMIC".into(),
        machine: "x86_64".into(),
        cgroup_dir: None,
        memory_max: Some(8 << 30),
        swap_max: Some(0),
    }
}

fn field(bytes: &[u8], i: usize) -> &str {
    let f = &bytes[i * UTS_FIELD..(i + 1) * UTS_FIELD];
    let end = f.iter().position(|b| *b == 0).unwrap();
    std::str::from_utf8(&f[..end]).unwrap()
}

#[test]
fn utsname_names_the_jail_and_the_cleaned_kernel() {
    let bytes = utsname_bytes(&answers());
    assert_eq!(bytes.len(), 390);
    assert_eq!(field(&bytes, 0), "Linux");
    assert_eq!(field(&bytes, 1), "ai-sandbox");
    assert_eq!(field(&bytes, 2), "7.3.5");
    assert_eq!(field(&bytes, 3), "#1 SMP PREEMPT_DYNAMIC");
    assert_eq!(field(&bytes, 4), "x86_64");
    assert_eq!(field(&bytes, 5), "(none)");
}

#[test]
fn utsname_cuts_a_long_value_and_keeps_its_terminator() {
    let a = Answers {
        version: "x".repeat(200),
        ..answers()
    };
    let bytes = utsname_bytes(&a);
    assert_eq!(field(&bytes, 3).len(), 64);
    assert_eq!(field(&bytes, 4), "x86_64");
}

fn host() -> libc::sysinfo {
    // SAFETY: zeroed is a valid sysinfo.
    let mut h: libc::sysinfo = unsafe { std::mem::zeroed() };
    h.uptime = 999_999;
    h.loads = [70_000, 60_000, 50_000];
    h.totalram = 64 << 20;
    h.freeram = 10 << 20;
    h.totalswap = 4 << 20;
    h.freeswap = 3 << 20;
    h.procs = 900;
    h.mem_unit = 1024;
    h
}

#[test]
fn sysinfo_is_sized_to_the_limits_and_aged_from_the_jail() {
    let info = sysinfo_for(
        &host(),
        Duration::from_secs(42),
        &answers(),
        Some(1 << 30),
        Some(12),
    );
    assert_eq!(info.uptime, 42);
    assert_eq!(info.loads, [0; 3]);
    assert_eq!(info.mem_unit, 1);
    assert_eq!(info.totalram, 8 << 30);
    assert_eq!(info.freeram, 7 << 30);
    assert_eq!((info.totalswap, info.freeswap), (0, 0));
    assert_eq!(info.procs, 12);
}

#[test]
fn sysinfo_keeps_the_hosts_sizes_without_a_limit_in_bytes() {
    let a = Answers {
        memory_max: None,
        swap_max: None,
        ..answers()
    };
    let info = sysinfo_for(&host(), Duration::from_secs(1), &a, None, None);
    assert_eq!(info.mem_unit, 1);
    assert_eq!(info.totalram, (64 << 20) * 1024);
    assert_eq!(info.freeswap, (3 << 20) * 1024);
    assert_eq!(info.procs, 900, "no pids.current: the host's count stays");
    assert_eq!(info.uptime, 1);
}

#[test]
fn sysinfo_never_reports_more_used_than_the_limit() {
    let info =
        sysinfo_for(&host(), Duration::ZERO, &answers(), Some(20 << 30), None);
    assert_eq!(info.freeram, 0);
}

#[test]
fn the_filter_traps_only_uname_and_sysinfo_of_this_architecture() {
    let p = notify_program();
    assert_eq!(p.len(), 7);
    assert_eq!(p[1].k, NATIVE_ARCH);
    assert_eq!(p[3].k, libc::SYS_uname as u32);
    assert_eq!(p[4].k, libc::SYS_sysinfo as u32);
    assert_eq!(p[5].k, libc::SECCOMP_RET_USER_NOTIF);
    assert_eq!(p[6].k, libc::SECCOMP_RET_ALLOW);
    // Every jump lands inside the program: on a foreign arch at ALLOW,
    // on uname at NOTIFY, on sysinfo at NOTIFY, on anything else at ALLOW.
    assert_eq!(1 + 1 + usize::from(p[1].jf), 6);
    assert_eq!(3 + 1 + usize::from(p[3].jt), 5);
    assert_eq!(4 + 1 + usize::from(p[4].jt), 5);
    assert_eq!(4 + 1 + usize::from(p[4].jf), 6);
}
