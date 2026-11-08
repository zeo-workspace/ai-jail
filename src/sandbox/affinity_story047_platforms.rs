// Story 047, Task 6.1 — the Linux-only limit and affinity code is reached
// only from code compiled on Linux (R3.20; design.md §C6 "Platforms (v5)").
//
// Materialization: append this whole file to the end of
// `src/sandbox/affinity.rs` on `feat/adjustable-rlimits`.
//
// Why a source trace: this host has no darwin target, so the macOS build
// upstream CI runs cannot be compiled here. `apply_cpus`, `validate_cpus` and
// `apply_sandbox` are `#[cfg(target_os = "linux")]` with no stub elsewhere,
// so the macOS compiler demands that every reference to them sits under a
// Linux cfg too. The trace reads every file reachable from `src/main.rs`
// (located through `CARGO_MANIFEST_DIR`) and checks exactly that.
//
// The parser is deliberately small:
// - comments, string and char literals are skipped, so a name in a comment
//   or a message is not a reference; strings inside attributes are kept;
// - an outer attribute covers the next item, block or statement: it ends at
//   `;`, at `,` outside `()`, `[]` and `<>`, or when the first `{` it opened
//   closes (so an `else` after a gated `if` reads as ungated — a false red,
//   never a false green);
// - `#![...]` covers the enclosing block or file; `mod x;` hands its flags
//   to `x.rs` or `x/mod.rs`;
// - "Linux" is a `cfg(...)` naming `target_os = "linux"` with no `not(` or
//   `any(`; "test" is `#[test]`, or a `cfg(...)` naming `test` with neither;
// - a name right after `fn` is the definition, not a reference.
#[cfg(test)]
mod affinity_platforms_tests {
    use std::path::{Path, PathBuf};

    const LINUX_ONLY: [&str; 3] =
        ["apply_cpus", "validate_cpus", "apply_sandbox"];

    #[derive(Clone, Copy, Default, Debug, PartialEq)]
    struct CfgFlags {
        linux: bool,
        test: bool,
    }

    impl CfgFlags {
        fn or(self, o: CfgFlags) -> CfgFlags {
            CfgFlags {
                linux: self.linux || o.linux,
                test: self.test || o.test,
            }
        }
    }

    enum Tok {
        Ident(String, usize),
        Punct(char),
        Attr(String, bool),
    }

    struct LinuxOnlyRef {
        name: String,
        line: usize,
        flags: CfgFlags,
    }

    /// End of the string literal (any prefix, raw or not) starting at `i`.
    fn string_end(c: &[char], i: usize) -> Option<usize> {
        let at = |k: usize| c.get(k).copied().unwrap_or('\0');
        let mut j = i;
        if at(j) == 'b' || at(j) == 'c' {
            j += 1;
        }
        let raw = at(j) == 'r';
        let mut hashes = 0;
        if raw {
            j += 1;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
        }
        if at(j) != '"' {
            return None;
        }
        j += 1;
        while j < c.len() {
            if !raw && c[j] == '\\' {
                j += 2;
            } else if c[j] == '"' && (j + 1..=j + hashes).all(|k| at(k) == '#')
            {
                return Some(j + 1 + hashes);
            } else {
                j += 1;
            }
        }
        Some(c.len())
    }

    fn lex(src: &str) -> Vec<Tok> {
        let c: Vec<char> = src.chars().collect();
        let at = |k: usize| c.get(k).copied().unwrap_or('\0');
        let lines =
            |a: usize, b: usize| c[a..b].iter().filter(|&&x| x == '\n').count();
        let (mut i, mut line, mut out) = (0, 1, Vec::new());
        while i < c.len() {
            let ch = c[i];
            if let Some(end) = string_end(&c, i) {
                line += lines(i, end);
                i = end;
            } else if ch == '/' && at(i + 1) == '/' {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            } else if ch == '/' && at(i + 1) == '*' {
                let (start, mut depth) = (i, 0);
                while i < c.len() {
                    if at(i) == '/' && at(i + 1) == '*' {
                        depth += 1;
                        i += 2;
                    } else if at(i) == '*' && at(i + 1) == '/' {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                line += lines(start, i.min(c.len()));
            } else if ch == '#'
                && (at(i + 1) == '[' || (at(i + 1) == '!' && at(i + 2) == '['))
            {
                let inner = at(i + 1) == '!';
                let open = if inner { i + 2 } else { i + 1 };
                let (mut j, mut depth) = (open, 0);
                while j < c.len() {
                    if let Some(end) = string_end(&c, j) {
                        j = end;
                        continue;
                    }
                    depth += match c[j] {
                        '[' => 1,
                        ']' => -1,
                        _ => 0,
                    };
                    j += 1;
                    if depth == 0 {
                        break;
                    }
                }
                let text: String = c[open + 1..j - 1].iter().collect();
                out.push(Tok::Attr(text, inner));
                line += lines(i, j);
                i = j;
            } else if ch == '\'' {
                // char literal, or a lifetime (skip just the quote)
                if at(i + 1) == '\\' {
                    i += 3;
                    while i < c.len() && c[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else if at(i + 2) == '\'' {
                    i += 3;
                } else {
                    i += 1;
                }
            } else if ch.is_alphanumeric() || ch == '_' {
                let start = i;
                while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                out.push(Tok::Ident(c[start..i].iter().collect(), line));
            } else if (ch == '-' || ch == '=') && at(i + 1) == '>' {
                i += 2; // `->` and `=>` are arrows, not a closing `>`
            } else {
                if ch == '\n' {
                    line += 1;
                } else if !ch.is_whitespace() {
                    out.push(Tok::Punct(ch));
                }
                i += 1;
            }
        }
        out
    }

    fn attr_flags(text: &str) -> CfgFlags {
        let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let cfg =
            t.starts_with("cfg(") && !t.contains("not(") && !t.contains("any(");
        let mut words = t.split(|c: char| !(c.is_alphanumeric() || c == '_'));
        CfgFlags {
            linux: cfg && t.contains("target_os=\"linux\""),
            test: t == "test" || (cfg && words.any(|w| w == "test")),
        }
    }

    /// References to the Linux-only names, and the `mod x;` declarations,
    /// each with the cfg flags in force where it appears.
    fn scan_linux_only_refs(
        src: &str,
        file: CfgFlags,
    ) -> (Vec<LinuxOnlyRef>, Vec<(String, CfgFlags)>) {
        let toks = lex(src);
        let mut stack = vec![(file, 0usize)]; // (flags, open brackets)
        let mut pending = CfgFlags::default();
        let (mut refs, mut mods) = (Vec::new(), Vec::new());
        for (k, tok) in toks.iter().enumerate() {
            let top = stack.len() - 1;
            let here = stack[top].0.or(pending);
            match tok {
                Tok::Attr(text, true) => {
                    stack[top].0 = stack[top].0.or(attr_flags(text))
                }
                Tok::Attr(text, false) => {
                    pending = pending.or(attr_flags(text))
                }
                Tok::Punct('{') => {
                    stack.push((here, 0));
                    pending = CfgFlags::default();
                }
                Tok::Punct('}') => {
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    pending = CfgFlags::default();
                }
                Tok::Punct(';') => pending = CfgFlags::default(),
                Tok::Punct('(' | '[' | '<') => stack[top].1 += 1,
                Tok::Punct(')' | ']' | '>') => {
                    stack[top].1 = stack[top].1.saturating_sub(1)
                }
                Tok::Punct(',') if stack[top].1 == 0 => {
                    pending = CfgFlags::default()
                }
                Tok::Ident(name, line) => {
                    let after_fn = k > 0
                        && matches!(&toks[k - 1], Tok::Ident(p, _) if p == "fn");
                    if LINUX_ONLY.contains(&name.as_str()) && !after_fn {
                        refs.push(LinuxOnlyRef {
                            name: name.clone(),
                            line: *line,
                            flags: here,
                        });
                    }
                    if let (
                        "mod",
                        Some(Tok::Ident(m, _)),
                        Some(Tok::Punct(';')),
                    ) = (name.as_str(), toks.get(k + 1), toks.get(k + 2))
                    {
                        mods.push((m.clone(), here));
                    }
                }
                _ => {}
            }
        }
        (refs, mods)
    }

    /// Every Linux-only reference in the crate, as `path:line name`.
    fn crate_refs() -> Vec<(String, LinuxOnlyRef)> {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut queue = vec![(src.join("main.rs"), CfgFlags::default())];
        let mut out = Vec::new();
        while let Some((path, flags)) = queue.pop() {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let (refs, mods) = scan_linux_only_refs(&text, flags);
            let dir: PathBuf = match path.file_name().and_then(|n| n.to_str()) {
                Some("main.rs" | "lib.rs" | "mod.rs") => {
                    path.with_file_name("")
                }
                _ => path.with_extension(""),
            };
            for (name, f) in mods {
                let file = dir.join(format!("{name}.rs"));
                let child = if file.exists() {
                    file
                } else {
                    dir.join(&name).join("mod.rs")
                };
                queue.push((child, f));
            }
            let rel = path.strip_prefix(&src).unwrap().display().to_string();
            out.extend(refs.into_iter().map(|r| (rel.clone(), r)));
        }
        out
    }

    fn ungated(in_tests: bool) -> (Vec<String>, Vec<String>) {
        let refs = crate_refs();
        let names = refs
            .iter()
            .filter(|(_, r)| r.flags.test == in_tests)
            .map(|(_, r)| r.name.clone())
            .collect();
        let bad = refs
            .iter()
            .filter(|(_, r)| r.flags.test == in_tests && !r.flags.linux)
            .map(|(p, r)| format!("src/{p}:{} {}", r.line, r.name))
            .collect();
        (names, bad)
    }

    #[test]
    fn linux_only_calls_outside_tests_are_linux_gated() {
        let (names, bad) = ungated(false);
        for name in LINUX_ONLY {
            assert!(
                names.iter().any(|n| n == name),
                "the trace found no non-test reference to {name}"
            );
        }
        assert!(
            bad.is_empty(),
            "Linux-only calls compiled on macOS: {bad:?}"
        );
    }

    #[test]
    fn linux_only_calls_in_tests_are_linux_gated() {
        let (_, bad) = ungated(true);
        assert!(
            bad.is_empty(),
            "Linux-only calls in tests compiled on macOS: {bad:?}"
        );
    }

    fn trace(src: &str) -> Vec<(usize, bool, bool)> {
        let (refs, _) = scan_linux_only_refs(src, CfgFlags::default());
        refs.iter()
            .map(|r| (r.line, r.flags.linux, r.flags.test))
            .collect()
    }

    #[test]
    fn platform_trace_flags_calls_a_gate_does_not_cover() {
        // Shapes that look gated and are not; `'{'` must not open a block.
        let src = r#"#[cfg(not(target_os = "linux"))]
{ apply_cpus(&s); }
#[cfg(target_os = "linux")] let a = 1;
apply_cpus(&s);
#[cfg(any(target_os = "linux", test))]
fn f() { validate_cpus(&s) }
#[cfg(target_os = "linux")]
fn g<'a>(x: &'a str) { let c = '{'; }
apply_sandbox(&c, false);
"#;
        let all_ungated = vec![
            (2, false, false),
            (4, false, false),
            (6, false, false),
            (9, false, false),
        ];
        assert_eq!(trace(src), all_ungated);
    }

    #[test]
    fn platform_trace_ignores_what_is_not_a_reference() {
        let src = "// apply_cpus(x)\n/* validate_cpus /* n */ apply_sandbox */\n\
                   let m = \"apply_cpus\"; let r = r#\"validate_cpus\"#;\n\
                   fn apply_cpus(c: &S) {}\n";
        assert_eq!(trace(src), vec![]);
    }

    #[test]
    fn platform_trace_accepts_the_gates_the_crate_uses() {
        let src = r#"#[cfg(target_os = "linux")]
fn a(x: u8) -> Result<(), String> { validate_cpus(&s) }
fn b() {
    #[cfg(target_os = "linux")]
    if let Some(c) = x { apply_cpus(&c)?; }
    #[cfg(target_os = "linux")]
    apply_sandbox(&config, v)?;
    #[cfg(target_os = "linux")]
    { validate_cpus(&set) }
}
#[cfg(test)]
mod t { #[cfg(target_os = "linux")] fn x() { apply_sandbox(&c, false); } }
#[cfg(target_os = "linux")]
mod bwrap;
"#;
        let want = vec![
            (2, true, false),
            (5, true, false),
            (7, true, false),
            (9, true, false),
            (12, true, true),
        ];
        assert_eq!(trace(src), want);
        let (_, mods) = scan_linux_only_refs(src, CfgFlags::default());
        let linux = CfgFlags {
            linux: true,
            test: false,
        };
        assert_eq!(mods, vec![("bwrap".to_string(), linux)]);
    }
}
