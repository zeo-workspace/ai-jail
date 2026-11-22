//! `--state-root DIR`: the sandbox's own home, `/tmp` and Claude config on disk.
//!
//! Without it the sandbox's `$HOME` and `/tmp` are tmpfs mounts: RAM-backed,
//! uncapped, and gone when the run ends. A caller that wants them bounded and
//! kept between runs (Zeo's per-project jail, proposal §6.54) names one
//! directory instead, and ai-jail binds three children of it:
//!
//! - `DIR/home`   as the sandbox's `$HOME` (the host dotfiles ai-jail exposes
//!   are still mounted on top of it, exactly as on the tmpfs);
//! - `DIR/tmp`    as the sandbox's `/tmp`;
//! - `DIR/claude` as `CLAUDE_CONFIG_DIR`, unless `--claude-dir` names another.
//!
//! The directory holds credentials (the agent's login lands in `claude/`), so
//! it is checked the way a private directory must be: an absolute path, never
//! a symlink, owned by the caller, and writable by nobody else. Missing parts
//! are created with mode 0700; an existing part that fails a check refuses the
//! launch rather than being repaired.

use std::path::{Path, PathBuf};

/// The three directories a state root provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRoot {
    pub home: PathBuf,
    pub tmp: PathBuf,
    pub claude: PathBuf,
}

impl StateRoot {
    /// The layout under `root`, without touching the filesystem.
    pub fn layout(root: &Path) -> Self {
        Self {
            home: root.join("home"),
            tmp: root.join("tmp"),
            claude: root.join("claude"),
        }
    }
}

/// Validate `root` and make sure it and its three children exist and are
/// private. `create` is false for `--dry-run`, which must not write to the
/// host: missing directories are then reported as what a launch would create.
#[cfg(unix)]
pub fn prepare(root: &Path, create: bool) -> Result<StateRoot, String> {
    if !root.is_absolute() {
        return Err(format!(
            "--state-root: {} is not an absolute path",
            root.display()
        ));
    }
    let layout = StateRoot::layout(root);
    ensure_private_dir(root, create, true)?;
    for dir in [&layout.home, &layout.tmp, &layout.claude] {
        ensure_private_dir(dir, create, false)?;
    }
    Ok(layout)
}

#[cfg(not(unix))]
pub fn prepare(_root: &Path, _create: bool) -> Result<StateRoot, String> {
    Err("--state-root is supported on Linux only".into())
}

/// `path` must be a real directory owned by this user and writable by
/// nobody else. With `create`, a missing `path` is made with mode 0700 --
/// and, for the root, so are its missing parents (an existing parent is left
/// as it is: `/var/tmp` is world-writable by design).
#[cfg(unix)]
fn ensure_private_dir(
    path: &Path,
    create: bool,
    parents: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    match path.symlink_metadata() {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "--state-root: {} is a symlink; refusing to follow it",
                    path.display()
                ));
            }
            if !meta.is_dir() {
                return Err(format!(
                    "--state-root: {} exists and is not a directory",
                    path.display()
                ));
            }
            let uid = nix::unistd::geteuid().as_raw();
            if meta.uid() != uid {
                return Err(format!(
                    "--state-root: {} is owned by uid {}, not by you (uid {uid})",
                    path.display(),
                    meta.uid()
                ));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(format!(
                    "--state-root: {} is writable by group or others (mode {:o}); \
                     it holds the sandbox's credentials",
                    path.display(),
                    meta.mode() & 0o7777
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(());
            }
            std::fs::DirBuilder::new()
                .recursive(parents)
                .mode(0o700)
                .create(path)
                .map_err(|e| {
                    format!(
                        "--state-root: cannot create {}: {e}",
                        path.display()
                    )
                })?;
            // Re-check what now exists: a racing symlink must not pass.
            ensure_private_dir(path, false, false)
        }
        Err(e) => Err(format!(
            "--state-root: cannot inspect {}: {e}",
            path.display()
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-state-root-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_missing_root_and_its_parents_are_created_private() {
        let base = scratch("create");
        let root = base.join("zeo-jail/abc123");
        let layout = prepare(&root, true).unwrap();
        assert_eq!(layout, StateRoot::layout(&root));
        for dir in [&root, &layout.home, &layout.tmp, &layout.claude] {
            assert!(dir.is_dir(), "{}", dir.display());
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        assert_eq!(mode(&base.join("zeo-jail")), 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn dry_run_creates_nothing() {
        let base = scratch("dry");
        let root = base.join("state");
        prepare(&root, false).unwrap();
        assert!(!root.exists(), "--dry-run must not write to the host");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_relative_root_is_refused() {
        let err = prepare(Path::new("state"), true).unwrap_err();
        assert!(err.contains("not an absolute path"), "{err}");
    }

    #[test]
    fn a_symlinked_root_is_refused() {
        let base = scratch("symlink");
        let target = base.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let root = base.join("state");
        std::os::unix::fs::symlink(&target, &root).unwrap();
        let err = prepare(&root, true).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlinked_child_is_refused() {
        let base = scratch("child-symlink");
        let root = base.join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::os::unix::fs::symlink("/etc", root.join("home")).unwrap();
        let err = prepare(&root, true).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_group_writable_root_is_refused_not_repaired() {
        let base = scratch("mode");
        let root = base.join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let err = prepare(&root, true).unwrap_err();
        assert!(err.contains("writable by group or others"), "{err}");
        assert_eq!(mode(&root), 0o770, "left as it was");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_file_in_place_of_a_child_is_refused() {
        let base = scratch("file");
        let root = base.join("state");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::write(root.join("tmp"), b"").unwrap();
        let err = prepare(&root, true).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
