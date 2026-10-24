//! The `sqlite:` block of a target in `agent.yaml` (ADR-0059 decision 2),
//! validated and resolved when the configuration is loaded.
//!
//! ```yaml
//! targets:
//!   - id: crm-app
//!     engine: sqlite
//!     sqlite:
//!       path: /srv/crm/data/crm.db
//!       max_statement_ms: 500   # optional, 50..=5000
//!       rollback_mode: skip     # optional: skip (default) or read
//! ```
//!
//! One target is one declared database file: no directory, no glob, no
//! search (I5). No `host`, `port`, `socket`, `account` or `secret` (refused
//! by the target validation for `engine: sqlite`). The path never leaves
//! the agent and is never logged: a refusal names the target (its index in
//! `agent.yaml`, or its id) and the rule broken, never the path.
//!
//! The path rules checked here (syntax, refused locations, no symlink in
//! any existing component, no duplicate file) are checked again by the
//! connector at every open, with the file rules of decision 2.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// `sqlite.max_statement_ms` range (decision 3, a local limit the console
/// cannot raise).
pub const MAX_STATEMENT_MS_RANGE: (u32, u32) = (50, 5_000);
/// `sqlite.max_statement_ms` default.
pub const DEFAULT_MAX_STATEMENT_MS: u32 = 500;
/// Longest declared path, in bytes (decision 2).
pub const MAX_PATH_BYTES: usize = 1_024;
/// Directories a declared path may never be under (decision 2), besides the
/// agent's own directories and the files `agent.yaml` references.
pub const SYSTEM_ROOTS: [&str; 5] = ["/proc", "/sys", "/dev", "/run/user", "/etc/databastion"];

/// How a rollback-journal mode file is handled (decision 3, security review
/// M5): every read in that mode delays the application's commits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackMode {
    /// Not read (`coverage.rollback_mode_not_read`), the default.
    #[default]
    Skip,
    /// Read under `SHARED` locks, one bounded statement at a time.
    Read,
}

/// `sqlite:` as written in `agent.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSqliteSettings {
    /// The database file.
    pub path: PathBuf,
    /// Statement deadline in milliseconds (default 500).
    #[serde(default)]
    pub max_statement_ms: Option<u32>,
    /// Rollback-journal mode files: `skip` (default) or `read`.
    #[serde(default)]
    pub rollback_mode: RollbackMode,
}

/// Why a declared path is refused: a closed rule name, logged and returned
/// instead of the path (decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRule {
    /// Not absolute, not canonical (`.`, `..`, `//`, a trailing `/`), not
    /// UTF-8, longer than [`MAX_PATH_BYTES`] or with a control character.
    NotCanonical,
    /// A component of the path is a symbolic link.
    SymlinkComponent,
    /// Under a refused location (the agent's directories, `/etc/databastion`,
    /// a file `agent.yaml` references or its directory, `/proc`, `/sys`,
    /// `/dev`, `/run/user`).
    RefusedLocation,
    /// The same file as another target's.
    DuplicateFile,
}

impl PathRule {
    /// The rule's stable name, for logs and configuration errors.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCanonical => "not_canonical",
            Self::SymlinkComponent => "symlink_component",
            Self::RefusedLocation => "refused_location",
            Self::DuplicateFile => "duplicate_file",
        }
    }
}

/// The validated `sqlite:` block of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteSettings {
    path: PathBuf,
    max_statement_ms: u32,
    rollback_mode: RollbackMode,
    refused: Vec<PathBuf>,
    others: Vec<PathBuf>,
}

impl SqliteSettings {
    /// The declared database file. Never send it, log it or keep it in an
    /// error (decision 2).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The statement deadline (decision 3).
    #[must_use]
    pub const fn max_statement_ms(&self) -> u32 {
        self.max_statement_ms
    }

    /// How a rollback-journal mode file is handled.
    #[must_use]
    pub const fn rollback_mode(&self) -> RollbackMode {
        self.rollback_mode
    }

    /// Locations no declared file may be under, re-checked at every open:
    /// the agent's own directories, `/etc/databastion`, every file
    /// `agent.yaml` references and the directory holding it, and
    /// [`SYSTEM_ROOTS`].
    #[must_use]
    pub fn refused(&self) -> &[PathBuf] {
        &self.refused
    }

    /// The other `sqlite` targets' declared files: two targets may not name
    /// the same file (compared by `(st_dev, st_ino)` at every open).
    #[must_use]
    pub fn others(&self) -> &[PathBuf] {
        &self.others
    }

    /// Settings for tests of other crates (the connector's own tests).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(path: PathBuf, max_statement_ms: u32, rollback_mode: RollbackMode) -> Self {
        Self {
            path,
            max_statement_ms,
            rollback_mode,
            refused: SYSTEM_ROOTS.iter().map(PathBuf::from).collect(),
            others: Vec::new(),
        }
    }
}

/// Whether `path` passes the syntax rules of decision 2: absolute, already
/// canonical (no `.` or `..` component, no `//`, no trailing `/`), valid
/// UTF-8, at most [`MAX_PATH_BYTES`] bytes, no control character, and not
/// the root itself.
#[must_use]
pub fn is_canonical_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    text.len() <= MAX_PATH_BYTES
        && text.len() > 1
        && text.starts_with('/')
        && !text.ends_with('/')
        && !text.contains("//")
        && !text.chars().any(char::is_control)
        && path.components().skip(1).all(|c| match c {
            Component::Normal(n) => n != "." && n != "..",
            _ => false,
        })
        && !text.split('/').any(|s| s == "." || s == "..")
}

/// Whether `path` is under (or equal to) one of `refused`, compared by
/// component.
#[must_use]
pub fn is_refused_location(path: &Path, refused: &[PathBuf]) -> bool {
    refused.iter().any(|r| path.starts_with(r))
}

/// The first existing component of `path` (from `/` down) that is a
/// symbolic link: `Err` with [`PathRule::SymlinkComponent`]. Components that
/// do not exist (yet) end the walk (the connector re-checks at every open).
/// `lstat` only: no descriptor is opened (decision 2's lock rule).
///
/// # Errors
/// [`PathRule::SymlinkComponent`].
pub fn check_no_symlink_component(path: &Path) -> Result<(), PathRule> {
    let mut prefix = PathBuf::from("/");
    for c in path.components().skip(1) {
        prefix.push(c);
        match std::fs::symlink_metadata(&prefix) {
            Ok(m) if m.file_type().is_symlink() => return Err(PathRule::SymlinkComponent),
            Ok(_) => {}
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

impl SqliteSettings {
    /// Validates one block: the syntax rules, the statement deadline's
    /// range, the refused locations and the symbolic links of the existing
    /// components. `refused` holds the locations of decision 2 (built by the
    /// configuration loader); `others` the other `sqlite` targets' paths.
    ///
    /// # Errors
    /// `(key, reason)`: the key under `sqlite` and why, never the path.
    pub fn validate(
        raw: RawSqliteSettings,
        refused: Vec<PathBuf>,
        others: Vec<PathBuf>,
    ) -> Result<Self, (&'static str, &'static str)> {
        if !is_canonical_path(&raw.path) {
            return Err((
                "path",
                "not_canonical: must be an absolute canonical path (no `.`, `..`, `//` or \
                 trailing `/`), UTF-8, at most 1024 bytes, without control characters",
            ));
        }
        let max_statement_ms = raw.max_statement_ms.unwrap_or(DEFAULT_MAX_STATEMENT_MS);
        let (lo, hi) = MAX_STATEMENT_MS_RANGE;
        if !(lo..=hi).contains(&max_statement_ms) {
            return Err(("max_statement_ms", "must be in 50..=5000"));
        }
        if is_refused_location(&raw.path, &refused) {
            return Err((
                "path",
                "refused_location: under the agent's directories, /etc/databastion, a file \
                 agent.yaml references or its directory, /proc, /sys, /dev or /run/user",
            ));
        }
        if check_no_symlink_component(&raw.path).is_err() {
            return Err((
                "path",
                "symlink_component: a component of the path is a symbolic link (declare the \
                 real path)",
            ));
        }
        if others.iter().any(|o| o == &raw.path) {
            return Err(("path", "duplicate_file: the same file as another target's"));
        }
        Ok(Self {
            path: raw.path,
            max_statement_ms,
            rollback_mode: raw.rollback_mode,
            refused,
            others,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_paths() {
        for ok in ["/srv/crm/crm.db", "/a", "/srv/a b/c.db", "/srv/é/x"] {
            assert!(is_canonical_path(Path::new(ok)), "{ok}");
        }
        for bad in [
            "",
            "/",
            "relative/x.db",
            "/srv//x.db",
            "/srv/x.db/",
            "/srv/./x.db",
            "/srv/../x.db",
            "/srv/x\n.db",
            "/srv/x\u{7f}.db",
            "/srv/.",
            "/srv/..",
        ] {
            assert!(!is_canonical_path(Path::new(bad)), "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        assert!(!is_canonical_path(Path::new(&long)));
    }

    #[test]
    fn refused_locations_compare_by_component() {
        let refused = vec![
            PathBuf::from("/var/lib/databastion"),
            PathBuf::from("/proc"),
        ];
        assert!(is_refused_location(
            Path::new("/var/lib/databastion/spool/x.db"),
            &refused
        ));
        assert!(is_refused_location(Path::new("/proc/1/root/x"), &refused));
        assert!(!is_refused_location(
            Path::new("/var/lib/databastion-data/x.db"),
            &refused
        ));
    }

    fn raw(path: &str) -> RawSqliteSettings {
        RawSqliteSettings {
            path: PathBuf::from(path),
            max_statement_ms: None,
            rollback_mode: RollbackMode::Skip,
        }
    }

    #[test]
    fn validation_names_the_rule_never_the_path() {
        let refused = vec![PathBuf::from("/etc/databastion")];
        let s =
            SqliteSettings::validate(raw("/srv/none/x.db"), refused.clone(), Vec::new()).unwrap();
        assert_eq!(s.max_statement_ms(), 500);
        assert_eq!(s.rollback_mode(), RollbackMode::Skip);
        for (path, rule) in [
            ("/etc/databastion/x.db", "refused_location"),
            ("/srv//x.db", "not_canonical"),
        ] {
            let (key, reason) =
                SqliteSettings::validate(raw(path), refused.clone(), Vec::new()).unwrap_err();
            assert_eq!(key, "path");
            assert!(reason.starts_with(rule), "{reason}");
            assert!(!reason.contains(path));
        }
        let dup = SqliteSettings::validate(
            raw("/srv/x.db"),
            refused.clone(),
            vec![PathBuf::from("/srv/x.db")],
        )
        .unwrap_err();
        assert!(dup.1.starts_with("duplicate_file"));
        let mut r = raw("/srv/x.db");
        r.max_statement_ms = Some(49);
        assert_eq!(
            SqliteSettings::validate(r, refused, Vec::new())
                .unwrap_err()
                .0,
            "max_statement_ms"
        );
    }

    #[test]
    fn symlinked_components_are_refused() {
        let dir = std::env::temp_dir().join(format!("db-sqlite-cfg-{}", std::process::id()));
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canon = dir.canonicalize().unwrap();
        assert_eq!(
            check_no_symlink_component(&canon.join("link/x.db")),
            Err(PathRule::SymlinkComponent)
        );
        assert_eq!(check_no_symlink_component(&canon.join("real/x.db")), Ok(()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
