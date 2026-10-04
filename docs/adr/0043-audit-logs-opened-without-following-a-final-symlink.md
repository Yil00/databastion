# ADR-0043: Audit log files are opened without following a final symlink, with a per-source open check

- **Status**: Accepted (2026-10-04; the maintainer delegated the phase 8 technical decisions; subject to the security review of PR #140)
- **Date**: 2026-10-04
- **Refines**: [ADR-0032](0032-audit-stream-panic-isolation-and-openldap-probe-refresh.md) decision 8 (which stays Accepted): the writability check no longer runs "after symlinks are followed", because a final symlink is no longer followed
- **Context references**: security review of #138 (L2); ROADMAP P8-B, PR #140 (`feat/p8-b-wire-connector-cas`, commit 560e82c); [ADR-0041](0041-cas-connector.md) decision 3 (file handling of CAS targets); `agent/crates/core/src/audit/tail.rs` (`open_regular`, `OpenCheck`, `OpenedFile`, `Tailer::with_open_check`, rotation detection), `agent/crates/connector-cas/src/fsread.rs` (`log_open_check`, `check_opened_log`, `names`), `agent/crates/core/src/config/cas.rs` (`ResolvedPath::still_resolves`); `agent/README.md` ("Audit log files")

## Context
ADR-0032 decision 8 refuses an audit log file the agent's own account could have written, checked on the opened handle "after symlinks are followed". The core tailer opened the declared path, and reopened it after a rotation, following symlinks. Whoever can write the log directory (often the database or CAS server's account) could therefore replace the log with a symlink at rotation time and point the agent at another file the agent can read: the checks of ADR-0032 decision 8 ran on that other file, and the agent read it as audit evidence.

ADR-0041 decision 3 already opens the CAS service registry entries with `O_NOFOLLOW` and checks them on the descriptor, and said the CAS audit log "is opened the same way by the core tailer". The security review of #138 (L2) found that the tailer did not: it followed a symlink at the first open and at every reopen.

## Decision
1. **`O_NOFOLLOW` for every log-file Audit source.** The core tailer opens the audit log with `O_NOFOLLOW` (with `O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC` as before), at the first open and at the reopen after a rotation. This applies to every source read through the tailer: the pgaudit `csvlog` / `jsonlog` server log, MariaDB `server_audit`, the Percona `audit_log` and other MySQL JSON logs, the MongoDB `auditLog` and server log, and the CAS audit log.
2. **A final symlink is refused.** An `audit_log.path` whose last component is a symlink fails to open and is treated as unreadable: `check()` reports `audit.log_not_readable` and the stream re-evaluates its source, as for the other refusals of ADR-0032 decision 8. Symlinks in the parent directories are still resolved by the kernel and keep working. For a CAS target the tailer opens the path resolved when `agent.yaml` is loaded (ADR-0041 decision 3), so the declared path may be a symlink at load; any later change of where it resolves is refused (decision 4).
3. **Rotation detected with `lstat`.** At the end of the open file the tailer compares the path's `lstat` (`symlink_metadata`), not its `stat`, with the open handle's `(st_dev, st_ino)`. A symlink swapped in at the path counts as a rotation; the reopen then refuses it (decision 1) and nothing of the symlink's target is read.
4. **Per-source open check.** `Tailer::with_open_check` lets a source add its own checks. They run after the tailer's own checks (regular file, ADR-0032 decision 8), on the tailer's own handle (`OpenedFile`: the path, the handle and its `fstat` metadata), after every open and reopen. A refusal makes the file unreadable and it is not read. A check must decide on the handle, or bind any check made on the path to the handle's `(st_dev, st_ino)`. The CAS connector uses it to refuse the audit log unless:
   - the declared path still resolves where it did when `agent.yaml` was loaded (`still_resolves`);
   - the handle is a regular file with `st_nlink` = 1;
   - the file is not writable by the agent (owner, mode bits, `faccessat(W_OK)`) and has no ancestor directory the agent can write;
   - the path names the handle's `(st_dev, st_ino)` before and after the path-based checks.

## Consequences
- A symlink swap by whoever can write the log directory can no longer redirect the agent to another file (ADR-0041 decision 3 now holds for the CAS audit log and for every other log-file source).
- **Upgrade note**: an operator whose `audit_log.path` is a symlink (for instance to a dated or versioned file) gets `audit.log_not_readable` after the upgrade and must point the agent at the real file. This fails closed: no record is read from a refused path.
- A log rotated by replacing the file with a symlink is no longer followed; the stream stays unreadable until a regular file is back at the path.
- The `readable()` probe used by `check()` and the source choice applies the same `O_NOFOLLOW` open, so the reported level matches what the stream can read.
- No protocol change. `agent/README.md`, [08-engine-capabilities.md](../08-engine-capabilities.md) and the CHANGELOG describe the behavior.

### Residual risks
- Symlinks in parent directories are followed. Whoever can replace a parent directory of a non-CAS log can still redirect the agent; the CAS open check refuses an agent-writable ancestor and a path that no longer resolves where it did, the other sources rely on the directory permissions.
- The residual risks of ADR-0032 decision 8 (POSIX ACL write entries, an agent running as root or with `CAP_DAC_OVERRIDE`) are unchanged for the non-CAS sources.

## Rejected alternatives
- **Keep following symlinks for the non-CAS sources**: the same swap redirects the pgaudit, MySQL / MariaDB and MongoDB tailers, whose log directories are writable by the database server's account.
- **An opt-in flag (`follow_symlinks`) for operators with a symlinked log path**: it would reopen the redirection for exactly those deployments, and pointing the path at the real file is a one-line configuration change.
- **Edit ADR-0032 in place**: the ADR convention does not allow editing an accepted ADR.
