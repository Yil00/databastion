//! Panic isolation (security review H1 of #79, defence in depth).
//!
//! A connector parses what a database server sends. Bugs there must not
//! stop the agent: every connector future (`check`, `discover`,
//! `audit_stream`) runs through [`guard`], which turns a panic into an
//! error of that one call. The process-wide hook installed by
//! [`install_hook`] logs where a panic happened, never its message: a
//! panic message can quote the data being parsed (for example the string
//! a slice failed on), and logs never hold sampled or logged values (I2).

use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt as _;

/// Panics seen by the process hook: the id of the last one, logged by the
/// hook and by the code that caught it, to correlate the two lines.
static PANICS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A connector future panicked (its message is not kept). `id` is the
/// hook's panic id (0 when the hook is not installed, in tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Panicked {
    pub(crate) id: u64,
}

/// Runs `fut`, turning a panic into [`Panicked`]. The future's state is
/// dropped with it; nothing it shared with the core is left half-updated
/// (connectors only hand over results through sinks).
pub(crate) async fn guard<F: Future>(fut: F) -> Result<F::Output, Panicked> {
    AssertUnwindSafe(fut)
        .catch_unwind()
        .await
        .map_err(|_| Panicked {
            id: PANICS.load(std::sync::atomic::Ordering::Relaxed),
        })
}

/// Replaces the default panic hook (which prints the message) with one
/// that logs the code location, the thread name and a panic id, never the
/// message. Installed once per process: by the binary right after its
/// logging is set up (so enrollment is covered too), and by [`crate::run`].
pub fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let id = PANICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let (file, line) = info
                .location()
                .map_or(("unknown", 0), |l| (l.file(), l.line()));
            let thread = std::thread::current();
            tracing::error!(
                panic_id = id,
                thread = thread.name().unwrap_or("unnamed"),
                file,
                line,
                "internal error (panic); its message is not logged, it may quote data"
            );
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn panics_become_errors() {
        assert_eq!(guard(async { 7 }).await, Ok(7));
        let r = guard(async {
            let text = String::from("202é092920264Z");
            // The slice the security review found: a panic, caught.
            let _ = std::hint::black_box(&text).get(0..1);
            #[allow(clippy::string_slice)]
            let s = &text[..std::hint::black_box(4)];
            s.len()
        })
        .await;
        assert!(r.is_err());
    }
}
