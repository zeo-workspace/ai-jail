//! The live `/proc/uptime` of `--mask-host`.
//!
//! A bind mount pins an inode, so the synthetic file cannot be swapped by
//! rename; a supervisor thread rewrites it in place once a second instead.
//! Every write has the same length (`synth::UPTIME_LEN`) and lands at offset
//! 0 in one `pwrite`, so a reader sees one value or the next, never a file
//! that shrank or grew. The thread lives exactly as long as the view.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::host_view_synth as synth;

const TICK: Duration = Duration::from_secs(1);

/// Keeps one `/proc/uptime` file current; stopped and joined on drop.
#[derive(Debug)]
pub(super) struct UptimeTicker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UptimeTicker {
    /// Count from `start` (the jail's start) for `cpus` idle CPUs, writing
    /// through `file`, opened for writing before it was made read-only.
    pub fn start(
        file: File,
        start: Instant,
        cpus: usize,
    ) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("ai-jail-uptime".into())
            .spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    std::thread::park_timeout(TICK);
                    if flag.load(Ordering::Acquire) {
                        break;
                    }
                    let text =
                        synth::uptime(start.elapsed().as_secs_f64(), cpus);
                    // A failed write leaves the last value in place; the
                    // jail keeps running either way.
                    let _ = file.write_all_at(text.as_bytes(), 0);
                }
            })
            .map_err(|e| format!("--mask-host: cannot start uptime: {e}"))?;
        Ok(UptimeTicker {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for UptimeTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}
