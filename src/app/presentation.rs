//! Terminal presentation, separate from processing and acquisition state.
use crate::app::cli::{ColorMode, Presentation};
use std::{
    io::IsTerminal,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
static PROGRESS: AtomicBool = AtomicBool::new(false);
static COLOR: AtomicBool = AtomicBool::new(false);
static BARS: LazyLock<Mutex<indicatif::MultiProgress>> = LazyLock::new(|| {
    Mutex::new(indicatif::MultiProgress::with_draw_target(
        indicatif::ProgressDrawTarget::stderr_with_hz(8),
    ))
});

/// Clear the terminal before exiting a command that uses the default interrupt behavior.
pub fn exit_on_interrupt() -> Result<(), ctrlc::Error> {
    if PROGRESS.load(Ordering::Relaxed) {
        ctrlc::set_handler(|| {
            BARS.lock().unwrap().suspend(|| std::process::exit(130));
        })?;
    }
    Ok(())
}

pub fn color_enabled(
    mode: ColorMode,
    no_color: bool,
    json: bool,
    tty: bool,
    env_no_color: bool,
) -> bool {
    !json
        && !no_color
        && match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => tty && !env_no_color,
        }
}
pub fn progress_enabled(quiet: bool, json: bool, no_progress: bool, tty: bool) -> bool {
    !quiet && !json && !no_progress && tty
}
pub fn initialize(args: &Presentation) {
    COLOR.store(
        color_enabled(
            args.color,
            args.no_color,
            args.json,
            std::io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR").is_some(),
        ),
        Ordering::Relaxed,
    );
    PROGRESS.store(
        progress_enabled(
            args.quiet,
            args.json,
            args.no_progress,
            std::io::stderr().is_terminal(),
        ),
        Ordering::Relaxed,
    );
}
pub fn label(text: &str, code: &str) -> String {
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.into()
    }
}
/// One shared aggregate bar per operation. Drop always clears it, including early errors.
pub struct Progress(pub indicatif::ProgressBar, Mutex<Instant>);
impl Progress {
    pub fn new(total: Option<u64>, operation: &str) -> Self {
        Self::start(total, operation, None)
    }

    pub fn delayed(operation: &str) -> Self {
        Self::start(None, operation, Some(Duration::from_millis(350)))
    }

    fn start(total: Option<u64>, operation: &str, delay: Option<Duration>) -> Self {
        let bar = indicatif::ProgressBar::with_draw_target(
            total,
            indicatif::ProgressDrawTarget::hidden(),
        );
        bar.set_style(
            indicatif::ProgressStyle::with_template(match (total.is_some(), COLOR.load(Ordering::Relaxed)) {
                (true, true) => "{prefix} [{wide_bar:.cyan/blue}] {pos}/{len} {percent}% [{elapsed_precise}] {per_sec} ETA {eta_precise} {msg}",
                (true, false) => "{prefix} [{wide_bar}] {pos}/{len} {percent}% [{elapsed_precise}] {per_sec} ETA {eta_precise} {msg}",
                (false, true) => "{prefix} {spinner:.cyan} [{elapsed_precise}] {msg}",
                (false, false) => "{prefix} {spinner} [{elapsed_precise}] {msg}",
            })
            .expect("static progress template").progress_chars("=>-"),
        );
        bar.set_prefix(operation.to_owned());
        if PROGRESS.load(Ordering::Relaxed) {
            if let Some(delay) = delay {
                let weak = bar.downgrade();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    let bars = BARS.lock().unwrap();
                    if let Some(bar) = weak.upgrade().filter(|bar| !bar.is_finished()) {
                        bars.add(bar.clone());
                        bar.enable_steady_tick(Duration::from_millis(125));
                        bar.force_draw();
                    }
                });
            } else {
                BARS.lock().unwrap().add(bar.clone());
                bar.enable_steady_tick(Duration::from_millis(125));
            }
        }
        Self(bar, Mutex::new(Instant::now()))
    }

    /// Keep formatting and rendering off the hot path of streaming reads.
    pub fn streaming_message(&self, message: impl FnOnce() -> String) {
        if !PROGRESS.load(Ordering::Relaxed) {
            return;
        }
        let mut last = self.1.lock().unwrap();
        if last.elapsed() >= Duration::from_millis(125) {
            self.0.set_message(message());
            *last = Instant::now();
        }
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        if PROGRESS.load(Ordering::Relaxed) {
            let bars = BARS.lock().unwrap();
            self.0.finish_and_clear();
            bars.remove(&self.0);
        } else {
            self.0.finish_and_clear();
        }
    }
}

/// Escape remote control and bidi characters before inserting names into terminal text.
pub fn safe_text(value: &str) -> String {
    value.chars().flat_map(|c| {
        if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
            c.escape_default().collect::<Vec<_>>()
        } else { vec![c] }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_policy() {
        assert!(progress_enabled(false, false, false, true));
        assert!(!progress_enabled(true, false, false, true));
        assert!(!progress_enabled(false, true, false, true));
        assert!(!progress_enabled(false, false, true, true));
        assert!(!progress_enabled(false, false, false, false));
    }
    #[test]
    fn hidden_progress_tracks_zero_unknown_and_completed_work() {
        let empty = Progress::new(Some(0), "empty");
        assert!(empty.0.is_hidden());
        assert_eq!(empty.0.length(), Some(0));
        let unknown = Progress::new(None, "unknown");
        assert_eq!(unknown.0.length(), None);
        let bar = Progress::new(Some(2), "objects");
        bar.0.inc(1);
        bar.0.inc(1);
        assert_eq!(bar.0.position(), 2);
        let observer = bar.0.clone();
        drop(bar);
        assert!(observer.is_finished());
    }
    #[test]
    fn progress_clears_on_error_and_cancellation() {
        for cancelled in [false, true] {
            let observer = std::cell::RefCell::new(None);
            let operation = || -> Result<(), &'static str> {
                let progress = Progress::new(None, "operation");
                *observer.borrow_mut() = Some(progress.0.clone());
                if cancelled {
                    return Err("interrupted");
                }
                Err("failed")
            };
            assert!(operation().is_err());
            assert!(observer.borrow().as_ref().unwrap().is_finished());
        }
    }
    #[test]
    fn color_precedence() {
        assert_eq!(safe_text("a\x1b[31m\n.zip"), "a\\u{1b}[31m\\n.zip");
        assert!(!color_enabled(ColorMode::Auto, false, false, false, false));
        assert!(!color_enabled(ColorMode::Auto, false, false, true, true));
        assert!(color_enabled(ColorMode::Auto, false, false, true, false));
        assert!(color_enabled(ColorMode::Always, false, false, false, true));
        assert!(!color_enabled(ColorMode::Always, true, false, true, false));
        assert!(!color_enabled(ColorMode::Always, false, true, true, false));
        assert!(!color_enabled(ColorMode::Never, false, false, true, false));
    }
}

/// Binary byte units for human output; serialized byte fields remain integers.
pub fn bytes(value: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if value < 1024 {
        return format!("{value} B");
    }
    let mut number = value as f64;
    let mut unit = 0;
    while number >= 1024.0 && unit < UNITS.len() - 1 {
        number /= 1024.0;
        unit += 1;
    }
    format!("{number:.2} {}", UNITS[unit])
}

/// Format byte progress with a denominator only when the full amount is known.
pub fn byte_progress(done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) => format!("{} / {}", bytes(done), bytes(total)),
        None => bytes(done),
    }
}

pub fn byte_rate(done: u64, elapsed: Duration) -> String {
    let rate = if elapsed.is_zero() {
        0
    } else {
        (done as f64 / elapsed.as_secs_f64()) as u64
    };
    format!("{}/s", bytes(rate))
}

pub fn stats(repository: &std::path::Path, summary: &crate::output::report::Summary) -> String {
    use std::fmt::Write;
    let mismatches = summary
        .by_mismatch_status
        .get("mismatch")
        .map_or(0, |v| v.occurrences);
    let mut text = format!(
        "Repository  {}\nSamples     {} unique / {} occurrences\nDuplicates  {} occurrences\nStored      {}\nLogical     {}\nMismatches  {} occurrences\n",
        safe_text(&repository.display().to_string()),
        summary.unique_samples,
        summary.occurrences,
        summary.duplicate_occurrences,
        bytes(summary.stored_bytes),
        bytes(summary.logical_bytes),
        mismatches
    );
    if !summary.nested.occurrences_by_depth.is_empty()
        || !summary.nested.archive_outcomes.is_empty()
    {
        let _ = write!(
            text,
            "\nNested archive analysis\n  Parent-child links: {}\n  Maximum sample depth: {}\n",
            summary.nested.parent_child_relationships, summary.nested.maximum_depth
        );
        for (status, count) in &summary.nested.archive_outcomes {
            let _ = writeln!(text, "  {:24} {}", safe_text(status), count);
        }
        for (depth, count) in &summary.nested.occurrences_by_depth {
            let _ = writeln!(
                text,
                "  Depth {depth}: {count} occurrences / {} unique hashes",
                summary.nested.unique_hashes_by_depth[depth]
            );
        }
    }
    for (title, groups) in [
        ("Detected formats", &summary.by_detected_format),
        ("Detected families", &summary.by_detected_family),
        ("Mismatch statuses", &summary.by_mismatch_status),
    ] {
        let _ = write!(
            text,
            "\n{title}\n  {:24} {:>12} {:>13}\n",
            "Value", "Occurrences", "Unique hashes"
        );
        for (name, counts) in groups {
            let _ = writeln!(
                text,
                "  {:24} {:>12} {:>13}",
                safe_text(name),
                counts.occurrences,
                counts.unique_hashes
            );
        }
    }
    text
}

#[cfg(test)]
mod formatting_tests {
    #[test]
    fn binary_byte_boundaries() {
        for (value, expected) in [
            (0, "0 B"),
            (512, "512 B"),
            (1024, "1.00 KiB"),
            (1048576, "1.00 MiB"),
            (1073741824, "1.00 GiB"),
            (u64::MAX, "16.00 EiB"),
        ] {
            assert_eq!(super::bytes(value), expected);
        }
    }
}
