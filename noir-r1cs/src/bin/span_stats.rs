//! Using `tracing` spans to print performance statistics for the program.
//!
//! NOTE: This module is only included in the bin, not in the lib.
use {
    crate::ALLOC,
    nu_ansi_term::{Color, Style},
    std::{
        fmt::{Display, Formatter, Write as _},
        sync::{Arc, Mutex},
        time::Instant,
    },
    tracing::{span, Subscriber},
    tracing_subscriber::{self, layer::Context, registry::LookupSpan, Layer},
};

const BOLD: &'static str = "\x1b[1m";
const UNBOLD: &'static str = "\x1b[22m";

/// Logging layer that keeps track of time and memory consumption of spans.
pub struct SpanStats {
    start: Arc<Mutex<Vec<SpanStart>>>,
}

/// Statistics at start of the span.
struct SpanStart {
    time:        Instant,
    memory:      usize,
    allocations: usize,

    /// `peak_memory` will be updated as it is not monotonic
    peak_memory: usize,
}

impl SpanStats {
    pub fn new() -> Self {
        Self {
            start: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S> Layer<S> for SpanStats
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        let mut lock = self.start.lock().unwrap();
        let depth = lock.len();

        // Propagate current max down the stack.
        let peak_memory = ALLOC.max();
        for entry in lock.iter_mut() {
            entry.peak_memory = std::cmp::max(entry.peak_memory, peak_memory);
        }
        let current = ALLOC.reset_max(); // Reset so we can measure the new span.

        // Add the new span stats entry
        lock.push(SpanStart {
            time:        Instant::now(),
            memory:      current,
            allocations: ALLOC.count(),
            peak_memory: current,
        });

        let span = ctx.span(id).expect("expected: span id exists in registry");

        let mut buffer = String::with_capacity(100);

        // Box draw tree indentation
        if depth >= 1 {
            for _ in 0..(depth - 1) {
                let _ = write!(&mut buffer, "│ ");
            }
            let _ = write!(&mut buffer, "├─");
        }
        let _ = write!(&mut buffer, "╮ ");

        // Span name
        let _ = write!(
            &mut buffer,
            "{}::{BOLD}{}{UNBOLD}",
            span.metadata().target(),
            span.metadata().name()
        );

        eprintln!("{}", buffer);
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        let mut lock = self.start.lock().unwrap();
        let depth = lock.len() - 1;
        let start = lock.pop().expect("expected: start time exists");

        let duration = start.time.elapsed();
        let peak_memory: usize = std::cmp::max(ALLOC.max(), start.peak_memory);
        let allocations = ALLOC.count() - start.allocations;
        let own = peak_memory - start.memory;

        let span: tracing_subscriber::registry::SpanRef<'_, S> =
            ctx.span(id).expect("expected: span id exists in registry");

        let mut buffer = String::with_capacity(100);

        // Box draw tree indentation
        if depth >= 1 {
            for _ in 0..(depth - 1) {
                let _ = write!(&mut buffer, "│ ");
            }
            let _ = write!(&mut buffer, "├─");
        }
        let _ = write!(&mut buffer, "╯ ");

        // Short span name
        let _ = write!(&mut buffer, "{}: ", span.metadata().name());

        // Print stats
        let _ = write!(
            &mut buffer,
            "duration {BOLD}{}s{UNBOLD}, {BOLD}{}B{UNBOLD} peak memory, {BOLD}{}B{UNBOLD} local, \
             {BOLD}{:#}{UNBOLD} allocations",
            human(duration.as_secs_f64()),
            human(peak_memory as f64),
            human(own as f64),
            human(allocations as f64)
        );

        eprintln!("{}", buffer);
    }
}

/// Pretty print a float using SI-prefixes.
pub fn human(value: f64) -> impl Display {
    pub struct Human(f64);
    impl Display for Human {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            let log10 = if self.0.is_normal() {
                self.0.abs().log10()
            } else {
                0.0
            };
            let si_power = ((log10 / 3.0).floor() as isize).clamp(-10, 10);
            let value = self.0 * 10_f64.powi((-si_power * 3) as i32);
            let digits = f.precision().unwrap_or(3) - 1 - (log10 - 3.0 * si_power as f64) as usize;
            let separator = if f.alternate() { "" } else { "\u{202F}" };
            write!(f, "{value:.digits$}{separator}")?;
            let suffix = "qryzafpnμm kMGTPEZYRQ"
                .chars()
                .nth((si_power + 10) as usize)
                .unwrap();
            if suffix != ' ' {
                write!(f, "{suffix}")?;
            }
            Ok(())
        }
    }
    Human(value)
}
