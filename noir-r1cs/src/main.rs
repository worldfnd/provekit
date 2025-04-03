#![doc = include_str!("../README.md")]
mod cmd;

use {
    self::cmd::Command,
    anyhow::Result,
    std::{
        alloc::{GlobalAlloc, Layout, System as SystemAlloc},
        fmt::{Display, Formatter},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Instant,
    },
    tracing::{span, Subscriber},
    tracing_subscriber::{
        self, fmt,
        layer::{Context, SubscriberExt as _},
        registry::LookupSpan,
        Layer, Registry,
    },
};

#[global_allocator]
static ALLOC: MeasuringAllocator = MeasuringAllocator::new();

/// Custom allocator that keeps track of statistics to see program memory
/// consumption.
struct MeasuringAllocator {
    current: AtomicUsize,
    max:     AtomicUsize,
    count:   AtomicUsize,
}

/// Logging layer that keeps track of time and memory consumption.
struct DurationLayer {
    start: Arc<Mutex<Vec<SpanStart>>>,
}

struct SpanStart {
    time:        Instant,
    memory:      usize,
    max:         usize,
    allocations: usize,
}

fn main() -> Result<()> {
    let fmt_layer = fmt::Layer::default();
    let subscriber = Registry::default()
        .with(fmt_layer)
        .with(DurationLayer::new());
    tracing::subscriber::set_global_default(subscriber)?;

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}

impl MeasuringAllocator {
    const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            max:     AtomicUsize::new(0),
            count:   AtomicUsize::new(0),
        }
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }

    fn reset_max(&self) {
        self.max.store(self.current(), Ordering::SeqCst);
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for MeasuringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // We just ignore the race conditions here...
        let prev = self.current.fetch_add(layout.size(), Ordering::SeqCst);
        self.max.fetch_max(prev + layout.size(), Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
        SystemAlloc.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.current.fetch_sub(layout.size(), Ordering::SeqCst);
        SystemAlloc.dealloc(ptr, layout)
    }
}

impl DurationLayer {
    fn new() -> Self {
        Self {
            start: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S> Layer<S> for DurationLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_enter(&self, id: &span::Id, ctx: Context<'_, S>) {
        let mut lock = self.start.lock().unwrap();
        let depth = lock.len();

        // Propagate current max down the stack.
        let max = ALLOC.max();
        for entry in lock.iter_mut() {
            entry.max = std::cmp::max(entry.max, max);
        }
        ALLOC.reset_max();

        lock.push(SpanStart {
            time:        Instant::now(),
            memory:      ALLOC.current(),
            max:         ALLOC.current(),
            allocations: ALLOC.count(),
        });

        let span = ctx.span(id).expect("expected: span id exists in registry");

        for _ in 0..depth {
            eprint!("│ ");
        }

        eprintln!("├─╮ {}", span.name());
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        let mut lock = self.start.lock().unwrap();
        let depth = lock.len();
        let start = lock.pop().expect("expected: start time exists");

        let duration = start.time.elapsed();
        let max = std::cmp::max(ALLOC.max(), start.max);
        let allocations = ALLOC.count() - start.allocations;
        let own = max - start.memory;

        let _span: tracing_subscriber::registry::SpanRef<'_, S> =
            ctx.span(id).expect("expected: span id exists in registry");

        for _ in 0..(depth - 1) {
            eprint!("│ ");
        }

        eprintln!(
            "├─╯ took {}s, {} allocations, {}B peak memory, {}B own memory",
            human(duration.as_secs_f64()),
            human(allocations as f64),
            human(max as f64),
            human(own as f64)
        );
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
