#![doc = include_str!("../README.md")]
mod cmd;
mod compiler;
mod sparse_matrix;
mod utils;
mod witness;

use {
    self::{cmd::Command, sparse_matrix::SparseMatrix},
    anyhow::Result,
    std::{
        fmt::{Display, Formatter},
        sync::{Arc, Mutex},
        time::Instant,
    },
    tracing::{level_filters::LevelFilter, span, Subscriber},
    tracing_subscriber::{
        self, fmt,
        layer::{Context, SubscriberExt as _},
        registry::LookupSpan,
        util::SubscriberInitExt as _,
        EnvFilter, Layer, Registry,
    },
};

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

struct DurationLayer {
    start: Arc<Mutex<Vec<Instant>>>,
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
        lock.push(Instant::now());
        let span = ctx.span(id).expect("expected: span id exists in registry");

        for _ in 0..depth {
            eprint!("│ ");
        }

        eprintln!("├─╮ {}", span.name());
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        let mut lock = self.start.lock().unwrap();
        let depth = lock.len();
        let duration = lock.pop().expect("expected: start time exists").elapsed();

        let span: tracing_subscriber::registry::SpanRef<'_, S> =
            ctx.span(id).expect("expected: span id exists in registry");

        for _ in 0..(depth - 1) {
            eprint!("│ ");
        }

        eprintln!("├─╯ {}s", human(duration.as_secs_f64()));
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
