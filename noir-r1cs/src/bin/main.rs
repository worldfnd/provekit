#![allow(missing_docs)]
mod cmd;
mod file;
mod measuring_alloc;
mod span_stats;

use {
    self::{cmd::Command, measuring_alloc::MeasuringAllocator, span_stats::SpanStats},
    anyhow::Result,
    file::write,
    std::fmt::{Display, Formatter, Result as FmtResult},
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};

#[global_allocator]
static ALLOC: MeasuringAllocator = MeasuringAllocator::new();

fn main() -> Result<()> {
    let subscriber = Registry::default().with(SpanStats);
    tracing::subscriber::set_global_default(subscriber)?;

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}

/// Pretty print a float using SI-prefixes.
fn human(value: f64) -> impl Display {
    struct Human(f64);
    impl Display for Human {
        fn fmt(&self, f: &mut Formatter) -> FmtResult {
            let log10 = if self.0.is_normal() {
                self.0.abs().log10()
            } else {
                0.0
            };
            let si_power = ((log10 / 3.0).floor() as isize).clamp(-10, 10);
            let value = self.0 * 10_f64.powi((-si_power * 3) as i32);
            let digits = f.precision().unwrap_or(3) - 1 - (log10 - 3.0 * si_power as f64) as usize;
            let separator = if f.alternate() { "" } else { "\u{202F}" };
            if f.width() == Some(6) && digits == 0 {
                write!(f, " ")?;
            }
            write!(f, "{value:.digits$}{separator}")?;
            let suffix = "qryzafpnμm kMGTPEZYRQ"
                .chars()
                .nth((si_power + 10) as usize)
                .unwrap();
            if suffix != ' ' || f.width() == Some(6) {
                write!(f, "{suffix}")?;
            }
            Ok(())
        }
    }
    Human(value)
}
