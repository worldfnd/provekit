#![allow(missing_docs)]
mod cmd;
mod measuring_alloc;
mod span_stats;

use {
    self::{cmd::Command, measuring_alloc::MeasuringAllocator, span_stats::SpanStats},
    anyhow::Result,
    tracing_subscriber::{self, fmt, layer::SubscriberExt as _, Registry},
};

#[global_allocator]
static ALLOC: MeasuringAllocator = MeasuringAllocator::new();

fn main() -> Result<()> {
    let fmt_layer = fmt::Layer::default();
    let subscriber = Registry::default().with(fmt_layer).with(SpanStats::new());
    tracing::subscriber::set_global_default(subscriber)?;

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}
