#![allow(missing_docs)]
mod cmd;
#[cfg(feature = "profiling")]
mod measuring_alloc;
#[cfg(feature = "profiling")]
mod span_stats;

use {
    self::cmd::Command,
    anyhow::Result,
    std::{clone::Clone, convert::Into},
};
#[cfg(feature = "profiling")]
use {
    crate::measuring_alloc::{MeasuringAllocator, MeasuringAllocatorState},
    span_stats::SpanStats,
    tracing::subscriber,
    tracing_subscriber::Layer,
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};

#[cfg(feature = "profiling")]
static ALLOC_STATE: MeasuringAllocatorState = MeasuringAllocatorState::new();

#[cfg(feature = "profiling")]
#[global_allocator]
static ALLOC_TRACY: tracy_client::ProfiledAllocator<MeasuringAllocator> =
    tracy_client::ProfiledAllocator::new(MeasuringAllocator::new(&ALLOC_STATE), 100);

#[cfg(not(feature = "profiling"))]
fn main() -> Result<()> {
    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}

#[cfg(feature = "profiling")]
fn main() -> Result<()> {
    let subscriber = Registry::default()
        .with(tracing_tracy::TracyLayer::default())
        .with(SpanStats);

    subscriber::set_global_default(subscriber)?;

    let _client = tracy_client::Client::start();

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    let res = args.run();

    // SAFETY: It is safe to call `___tracy_shutdown_profiler()` here because all
    // profiling work is complete, and no further Tracy API calls will be made
    // after this point. This function must be called to properly shut down the
    // Tracy profiler before program exit.
    unsafe {
        tracy_client_sys::___tracy_shutdown_profiler();
    }

    res
}
