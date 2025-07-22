#![allow(missing_docs)]
mod cmd;
#[cfg(feature = "cli-profiled")]
mod measuring_alloc;
#[cfg(feature = "cli-profiled")]
mod span_stats;

use std::clone::Clone;
use std::convert::Into;
use self::cmd::Command;
use anyhow::Result;

#[cfg(feature = "cli-profiled")]
use {
    tracing::subscriber,
    tracing_subscriber::Layer,
    crate::measuring_alloc::{MeasuringAllocatorState, MeasuringAllocator},
    span_stats::SpanStats,
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};

#[cfg(feature = "cli-profiled")]
static ALLOC_STATE: MeasuringAllocatorState = MeasuringAllocatorState::new();

#[cfg(feature = "cli-profiled")]
#[global_allocator]
static ALLOC_TRACY: tracy_client::ProfiledAllocator<MeasuringAllocator> = tracy_client::ProfiledAllocator::new(MeasuringAllocator::new(&ALLOC_STATE), 100);

#[cfg(not(feature = "cli-profiled"))]
fn main() -> Result<()> {
    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}

#[cfg(feature = "cli-profiled")]
fn main() -> Result<()> {
    let subscriber = Registry::default()
        .with(tracing_tracy::TracyLayer::default())
        .with(SpanStats);

    subscriber::set_global_default(subscriber)?;

    let _client = tracy_client::Client::start();

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    let res = args.run();

    unsafe {
        tracy_client_sys::___tracy_shutdown_profiler();
    }

    res
}
