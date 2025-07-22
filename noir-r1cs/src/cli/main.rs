#![allow(missing_docs)]
mod cmd;
mod measuring_alloc;
mod span_stats;

use std::clone::Clone;
use std::convert::Into;
use tracing::subscriber;
use tracing_subscriber::Layer;
use {
    self::{cmd::Command, measuring_alloc::MeasuringAllocator, span_stats::SpanStats},
    anyhow::Result,
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};
use crate::measuring_alloc::MeasuringAllocatorState;

static ALLOC_STATE: MeasuringAllocatorState = MeasuringAllocatorState::new();

#[global_allocator]
static ALLOC_TRACY: tracy_client::ProfiledAllocator<MeasuringAllocator> = tracy_client::ProfiledAllocator::new(MeasuringAllocator::new(&ALLOC_STATE), 100);

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
