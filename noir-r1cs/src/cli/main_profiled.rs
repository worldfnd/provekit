#![allow(missing_docs)]
mod cmd;
mod measuring_alloc;
mod span_stats;

use {
    self::{cmd::Command, measuring_alloc::MeasuringAllocator, span_stats::SpanStats},
    crate::measuring_alloc::MeasuringAllocatorState,
    anyhow::Result,
    std::{clone::Clone, convert::Into},
    tracing::subscriber,
    tracing_subscriber::{self, layer::SubscriberExt as _, Layer, Registry},
};

static ALLOC_STATE: MeasuringAllocatorState = MeasuringAllocatorState::new();

#[global_allocator]
static ALLOC_TRACY: tracy_client::ProfiledAllocator<MeasuringAllocator> =
    tracy_client::ProfiledAllocator::new(MeasuringAllocator::new(&ALLOC_STATE), 100);

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
