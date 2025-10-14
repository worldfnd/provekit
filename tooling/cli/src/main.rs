#![allow(missing_docs)]
mod cmd;
#[cfg(feature = "profiling-allocator")]
mod profiling_alloc;
mod span_stats;

#[cfg(feature = "profiling-allocator")]
use crate::profiling_alloc::ProfilingAllocator;
#[cfg(feature = "tracy")]
use tracing::info;
use {
    self::cmd::Command,
    anyhow::Result,
    span_stats::SpanStats,
    tracing::subscriber,
    tracing_subscriber::{self, layer::SubscriberExt as _, Registry},
};

#[cfg(feature = "profiling-allocator")]
#[global_allocator]
static ALLOCATOR: ProfilingAllocator = ProfilingAllocator::new();

fn main() -> Result<()> {
    let args = argh::from_env::<cmd::Args>();
    let subscriber = Registry::default().with(SpanStats);

    #[cfg(feature = "tracy")]
    let subscriber = {
        if args.tracy {
            if let Some(depth) = args.tracy_allocations {
                info!("Tracy profiling enabled with allocation tracking (depth {depth}).");
                ALLOCATOR.enable_tracy(depth);
            } else {
                info!("Tracy profiling enabled (without allocation tracking).");
            }
        };
        subscriber.with(args.tracy.then(tracing_tracy::TracyLayer::default))
    };

    subscriber::set_global_default(subscriber)?;

    // Run CLI command
    let res = args.run();

    // SAFETY: It is safe to call `___tracy_shutdown_profiler()` here because all
    // profiling work is complete, and no further Tracy API calls will be made
    // after this point. This function must be called to properly shut down the
    // Tracy profiler before program exit.
    //
    // @recmo: This is not safe. tracing_tracy may still
    // be doing work in other threads. We should properly join all threads and
    // ensure all work is complete before calling this function.
    #[cfg(feature = "tracy")]
    if args.tracy {
        info!("Shutting down Tracy client.");
        ALLOCATOR.disable_tracy();
        unsafe {
            tracing_tracy::client::sys::___tracy_shutdown_profiler();
        }
    }

    res
}
