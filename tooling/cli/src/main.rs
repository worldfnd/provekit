#![allow(missing_docs)]
mod cmd;
#[cfg(feature = "profiling-allocator")]
mod profiling_alloc;
mod span_stats;

#[cfg(feature = "profiling-allocator")]
use crate::profiling_alloc::ProfilingAllocator;
#[cfg(feature = "tracy")]
use tracing::{info, warn};
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
        } else {
            if args.tracy_allocations.is_some() {
                warn!("--tracy-allocations specified without --tracy, ignoring.");
            }
            if args.tracy_keepalive {
                warn!("--tracy-keepalive specified without --tracy, ignoring.");
            }
        }
        subscriber.with(args.tracy.then(tracing_tracy::TracyLayer::default))
    };

    subscriber::set_global_default(subscriber)?;

    // Run CLI command
    let res = args.run();

    #[cfg(feature = "tracy")]
    if args.tracy_keepalive {
        use std::io::{stderr, stdin, stdout, Write};
        eprintln!("Tracy keepalive enabled, press Enter to exit.");
        stdout().flush()?;
        stderr().flush()?;
        stdin().read_line(&mut String::new())?;
    }

    res
}
