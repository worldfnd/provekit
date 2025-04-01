#![doc = include_str!("../README.md")]
mod cmd;
mod compiler;
mod sparse_matrix;
mod utils;
mod witness;

use {
    self::{cmd::Command, sparse_matrix::SparseMatrix},
    anyhow::Result,
    tracing::level_filters::LevelFilter,
    tracing_subscriber::{
        self, fmt::format::FmtSpan, layer::SubscriberExt as _, util::SubscriberInitExt as _,
        EnvFilter,
    },
    tracing_tree::{time::Uptime, HierarchicalLayer},
};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::NONE)
        .with_ansi(true)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .with_env_var("PROVEKIT_LOG")
                .from_env_lossy(),
        )
        .finish()
        .with(HierarchicalLayer::new(2).with_timer(Uptime::default()))
        .init();

    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}
