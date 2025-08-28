#![allow(missing_docs)]
mod cmd;

use {
    self::cmd::Command,
    anyhow::Result,
    std::{clone::Clone, convert::Into},
    tracing_subscriber::{self, layer::SubscriberExt as _, Layer},
};

fn main() -> Result<()> {
    // Run CLI command
    let args = argh::from_env::<cmd::Args>();
    args.run()
}
