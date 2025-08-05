#!/usr/bin/env bash
set -e

# dependencies:
#
# - `nargo`
# - `cargo`

# export noir functions purely in brillig
nargo export --force-brillig

# run rust prop tests against brillig functions
cargo test

# export noir functions as-is
nargo export

# run rust prop tests against noir functions
cargo test
