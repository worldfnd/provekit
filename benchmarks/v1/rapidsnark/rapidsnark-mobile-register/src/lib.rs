//! Static benchmark declarations for Mobench 0.1.48 source discovery.
//!
//! The package compiles the shared implementation selected by `[lib].path` in
//! `Cargo.toml`. Mobench 0.1.48 scans only this conventional path when choosing
//! the generated runner's default function, so these compile-disabled
//! declarations keep its generated metadata aligned with the runtime registry.

#[cfg(any())]
#[benchmark]
pub fn bench_passport_rapidsnark_prove() {}

#[cfg(any())]
#[benchmark]
pub fn bench_passport_rapidsnark_verify() {}

#[cfg(any())]
#[benchmark]
pub fn bench_passport_rapidsnark_proof_verify() {}
