//! Goldilocks soundness checks: malformed witnesses and public inputs must be
//! rejected at verification.
//!
//! See `goldilocks_roundtrip.rs` for the base-leaf vs ext-leaf field split.

mod shared;

use provekit_backend_goldilocks::{register, GoldilocksEfField, GoldilocksField};

soundness_suite!(GoldilocksField, register);
challenge_soundness_suite!(GoldilocksEfField, register);
