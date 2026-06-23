//! Goldilocks soundness checks: malformed witnesses and public inputs must be
//! rejected at verification.

mod shared;

use provekit_backend_goldilocks::{register, GoldilocksField};

soundness_suite!(GoldilocksField, register);
