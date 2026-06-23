//! bn254 soundness checks: malformed witnesses and public inputs must be
//! rejected at verification.

mod shared;

use provekit_backend_bn254::{register, Bn254Field};

soundness_suite!(Bn254Field, register);
