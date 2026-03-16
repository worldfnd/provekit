//! Compile-time EC point precomputation.
//! Only used to precompute accumulated offset points; not performance-critical.

pub(super) use provekit_common::u256_arith::{mod_add, mod_mul, U256};
use provekit_common::u256_arith::{mod_inv, mod_sub};

/// EC point doubling on y^2 = x^3 + ax + b.
pub fn ec_point_double(x: &U256, y: &U256, a: &U256, p: &U256) -> (U256, U256) {
    // lambda = (3*x^2 + a) / (2*y)
    let x_sq = mod_mul(x, x, p);
    let two_x_sq = mod_add(&x_sq, &x_sq, p);
    let three_x_sq = mod_add(&two_x_sq, &x_sq, p);
    let num = mod_add(&three_x_sq, a, p);
    let two_y = mod_add(y, y, p);
    let denom_inv = mod_inv(&two_y, p);
    let lambda = mod_mul(&num, &denom_inv, p);

    // x3 = lambda^2 - 2*x
    let lambda_sq = mod_mul(&lambda, &lambda, p);
    let two_x = mod_add(x, x, p);
    let x3 = mod_sub(&lambda_sq, &two_x, p);

    // y3 = lambda * (x - x3) - y
    let x_minus_x3 = mod_sub(x, &x3, p);
    let lambda_dx = mod_mul(&lambda, &x_minus_x3, p);
    let y3 = mod_sub(&lambda_dx, y, p);

    (x3, y3)
}
