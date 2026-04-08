//! Twist sumcheck: verifies RAM consistency via sumcheck over sorted trace.
//!
//! The Twist protocol checks two properties via sumcheck:
//!
//! 1. **Value consistency**: For consecutive operations to the same address
//!    (Inc[j] = 1), if the later operation is a read, its value must equal
//!    the preceding operation's value:
//!    `Inc[j] * (1 - is_write[j]) * (val[j] - val[j-1]) = 0` for all j.
//!
//! 2. **Address continuity**: The Inc vector correctly marks same-address
//!    transitions:
//!    `Inc[j] * (addr[j] - addr[j-1]) = 0` for all j.
//!
//! These are batched into a single sumcheck using random linear combination:
//!
//! ```text
//! Σ_{j ∈ {0,1}^n} eq(r, j) * [
//!     β₀ * Inc(j) * (1 - W(j)) * (V(j) - V_prev(j))
//!   + β₁ * Inc(j) * (A(j) - A_prev(j))
//! ] = 0
//! ```
//!
//! The value-check term is degree 4 in each round variable (product of 4
//! multilinear polynomials: eq, Inc, (1-W), (V-V_prev)). The address-check
//! term is degree 3 (eq, Inc, (A-A_prev)). We use 5 evaluation points per
//! round: p(0), p(1), p(2), p(3), p(4).

use {ark_ff::Field, ark_std::Zero, crate::FieldElement};

/// Number of evaluation points per sumcheck round (degree 4 + 1).
pub const DEGREE_PLUS_ONE: usize = 5;

/// Polynomials that the Twist sumcheck operates over.
/// Each vector has length = padded trace size (power of 2).
pub struct TwistPolynomials {
    /// Inc[j] = 1 if sorted_ops[j] and sorted_ops[j-1] share the same address.
    pub inc: Vec<FieldElement>,
    /// is_write[j] = 1 if the operation at position j is a write.
    pub is_write: Vec<FieldElement>,
    /// val[j] = value of the operation at position j.
    pub val: Vec<FieldElement>,
    /// val_prev[j] = val[j-1] (shifted by 1, with val_prev[0] = 0).
    pub val_prev: Vec<FieldElement>,
    /// addr[j] = address of the operation at position j.
    pub addr: Vec<FieldElement>,
    /// addr_prev[j] = addr[j-1] (shifted by 1, with addr_prev[0] = 0).
    pub addr_prev: Vec<FieldElement>,
}

impl TwistPolynomials {
    /// Build Twist polynomials from a sorted trace, padded to the next power
    /// of 2.
    pub fn from_trace(trace: &super::TwistTrace) -> Self {
        let n = trace.len();
        let padded_len = n.next_power_of_two();

        let mut inc = vec![FieldElement::zero(); padded_len];
        let mut is_write = vec![FieldElement::zero(); padded_len];
        let mut val = vec![FieldElement::zero(); padded_len];
        let mut val_prev = vec![FieldElement::zero(); padded_len];
        let mut addr = vec![FieldElement::zero(); padded_len];
        let mut addr_prev = vec![FieldElement::zero(); padded_len];

        for j in 0..n {
            let op = &trace.sorted_ops[j];
            inc[j] = trace.inc[j];
            is_write[j] = if op.is_write {
                FieldElement::from(1u64)
            } else {
                FieldElement::zero()
            };
            val[j] = op.value;
            addr[j] = FieldElement::from(op.address as u64);

            if j > 0 {
                let prev = &trace.sorted_ops[j - 1];
                val_prev[j] = prev.value;
                addr_prev[j] = FieldElement::from(prev.address as u64);
            }
        }

        Self {
            inc,
            is_write,
            val,
            val_prev,
            addr,
            addr_prev,
        }
    }

    /// Evaluate the Twist constraint polynomial at a single point j.
    ///
    /// Returns `(value_check, addr_check)` where both should be zero for valid
    /// traces.
    pub fn eval_at(&self, j: usize) -> (FieldElement, FieldElement) {
        let one = FieldElement::from(1u64);
        let value_check =
            self.inc[j] * (one - self.is_write[j]) * (self.val[j] - self.val_prev[j]);
        let addr_check = self.inc[j] * (self.addr[j] - self.addr_prev[j]);
        (value_check, addr_check)
    }

    /// Verify that the constraint polynomial is zero everywhere (prover sanity
    /// check).
    pub fn check_zero_everywhere(&self) -> bool {
        let n = self.inc.len();
        for j in 0..n {
            let (vc, ac) = self.eval_at(j);
            if vc != FieldElement::zero() || ac != FieldElement::zero() {
                return false;
            }
        }
        true
    }

    /// Length of the padded polynomials.
    pub fn len(&self) -> usize {
        self.inc.len()
    }

    /// Whether polynomials are empty.
    pub fn is_empty(&self) -> bool {
        self.inc.is_empty()
    }
}

/// Interpolate a multilinear polynomial at a point `t` given its values at
/// `x = 0` and `x = 1`: `f(t) = f0 + t * (f1 - f0)`.
#[inline(always)]
fn mle_at(f0: FieldElement, f1: FieldElement, t: FieldElement) -> FieldElement {
    f0 + t * (f1 - f0)
}

/// Compute the Twist constraint at a given evaluation point, using
/// interpolated polynomial values.
#[inline(always)]
fn twist_constraint(
    eq_t: FieldElement,
    inc_t: FieldElement,
    is_write_t: FieldElement,
    val_t: FieldElement,
    val_prev_t: FieldElement,
    addr_t: FieldElement,
    addr_prev_t: FieldElement,
    beta: &[FieldElement; 2],
) -> FieldElement {
    let one = FieldElement::from(1u64);
    let vc = inc_t * (one - is_write_t) * (val_t - val_prev_t);
    let ac = inc_t * (addr_t - addr_prev_t);
    eq_t * (beta[0] * vc + beta[1] * ac)
}

/// Run the Twist sumcheck prover for a single round.
///
/// The value-check term `eq * Inc * (1-W) * (V-V_prev)` is degree 4 in the
/// round variable, so we compute 5 evaluation points: p(0)..p(4).
///
/// Returns `[p(0), p(1), p(2), p(3), p(4)]`.
pub fn twist_sumcheck_round(
    eq_evals: &[FieldElement],
    polys: &TwistPolynomials,
    beta: &[FieldElement; 2],
) -> [FieldElement; DEGREE_PLUS_ONE] {
    let half = eq_evals.len() / 2;
    let mut evals = [FieldElement::zero(); DEGREE_PLUS_ONE];

    for i in 0..half {
        let eq0 = eq_evals[i];
        let eq1 = eq_evals[half + i];

        let inc0 = polys.inc[i];
        let inc1 = polys.inc[half + i];
        let w0 = polys.is_write[i];
        let w1 = polys.is_write[half + i];
        let v0 = polys.val[i];
        let v1 = polys.val[half + i];
        let vp0 = polys.val_prev[i];
        let vp1 = polys.val_prev[half + i];
        let a0 = polys.addr[i];
        let a1 = polys.addr[half + i];
        let ap0 = polys.addr_prev[i];
        let ap1 = polys.addr_prev[half + i];

        // Evaluate at t = 0, 1, 2, 3, 4
        for (idx, t_val) in [0u64, 1, 2, 3, 4].iter().enumerate() {
            let t = FieldElement::from(*t_val);
            let eq_t = if idx == 0 {
                eq0
            } else if idx == 1 {
                eq1
            } else {
                mle_at(eq0, eq1, t)
            };

            let (inc_t, w_t, v_t, vp_t, a_t, ap_t) = if idx == 0 {
                (inc0, w0, v0, vp0, a0, ap0)
            } else if idx == 1 {
                (inc1, w1, v1, vp1, a1, ap1)
            } else {
                (
                    mle_at(inc0, inc1, t),
                    mle_at(w0, w1, t),
                    mle_at(v0, v1, t),
                    mle_at(vp0, vp1, t),
                    mle_at(a0, a1, t),
                    mle_at(ap0, ap1, t),
                )
            };

            evals[idx] += twist_constraint(eq_t, inc_t, w_t, v_t, vp_t, a_t, ap_t, beta);
        }
    }

    evals
}

/// Fold the MLE polynomials after a sumcheck round, fixing the first variable
/// to the challenge value `alpha`.
///
/// For each polynomial f of length 2n:
/// `f'[i] = f[i] + alpha * (f[n + i] - f[i])`
/// The result has length n.
pub fn fold_polynomial(poly: &mut Vec<FieldElement>, alpha: FieldElement) {
    let half = poly.len() / 2;
    for i in 0..half {
        poly[i] = poly[i] + alpha * (poly[half + i] - poly[i]);
    }
    poly.truncate(half);
}

/// Fold all Twist polynomials and eq_evals after receiving challenge `alpha`.
pub fn fold_twist_polys(
    polys: &mut TwistPolynomials,
    eq_evals: &mut Vec<FieldElement>,
    alpha: FieldElement,
) {
    fold_polynomial(&mut polys.inc, alpha);
    fold_polynomial(&mut polys.is_write, alpha);
    fold_polynomial(&mut polys.val, alpha);
    fold_polynomial(&mut polys.val_prev, alpha);
    fold_polynomial(&mut polys.addr, alpha);
    fold_polynomial(&mut polys.addr_prev, alpha);
    fold_polynomial(eq_evals, alpha);
}

/// Verify a single sumcheck round: check that p(0) + p(1) == claimed_sum.
pub fn verify_round(
    round_poly: &[FieldElement; DEGREE_PLUS_ONE],
    claimed_sum: FieldElement,
) -> bool {
    round_poly[0] + round_poly[1] == claimed_sum
}

/// Evaluate the degree-4 round polynomial at a point `x` using Lagrange
/// interpolation through the 5 points (0, p[0]), (1, p[1]), ..., (4, p[4]).
pub fn eval_round_poly(
    p: &[FieldElement; DEGREE_PLUS_ONE],
    x: FieldElement,
) -> FieldElement {
    // Lagrange basis: L_k(x) = Π_{j≠k} (x - j) / (k - j)
    let points: [FieldElement; 5] = [
        FieldElement::from(0u64),
        FieldElement::from(1u64),
        FieldElement::from(2u64),
        FieldElement::from(3u64),
        FieldElement::from(4u64),
    ];

    // Precompute (x - j) for j = 0..4
    let diffs: [FieldElement; 5] = std::array::from_fn(|j| x - points[j]);

    // Precompute the product Π_{j=0}^{4} (x - j)
    let full_product = diffs.iter().copied().fold(FieldElement::from(1u64), |a, b| a * b);

    // Precompute barycentric weights: w_k = 1 / Π_{j≠k} (k - j)
    // w_0 = 1/(0-1)(0-2)(0-3)(0-4) = 1/((-1)(-2)(-3)(-4)) = 1/24
    // w_1 = 1/(1-0)(1-2)(1-3)(1-4) = 1/((1)(-1)(-2)(-3)) = 1/6 = -1/(-6)
    // w_2 = 1/(2-0)(2-1)(2-3)(2-4) = 1/((2)(1)(-1)(-2)) = 1/4
    // w_3 = 1/(3-0)(3-1)(3-2)(3-4) = 1/((3)(2)(1)(-1)) = -1/6
    // w_4 = 1/(4-0)(4-1)(4-2)(4-3) = 1/((4)(3)(2)(1)) = 1/24
    let bary_weights: [FieldElement; 5] = {
        let inv6 = FieldElement::from(6u64)
            .inverse()
            .expect("6 is invertible");
        let inv24 = FieldElement::from(24u64)
            .inverse()
            .expect("24 is invertible");
        let inv4 = FieldElement::from(4u64)
            .inverse()
            .expect("4 is invertible");
        let neg_one = -FieldElement::from(1u64);
        [inv24, neg_one * inv6, inv4, neg_one * inv6, inv24]
    };

    let mut result = FieldElement::zero();
    for k in 0..5 {
        if diffs[k] == FieldElement::zero() {
            // x == points[k], so L_k(x) = 1 and all other L_j(x) = 0
            return p[k];
        }
        // L_k(x) = full_product / (x - points[k]) * bary_weights[k]
        let l_k = full_product
            * diffs[k]
                .inverse()
                .expect("diff should be nonzero")
            * bary_weights[k];
        result += p[k] * l_k;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::twist::{MemoryOp, TwistTrace};

    #[test]
    fn test_twist_polynomials_zero_for_valid_trace() {
        let initial = [FieldElement::from(10u64), FieldElement::from(20u64)];
        let ops = vec![
            MemoryOp {
                address: 0,
                value: FieldElement::from(10u64),
                is_write: false,
                timestamp: 1,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(30u64),
                is_write: true,
                timestamp: 2,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(30u64),
                is_write: false,
                timestamp: 3,
            },
        ];

        let trace = TwistTrace::from_operations(&initial, &ops);
        let polys = TwistPolynomials::from_trace(&trace);
        assert!(polys.check_zero_everywhere());
    }

    #[test]
    fn test_twist_polynomials_nonzero_for_invalid_read() {
        let initial = [FieldElement::from(10u64)];
        let ops = vec![MemoryOp {
            address: 0,
            value: FieldElement::from(99u64), // wrong value
            is_write: false,
            timestamp: 1,
        }];

        let trace = TwistTrace::from_operations(&initial, &ops);
        let polys = TwistPolynomials::from_trace(&trace);
        assert!(!polys.check_zero_everywhere());
    }

    #[test]
    fn test_sumcheck_total_is_zero_for_valid_trace() {
        let initial = [
            FieldElement::from(10u64),
            FieldElement::from(20u64),
            FieldElement::from(30u64),
            FieldElement::from(40u64),
        ];
        let ops = vec![
            MemoryOp {
                address: 0,
                value: FieldElement::from(10u64),
                is_write: false,
                timestamp: 1,
            },
            MemoryOp {
                address: 2,
                value: FieldElement::from(30u64),
                is_write: false,
                timestamp: 2,
            },
            MemoryOp {
                address: 3,
                value: FieldElement::from(40u64),
                is_write: false,
                timestamp: 3,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(20u64),
                is_write: false,
                timestamp: 4,
            },
        ];

        let trace = TwistTrace::from_operations(&initial, &ops);
        let polys = TwistPolynomials::from_trace(&trace);
        assert!(polys.check_zero_everywhere());

        let num_vars = (polys.len() as f64).log2() as usize;
        let r: Vec<FieldElement> = (0..num_vars)
            .map(|i| FieldElement::from((i + 3) as u64))
            .collect();
        let eq_evals =
            crate::utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq(
                &r,
                polys.len(),
            );

        let beta = [FieldElement::from(7u64), FieldElement::from(13u64)];

        let mut total = FieldElement::zero();
        for j in 0..polys.len() {
            let (vc, ac) = polys.eval_at(j);
            total += eq_evals[j] * (beta[0] * vc + beta[1] * ac);
        }
        assert_eq!(total, FieldElement::zero());
    }

    #[test]
    fn test_eval_round_poly_quadratic() {
        // p(0)=1, p(1)=4, p(2)=9, p(3)=16, p(4)=25 → p(x) = (x+1)^2
        // p(5) should be 36
        let p = [
            FieldElement::from(1u64),
            FieldElement::from(4u64),
            FieldElement::from(9u64),
            FieldElement::from(16u64),
            FieldElement::from(25u64),
        ];
        let result = eval_round_poly(&p, FieldElement::from(5u64));
        assert_eq!(result, FieldElement::from(36u64));
    }

    #[test]
    fn test_eval_round_poly_quartic() {
        // p(x) = x^4. p(0)=0, p(1)=1, p(2)=16, p(3)=81, p(4)=256
        // p(5) should be 625
        let p = [
            FieldElement::from(0u64),
            FieldElement::from(1u64),
            FieldElement::from(16u64),
            FieldElement::from(81u64),
            FieldElement::from(256u64),
        ];
        let result = eval_round_poly(&p, FieldElement::from(5u64));
        assert_eq!(result, FieldElement::from(625u64));
    }

    #[test]
    fn test_eval_round_poly_at_known_points() {
        let p = [
            FieldElement::from(3u64),
            FieldElement::from(7u64),
            FieldElement::from(15u64),
            FieldElement::from(100u64),
            FieldElement::from(42u64),
        ];
        // Evaluating at known points should return the values themselves
        for (i, &expected) in p.iter().enumerate() {
            let result = eval_round_poly(&p, FieldElement::from(i as u64));
            assert_eq!(result, expected, "Failed at point {i}");
        }
    }

    #[test]
    fn test_full_sumcheck_protocol() {
        // Build a valid trace with writes and reads
        let initial = [FieldElement::from(100u64), FieldElement::from(200u64)];
        let ops = vec![
            MemoryOp {
                address: 0,
                value: FieldElement::from(100u64),
                is_write: false,
                timestamp: 1,
            },
            MemoryOp {
                address: 1,
                value: FieldElement::from(200u64),
                is_write: false,
                timestamp: 2,
            },
        ];

        let trace = TwistTrace::from_operations(&initial, &ops);
        let mut polys = TwistPolynomials::from_trace(&trace);
        assert!(polys.check_zero_everywhere());

        let num_vars = (polys.len() as f64).log2() as usize;

        let r: Vec<FieldElement> = (0..num_vars)
            .map(|i| FieldElement::from((i * 7 + 3) as u64))
            .collect();
        let mut eq_evals =
            crate::utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq(
                &r,
                polys.len(),
            );

        let beta = [FieldElement::from(5u64), FieldElement::from(11u64)];
        let mut claimed_sum = FieldElement::zero();

        let challenges: Vec<FieldElement> = (0..num_vars)
            .map(|i| FieldElement::from((i * 13 + 7) as u64))
            .collect();

        for round in 0..num_vars {
            let round_poly = twist_sumcheck_round(&eq_evals, &polys, &beta);

            assert!(
                verify_round(&round_poly, claimed_sum),
                "Round {round} failed: p(0)+p(1) = {:?} != claimed_sum = {:?}",
                round_poly[0] + round_poly[1],
                claimed_sum,
            );

            claimed_sum = eval_round_poly(&round_poly, challenges[round]);
            fold_twist_polys(&mut polys, &mut eq_evals, challenges[round]);
        }

        // After all rounds, verify final evaluation matches
        assert_eq!(polys.len(), 1);
        let one = FieldElement::from(1u64);
        let vc = polys.inc[0] * (one - polys.is_write[0]) * (polys.val[0] - polys.val_prev[0]);
        let ac = polys.inc[0] * (polys.addr[0] - polys.addr_prev[0]);
        let final_eval = eq_evals[0] * (beta[0] * vc + beta[1] * ac);
        assert_eq!(final_eval, claimed_sum);
    }

    #[test]
    fn test_full_sumcheck_with_writes() {
        // Memory of 4 cells, with writes and subsequent reads
        let initial = [
            FieldElement::from(10u64),
            FieldElement::from(20u64),
            FieldElement::from(30u64),
            FieldElement::from(40u64),
        ];
        let ops = vec![
            // Write 99 to addr 0
            MemoryOp {
                address: 0,
                value: FieldElement::from(99u64),
                is_write: true,
                timestamp: 1,
            },
            // Read addr 0 → should get 99
            MemoryOp {
                address: 0,
                value: FieldElement::from(99u64),
                is_write: false,
                timestamp: 2,
            },
            // Read addr 2 → should get 30
            MemoryOp {
                address: 2,
                value: FieldElement::from(30u64),
                is_write: false,
                timestamp: 3,
            },
            // Write 77 to addr 3
            MemoryOp {
                address: 3,
                value: FieldElement::from(77u64),
                is_write: true,
                timestamp: 4,
            },
            // Read addr 3 → should get 77
            MemoryOp {
                address: 3,
                value: FieldElement::from(77u64),
                is_write: false,
                timestamp: 5,
            },
            // Read addr 1 → should get 20
            MemoryOp {
                address: 1,
                value: FieldElement::from(20u64),
                is_write: false,
                timestamp: 6,
            },
            // Write 55 to addr 1
            MemoryOp {
                address: 1,
                value: FieldElement::from(55u64),
                is_write: true,
                timestamp: 7,
            },
            // Read addr 1 → should get 55
            MemoryOp {
                address: 1,
                value: FieldElement::from(55u64),
                is_write: false,
                timestamp: 8,
            },
        ];

        let trace = TwistTrace::from_operations(&initial, &ops);
        assert!(trace.check_consistency());
        let mut polys = TwistPolynomials::from_trace(&trace);
        assert!(polys.check_zero_everywhere());

        let num_vars = (polys.len() as f64).log2() as usize;
        let r: Vec<FieldElement> = (0..num_vars)
            .map(|i| FieldElement::from((i * 11 + 2) as u64))
            .collect();
        let mut eq_evals =
            crate::utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq(
                &r,
                polys.len(),
            );

        let beta = [FieldElement::from(17u64), FieldElement::from(31u64)];
        let mut claimed_sum = FieldElement::zero();
        let challenges: Vec<FieldElement> = (0..num_vars)
            .map(|i| FieldElement::from((i * 19 + 5) as u64))
            .collect();

        for round in 0..num_vars {
            let round_poly = twist_sumcheck_round(&eq_evals, &polys, &beta);
            assert!(
                verify_round(&round_poly, claimed_sum),
                "Round {round} failed"
            );
            claimed_sum = eval_round_poly(&round_poly, challenges[round]);
            fold_twist_polys(&mut polys, &mut eq_evals, challenges[round]);
        }

        assert_eq!(polys.len(), 1);
        let one = FieldElement::from(1u64);
        let vc = polys.inc[0] * (one - polys.is_write[0]) * (polys.val[0] - polys.val_prev[0]);
        let ac = polys.inc[0] * (polys.addr[0] - polys.addr_prev[0]);
        let final_eval = eq_evals[0] * (beta[0] * vc + beta[1] * ac);
        assert_eq!(final_eval, claimed_sum);
    }
}
