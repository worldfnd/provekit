//! Ring `R_q` forms (`Forms(M)`), extension-field weights `U, V in F_{q^n}`,
//! tie masks `vartheta_leg`, and cancellation polynomials `x_a^iota` (Section
//! 5.1 & Appendix B.1).

use {
    crate::{params::PraxisParams, qap::poly_mul},
    anyhow::{ensure, Result},
    ark_bn254::Fr,
    ark_ff::{Field, One, PrimeField, Zero},
    rayon::prelude::*,
};

/// Right-leg kind in the shared factor grid `K_1 x 3 K_2` (Figure 5 & Section
/// 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegKind {
    /// Even-exponent `U` copies (`k_leg = 2 * K_1 * k_2`).
    E = 0,
    /// Odd-exponent `U` copies (`k_leg = 2 * K_1 * k_2 + 1`).
    O = 1,
    /// `V` copies (`k_leg = 2 * K_1 * k_2`, exponent `k_c = 2 * k_1 + k_leg` is
    /// even).
    V = 2,
}

impl LegKind {
    /// All three kinds in canonical order `[E, O, V]`.
    pub const ALL: [Self; 3] = [Self::E, Self::O, Self::V];
}

/// Identifier of one of the `3 * K_2` right legs: `(kind, k2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RightLeg {
    pub kind: LegKind,
    pub k2:   usize,
}

impl RightLeg {
    /// Linear index in `0..3 * K_2`.
    #[inline]
    #[must_use]
    pub fn index(self, k2_count: usize) -> usize {
        (self.kind as usize) * k2_count + self.k2
    }

    /// Right-leg exponent `k_leg` (Section 5.1, p. 30).
    #[inline]
    #[must_use]
    pub fn k_leg(self, k1_count: usize) -> usize {
        match self.kind {
            LegKind::E | LegKind::V => 2 * k1_count * self.k2,
            LegKind::O => 2 * k1_count * self.k2 + 1,
        }
    }

    /// Enumerate all `3 * K_2` right legs in index order.
    #[must_use]
    pub fn all(k2_count: usize) -> Vec<Self> {
        let mut out = Vec::with_capacity(3 * k2_count);
        for kind in LegKind::ALL {
            for k2 in 0..k2_count {
                out.push(Self { kind, k2 });
            }
        }
        out
    }
}

/// Cell `c = (k1, leg)` in the `K_1 x 3 K_2` grid (total `3 * n / 2` cells).
/// Linear cell index: `leg_idx * K_1 + k1`, so key cell `(0, (E, 0))` has index
/// `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub k1:  usize,
    pub leg: RightLeg,
}

impl Cell {
    /// Exponent `k_c = 2 * k_1 + k_leg`.
    #[inline]
    #[must_use]
    pub fn k_c(self, k1_count: usize) -> usize {
        2 * self.k1 + self.leg.k_leg(k1_count)
    }

    /// Whether this cell is the unique key copy `c_key = (0, (E, 0))`.
    #[inline]
    #[must_use]
    pub fn is_key(self) -> bool {
        self.k1 == 0 && self.leg.kind == LegKind::E && self.leg.k2 == 0
    }

    /// Enumerate all `3 * n / 2` cells in linear index order.
    #[must_use]
    pub fn all(k1_count: usize, k2_count: usize) -> Vec<Self> {
        let legs = RightLeg::all(k2_count);
        let mut out = Vec::with_capacity(legs.len() * k1_count);
        for leg in legs {
            for k1 in 0..k1_count {
                out.push(Self { k1, leg });
            }
        }
        out
    }
}

/// Expanded MSIS matrix `M in R_q^{k x (ell + 1)}` (Definition 5.1 & Section
/// 5.2). Stored as `entries[row * (ell + 1) + col][0..d_r]`, where `row in
/// 0..k` corresponds to paper row `i = row + 1 in [1, k]` and `col in 0..=ell`.
#[derive(Debug, Clone)]
pub struct FormMatrix {
    pub k:          usize,
    pub ell:        usize,
    pub d_r:        usize,
    pub n_unknowns: usize,
    /// Flat `k * (ell + 1)` polynomials, each of length `d_r`.
    pub entries:    Vec<Vec<Fr>>,
}

impl FormMatrix {
    /// Deterministically expand `M` from `seed` via `H_seed(seed, i, j)` using
    /// BLAKE3 XOF.
    #[must_use]
    pub fn from_seed(seed: &[u8], params: &PraxisParams, n_unknowns: usize) -> Self {
        let k = params.k;
        let ell = params.ell(n_unknowns);
        let d_r = params.d_r;
        let total = k * (ell + 1);

        let entries: Vec<Vec<Fr>> = (0..total)
            .into_par_iter()
            .map(|idx| {
                let row_1based = (idx / (ell + 1)) + 1;
                let col = idx % (ell + 1);
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"praxis-v1-H_seed");
                hasher.update(seed);
                hasher.update(&(row_1based as u64).to_le_bytes());
                hasher.update(&(col as u64).to_le_bytes());
                let mut xof = hasher.finalize_xof();
                let mut coeffs = Vec::with_capacity(d_r);
                let mut buf = [0u8; 64];
                for _ in 0..d_r {
                    xof.fill(&mut buf);
                    // 512 bits mod ~254-bit prime q gives statistical bias < 2^-256.
                    coeffs.push(Fr::from_le_bytes_mod_order(&buf));
                }
                coeffs
            })
            .collect();

        Self {
            k,
            ell,
            d_r,
            n_unknowns,
            entries,
        }
    }

    #[inline]
    fn entry(&self, row0: usize, col: usize) -> &[Fr] {
        &self.entries[row0 * (self.ell + 1) + col]
    }

    /// Evaluate the vector `z[x] = sum_{e < n} x^e * phi_e in F_q^{N+1}` at `x
    /// in F_q*` using prefix sums along each `M_{i,j}` (Proof of
    /// Proposition 5.7, p. 48).
    #[must_use]
    pub fn eval_z_vector(&self, x: Fr) -> Vec<Fr> {
        let d_r = self.d_r;
        let x_pow = powers(x, d_r + 1);
        let x_dr = x_pow[d_r];
        let x_dr_inv = x_dr.inverse().expect("x must be nonzero");

        // Powers x^{i * d_r} for i = 1..=k.
        let mut x_block = Vec::with_capacity(self.k);
        let mut cur = x_dr;
        for _ in 0..self.k {
            x_block.push(cur);
            cur *= x_dr;
        }

        let mut out = vec![Fr::zero(); self.n_unknowns + 1];
        // Coordinate 0: phi_0 = e_0 (contributes 1) + sum_{i=1..k} x^{i*d_r} *
        // M_{i,0}(x).
        let mut acc0 = Fr::one();
        for row0 in 0..self.k {
            let m = self.entry(row0, 0);
            let mut val = Fr::zero();
            for s in 0..d_r {
                val += m[s] * x_pow[s];
            }
            acc0 += x_block[row0] * val;
        }
        out[0] = acc0;

        // Coordinates c = (j - 1) * d_r + b + 1 for j in 1..=ell, b in 0..d_r.
        // Sum_s x^s * coeff_{Y^s}(M(Y) * Y^b mod (Y^{d_r} + 1))
        //   = x^b * prefix[d_r - b] - x^b * x^{-d_r} * (total - prefix[d_r - b]).
        let mut prefix = vec![Fr::zero(); d_r + 1];
        for j in 1..=self.ell {
            let base = (j - 1) * d_r + 1;
            let b_limit = (self.n_unknowns + 1).saturating_sub(base).min(d_r);
            for row0 in 0..self.k {
                let m = self.entry(row0, j);
                prefix[0] = Fr::zero();
                for a in 0..d_r {
                    prefix[a + 1] = prefix[a] + m[a] * x_pow[a];
                }
                let total = prefix[d_r];
                let scale = x_block[row0];
                for b in 0..b_limit {
                    let split = d_r - b;
                    let low = prefix[split];
                    let high = total - low;
                    let term = x_pow[b] * (low - high * x_dr_inv);
                    out[base + b] += scale * term;
                }
            }
        }
        out
    }

    /// Evaluate the `n` forms `(phi_0(w), ..., phi_{n-1}(w))` at a Boolean
    /// witness `w in {0,1}^{N+1}`.
    #[must_use]
    pub fn eval_forms_at_witness(&self, w: &[u8]) -> Vec<Fr> {
        let d_r = self.d_r;
        let n = (self.k + 1) * d_r;
        let mut phi = vec![Fr::zero(); n];
        phi[0] = Fr::from(u64::from(w[0]));
        // phi_e = 0 for 0 < e < d_r.

        // For each row i in 1..=k, compute M_{i,0} * w_0 + sum_{j=1..ell} M_{i,j} *
        // w_hat_j mod (Y^{d_r} + 1).
        for row0 in 0..self.k {
            let dst = &mut phi[(row0 + 1) * d_r..(row0 + 2) * d_r];
            if w[0] != 0 {
                let m0 = self.entry(row0, 0);
                for s in 0..d_r {
                    dst[s] += m0[s];
                }
            }
            for j in 1..=self.ell {
                let base = (j - 1) * d_r + 1;
                let b_limit = w.len().saturating_sub(base).min(d_r);
                let m = self.entry(row0, j);
                for b in 0..b_limit {
                    if w[base + b] == 0 {
                        continue;
                    }
                    // Add M_{i,j}(Y) * Y^b mod (Y^{d_r} + 1).
                    for a in 0..(d_r - b) {
                        dst[a + b] += m[a];
                    }
                    for a in (d_r - b)..d_r {
                        dst[a + b - d_r] -= m[a];
                    }
                }
            }
        }
        phi
    }
}

/// All `3 * n / 2` cell weights `xi_c(w)` and the eight cancellation
/// polynomials `x_a^iota(T)` computed by `Dec` (Lines 1 and 4 of Figure 10,
/// Equation (6), p. 47).
#[derive(Debug, Clone)]
pub struct WitnessWeightsAndCancellations {
    /// Weight `xi_c(w)` for every cell `c` in `Cell::all(K1, K2)` order
    /// (`xi_key = xi[0]`).
    pub xi:      Vec<Fr>,
    /// Three tie cancellation polynomials `x_a^0` (`a in 0..3`, degree `< n -
    /// 1`).
    pub x0:      [Vec<Fr>; 3],
    /// Five cross cancellation polynomials `x_a^iota` for `(a, iota) in I, iota
    /// != 0` in canonical order: `[(1,+1), (2,+1), (2,-1), (3,+1), (3,-1)]`
    /// (degree `< 2n - 1`).
    pub x_cross: [Vec<Fr>; 5],
}

/// Canonical list of the 5 cross-base pairs `(a_1based, iota)` in `I` with
/// `iota != 0`.
pub const CROSS_PAIRS: [(usize, i8); 5] = [(1, 1), (2, 1), (2, -1), (3, 1), (3, -1)];

/// Compute `xi_c(w)` for all `3n/2` cells and the 8 cancellation polynomials
/// (Equation (6)).
pub fn compute_weights_and_cancellations(
    phi: &[Fr],
    params: &PraxisParams,
    omega: Fr,
) -> Result<WitnessWeightsAndCancellations> {
    let n = params.n;
    ensure!(phi.len() == n, "phi length mismatch");
    let c0 = Fr::from(params.c0);
    let omega_inv = omega.inverse().expect("omega != 0");

    // z_w(T) = sum_{e < n} phi_e T^e.
    // Conjugates:
    //   z_minus = z[-T / omega]  (sigma^{n/2 - 1}(z))
    //   z_circ  = z[-T]          (sigma^{n/2}(z))
    //   z_plus  = z[-omega * T]  (sigma^{n/2 + 1}(z))
    let z_minus = scale_poly_arg(phi, -omega_inv);
    let z_circ = scale_poly_arg(phi, -Fr::one());
    let z_plus = scale_poly_arg(phi, -omega);

    // U_w(T) = z_w * z_minus mod (T^n - c_0)
    // V_w(T) = z_w * z_circ  mod (T^n - c_0)  (only even powers survive!)
    let u_w = mul_mod_tn_minus_c0(phi, &z_minus, n, c0);
    let v_w = mul_mod_tn_minus_c0(phi, &z_circ, n, c0);
    for e in (1..n).step_by(2) {
        ensure!(v_w[e].is_zero(), "V(w) has nonzero odd coeff at {e}");
    }

    // Populate xi_c(w) for every cell c = (k1, leg) in Cell::all(K1, K2) order,
    // and simultaneously build U'_w, V'_w, U''_w (Appendix B.1, pp. 46-47).
    let cells = Cell::all(params.k1, params.k2);
    let mut xi = vec![Fr::zero(); cells.len()];
    let mut u_prime = vec![Fr::zero(); n];
    let mut v_prime = vec![Fr::zero(); n];
    let mut u_double_prime = vec![Fr::zero(); n];

    let omega2 = omega.square();
    let omega2_pows = powers(omega2, params.k1);
    let neg_omega = -omega;

    for (idx, &cell) in cells.iter().enumerate() {
        let kc = cell.k_c(params.k1);
        let k_leg = cell.leg.k_leg(params.k1);
        match cell.leg.kind {
            LegKind::E | LegKind::O => {
                let w_val = u_w[kc];
                xi[idx] = w_val;
                u_prime[kc] = omega2_pows[cell.k1] * w_val;
                u_double_prime[kc] = neg_omega.pow([k_leg as u64]) * w_val;
            }
            LegKind::V => {
                let w_val = v_w[kc];
                xi[idx] = w_val;
                v_prime[kc] = omega2_pows[cell.k1] * w_val;
            }
        }
    }

    // U_w(-omega * T)
    let u_w_neg_omega = scale_poly_arg(&u_w, neg_omega);

    // Equation (6):
    //   x_1^0 = (U_w * z_circ - V_w * z_minus) / (T^n - c_0)
    //   x_2^0 = (U_w * z_plus - U_w(-omega T) * z_minus) / (T^n - c_0)
    //   x_3^0 = (V_w * z_plus - U_w(-omega T) * z_circ) / (T^n - c_0)
    let x1_0 = div_exact_tn_minus_c0(
        &poly_sub(&poly_mul(&u_w, &z_circ), &poly_mul(&v_w, &z_minus)),
        n,
        c0,
    )?;
    let x2_0 = div_exact_tn_minus_c0(
        &poly_sub(
            &poly_mul(&u_w, &z_plus),
            &poly_mul(&u_w_neg_omega, &z_minus),
        ),
        n,
        c0,
    )?;
    let x3_0 = div_exact_tn_minus_c0(
        &poly_sub(&poly_mul(&v_w, &z_plus), &poly_mul(&u_w_neg_omega, &z_circ)),
        n,
        c0,
    )?;

    // Cross polynomials (degree <= 2n - 2):
    //   x_1^+ = U'_w * z_circ - V'_w * z_minus
    //   x_2^+ = U'_w * z_plus
    //   x_2^- = -U''_w * z_minus
    //   x_3^+ = V'_w * z_plus
    //   x_3^- = -U''_w * z_circ
    let x1_p = pad_to(
        poly_sub(&poly_mul(&u_prime, &z_circ), &poly_mul(&v_prime, &z_minus)),
        2 * n - 1,
    );
    let x2_p = pad_to(poly_mul(&u_prime, &z_plus), 2 * n - 1);
    let x2_m = pad_to(poly_neg(&poly_mul(&u_double_prime, &z_minus)), 2 * n - 1);
    let x3_p = pad_to(poly_mul(&v_prime, &z_plus), 2 * n - 1);
    let x3_m = pad_to(poly_neg(&poly_mul(&u_double_prime, &z_circ)), 2 * n - 1);

    Ok(WitnessWeightsAndCancellations {
        xi,
        x0: [x1_0, x2_0, x3_0],
        x_cross: [x1_p, x2_p, x2_m, x3_p, x3_m],
    })
}

/// Compute `[1, base, base^2, ..., base^{len-1}]`.
#[must_use]
pub fn powers(base: Fr, len: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(len);
    let mut cur = Fr::one();
    for _ in 0..len {
        out.push(cur);
        cur *= base;
    }
    out
}

/// Compute `p(scale * T)` from coefficients of `p(T)`.
fn scale_poly_arg(p: &[Fr], scale: Fr) -> Vec<Fr> {
    let mut out = Vec::with_capacity(p.len());
    let mut cur = Fr::one();
    for &c in p {
        out.push(c * cur);
        cur *= scale;
    }
    out
}

/// Multiply two degree-`<n` polynomials modulo `P(T) = T^n - c_0`.
fn mul_mod_tn_minus_c0(a: &[Fr], b: &[Fr], n: usize, c0: Fr) -> Vec<Fr> {
    let prod = poly_mul(a, b);
    let mut out = vec![Fr::zero(); n];
    for (i, &v) in prod.iter().enumerate() {
        if i < n {
            out[i] += v;
        } else {
            out[i - n] += c0 * v;
        }
    }
    out
}

/// Exact division of a polynomial `q(T)` of degree `<= 2n - 2` by `P(T) = T^n -
/// c_0`. Since `q = q_lo + T^n * q_hi = (T^n - c_0) * q_hi + (q_lo + c_0 *
/// q_hi)`, exact divisibility holds iff `q_lo + c_0 * q_hi == 0`, with quotient
/// `q_hi`.
fn div_exact_tn_minus_c0(q: &[Fr], n: usize, c0: Fr) -> Result<Vec<Fr>> {
    let mut quot = vec![Fr::zero(); n - 1];
    for (i, slot) in quot.iter_mut().enumerate() {
        if n + i < q.len() {
            *slot = q[n + i];
        }
    }
    for i in 0..n {
        let lo = if i < q.len() { q[i] } else { Fr::zero() };
        let hi = if i < quot.len() { quot[i] } else { Fr::zero() };
        let rem = lo + c0 * hi;
        ensure!(
            rem.is_zero(),
            "cancellation polynomial not divisible by T^n - c_0 at coeff {i}"
        );
    }
    Ok(quot)
}

fn poly_sub(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let len = a.len().max(b.len());
    let mut out = vec![Fr::zero(); len];
    for i in 0..a.len() {
        out[i] += a[i];
    }
    for i in 0..b.len() {
        out[i] -= b[i];
    }
    out
}

fn poly_neg(a: &[Fr]) -> Vec<Fr> {
    a.iter().map(|&v| -v).collect()
}

fn pad_to(mut v: Vec<Fr>, len: usize) -> Vec<Fr> {
    v.resize(len, Fr::zero());
    v
}
