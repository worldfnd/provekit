//! QAP Setup (Definition 4.6), sparse barycentric evaluation for `Enc`, and
//! fast coset-FFT polynomial interpolation/division for `Dec` (Equation 4).

use {
    crate::bqs::{eval_sparse_bits, Bqs},
    anyhow::{ensure, Result},
    ark_bn254::Fr,
    ark_ff::{batch_inversion, Field, One, Zero},
    ark_poly::{EvaluationDomain, Radix2EvaluationDomain},
};

/// Coset shift `5` (a quadratic non-residue mod BN254 `q`, hence disjoint from
/// any power-of-two subgroup `H` of order `<= 2^27`).
const COSET_SHIFT: u64 = 5;

/// Deterministic QAP public parameters produced by `Setup(S)` (Definition 4.6 &
/// Figure 9).
#[derive(Debug, Clone)]
pub struct QapSetup {
    /// Underlying Boolean Quadratic System (already padded if needed).
    pub bqs:               Bqs,
    /// Coset size `nu` (power of two `> F_max`).
    pub nu:                usize,
    /// Total evaluation points `D = N + 2 + nu * n_c`.
    pub d:                 usize,
    /// Radix-2 domain `H` of size `2^ceil(log2 D)` containing `P`.
    pub domain_h:          Radix2EvaluationDomain<Fr>,
    /// Shifted coset `COSET_SHIFT * H` for exact polynomial division in `O(H
    /// log H)`.
    pub coset_h:           Radix2EvaluationDomain<Fr>,
    /// Radix-2 domain of size `2 * |H|` for products `A_w * B_w` of degree `<
    /// 2D`.
    pub domain_2h:         Radix2EvaluationDomain<Fr>,
    /// Shifted coset `COSET_SHIFT * domain_2h`.
    pub coset_2h:          Radix2EvaluationDomain<Fr>,
    /// Indices in `domain_h` for `d_0, d_1, ..., d_N` (length `N + 1`).
    pub d_indices:         Vec<usize>,
    /// Index in `domain_h` for the key point `rho`.
    pub rho_index:         usize,
    /// Key point `rho in F_q`.
    pub rho:               Fr,
    /// For each constraint `t in 0..n_c`: indices in `domain_h` of coset `K_t`
    /// (`[p_{t,0}, ..., p_{t,nu-1}]`).
    pub coset_indices:     Vec<Vec<usize>>,
    /// All indices of `P` inside `domain_h` (length `D`).
    pub p_indices:         Vec<usize>,
    /// Vanishing polynomial `Z_0(X) = prod_{p in P_0} (X - p)` (degree `N +
    /// 2`).
    pub z0_poly:           Vec<Fr>,
    /// Vanishing polynomial `Z_P(X) = prod_{p in P} (X - p) = Z(X) * (X - rho)`
    /// (degree `D`).
    pub zp_poly:           Vec<Fr>,
    /// `Z(rho) = Z_P'(rho)`.
    pub z_at_rho:          Fr,
    /// Values `Z_0(p)` for every `p in domain_h` (indexed by `domain_h` index).
    pub z0_on_h:           Vec<Fr>,
    /// Barycentric weights `w_p = 1 / Z_P'(p)` for each `p` in `p_indices`
    /// (same order).
    pub bary_weights:      Vec<Fr>,
    /// `Z_{H \ P}` evaluated on `domain_h`.
    pub z_out_p_on_h:      Vec<Fr>,
    /// Inverse of `Z_{H \ P}` evaluated on `coset_h`.
    pub z_out_p_inv_coset: Vec<Fr>,
    /// `Z_{H \ K}` evaluated on `domain_h`, where `K = union_t K_t`.
    pub z_out_k_on_h:      Vec<Fr>,
    /// Inverse of `Z_{H \ K}` evaluated on `coset_h`.
    pub z_out_k_inv_coset: Vec<Fr>,
    /// Precomputed `L_rho`, `Z_0`, and `1 / Z_P` evaluated on `coset_2h`.
    pub l_rho_coset_2h:    Vec<Fr>,
    pub z0_coset_2h:       Vec<Fr>,
    pub zp_inv_coset_2h:   Vec<Fr>,
}

/// Build monic polynomial `prod_{r in roots} (X - r)` via a balanced subproduct
/// tree.
pub fn vanishing_poly_from_roots(roots: &[Fr]) -> Vec<Fr> {
    if roots.is_empty() {
        return vec![Fr::one()];
    }
    let mut layer: Vec<Vec<Fr>> = roots.iter().map(|&r| vec![-r, Fr::one()]).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < layer.len() {
            next.push(poly_mul(&layer[i], &layer[i + 1]));
            i += 2;
        }
        if i < layer.len() {
            next.push(std::mem::take(&mut layer[i]));
        }
        layer = next;
    }
    layer.pop().unwrap_or_else(|| vec![Fr::one()])
}

/// Multiply two polynomials over `Fr` (schoolbook for small degree, Radix-2 FFT
/// for large).
pub fn poly_mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    if a.len().min(b.len()) <= 64 {
        let mut out = vec![Fr::zero(); a.len() + b.len() - 1];
        for (i, &ai) in a.iter().enumerate() {
            if ai.is_zero() {
                continue;
            }
            for (j, &bj) in b.iter().enumerate() {
                out[i + j] += ai * bj;
            }
        }
        trim_zeros(&mut out);
        return out;
    }
    let out_len = a.len() + b.len() - 1;
    let domain = Radix2EvaluationDomain::<Fr>::new(out_len)
        .expect("BN254 supports radix-2 domains up to 2^28");
    let mut fa = a.to_vec();
    let mut fb = b.to_vec();
    domain.fft_in_place(&mut fa);
    domain.fft_in_place(&mut fb);
    for (x, y) in fa.iter_mut().zip(fb.iter()) {
        *x *= *y;
    }
    domain.ifft_in_place(&mut fa);
    fa.truncate(out_len);
    trim_zeros(&mut fa);
    fa
}

/// Evaluate polynomial `coeffs` at `x` via Horner's rule.
#[must_use]
pub fn poly_eval(coeffs: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::zero();
    for &c in coeffs.iter().rev() {
        acc *= x;
        acc += c;
    }
    acc
}

fn trim_zeros(v: &mut Vec<Fr>) {
    while v.last().is_some_and(Zero::is_zero) {
        v.pop();
    }
}

/// Formal derivative `p'(X)`.
fn poly_deriv(p: &[Fr]) -> Vec<Fr> {
    if p.len() <= 1 {
        return Vec::new();
    }
    (1..p.len()).map(|i| p[i] * Fr::from(i as u64)).collect()
}

/// Values of `A(tau), B(tau), Z_0(tau), Z(tau), Z_P(tau), L_rho(tau)` at a
/// secret `tau not in P`.
#[derive(Debug, Clone)]
pub struct QapEvalAtTau {
    pub a_tau:     Vec<Fr>,
    pub b_tau:     Vec<Fr>,
    pub z0_tau:    Fr,
    pub z_tau:     Fr,
    pub zp_tau:    Fr,
    pub l_rho_tau: Fr,
}

/// Witness polynomials from Equation (4): `h_key`, `h_oth`, and allowed
/// remainder `R_w`.
#[derive(Debug, Clone)]
pub struct WitnessPolys {
    pub h_key: Vec<Fr>,
    pub h_oth: Vec<Fr>,
    pub r_w:   Vec<Fr>,
}

impl QapSetup {
    /// Deterministic QAP setup for `bqs` (Definition 4.6).
    pub fn setup(bqs: Bqs) -> Result<Self> {
        let nu = bqs.coset_size();
        let n_c = bqs.constraints.len();
        let n_unknowns = bqs.n_unknowns;
        let d = bqs.num_eval_points();

        let h_size = d.next_power_of_two();
        let domain_h = Radix2EvaluationDomain::<Fr>::new(h_size)
            .ok_or_else(|| anyhow::anyhow!("failed to build radix-2 domain of size {h_size}"))?;
        let coset_shift = Fr::from(COSET_SHIFT);
        let coset_h = domain_h
            .get_coset(coset_shift)
            .ok_or_else(|| anyhow::anyhow!("failed to build coset_h"))?;
        let domain_2h = Radix2EvaluationDomain::<Fr>::new(2 * h_size)
            .ok_or_else(|| anyhow::anyhow!("failed to build domain_2h"))?;
        let coset_2h = domain_2h
            .get_coset(coset_shift)
            .ok_or_else(|| anyhow::anyhow!("failed to build coset_2h"))?;

        let h_elems: Vec<Fr> = domain_h.elements().collect();
        let num_cosets_in_h = h_size / nu;
        ensure!(
            n_c <= num_cosets_in_h,
            "not enough cosets in H ({num_cosets_in_h}) for n_c = {n_c}"
        );

        // Place constraint cosets K_0, ..., K_{n_c - 1} in the first n_c cosets of
        // subgroup G.
        let mut in_p = vec![false; h_size];
        let mut in_k = vec![false; h_size];
        let mut coset_indices = Vec::with_capacity(n_c);
        for t in 0..n_c {
            let mut idxs = Vec::with_capacity(nu);
            for j in 0..nu {
                let idx = t + j * num_cosets_in_h;
                idxs.push(idx);
                in_p[idx] = true;
                in_k[idx] = true;
            }
            coset_indices.push(idxs);
        }

        // Collect unused points of H for P_0 = {d_0, ..., d_N, rho}.
        let mut free_indices = Vec::with_capacity(n_unknowns + 2);
        for idx in 0..h_size {
            if !in_p[idx] {
                free_indices.push(idx);
                if free_indices.len() == n_unknowns + 2 {
                    break;
                }
            }
        }
        ensure!(
            free_indices.len() == n_unknowns + 2,
            "insufficient free points in H for P_0"
        );

        let d_indices = free_indices[..=n_unknowns].to_vec();
        let rho_index = free_indices[n_unknowns + 1];
        let rho = h_elems[rho_index];
        for &idx in &free_indices {
            in_p[idx] = true;
        }

        let p_indices: Vec<usize> = (0..h_size).filter(|&i| in_p[i]).collect();
        ensure!(p_indices.len() == d, "P size mismatch");

        // Build vanishing polynomials Z_0, Z_P, Z_{H \ P}, Z_{H \ K}.
        let p0_roots: Vec<Fr> = free_indices.iter().map(|&i| h_elems[i]).collect();
        let p_roots: Vec<Fr> = p_indices.iter().map(|&i| h_elems[i]).collect();
        let out_p_roots: Vec<Fr> = (0..h_size)
            .filter(|&i| !in_p[i])
            .map(|i| h_elems[i])
            .collect();
        let out_k_roots: Vec<Fr> = (0..h_size)
            .filter(|&i| !in_k[i])
            .map(|i| h_elems[i])
            .collect();

        let z0_poly = vanishing_poly_from_roots(&p0_roots);
        let zp_poly = vanishing_poly_from_roots(&p_roots);
        let z_out_p_poly = vanishing_poly_from_roots(&out_p_roots);
        let z_out_k_poly = vanishing_poly_from_roots(&out_k_roots);

        let z0_on_h = domain_h.fft(&z0_poly);
        let zp_deriv = poly_deriv(&zp_poly);
        let zp_deriv_on_h = domain_h.fft(&zp_deriv);
        let z_at_rho = zp_deriv_on_h[rho_index];
        ensure!(!z_at_rho.is_zero(), "Z(rho) must be nonzero");

        // Barycentric weights w_p = 1 / Z_P'(p) for p in P.
        let mut bary_weights: Vec<Fr> = p_indices.iter().map(|&i| zp_deriv_on_h[i]).collect();
        batch_inversion(&mut bary_weights);

        let z_out_p_on_h = domain_h.fft(&z_out_p_poly);
        let mut z_out_p_inv_coset = coset_h.fft(&z_out_p_poly);
        batch_inversion(&mut z_out_p_inv_coset);

        let z_out_k_on_h = domain_h.fft(&z_out_k_poly);
        let mut z_out_k_inv_coset = coset_h.fft(&z_out_k_poly);
        batch_inversion(&mut z_out_k_inv_coset);

        // Precompute L_rho, Z_0, and 1 / Z_P on coset_2h for Dec's quotient
        // computation.
        let z0_coset_2h = coset_2h.fft(&z0_poly);
        let zp_coset_2h = coset_2h.fft(&zp_poly);
        let mut zp_inv_coset_2h = zp_coset_2h.clone();
        batch_inversion(&mut zp_inv_coset_2h);

        // L_rho(X) = Z_P(X) / ((X - rho) * Z(rho)).
        let z_at_rho_inv = z_at_rho.inverse().expect("Z(rho) != 0");
        let mut denom_rho: Vec<Fr> = coset_2h.elements().map(|x| x - rho).collect();
        batch_inversion(&mut denom_rho);
        let l_rho_coset_2h: Vec<Fr> = zp_coset_2h
            .iter()
            .zip(denom_rho.iter())
            .map(|(&zp, &inv_xr)| zp * inv_xr * z_at_rho_inv)
            .collect();

        Ok(Self {
            bqs,
            nu,
            d,
            domain_h,
            coset_h,
            domain_2h,
            coset_2h,
            d_indices,
            rho_index,
            rho,
            coset_indices,
            p_indices,
            z0_poly,
            zp_poly,
            z_at_rho,
            z0_on_h,
            bary_weights,
            z_out_p_on_h,
            z_out_p_inv_coset,
            z_out_k_on_h,
            z_out_k_inv_coset,
            l_rho_coset_2h,
            z0_coset_2h,
            zp_inv_coset_2h,
        })
    }

    /// Evaluate `A_i(tau)`, `B_i(tau)` for all `i in 0..=N`, plus `Z_0(tau)`,
    /// `Z(tau)`, `Z_P(tau)`, and `L_rho(tau)`, in `O(D + |S|)` field
    /// operations via barycentric Lagrange.
    pub fn eval_at_tau(&self, tau: Fr) -> Result<QapEvalAtTau> {
        let h_elems: Vec<Fr> = self.domain_h.elements().collect();
        let zp_tau = poly_eval(&self.zp_poly, tau);
        ensure!(!zp_tau.is_zero(), "tau must not lie in P");
        let z0_tau = poly_eval(&self.z0_poly, tau);
        let tau_minus_rho_inv = (tau - self.rho)
            .inverse()
            .ok_or_else(|| anyhow::anyhow!("tau == rho"))?;
        let z_tau = zp_tau * tau_minus_rho_inv;
        let l_rho_tau = z_tau * self.z_at_rho.inverse().expect("Z(rho) != 0");

        // Compute L_p(tau) = Z_P(tau) * w_p / (tau - p) for every p in P, indexed by
        // domain_h idx.
        let mut diffs: Vec<Fr> = self
            .p_indices
            .iter()
            .map(|&idx| tau - h_elems[idx])
            .collect();
        batch_inversion(&mut diffs);
        let mut lp_on_h = vec![Fr::zero(); self.domain_h.size()];
        for ((&idx, &w_p), &inv_diff) in self
            .p_indices
            .iter()
            .zip(self.bary_weights.iter())
            .zip(diffs.iter())
        {
            lp_on_h[idx] = zp_tau * w_p * inv_diff;
        }

        let n = self.bqs.n_unknowns;
        let mut a_tau = vec![Fr::zero(); n + 1];
        let mut b_tau = vec![Fr::zero(); n + 1];

        // 1. Point d_0: A(d_0) = 0, B(d_0) = e_0.
        b_tau[0] += lp_on_h[self.d_indices[0]];

        // 2. Points d_j for j in 1..=N: A(d_j) = e_j - e_0, B(d_j) = e_j.
        for j in 1..=n {
            let l_dj = lp_on_h[self.d_indices[j]];
            a_tau[j] += l_dj;
            a_tau[0] -= l_dj;
            b_tau[j] += l_dj;
        }

        // 3. Key point rho: A(rho) = e_0, B(rho) = e_0.
        let l_rho = lp_on_h[self.rho_index];
        a_tau[0] += l_rho;
        b_tau[0] += l_rho;

        // 4. Constraint cosets K_t.
        for (t, constraint) in self.bqs.constraints.iter().enumerate() {
            let idxs = &self.coset_indices[t];
            for (f, (a_vec, b_vec)) in constraint.products.iter().enumerate() {
                let p_idx = idxs[f];
                let lp = lp_on_h[p_idx];
                let scale_a = self.z0_on_h[p_idx] * lp;
                for &(col, coeff) in a_vec {
                    a_tau[col] += scale_a * coeff;
                }
                for &(col, coeff) in b_vec {
                    b_tau[col] += lp * coeff;
                }
            }
            let p_prime_idx = idxs[constraint.products.len()];
            let lp_prime = lp_on_h[p_prime_idx];
            a_tau[0] += self.z0_on_h[p_prime_idx] * lp_prime;
            for &(col, coeff) in &constraint.c {
                b_tau[col] -= lp_prime * coeff;
            }
        }

        Ok(QapEvalAtTau {
            a_tau,
            b_tau,
            z0_tau,
            z_tau,
            zp_tau,
            l_rho_tau,
        })
    }

    /// Interpolate a polynomial of degree `< |S|` from its evaluations on `S
    /// subset H` given `z_out_on_h` (`Z_{H \ S}` on `H`) and
    /// `z_out_inv_coset` (`1 / Z_{H \ S}` on `coset_h`).
    fn interpolate_subset(
        &self,
        evals_on_h: &[Fr],
        z_out_on_h: &[Fr],
        z_out_inv_coset: &[Fr],
        max_len: usize,
    ) -> Result<Vec<Fr>> {
        let mut f_evals: Vec<Fr> = evals_on_h
            .iter()
            .zip(z_out_on_h.iter())
            .map(|(&v, &z)| v * z)
            .collect();
        self.domain_h.ifft_in_place(&mut f_evals);
        self.coset_h.fft_in_place(&mut f_evals);
        for (v, &inv_z) in f_evals.iter_mut().zip(z_out_inv_coset.iter()) {
            *v *= inv_z;
        }
        self.coset_h.ifft_in_place(&mut f_evals);
        // Verify exact division: coefficients at >= max_len must vanish.
        for (i, &c) in f_evals.iter().enumerate().skip(max_len) {
            ensure!(
                c.is_zero(),
                "subset interpolation non-zero coeff at degree {i} >= {max_len}"
            );
        }
        f_evals.truncate(max_len);
        Ok(f_evals)
    }

    /// Compute the quotients `h_key`, `h_oth`, and allowed remainder `R_w` for
    /// a witness `w` (Equation (4), p. 27). Returns an error if `w` fails
    /// any constraint or Booleanity test.
    pub fn witness_polynomials(&self, w: &[u8]) -> Result<WitnessPolys> {
        let n = self.bqs.n_unknowns;
        ensure!(w.len() == n + 1 && w[0] == 1, "invalid witness shape");

        let h_size = self.domain_h.size();
        let mut aw_on_h = vec![Fr::zero(); h_size];
        let mut bw_on_h = vec![Fr::zero(); h_size];
        let mut rw_on_h = vec![Fr::zero(); h_size];

        // d_0: A = 0, B = e_0 => A_w = 0, B_w = w_0 = 1.
        bw_on_h[self.d_indices[0]] = Fr::one();

        // d_j: A = e_j - e_0, B = e_j => A_w = w_j - 1, B_w = w_j.
        for j in 1..=n {
            let wj = Fr::from(u64::from(w[j]));
            aw_on_h[self.d_indices[j]] = wj - Fr::one();
            bw_on_h[self.d_indices[j]] = wj;
        }

        // rho: A = e_0, B = e_0 => A_w = 1, B_w = 1.
        aw_on_h[self.rho_index] = Fr::one();
        bw_on_h[self.rho_index] = Fr::one();

        // Cosets K_t.
        for (t, constraint) in self.bqs.constraints.iter().enumerate() {
            let idxs = &self.coset_indices[t];
            for (f, (a_vec, b_vec)) in constraint.products.iter().enumerate() {
                let p_idx = idxs[f];
                let a_val = eval_sparse_bits(a_vec, w);
                let b_val = eval_sparse_bits(b_vec, w);
                aw_on_h[p_idx] = self.z0_on_h[p_idx] * a_val;
                bw_on_h[p_idx] = b_val;
                rw_on_h[p_idx] = a_val * b_val;
            }
            let p_prime_idx = idxs[constraint.products.len()];
            let c_val = eval_sparse_bits(&constraint.c, w);
            aw_on_h[p_prime_idx] = self.z0_on_h[p_prime_idx];
            bw_on_h[p_prime_idx] = -c_val;
            rw_on_h[p_prime_idx] = -c_val;
        }

        let aw_poly = self.interpolate_subset(
            &aw_on_h,
            &self.z_out_p_on_h,
            &self.z_out_p_inv_coset,
            self.d,
        )?;
        let bw_poly = self.interpolate_subset(
            &bw_on_h,
            &self.z_out_p_on_h,
            &self.z_out_p_inv_coset,
            self.d,
        )?;

        let k_size = self.nu * self.bqs.constraints.len();
        let r_w = self.interpolate_subset(
            &rw_on_h,
            &self.z_out_k_on_h,
            &self.z_out_k_inv_coset,
            k_size,
        )?;

        // Check that R_w is allowed (no exponent divisible by nu).
        // If w is not a valid witness, this fails immediately!
        for k in (0..r_w.len()).step_by(self.nu) {
            ensure!(
                r_w[k].is_zero(),
                "remainder R_w is not allowed (coeff at degree {k} nonzero) — witness fails \
                 constraints"
            );
        }

        // Compute h_key = (A_w * B_w - L_rho - Z_0 * R_w) / Z_P via coset_2h.
        let aw_2h = self.coset_2h.fft(&aw_poly);
        let bw_2h = self.coset_2h.fft(&bw_poly);
        let rw_2h = self.coset_2h.fft(&r_w);

        let mut h_key: Vec<Fr> = (0..self.domain_2h.size())
            .map(|i| {
                let num =
                    aw_2h[i] * bw_2h[i] - self.l_rho_coset_2h[i] - self.z0_coset_2h[i] * rw_2h[i];
                num * self.zp_inv_coset_2h[i]
            })
            .collect();
        self.coset_2h.ifft_in_place(&mut h_key);

        for (i, &c) in h_key.iter().enumerate().skip(self.d - 1) {
            ensure!(
                c.is_zero(),
                "h_key division not exact at degree {i} >= {} — witness fails \
                 Booleanity/constraints",
                self.d - 1
            );
        }
        h_key.truncate(self.d - 1);

        // h_oth(X) = h_key(X) * (X - rho) + 1 / Z(rho).
        let mut h_oth = vec![Fr::zero(); self.d];
        let z_rho_inv = self.z_at_rho.inverse().expect("Z(rho) != 0");
        h_oth[0] = z_rho_inv;
        for (i, &hk) in h_key.iter().enumerate() {
            h_oth[i] -= hk * self.rho;
            h_oth[i + 1] += hk;
        }

        Ok(WitnessPolys { h_key, h_oth, r_w })
    }
}
