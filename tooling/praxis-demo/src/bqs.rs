//! Boolean Quadratic Systems (Section 4.1) and conversion from ProveKit
//! `R1CS<Fr>`.

use {
    anyhow::{bail, ensure, Result},
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, BigInteger, One, PrimeField, Zero},
    provekit_common::R1CS,
    std::collections::HashSet,
};

/// A sparse linear form `v(w) = sum_{(idx, coeff)} coeff * w[idx]` over
/// `F_q^{N+1}`, where index `0` is the constant `w_0 = 1`.
pub type SparseVec = Vec<(usize, Fr)>;

/// A single BQS constraint:
/// `sum_{f in [F_t]} a_{t,f}(w) * b_{t,f}(w) = w_0 * c_t(w)`.
#[derive(Debug, Clone)]
pub struct BqsConstraint {
    /// Product pairs `(a_{t,f}, b_{t,f})`.
    pub products: Vec<(SparseVec, SparseVec)>,
    /// Right-hand linear form `c_t`.
    pub c:        SparseVec,
}

/// Boolean Quadratic System (Definition 4.1) of shape `(n_unknowns,
/// constraints.len(), f_max)`.
#[derive(Debug, Clone)]
pub struct Bqs {
    /// Number of Boolean unknowns `N` (indices `1..=N`; index `0` is constant
    /// `1`).
    pub n_unknowns:  usize,
    /// Quadratic constraints over `F_q`.
    pub constraints: Vec<BqsConstraint>,
    /// Maximum number of products per constraint `F_max`.
    pub f_max:       usize,
}

impl Bqs {
    /// Pad with trivial `0 = 0` constraints so `D = N + 2 + nu * n_c >= min_d`
    /// and `n_c` is divisible by `j_rem`. Preserves the witness set (Section
    /// 4.1).
    pub fn pad_for_params(&mut self, min_d: usize, j_rem: usize) {
        let nu = self.coset_size();
        let needed_nc = min_d
            .saturating_sub(self.n_unknowns + 2)
            .div_ceil(nu)
            .max(self.constraints.len())
            .max(1);
        let padded_nc = needed_nc.div_ceil(j_rem) * j_rem;
        while self.constraints.len() < padded_nc {
            self.constraints.push(BqsConstraint {
                products: vec![(Vec::new(), Vec::new())],
                c:        Vec::new(),
            });
        }
    }

    /// Least power of two strictly greater than `F_max` (Section 4.4).
    #[must_use]
    pub fn coset_size(&self) -> usize {
        (self.f_max + 1).next_power_of_two()
    }

    /// Total number of QAP evaluation points `D = N + 2 + nu * n_c`.
    #[must_use]
    pub fn num_eval_points(&self) -> usize {
        self.n_unknowns + 2 + self.coset_size() * self.constraints.len()
    }

    /// Verify that `w` (`len == N + 1`, `w[0] == 1`, all entries in `{0, 1}`)
    /// satisfies every constraint of this BQS.
    pub fn is_satisfied(&self, w: &[u8]) -> Result<bool> {
        ensure!(w.len() == self.n_unknowns + 1, "witness length mismatch");
        if w[0] != 1 {
            return Ok(false);
        }
        if w.iter().any(|&b| b > 1) {
            return Ok(false);
        }
        for c in &self.constraints {
            let mut lhs = Fr::zero();
            for (a, b) in &c.products {
                lhs += eval_sparse_bits(a, w) * eval_sparse_bits(b, w);
            }
            let rhs = eval_sparse_bits(&c.c, w);
            if lhs != rhs {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Evaluate a sparse linear form on a Boolean vector `w in {0, 1}^{N+1}`.
#[inline]
#[must_use]
pub fn eval_sparse_bits(v: &[(usize, Fr)], w: &[u8]) -> Fr {
    let mut acc = Fr::zero();
    for &(idx, coeff) in v {
        if w[idx] != 0 {
            acc += coeff;
        }
    }
    acc
}

/// Mapping from original ProveKit R1CS witness columns to Boolean BQS unknown
/// ranges.
#[derive(Debug, Clone)]
pub struct WitnessBitMap {
    /// For each original R1CS column `col in 0..orig_num_witnesses`:
    /// - `None` if `col == 0` (constant 1) or folded public input;
    /// - `Some((start_idx, num_bits))` where BQS indices `start_idx..start_idx
    ///   + num_bits` encode `W[col] = sum_{b=0}^{num_bits-1} 2^b * w[start_idx
    ///   + b]`.
    pub col_bits:            Vec<Option<(usize, usize)>>,
    /// Total Boolean unknowns `N`.
    pub n_unknowns:          usize,
    /// Number of witnesses detected as already Boolean in the R1CS.
    pub num_native_bools:    usize,
    /// Number of full 254-bit field witnesses expanded.
    pub num_expanded_fields: usize,
}

impl WitnessBitMap {
    /// Convert a solved ProveKit R1CS witness vector (`Fr` values, index 0 = 1)
    /// into a Boolean BQS witness `w in {0, 1}^{N+1}` with `w[0] = 1`.
    pub fn expand_witness(&self, r1cs_witness: &[Fr]) -> Result<Vec<u8>> {
        ensure!(
            r1cs_witness.len() >= self.col_bits.len(),
            "R1CS witness too short: {} < {}",
            r1cs_witness.len(),
            self.col_bits.len()
        );
        let mut w = vec![0u8; self.n_unknowns + 1];
        w[0] = 1;
        for (col, mapping) in self.col_bits.iter().enumerate() {
            let Some((start, nbits)) = *mapping else {
                continue;
            };
            let val = r1cs_witness[col];
            let bigint = val.into_bigint();
            if nbits == 1 {
                if val.is_zero() {
                    w[start] = 0;
                } else if val.is_one() {
                    w[start] = 1;
                } else {
                    bail!(
                        "R1CS witness column {} expected Boolean, got {:?}",
                        col,
                        val
                    );
                }
            } else {
                for b in 0..nbits {
                    w[start + b] = u8::from(bigint.get_bit(b));
                }
            }
        }
        Ok(w)
    }
}

/// Detect R1CS witness columns that are constrained to `{0, 1}` via a
/// Booleanity constraint of the form `w_j * w_j = w_j`, `w_j * (w_j - 1) = 0`,
/// or `(1 - w_j) * w_j = 0` (up to nonzero scalar multiples). Returns
/// `(boolean_columns, boolean_constraint_rows)`.
fn detect_boolean_columns(r1cs: &R1CS<Fr>) -> (HashSet<usize>, HashSet<usize>) {
    let a = r1cs.a();
    let b = r1cs.b();
    let c = r1cs.c();
    let mut bool_cols = HashSet::new();
    let mut bool_rows = HashSet::new();

    for row in 0..r1cs.num_constraints() {
        let ra: Vec<(usize, Fr)> = a.iter_row(row).collect();
        let rb: Vec<(usize, Fr)> = b.iter_row(row).collect();
        let rc: Vec<(usize, Fr)> = c.iter_row(row).collect();

        // Form 1: (alpha * w_j) * (beta * w_j) = (alpha * beta * w_j)
        if ra.len() == 1 && rb.len() == 1 && rc.len() == 1 {
            let (ja, ca) = ra[0];
            let (jb, cb) = rb[0];
            let (jc, cc) = rc[0];
            if ja > 0 && ja == jb && jb == jc && ca * cb == cc && !cc.is_zero() {
                bool_cols.insert(ja);
                bool_rows.insert(row);
                continue;
            }
        }

        // Form 2: (alpha * w_j) * (beta * w_j - beta) = 0  (or swapped a/b)
        if rc.is_empty() {
            let check_pair = |single: &[(usize, Fr)], pair: &[(usize, Fr)]| -> Option<usize> {
                if single.len() == 1 && pair.len() == 2 {
                    let (j, ca) = single[0];
                    if j == 0 || ca.is_zero() {
                        return None;
                    }
                    let mut c0 = Fr::zero();
                    let mut cj = Fr::zero();
                    for &(col, val) in pair {
                        if col == 0 {
                            c0 = val;
                        } else if col == j {
                            cj = val;
                        } else {
                            return None;
                        }
                    }
                    if !cj.is_zero() && c0 == -cj {
                        return Some(j);
                    }
                }
                None
            };
            if let Some(j) = check_pair(&ra, &rb).or_else(|| check_pair(&rb, &ra)) {
                bool_cols.insert(j);
                bool_rows.insert(row);
            }
        }
    }

    (bool_cols, bool_rows)
}

/// Convert a challenge-free ProveKit `R1CS<Fr>` (with optional fixed public
/// inputs) into a Praxis Boolean Quadratic System (`Bqs`) and its
/// `WitnessBitMap`.
///
/// - Column `0` is constant `1`.
/// - Columns `1..=public_inputs.len()` are folded into column `0` as constants.
/// - Remaining columns detected as Boolean map to 1 BQS unknown; general `Fr`
///   columns expand into 254 Boolean unknowns with weights `2^0, ..., 2^253`.
pub fn r1cs_to_bqs(r1cs: &R1CS<Fr>, public_inputs: &[Fr]) -> Result<(Bqs, WitnessBitMap)> {
    ensure!(
        public_inputs.len() == r1cs.num_public_inputs,
        "expected {} public inputs, got {}",
        r1cs.num_public_inputs,
        public_inputs.len()
    );

    let (bool_cols, bool_rows) = detect_boolean_columns(r1cs);
    let num_w = r1cs.num_witnesses();

    // Determine which columns are actually referenced in non-Booleanity constraints
    // (or all).
    let mut col_bits: Vec<Option<(usize, usize)>> = vec![None; num_w];
    let mut next_idx = 1usize;
    let mut num_native_bools = 0usize;
    let mut num_expanded_fields = 0usize;

    for col in (1 + public_inputs.len())..num_w {
        if bool_cols.contains(&col) {
            col_bits[col] = Some((next_idx, 1));
            next_idx += 1;
            num_native_bools += 1;
        } else {
            let nbits = Fr::MODULUS_BIT_SIZE as usize; // 254 for BN254 Fr
            col_bits[col] = Some((next_idx, nbits));
            next_idx += nbits;
            num_expanded_fields += 1;
        }
    }

    let n_unknowns = next_idx - 1;
    let mut pow2 = Vec::with_capacity(Fr::MODULUS_BIT_SIZE as usize);
    let mut cur = Fr::one();
    for _ in 0..Fr::MODULUS_BIT_SIZE {
        pow2.push(cur);
        cur.double_in_place();
    }

    let expand_row = |iter: Box<dyn Iterator<Item = (usize, Fr)> + '_>| -> SparseVec {
        let mut const_term = Fr::zero();
        let mut out: Vec<(usize, Fr)> = Vec::new();
        for (col, coeff) in iter {
            if coeff.is_zero() {
                continue;
            }
            if col == 0 {
                const_term += coeff;
            } else if col <= public_inputs.len() {
                const_term += coeff * public_inputs[col - 1];
            } else if let Some((start, nbits)) = col_bits[col] {
                if nbits == 1 {
                    out.push((start, coeff));
                } else {
                    for b in 0..nbits {
                        out.push((start + b, coeff * pow2[b]));
                    }
                }
            }
        }
        if !const_term.is_zero() {
            out.push((0, const_term));
        }
        // Merge duplicate indices if any.
        out.sort_unstable_by_key(|&(idx, _)| idx);
        let mut merged: SparseVec = Vec::with_capacity(out.len());
        for (idx, val) in out {
            if let Some(last) = merged.last_mut() {
                if last.0 == idx {
                    last.1 += val;
                    continue;
                }
            }
            merged.push((idx, val));
        }
        merged.retain(|&(_, v)| !v.is_zero());
        merged
    };

    let a_mat = r1cs.a();
    let b_mat = r1cs.b();
    let c_mat = r1cs.c();
    let mut constraints = Vec::new();

    for row in 0..r1cs.num_constraints() {
        // Skip redundant Booleanity constraints: Praxis enforces w_j^2 = w_j for every
        // j in [N].
        if bool_rows.contains(&row) {
            continue;
        }
        let a_vec = expand_row(Box::new(a_mat.iter_row(row)));
        let b_vec = expand_row(Box::new(b_mat.iter_row(row)));
        let c_vec = expand_row(Box::new(c_mat.iter_row(row)));
        if a_vec.is_empty() && b_vec.is_empty() && c_vec.is_empty() {
            continue;
        }
        constraints.push(BqsConstraint {
            products: vec![(a_vec, b_vec)],
            c:        c_vec,
        });
    }

    let bqs = Bqs {
        n_unknowns,
        constraints,
        f_max: 1,
    };
    let map = WitnessBitMap {
        col_bits,
        n_unknowns,
        num_native_bools,
        num_expanded_fields,
    };
    Ok((bqs, map))
}
