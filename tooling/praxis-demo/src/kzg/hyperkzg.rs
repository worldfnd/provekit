//! HyperKZG multilinear polynomial commitment scheme over BN254.
//!
//! Uses a standard **univariate** Powers-of-Tau SRS (`KzgSrs`) and reduces an
//! `ell`-variate multilinear evaluation claim `f(r_0, ..., r_{ell-1}) = v` to
//! **3 univariate KZG claims** (which batch across any number of committed
//! multilinear polynomials into **one single 2-pairing check**!).
//!
//! ## Bit Ordering (Matches ProveKit's MSB-first `sumcheck` / `eq`)
//! An evaluation table `evals` of length `2^ell` indexes `b = (b_0, ...,
//! b_{ell-1})` in big-endian (`idx = sum_k b_k * 2^{ell - 1 - k}`).
//! Treating `evals` as coefficients of `P_0(X) = sum_{idx} evals[idx] X^{idx}`:
//! - Even indices have `b_{ell-1} = 0`, odd indices have `b_{ell-1} = 1`.
//! - Folding `P_{i+1}(Y) = (1 - r_{ell-1-i}) P_{i,even}(Y) + r_{ell-1-i}
//!   P_{i,odd}(Y)` binds variables from `r_{ell-1}` down to `r_0`.
//! - After `ell` rounds, `P_ell(Y)` is the constant polynomial `v = f(r)`.
//! - At a random point `x`, every folding round satisfies the denominator-free
//!   algebraic identity:
//!   ```text
//!   2*x * P_{i+1}(x^2) == (1 - r_rev[i]) * x * (P_i(x) + P_i(-x))
//!                       + r_rev[i]       *     (P_i(x) - P_i(-x))
//!   ```

use {
    crate::kzg::univariate::{self, g1_to_bytes32, KzgOpeningClaim, KzgSrs},
    anyhow::{ensure, Result},
    ark_bn254::{Fr, G1Affine, G1Projective},
    ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM},
    ark_ff::{One, Zero},
    ark_serialize::CanonicalSerialize,
    provekit_backend_bn254::TranscriptSponge,
    rayon::prelude::*,
    whir::transcript::{ProverState, VerifierMessage, VerifierState},
};

/// A HyperKZG opening proof for a single `ell`-variate MLE evaluation `f(r) =
/// v`.
#[derive(Debug, Clone)]
pub struct HyperKzgOpening {
    /// Intermediate folded polynomial commitments `C_1, ..., C_{ell - 1}`.
    pub round_commitments: Vec<G1Affine>,
    /// Evaluations `P_i(x)` for `i in 0..ell`.
    pub evals_pos:         Vec<Fr>,
    /// Evaluations `P_i(-x)` for `i in 0..ell`.
    pub evals_neg:         Vec<Fr>,
    /// Evaluations `P_i(x^2)` for `i in 1..ell` (`P_ell(x^2) == claimed_eval`).
    pub evals_sq:          Vec<Fr>,
    /// Batched univariate KZG quotient `W_1` for `Q_1 = sum_{i=0}^{ell-1}
    /// beta^i P_i` at `x`.
    pub w_pos:             G1Affine,
    /// Batched univariate KZG quotient `W_2` for `Q_1` at `-x`.
    pub w_neg:             G1Affine,
    /// Batched univariate KZG quotient `W_3` for `Q_3 = sum_{i=1}^{ell-1}
    /// beta^i P_i` at `x^2`.
    pub w_sq:              G1Affine,
}

impl HyperKzgOpening {
    /// Exact compressed proof size in bytes (32 B per `G1Affine`, 32 B per
    /// `Fr`).
    #[must_use]
    pub fn compressed_bytes(&self) -> usize {
        let g1_count = self.round_commitments.len() + 3;
        let fr_count = self.evals_pos.len() + self.evals_neg.len() + self.evals_sq.len();
        (g1_count + fr_count) * 32
    }
}

/// Evaluate an MSB-indexed MLE directly at `point` (`evals.len() ==
/// 2^point.len()`).
pub fn eval_mle(evals: &[Fr], point: &[Fr]) -> Fr {
    assert_eq!(evals.len(), 1 << point.len());
    let mut cur = evals.to_vec();
    for &r in point.iter().rev() {
        let one_minus_r = Fr::one() - r;
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        for k in 0..half {
            next.push(one_minus_r * cur[2 * k] + r * cur[2 * k + 1]);
        }
        cur = next;
    }
    cur[0]
}

/// Absorb a `G1Affine` commitment into a ProveKit `ProverState` as 32 bytes.
pub fn absorb_g1_prover(merlin: &mut ProverState<TranscriptSponge>, pt: &G1Affine) {
    let bytes = g1_to_bytes32(pt);
    merlin.prover_message(&bytes);
}

/// Read & absorb a `G1Affine` commitment into a ProveKit `VerifierState`.
pub fn absorb_g1_verifier(arthur: &mut VerifierState<TranscriptSponge>, pt: &G1Affine) -> Result<()> {
    let bytes: [u8; 32] = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed reading G1 commitment from transcript"))?;
    ensure!(
        bytes == g1_to_bytes32(pt),
        "G1 commitment transcript mismatch"
    );
    Ok(())
}

/// Absorb an `Fr` scalar into a ProveKit `ProverState` as 32 LE bytes.
pub fn absorb_fr_prover(merlin: &mut ProverState<TranscriptSponge>, x: &Fr) {
    let mut buf = [0u8; 32];
    x.serialize_compressed(&mut buf[..])
        .expect("BN254 Fr is 32 bytes");
    merlin.prover_message(&buf);
}

/// Read & verify an `Fr` scalar from a ProveKit `VerifierState`.
pub fn absorb_fr_verifier(arthur: &mut VerifierState<TranscriptSponge>, expected: &Fr) -> Result<()> {
    let bytes: [u8; 32] = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed reading Fr from transcript"))?;
    let mut exp = [0u8; 32];
    expected
        .serialize_compressed(&mut exp[..])
        .expect("BN254 Fr is 32 bytes");
    ensure!(bytes == exp, "Fr transcript mismatch");
    Ok(())
}

/// Commit to an `ell`-variate MLE (`evals.len() == 2^ell`) with universal
/// univariate KZG SRS.
pub fn commit(srs: &KzgSrs, evals: &[Fr]) -> Result<G1Affine> {
    ensure!(
        evals.len().is_power_of_two(),
        "MLE length {} must be a power of two",
        evals.len()
    );
    univariate::commit(srs, evals)
}

/// Open an `ell`-variate MLE `evals` at `point` (`evals.len() ==
/// 2^point.len()`), returning `(claimed_value, HyperKzgOpening)`.
pub fn open(
    srs: &KzgSrs,
    evals: &[Fr],
    point: &[Fr],
    merlin: &mut ProverState<TranscriptSponge>,
) -> Result<(Fr, HyperKzgOpening)> {
    let ell = point.len();
    ensure!(
        evals.len() == (1usize << ell),
        "MLE length {} != 2^{}",
        evals.len(),
        ell
    );
    ensure!(ell >= 1, "HyperKZG requires ell >= 1");

    // 1. Fold P_0 -> P_1 -> ... -> P_ell, committing C_1, ..., C_{ell-1}.
    let mut polys: Vec<Vec<Fr>> = Vec::with_capacity(ell);
    polys.push(evals.to_vec());
    let mut round_commitments = Vec::with_capacity(ell - 1);

    for (round, &r) in point.iter().rev().enumerate() {
        let prev = &polys[round];
        let half = prev.len() / 2;
        let one_minus_r = Fr::one() - r;

        let next: Vec<Fr> = if half >= 4096 {
            (0..half)
                .into_par_iter()
                .map(|k| one_minus_r * prev[2 * k] + r * prev[2 * k + 1])
                .collect()
        } else {
            (0..half)
                .map(|k| one_minus_r * prev[2 * k] + r * prev[2 * k + 1])
                .collect()
        };

        if round + 1 < ell {
            let c_next = univariate::commit(srs, &next)?;
            absorb_g1_prover(merlin, &c_next);
            round_commitments.push(c_next);
            polys.push(next);
        } else {
            // Final round produces the constant polynomial P_ell = [f(point)].
            let claimed_value = next[0];
            // 2. Squeeze random evaluation point x != 0.
            let x: Fr = merlin.verifier_message();
            let neg_x = -x;
            let x_sq = x * x;

            // 3. Evaluate P_0..P_{ell-1} at x and -x, and P_1..P_{ell-1} at x^2.
            let evals_pos: Vec<Fr> = polys
                .par_iter()
                .map(|p| univariate::eval_poly(p, x))
                .collect();
            let evals_neg: Vec<Fr> = polys
                .par_iter()
                .map(|p| univariate::eval_poly(p, neg_x))
                .collect();
            let evals_sq: Vec<Fr> = polys[1..]
                .par_iter()
                .map(|p| univariate::eval_poly(p, x_sq))
                .collect();

            for &v in &evals_pos {
                absorb_fr_prover(merlin, &v);
            }
            for &v in &evals_neg {
                absorb_fr_prover(merlin, &v);
            }
            for &v in &evals_sq {
                absorb_fr_prover(merlin, &v);
            }

            // 4. Squeeze batching challenge beta and form Q_1, Q_3.
            let beta: Fr = merlin.verifier_message();
            let mut q1 = polys[0].clone();
            let mut q3 = vec![Fr::zero(); if ell > 1 { polys[1].len() } else { 1 }];

            let mut beta_pow = beta;
            for p in &polys[1..] {
                for (k, &coeff) in p.iter().enumerate() {
                    let term = beta_pow * coeff;
                    q1[k] += term;
                    q3[k] += term;
                }
                beta_pow *= beta;
            }

            // 5. Compute 3 univariate KZG openings: Q_1(x), Q_1(-x), Q_3(x^2).
            let (_y1, w_pos) = univariate::open(srs, &q1, x)?;
            let (_y2, w_neg) = univariate::open(srs, &q1, neg_x)?;
            let (_y3, w_sq) = if ell > 1 {
                univariate::open(srs, &q3, x_sq)?
            } else {
                (Fr::zero(), G1Affine::zero())
            };

            return Ok((claimed_value, HyperKzgOpening {
                round_commitments,
                evals_pos,
                evals_neg,
                evals_sq,
                w_pos,
                w_neg,
                w_sq,
            }));
        }
    }

    unreachable!("ell >= 1 guarantees loop returns on final round")
}

/// Verify all algebraic HyperKZG folding checks and reduce the opening to 3
/// univariate KZG opening claims `(Q_1(x), Q_1(-x), Q_3(x^2))` for final
/// 2-pairing batch verification.
pub fn verify_to_kzg_claims(
    commitment: G1Affine,
    point: &[Fr],
    claimed_eval: Fr,
    opening: &HyperKzgOpening,
    arthur: &mut VerifierState<TranscriptSponge>,
) -> Result<Vec<KzgOpeningClaim>> {
    let ell = point.len();
    ensure!(ell >= 1, "HyperKZG requires ell >= 1");
    ensure!(
        opening.round_commitments.len() == ell - 1,
        "expected {} round commitments, got {}",
        ell - 1,
        opening.round_commitments.len()
    );
    ensure!(opening.evals_pos.len() == ell, "evals_pos length mismatch");
    ensure!(opening.evals_neg.len() == ell, "evals_neg length mismatch");
    ensure!(
        opening.evals_sq.len() == ell - 1,
        "evals_sq length mismatch"
    );

    // 1. Absorb round commitments C_1, ..., C_{ell-1}.
    for c in &opening.round_commitments {
        absorb_g1_verifier(arthur, c)?;
    }

    // 2. Squeeze x and absorb claimed evaluations.
    let x: Fr = arthur.verifier_message();
    ensure!(!x.is_zero(), "degenerate evaluation challenge x == 0");
    let neg_x = -x;
    let x_sq = x * x;
    let two_x = x + x;

    for &v in &opening.evals_pos {
        absorb_fr_verifier(arthur, &v)?;
    }
    for &v in &opening.evals_neg {
        absorb_fr_verifier(arthur, &v)?;
    }
    for &v in &opening.evals_sq {
        absorb_fr_verifier(arthur, &v)?;
    }

    // 3. Check denominator-free folding identity at every round i = 0..ell:
    //    2x * P_{i+1}(x^2) == (1 - r_rev[i]) * x * (P_i(x) + P_i(-x))
    //                       + r_rev[i]       *     (P_i(x) - P_i(-x))
    for (i, &r) in point.iter().rev().enumerate() {
        let p_pos = opening.evals_pos[i];
        let p_neg = opening.evals_neg[i];
        let p_next_sq = if i + 1 < ell {
            opening.evals_sq[i]
        } else {
            claimed_eval
        };
        let lhs = two_x * p_next_sq;
        let rhs = (Fr::one() - r) * x * (p_pos + p_neg) + r * (p_pos - p_neg);
        ensure!(
            lhs == rhs,
            "HyperKZG folding check failed at round {i} (lhs != rhs)"
        );
    }

    // 4. Squeeze batching challenge beta and build batched commitments & evals.
    let beta: Fr = arthur.verifier_message();
    let mut beta_pows = Vec::with_capacity(ell);
    let mut bp = Fr::one();
    for _ in 0..ell {
        beta_pows.push(bp);
        bp *= beta;
    }

    let y_pos: Fr = opening
        .evals_pos
        .iter()
        .zip(beta_pows.iter())
        .map(|(&e, &b)| e * b)
        .sum();
    let y_neg: Fr = opening
        .evals_neg
        .iter()
        .zip(beta_pows.iter())
        .map(|(&e, &b)| e * b)
        .sum();

    let (c_q1, c_q3, y_sq) = if ell > 1 {
        let c_q3_proj =
            G1Projective::msm_unchecked(&opening.round_commitments, &beta_pows[1..]);
        let c_q3 = c_q3_proj.into_affine();
        let c_q1 = (c_q3_proj + commitment).into_affine();
        let y_sq: Fr = opening
            .evals_sq
            .iter()
            .zip(beta_pows[1..].iter())
            .map(|(&e, &b)| e * b)
            .sum();
        (c_q1, c_q3, y_sq)
    } else {
        (commitment, G1Affine::zero(), Fr::zero())
    };

    let mut claims = vec![
        KzgOpeningClaim {
            commitment: c_q1,
            point:      x,
            value:      y_pos,
            proof:      opening.w_pos,
        },
        KzgOpeningClaim {
            commitment: c_q1,
            point:      neg_x,
            value:      y_neg,
            proof:      opening.w_neg,
        },
    ];
    if ell > 1 {
        claims.push(KzgOpeningClaim {
            commitment: c_q3,
            point:      x_sq,
            value:      y_sq,
            proof:      opening.w_sq,
        });
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::praxis::FixedBaseTable,
        ark_ec::PrimeGroup,
        provekit_common::HashConfig,
        rand::{rngs::StdRng, SeedableRng},
        whir::transcript::DomainSeparator,
    };

    #[test]
    fn test_hyperkzg_roundtrip_and_tamper_rejection() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(7);
        let g1_tbl = FixedBaseTable::new(G1Projective::generator());
        let ell = 6;
        let n = 1usize << ell;
        let (srs, _) = KzgSrs::setup_with_table(n, &g1_tbl, &mut rng)?;

        let evals: Vec<Fr> = (0..n).map(|i| Fr::from((i as u64) * 31 + 17)).collect();
        let point: Vec<Fr> = (0..ell).map(|i| Fr::from((i as u64) * 97 + 11)).collect();
        let expected_val = eval_mle(&evals, &point);

        let comm = commit(&srs, &evals)?;

        let ds = DomainSeparator::protocol(&"hyperkzg-test").instance(&0u8);
        let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(HashConfig::Skyscraper));
        absorb_g1_prover(&mut merlin, &comm);
        let (val, opening) = open(&srs, &evals, &point, &mut merlin)?;
        assert_eq!(val, expected_val);

        let proof = merlin.proof();
        let mut arthur = VerifierState::new(
            &ds,
            &proof,
            TranscriptSponge::from_config(HashConfig::Skyscraper),
        );
        absorb_g1_verifier(&mut arthur, &comm)?;
        let claims = verify_to_kzg_claims(comm, &point, val, &opening, &mut arthur)?;
        let rho: Fr = arthur.verifier_message();
        assert!(univariate::verify_batched(&srs, &claims, rho)?);

        // Tamper with claimed_eval -> folding check must reject!
        let mut arthur_bad = VerifierState::new(
            &ds,
            &proof,
            TranscriptSponge::from_config(HashConfig::Skyscraper),
        );
        absorb_g1_verifier(&mut arthur_bad, &comm)?;
        assert!(verify_to_kzg_claims(comm, &point, val + Fr::one(), &opening, &mut arthur_bad).is_err());

        Ok(())
    }
}
