//! Universal BN254 univariate KZG polynomial commitment scheme.
//!
//! Built directly on `ark-bn254` `0.6.0` (matching ProveKit's workspace) with:
//! - Universal Powers-of-Tau SRS (`[tau^i]_1` in `G1`, `[1]_2` and `[tau]_2` in
//!   `G2`)
//! - Parallel fixed-base SRS generation via Praxis's `FixedBaseTable`
//! - Parallel Pippenger `VariableBaseMSM` commitments and Ruffini-division
//!   openings
//! - Batched multi-point verification in **exactly 2 BN254 pairings** (one
//!   `multi_pairing` call with one final exponentiation)

use {
    crate::praxis::FixedBaseTable,
    anyhow::{ensure, Result},
    ark_bn254::{Bn254, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM},
    ark_ff::{Field, One, PrimeField, Zero},
    ark_serialize::CanonicalSerialize,
    rand::RngCore,
    rayon::prelude::*,
    std::time::{Duration, Instant},
};

/// Universal Powers-of-Tau Structured Reference String (SRS) on BN254.
#[derive(Debug, Clone)]
pub struct KzgSrs {
    /// `[1]_1, [tau]_1, ..., [tau^{max_degree}]_1`.
    pub g1_powers: Vec<G1Affine>,
    /// `[1]_2`.
    pub g2_gen:    G2Affine,
    /// `[tau]_2`.
    pub g2_tau:    G2Affine,
}

/// A single univariate KZG opening claim: `P(point) = value`, witnessed by
/// `proof = [(P(tau) - value) / (tau - point)]_1`.
#[derive(Debug, Clone, Copy)]
pub struct KzgOpeningClaim {
    pub commitment: G1Affine,
    pub point:      Fr,
    pub value:      Fr,
    pub proof:      G1Affine,
}

impl KzgSrs {
    /// Generate a universal Powers-of-Tau SRS supporting polynomials of length
    /// up to `max_len` (degree `< max_len`), using a precomputed `G1` fixed-base
    /// table for fast parallel generation.
    pub fn setup_with_table(
        max_len: usize,
        g1_table: &FixedBaseTable<G1Projective>,
        rng: &mut impl RngCore,
    ) -> Result<(Self, Duration)> {
        ensure!(max_len >= 2, "KZG SRS length must be >= 2");
        let t0 = Instant::now();

        let tau = loop {
            let mut buf = [0u8; 64];
            rng.fill_bytes(&mut buf);
            let cand = Fr::from_le_bytes_mod_order(&buf);
            if !cand.is_zero() {
                break cand;
            }
        };

        // Compute powers `[1, tau, ..., tau^{max_len - 1}]` in parallel chunks.
        let chunk_size = 4096usize;
        let num_chunks = max_len.div_ceil(chunk_size);
        let tau_chunk = tau.pow([chunk_size as u64]);
        let mut chunk_starts = Vec::with_capacity(num_chunks);
        let mut cur = Fr::one();
        for _ in 0..num_chunks {
            chunk_starts.push(cur);
            cur *= tau_chunk;
        }

        let mut powers = vec![Fr::zero(); max_len];
        powers
            .par_chunks_mut(chunk_size)
            .zip(chunk_starts.par_iter())
            .for_each(|(chunk, &start)| {
                let mut v = start;
                for slot in chunk.iter_mut() {
                    *slot = v;
                    v *= tau;
                }
            });

        let g1_powers = g1_table.mul_batch_affine(&powers);
        let g2_gen = G2Affine::generator();
        let g2_tau = (G2Projective::generator() * tau).into_affine();

        Ok((
            Self {
                g1_powers,
                g2_gen,
                g2_tau,
            },
            t0.elapsed(),
        ))
    }

    /// Maximum polynomial length (number of coefficients) supported by this
    /// SRS.
    #[must_use]
    pub fn max_len(&self) -> usize {
        self.g1_powers.len()
    }
}

/// Commit to a univariate polynomial `P(X) = sum_i coeffs[i] X^i` in `G1`.
pub fn commit(srs: &KzgSrs, coeffs: &[Fr]) -> Result<G1Affine> {
    ensure!(
        coeffs.len() <= srs.g1_powers.len(),
        "polynomial length {} exceeds SRS capacity {}",
        coeffs.len(),
        srs.g1_powers.len()
    );
    if coeffs.is_empty() {
        return Ok(G1Affine::zero());
    }
    Ok(G1Projective::msm_unchecked(&srs.g1_powers[..coeffs.len()], coeffs).into_affine())
}

/// Evaluate `P(z)` using Horner's rule.
#[inline]
#[must_use]
pub fn eval_poly(coeffs: &[Fr], z: Fr) -> Fr {
    let mut acc = Fr::zero();
    for &c in coeffs.iter().rev() {
        acc = acc * z + c;
    }
    acc
}

/// Open `P(X)` at `z`, returning `(P(z), W)` where `W = [(P(tau) - P(z)) /
/// (tau - z)]_1` via Ruffini synthetic division in `O(len)` field ops + one
/// `G1` MSM.
pub fn open(srs: &KzgSrs, coeffs: &[Fr], z: Fr) -> Result<(Fr, G1Affine)> {
    ensure!(
        coeffs.len() <= srs.g1_powers.len(),
        "polynomial length {} exceeds SRS capacity {}",
        coeffs.len(),
        srs.g1_powers.len()
    );
    if coeffs.len() <= 1 {
        let val = coeffs.first().copied().unwrap_or(Fr::zero());
        return Ok((val, G1Affine::zero()));
    }

    let n = coeffs.len();
    let mut q = vec![Fr::zero(); n - 1];
    // Synthetic division from top coefficient down:
    //   q[n - 2] = coeffs[n - 1]
    //   q[i - 1] = coeffs[i] + z * q[i]
    //   rem      = coeffs[0] + z * q[0] = P(z)
    let mut acc = coeffs[n - 1];
    q[n - 2] = acc;
    for i in (1..n - 1).rev() {
        acc = coeffs[i] + z * acc;
        q[i - 1] = acc;
    }
    let value = coeffs[0] + z * acc;
    let proof = commit(srs, &q)?;
    Ok((value, proof))
}

/// Verify an arbitrary batch of univariate KZG opening claims `(C_k, z_k, y_k,
/// W_k)` using random batching challenge `rho` in **exactly 2 BN254 pairings**:
///
/// ```text
///   L = sum_k rho^k * W_k
///   R = sum_k rho^k * (C_k - [y_k]_1 + z_k * W_k)
///   check: e(L, [tau]_2) * e(-R, [1]_2) == 1_{G_T}
/// ```
///
/// Notice `L * tau - R = sum_k rho^k * ((tau - z_k) W_k - (C_k - [y_k]_1)) = 0`.
pub fn verify_batched(srs: &KzgSrs, claims: &[KzgOpeningClaim], rho: Fr) -> Result<bool> {
    if claims.is_empty() {
        return Ok(true);
    }

    let mut l_bases = Vec::with_capacity(claims.len());
    let mut l_scalars = Vec::with_capacity(claims.len());

    let mut r_bases = Vec::with_capacity(2 * claims.len() + 1);
    let mut r_scalars = Vec::with_capacity(2 * claims.len() + 1);
    let mut y_acc = Fr::zero();

    let mut rho_pow = Fr::one();
    for c in claims {
        // L += rho^k * W_k
        l_bases.push(c.proof);
        l_scalars.push(rho_pow);

        // R += rho^k * C_k + (rho^k * z_k) * W_k - (rho^k * y_k) * G1
        r_bases.push(c.commitment);
        r_scalars.push(rho_pow);
        r_bases.push(c.proof);
        r_scalars.push(rho_pow * c.point);
        y_acc += rho_pow * c.value;

        rho_pow *= rho;
    }

    if !y_acc.is_zero() {
        r_bases.push(G1Affine::generator());
        r_scalars.push(-y_acc);
    }

    let l_pt = G1Projective::msm_unchecked(&l_bases, &l_scalars).into_affine();
    let r_pt = G1Projective::msm_unchecked(&r_bases, &r_scalars).into_affine();

    let res = Bn254::multi_pairing([l_pt, -r_pt], [srs.g2_tau, srs.g2_gen]);
    Ok(res.0 == Fq12::ONE)
}

/// Serialize a `G1Affine` point into a canonical 32-byte compressed buffer for
/// Fiat-Shamir absorption.
pub fn g1_to_bytes32(pt: &G1Affine) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32);
    pt.serialize_compressed(&mut buf)
        .expect("BN254 G1 compressed serialization is 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf);
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        rand::{rngs::StdRng, SeedableRng},
    };

    #[test]
    fn test_univariate_kzg_commit_open_batch_verify() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(42);
        let g1_tbl = FixedBaseTable::new(G1Projective::generator());
        let (srs, _) = KzgSrs::setup_with_table(32, &g1_tbl, &mut rng)?;

        let p1: Vec<Fr> = (1..=16).map(|i| Fr::from(i * 7 + 3)).collect();
        let p2: Vec<Fr> = (1..=12).map(|i| Fr::from(i * 13 + 5)).collect();
        let c1 = commit(&srs, &p1)?;
        let c2 = commit(&srs, &p2)?;

        let z1 = Fr::from(99u64);
        let z2 = Fr::from(12345u64);
        let (y1, w1) = open(&srs, &p1, z1)?;
        let (y2, w2) = open(&srs, &p2, z2)?;
        assert_eq!(y1, eval_poly(&p1, z1));
        assert_eq!(y2, eval_poly(&p2, z2));

        let claims = vec![
            KzgOpeningClaim {
                commitment: c1,
                point:      z1,
                value:      y1,
                proof:      w1,
            },
            KzgOpeningClaim {
                commitment: c2,
                point:      z2,
                value:      y2,
                proof:      w2,
            },
        ];
        let rho = Fr::from(777u64);
        assert!(verify_batched(&srs, &claims, rho)?);

        // Tamper with one evaluation -> must fail!
        let mut bad = claims.clone();
        bad[1].value += Fr::one();
        assert!(!verify_batched(&srs, &bad, rho)?);

        Ok(())
    }
}
