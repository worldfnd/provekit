/// Pedersen commitment scheme for BSB22 extension.
///
/// A Pedersen commitment C = Σ vᵢ·Gᵢ binds the prover to values v₁..vₖ
/// using bases G₁..Gₖ from the trusted setup. The proof of knowledge (PoK)
/// proves the prover knows the committed values without revealing them.
use anyhow::{ensure, Result};
use {
    ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM},
    ark_ff::{One, UniformRand, Zero},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    zeroize::Zeroizing,
};

/// A Pedersen commitment `C = Σ vᵢ · Gᵢ` — binds the prover to values.
///
/// Wrapping `G1Affine` in a distinct newtype prevents accidentally passing a
/// proof of knowledge where a commitment is expected (or vice versa): they're
/// both `G1Affine` at the curve level but represent semantically distinct
/// objects, and a swap would silently verify the wrong pairing equation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Commitment(pub G1Affine);

/// A Pedersen proof of knowledge `PoK = Σ vᵢ · (σ·Gᵢ)` — proves the prover
/// knows the opening of a [`Commitment`] without revealing the values. See
/// [`Commitment`] for the rationale behind making this a newtype.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProofOfKnowledge(pub G1Affine);

/// Pedersen proving key: bases for commitment and PoK generation.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey {
    /// Original bases [G₁, G₂, ..., Gₖ] from trusted setup.
    pub basis:           Vec<G1Affine>,
    /// Bases raised to secret sigma: [G₁^σ, G₂^σ, ..., Gₖ^σ].
    pub basis_exp_sigma: Vec<G1Affine>,
}

/// Pedersen verifying key: G2 elements for pairing-based verification.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey {
    /// Random G2 generator chosen during setup.
    pub g:           G2Affine,
    /// G^(-σ) where σ is the secret from setup.
    pub g_sigma_neg: G2Affine,
}

/// Generate Pedersen commitment keys from bases.
///
/// `bases_per_commitment` is a slice of slices — one set of bases per
/// commitment. `g2_point` is an optional pre-chosen G2 point (if None, a random
/// one is sampled).
pub fn setup(
    bases_per_commitment: &[&[G1Affine]],
    g2_point: Option<G2Affine>,
) -> Result<(Vec<ProvingKey>, VerifyingKey)> {
    let mut rng = ark_std::rand::thread_rng();

    // Choose G2 generator
    let g = g2_point.unwrap_or_else(|| G2Projective::rand(&mut rng).into_affine());

    // Sample secret sigma. `Zeroizing` wipes the field element when it drops,
    // so the toxic Pedersen secret can't be recovered from freed memory after
    // setup returns.
    let sigma = Zeroizing::new(Fr::rand(&mut rng));
    ensure!(!sigma.is_zero(), "sigma must be non-zero");

    // Compute G^(-sigma)
    let g_sigma_neg: G2Affine = (-(G2Projective::from(g) * *sigma)).into_affine();

    let vk = VerifyingKey { g, g_sigma_neg };

    let pks: Vec<ProvingKey> = bases_per_commitment
        .iter()
        .map(|bases| {
            // BasisExpSigma[i] = Basis[i] * sigma
            let basis_exp_sigma: Vec<G1Affine> = bases
                .iter()
                .map(|b| (G1Projective::from(*b) * *sigma).into_affine())
                .collect();

            ProvingKey {
                basis: bases.to_vec(),
                basis_exp_sigma,
            }
        })
        .collect();

    Ok((pks, vk))
}

/// Chunk size for Pedersen MSMs. arkworks' `VariableBaseMSM` keeps a
/// projective copy of every base plus per-thread bucket state, so a single
/// 1M-element call holds hundreds of MB of transient memory. Splitting into
/// 100k-element chunks caps that to ~tens of MB at the cost of ~10% wall
/// clock.
const PEDERSEN_MSM_CHUNK: usize = 100_000;

fn chunked_g1_msm(bases: &[G1Affine], values: &[Fr]) -> Result<G1Projective> {
    ensure!(
        bases.len() == values.len(),
        "chunked_g1_msm length mismatch: {} bases vs {} values",
        bases.len(),
        values.len()
    );
    let mut acc = G1Projective::zero();
    for (b_chunk, v_chunk) in bases
        .chunks(PEDERSEN_MSM_CHUNK)
        .zip(values.chunks(PEDERSEN_MSM_CHUNK))
    {
        acc += G1Projective::msm(b_chunk, v_chunk).map_err(crate::msm_err)?;
    }
    Ok(acc)
}

/// Borrowed view over a Pedersen `ProvingKey`'s bases. Same `commit` /
/// `prove_knowledge` API as [`ProvingKey`], but the basis slices can point
/// at either owned `Vec<G1Affine>`s (legacy path) or mmap'd file pages
/// (rapidsnark-style raw layout). Lets callers be polymorphic over the
/// backing store without a runtime indirection or memcpy.
#[derive(Clone, Copy)]
pub struct ProvingKeyView<'a> {
    pub basis:           &'a [G1Affine],
    pub basis_exp_sigma: &'a [G1Affine],
}

impl<'a> ProvingKeyView<'a> {
    /// Compute Pedersen commitment: `C = Σ vᵢ · Basis[i]`.
    pub fn commit(&self, values: &[Fr]) -> Result<Commitment> {
        ensure!(
            values.len() == self.basis.len(),
            "commit: got {} values, expected {}",
            values.len(),
            self.basis.len()
        );

        if values.is_empty() {
            return Ok(Commitment(G1Affine::zero()));
        }

        let commitment = chunked_g1_msm(self.basis, values)?;
        Ok(Commitment(commitment.into_affine()))
    }

    /// Generate proof of knowledge: `PoK = Σ vᵢ · BasisExpSigma[i]`.
    pub fn prove_knowledge(&self, values: &[Fr]) -> Result<ProofOfKnowledge> {
        ensure!(
            values.len() == self.basis_exp_sigma.len(),
            "prove_knowledge: got {} values, expected {}",
            values.len(),
            self.basis_exp_sigma.len()
        );

        if values.is_empty() {
            return Ok(ProofOfKnowledge(G1Affine::zero()));
        }

        let pok = chunked_g1_msm(self.basis_exp_sigma, values)?;
        Ok(ProofOfKnowledge(pok.into_affine()))
    }
}

impl ProvingKey {
    /// Borrow this owned key as a view. Cheap — just two slice references.
    pub fn view(&self) -> ProvingKeyView<'_> {
        ProvingKeyView {
            basis:           &self.basis,
            basis_exp_sigma: &self.basis_exp_sigma,
        }
    }

    /// Compute Pedersen commitment: `C = Σ vᵢ · Basis[i]`.
    pub fn commit(&self, values: &[Fr]) -> Result<Commitment> {
        self.view().commit(values)
    }

    /// Generate proof of knowledge: `PoK = Σ vᵢ · BasisExpSigma[i]`.
    ///
    /// Proves the prover knows the values inside the commitment without
    /// revealing them. The verifier checks e(C, G^(-σ)) · e(PoK, G) == 1.
    pub fn prove_knowledge(&self, values: &[Fr]) -> Result<ProofOfKnowledge> {
        self.view().prove_knowledge(values)
    }
}

/// Fold multiple G1 points into one using a random linear combination.
///
/// Returns: `points[0] + coeff·points[1] + coeff²·points[2] + ...`
pub fn fold(points: &[G1Affine], coeff: Fr) -> Result<G1Affine> {
    if points.is_empty() {
        return Ok(G1Affine::zero());
    }
    if points.len() == 1 {
        return Ok(points[0]);
    }

    // Build scalars: [1, coeff, coeff², coeff³, ...]
    let mut scalars = Vec::with_capacity(points.len());
    let mut power = Fr::one();
    for _ in 0..points.len() {
        scalars.push(power);
        power *= coeff;
    }

    let result = G1Projective::msm(points, &scalars).map_err(crate::msm_err)?;
    Ok(result.into_affine())
}

/// Batch verify multiple commitments against multiple verifying keys.
///
/// Checks that for each commitment Cᵢ with PoKᵢ and verifying key VKᵢ:
///   e(Cᵢ, VKᵢ.GSigmaNeg) · e(PoKᵢ, VKᵢ.G) == 1
///
/// All PoKs are expected to have already been folded into a single point.
pub fn batch_verify_multi_vk(
    vks: &[VerifyingKey],
    commitments: &[Commitment],
    folded_pok: ProofOfKnowledge,
    folding_challenge: Fr,
) -> Result<()> {
    use {ark_bn254::Bn254, ark_ec::pairing::Pairing};

    ensure!(
        vks.len() == commitments.len(),
        "batch_verify: {} vks vs {} commitments",
        vks.len(),
        commitments.len()
    );

    if vks.is_empty() {
        return Ok(());
    }

    // All VKs must share the same G point. `setup()` always emits a single G,
    // but a deserialized batch could mix VKs whose `g` differs — folding
    // `g_sigma_neg` against `vks[0].g` would then quietly check the wrong
    // pairing equation, so reject the batch outright.
    let g = vks[0].g;
    ensure!(
        vks.iter().all(|v| v.g == g),
        "batch_verify: all verifying keys must share the same G point"
    );

    // Fold commitments: C_folded = C₀ + challenge·C₁ + challenge²·C₂ + ...
    let commitments_g1: Vec<G1Affine> = commitments.iter().map(|c| c.0).collect();
    let folded_commitment = fold(&commitments_g1, folding_challenge)?;

    // Fold GSigmaNeg: we need Σ rⁱ·VKᵢ.GSigmaNeg
    // Since all G points are the same, this simplifies to:
    // GSigmaNeg_folded = Σ rⁱ · GSigmaNeg_i
    let g_sigma_negs: Vec<G2Affine> = vks.iter().map(|vk| vk.g_sigma_neg).collect();
    let fold_scalars: Vec<Fr> = {
        let mut s = Vec::with_capacity(vks.len());
        let mut power = Fr::one();
        for _ in 0..vks.len() {
            s.push(power);
            power *= folding_challenge;
        }
        s
    };
    let g_sigma_neg_folded: G2Affine = {
        use ark_ec::VariableBaseMSM;
        <G2Projective as VariableBaseMSM>::msm(&g_sigma_negs, &fold_scalars)
            .map_err(crate::msm_err)?
            .into_affine()
    };

    // Pairing check: e(folded_commitment, g_sigma_neg_folded) · e(folded_pok, g) ==
    // 1
    let result = Bn254::multi_pairing([folded_commitment, folded_pok.0], [g_sigma_neg_folded, g]);

    ensure!(
        result.0.is_one(),
        "pedersen batch verification failed: pairing check did not pass"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ff::UniformRand};

    #[test]
    fn test_commit_and_verify() {
        let mut rng = ark_std::test_rng();

        // Generate random bases
        let bases: Vec<G1Affine> = (0..5)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();

        let (pks, vk) = setup(&[&bases], None).unwrap();
        let pk = &pks[0];

        // Commit to random values
        let values: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let commitment = pk.commit(&values).unwrap();
        let pok = pk.prove_knowledge(&values).unwrap();

        // Verify
        batch_verify_multi_vk(
            &[vk],
            &[commitment],
            pok,
            Fr::one(), // trivial challenge for single commitment
        )
        .unwrap();
    }

    #[test]
    fn test_fold_single() {
        let mut rng = ark_std::test_rng();
        let p = G1Projective::rand(&mut rng).into_affine();
        let result = fold(&[p], Fr::rand(&mut rng)).unwrap();
        assert_eq!(result, p);
    }

    #[test]
    fn test_commit_wrong_values_fails() {
        let mut rng = ark_std::test_rng();
        let bases: Vec<G1Affine> = (0..3)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let (pks, vk) = setup(&[&bases], None).unwrap();
        let pk = &pks[0];

        let values: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let commitment = pk.commit(&values).unwrap();

        // Generate PoK with WRONG values
        let wrong_values: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let wrong_pok = pk.prove_knowledge(&wrong_values).unwrap();

        let result = batch_verify_multi_vk(&[vk], &[commitment], wrong_pok, Fr::one());
        assert!(result.is_err());
    }
}
