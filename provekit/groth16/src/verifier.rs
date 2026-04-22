/// Groth16+BSB22 verifier: verifies proofs against a verifying key.
///
/// Ported from gnark's `backend/groth16/bn254/verify.go`.
///
/// Verification steps:
/// 1. Subgroup check on proof elements
/// 2. Recompute BSB22 commitment challenges from proof commitments
/// 3. Verify Pedersen commitment PoKs via batch verification
/// 4. Compute public input contribution via MSM
/// 5. Check the Groth16 pairing equation
use anyhow::{ensure, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, Zero};

use crate::prover::{derive_commitment_challenge, hash_to_fr};
use crate::types::{Proof, VerifyingKey};
use crate::{pedersen, BSB22_FOLD_DST, FR_BYTES};

/// Verify a Groth16+BSB22 proof.
///
/// # Arguments
/// * `proof` - The proof to verify.
/// * `vk` - The verifying key (must have `precompute()` called).
/// * `public_witness` - Public input values (excluding the constant 1 wire).
pub fn verify(proof: &Proof, vk: &VerifyingKey, public_witness: &[Fr]) -> Result<()> {
    let nb_public_vars = vk.g1_k.len() - vk.public_and_commitment_committed.len();
    let expected_commitments = vk.public_and_commitment_committed.len();

    ensure!(
        vk.commitment_keys.len() == expected_commitments,
        "invalid verifying key: got {} commitment keys, expected {}",
        vk.commitment_keys.len(),
        expected_commitments
    );
    ensure!(
        proof.commitments.len() == expected_commitments,
        "invalid proof: got {} commitments, expected {}",
        proof.commitments.len(),
        expected_commitments
    );
    ensure!(
        public_witness.len() == nb_public_vars - 1,
        "invalid witness size: got {}, expected {} (public - ONE_WIRE)",
        public_witness.len(),
        nb_public_vars - 1
    );

    // Step 1: Subgroup check
    ensure!(proof.is_valid(), "proof elements not in correct subgroup");

    // Step 2: Recompute commitment challenges and verify BSB22
    //
    // For each commitment:
    //   - Hash(commitment_point || public_values) → challenge field element
    //   - Append challenge to public witness (commitments are treated as public)
    let mut extended_public = public_witness.to_vec();

    let mut commitments_serialized = vec![0u8; expected_commitments * FR_BYTES];

    for (i, committed_indices) in vk.public_and_commitment_committed.iter().enumerate() {
        // Collect public values for this commitment
        let public_vals: Vec<Fr> = committed_indices
            .iter()
            .map(|&idx| {
                ensure!(idx > 0 && idx - 1 < extended_public.len(),
                    "commitment public index out of bounds");
                Ok(extended_public[idx - 1])
            })
            .collect::<Result<Vec<_>>>()?;

        // Derive challenge: Hash(commitment || public_values)
        let challenge = derive_commitment_challenge(&proof.commitments[i], &public_vals)?;

        // Append challenge to public witness
        extended_public.push(challenge);

        // Serialize for PoK verification
        let bytes = crate::prover::fr_to_bytes(&challenge);
        commitments_serialized[FR_BYTES * i..FR_BYTES * (i + 1)].copy_from_slice(&bytes);
    }

    // Step 3: Verify BSB22 Pedersen commitments
    if !vk.commitment_keys.is_empty() {
        let folding_challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;

        pedersen::batch_verify_multi_vk(
            &vk.commitment_keys,
            &proof.commitments,
            proof.commitment_pok,
            folding_challenge,
        )?;
    }

    // Step 4: Compute public input contribution
    //   kSum = [K₀]₁ + Σ pubᵢ · [Kᵢ]₁ + Σ Cᵢ
    //   where K₀ is the constant-1 wire's key
    let k_sum = {
        let mut sum = G1Projective::from(vk.g1_k[0]); // K₀ (constant wire)

        if !extended_public.is_empty() {
            // MSM: Σ pubᵢ · [Kᵢ]₁ for i in 1..
            let msm = G1Projective::msm(
                &vk.g1_k[1..1 + extended_public.len()],
                &extended_public,
            ).map_err(crate::msm_err)?;
            sum += msm;
        }

        // Add commitment points to kSum
        for c in &proof.commitments {
            sum += G1Projective::from(*c);
        }

        sum.into_affine()
    };

    // Step 5: Pairing check
    //
    // The Groth16 verification equation:
    //   e(Ar, Bs) = e(α, β) · e(kSum, γ) · e(Krs, δ)
    //
    // Rearranged as:
    //   e(Krs, -δ) · e(Ar, Bs) · e(kSum, -γ) = e(α, β)
    //
    // Compute left side:
    //   ml1 = MillerLoop(Krs, -δ) · MillerLoop(Ar, Bs)
    //   ml2 = MillerLoop(kSum, -γ)
    //   left = FinalExp(ml1 · ml2)

    let left = Bn254::multi_pairing(
        [proof.krs, proof.ar, k_sum],
        [vk.g2_delta_neg, proof.bs, vk.g2_gamma_neg],
    );

    ensure!(
        left.0 == vk.e_alpha_beta,
        "pairing check failed: proof is invalid"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests would go here, requiring a full setup → prove → verify cycle.
    // See the setup and prover modules for building test fixtures.
}
