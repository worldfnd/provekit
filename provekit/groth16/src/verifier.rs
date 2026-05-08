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
use anyhow::{ensure, Context, Result};
use {
    crate::{
        pedersen,
        prover::{derive_commitment_challenge, hash_to_fr, hash_to_fr_multi},
        types::{Proof, VerifyingKey},
        BSB22_FOLD_DST, COMMITMENT_DST, FR_BYTES,
    },
    ark_bn254::{Bn254, Fr, G1Projective},
    ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM},
};

/// Verify a Groth16+BSB22 proof.
///
/// # Arguments
/// * `proof` - The proof to verify.
/// * `vk` - The verifying key (must have `precompute()` called).
/// * `public_witness` - Public input values (excluding the constant 1 wire).
pub fn verify(proof: &Proof, vk: &VerifyingKey, public_witness: &[Fr]) -> Result<()> {
    let total_challenges: usize = vk.num_challenges_per_commitment.iter().sum();
    // Guard the subtraction below: a malformed VK with more declared
    // challenges than g1_k entries would otherwise underflow `usize` (panic
    // in debug, wrap in release — release still rejects via the size-check
    // a few lines down, but the panic in debug is a DoS surface and the
    // wrap masks the real problem).
    ensure!(
        vk.g1_k.len() >= total_challenges + 1,
        "invalid verifying key: g1_k has {} entries but {} challenges + ONE_WIRE were declared",
        vk.g1_k.len(),
        total_challenges,
    );
    let nb_public_vars = vk.g1_k.len() - total_challenges;
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
        vk.num_challenges_per_commitment.len() == expected_commitments,
        "invalid verifying key: got {} challenge counts, expected {}",
        vk.num_challenges_per_commitment.len(),
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
    let mut extended_public = public_witness.to_vec();
    let mut commitments_serialized = vec![0u8; total_challenges * FR_BYTES];
    let mut serial_offset = 0usize;

    for (i, committed_indices) in vk.public_and_commitment_committed.iter().enumerate() {
        let num_challenges = vk.num_challenges_per_commitment[i];

        let public_vals: Vec<Fr> = committed_indices
            .iter()
            .map(|&idx| {
                ensure!(
                    idx > 0 && idx - 1 < extended_public.len(),
                    "commitment public index {} out of bounds (extended_public len = {})",
                    idx,
                    extended_public.len()
                );
                Ok(extended_public[idx - 1])
            })
            .collect::<Result<Vec<_>>>()?;

        if num_challenges <= 1 {
            let challenge = derive_commitment_challenge(&proof.commitments[i], &public_vals)?;
            extended_public.push(challenge);
            let bytes = crate::prover::fr_to_bytes(&challenge)?;
            commitments_serialized[FR_BYTES * serial_offset..FR_BYTES * (serial_offset + 1)]
                .copy_from_slice(&bytes);
            serial_offset += 1;
        } else {
            let challenge_data = {
                use ark_serialize::CanonicalSerialize;
                let mut data = Vec::new();
                let mut commitment_bytes = Vec::new();
                proof.commitments[i]
                    .serialize_uncompressed(&mut commitment_bytes)
                    .map_err(|e| anyhow::anyhow!("serialize commitment: {e}"))?;
                data.extend_from_slice(&commitment_bytes);
                for val in &public_vals {
                    let bytes = crate::prover::fr_to_bytes(val)?;
                    data.extend_from_slice(&bytes);
                }
                data
            };

            let challenges = hash_to_fr_multi(&challenge_data, COMMITMENT_DST, num_challenges)?;

            for ch in &challenges {
                let bytes = crate::prover::fr_to_bytes(ch)?;
                commitments_serialized[FR_BYTES * serial_offset..FR_BYTES * (serial_offset + 1)]
                    .copy_from_slice(&bytes);
                serial_offset += 1;
            }

            extended_public.extend_from_slice(&challenges);
        }
    }

    // Step 3: Verify BSB22 Pedersen commitments
    if !vk.commitment_keys.is_empty() {
        let folding_challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;

        pedersen::batch_verify_multi_vk(
            &vk.commitment_keys,
            &proof.commitments,
            proof.commitment_pok,
            folding_challenge,
        )
        .context("Pedersen batch verification failed")?;
    }

    // Step 4: Compute public input contribution
    let k_sum = {
        let mut sum = G1Projective::from(vk.g1_k[0]);

        if !extended_public.is_empty() {
            let msm_bases = &vk.g1_k[1..1 + extended_public.len()];
            let msm = G1Projective::msm(msm_bases, &extended_public).map_err(crate::msm_err)?;
            sum += msm;
        }

        for c in &proof.commitments {
            sum += G1Projective::from(*c);
        }

        sum.into_affine()
    };

    // Step 5: Pairing check
    let left = Bn254::multi_pairing([proof.krs, proof.ar, k_sum], [
        vk.g2_delta_neg,
        proof.bs,
        vk.g2_gamma_neg,
    ]);

    ensure!(
        left.0 == vk.e_alpha_beta,
        "pairing check failed: proof is invalid"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests would go here, requiring a full setup → prove → verify
    // cycle.
}
