//! Groth16+BSB22 prover building blocks: generates proofs from R1CS + witness.

use {
    crate::{pedersen, CommitmentInfo, BSB22_FOLD_DST, COMMITMENT_DST, FR_BYTES},
    anyhow::{ensure, Result},
    ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM},
    ark_ff::{FftField, Field, One, PrimeField, Zero},
    ark_poly::{EvaluationDomain, Radix2EvaluationDomain},
    rayon::{self, prelude::*},
    tracing::{info_span, instrument},
};

/// BSB22 batched proof of knowledge over all commitments, folded into a
/// single G1 element. Independent of `H`, so callers can run this in
/// parallel with [`compute_h`].
#[instrument(skip_all)]
pub fn bsb22_pok(
    commitment_keys: &[pedersen::ProvingKeyView<'_>],
    committed_values: &[Vec<Fr>],
    challenge_wire_indices: &[usize],
    wire_values: &[Fr],
) -> Result<G1Affine> {
    let poks: Vec<G1Affine> = commitment_keys
        .iter()
        .zip(committed_values.iter())
        .map(|(ck, vals)| ck.prove_knowledge(vals).map(|p| p.0))
        .collect::<Result<Vec<_>>>()?;

    if poks.is_empty() {
        return Ok(G1Affine::zero());
    }

    let mut commitments_serialized = vec![0u8; FR_BYTES * challenge_wire_indices.len()];
    for (j, &wire_idx) in challenge_wire_indices.iter().enumerate() {
        let val = wire_values.get(wire_idx).ok_or_else(|| {
            anyhow::anyhow!(
                "challenge wire index {wire_idx} out of bounds (witness len = {})",
                wire_values.len()
            )
        })?;
        let bytes = fr_to_bytes(val)?;
        commitments_serialized[FR_BYTES * j..FR_BYTES * (j + 1)].copy_from_slice(&bytes);
    }

    let challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;
    pedersen::fold(&poks, challenge)
}

/// Compute `A_r`, `B_s`, and `Bs1` (the G1 form of `B_s` needed later in the
/// `Krs` cross-term). Independent of `H`, so callers can run this in
/// parallel with `compute_h`.
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub fn prove_ar_bs_bs1(
    g1_a: &[G1Affine],
    g1_b: &[G1Affine],
    g2_b: &[G2Affine],
    non_inf_a: &[usize],
    non_inf_b: &[usize],
    wire_values: &[Fr],
    g1_alpha: G1Affine,
    g1_beta: G1Affine,
    g2_beta: G2Affine,
    g2_delta: G2Affine,
    r_delta: G1Affine,
    s_delta: G1Affine,
    s_scalar: Fr,
) -> Result<(G1Affine, G2Affine, G1Projective)> {
    // Direct gather using the precomputed non-infinity index lists from
    // setup. Replaces the original "iterate all wires, filter by
    // `infinity_a/b[i]`" pattern — fewer iterations, no bool branch.
    let (wire_values_a, wire_values_b) = {
        let _s = info_span!("gather_wires_ab").entered();
        rayon::join(
            || {
                non_inf_a
                    .iter()
                    .map(|&i| wire_values[i])
                    .collect::<Vec<Fr>>()
            },
            || {
                non_inf_b
                    .iter()
                    .map(|&i| wire_values[i])
                    .collect::<Vec<Fr>>()
            },
        )
    };

    let _s = info_span!("msm_ar_bs").entered();
    // Sequential, not nested-rayon::join: arkworks' MSM is already rayon-
    // parallel internally, so concurrent MSMs would just stack bucket
    // allocators (~3×) without speeding up wall-clock. Sequential keeps one
    // bucket set alive at a time — important when this whole function runs
    // in parallel with `compute_h`.
    let ar = {
        let msm = G1Projective::msm(g1_a, &wire_values_a).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G1Projective::from(g1_alpha);
        result += G1Projective::from(r_delta);
        result.into_affine()
    };
    let bs = {
        let msm =
            <G2Projective as VariableBaseMSM>::msm(g2_b, &wire_values_b).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G2Projective::from(g2_beta);
        result += G2Projective::from(g2_delta) * s_scalar;
        result.into_affine()
    };
    let bs1 = {
        let msm = G1Projective::msm(g1_b, &wire_values_b).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G1Projective::from(g1_beta);
        result += G1Projective::from(s_delta);
        result
    };
    Ok((ar, bs, bs1))
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub fn prove_krs(
    g1_k: &[G1Affine],
    g1_z: &[G1Affine],
    h: &[Fr],
    wire_values: &[Fr],
    r1cs_nb_public: usize,
    commitment_info: &[CommitmentInfo],
    challenge_wire_indices: &[usize],
    domain_size: u64,
    ar: G1Affine,
    bs1: G1Projective,
    kr_delta: G1Affine,
    r_scalar: Fr,
    s_scalar: Fr,
) -> Result<G1Affine> {
    let private_wire_values: Vec<Fr> = {
        let _s = info_span!("filter_private_wires").entered();
        let mut to_remove: Vec<usize> = Vec::new();
        for ci in commitment_info {
            to_remove.extend_from_slice(&ci.private_committed);
        }
        to_remove.extend_from_slice(challenge_wire_indices);
        to_remove.sort_unstable();
        to_remove.dedup();
        filter_by_sorted_indices(&wire_values[r1cs_nb_public..], &to_remove, r1cs_nb_public)
    };

    ensure!(
        private_wire_values.len() == g1_k.len(),
        "private wire count mismatch: got {}, expected {}",
        private_wire_values.len(),
        g1_k.len()
    );

    let _s = info_span!("msm_krs").entered();
    let size_h = domain_size as usize - 1;

    let (krs1_result, krs2_result) = rayon::join(
        || G1Projective::msm(g1_k, &private_wire_values).map_err(crate::msm_err),
        || {
            if !h.is_empty() && !g1_z.is_empty() {
                let h_slice = &h[..size_h.min(h.len())];
                let z_slice = &g1_z[..size_h.min(g1_z.len())];
                let min_len = h_slice.len().min(z_slice.len());
                G1Projective::msm(&z_slice[..min_len], &h_slice[..min_len]).map_err(crate::msm_err)
            } else {
                Ok(G1Projective::zero())
            }
        },
    );

    let mut result = krs1_result? + krs2_result?;
    result += G1Projective::from(kr_delta);

    // Cross-terms: s·Ar + r·Bs1
    let (s_ar, r_bs1) = rayon::join(|| G1Projective::from(ar) * s_scalar, || bs1 * r_scalar);
    result += s_ar;
    result += r_bs1;

    Ok(result.into_affine())
}

/// Merge-scan, O(n + k) — assumes `sorted_indices` is sorted and deduplicated.
fn filter_by_sorted_indices(slice: &[Fr], sorted_indices: &[usize], base_offset: usize) -> Vec<Fr> {
    if sorted_indices.is_empty() {
        return slice.to_vec();
    }
    let mut result = Vec::with_capacity(slice.len());
    let mut remove_idx = 0;
    for (i, val) in slice.iter().enumerate() {
        let abs_idx = i + base_offset;
        // Advance past any indices below current position
        while remove_idx < sorted_indices.len() && sorted_indices[remove_idx] < abs_idx {
            remove_idx += 1;
        }
        // Skip this element if it's in the removal list
        if remove_idx < sorted_indices.len() && sorted_indices[remove_idx] == abs_idx {
            remove_idx += 1;
            continue;
        }
        result.push(*val);
    }
    result
}

/// Compute quotient polynomial H from the R1CS solution vectors.
///
/// Buffers are consumed: `a_evals` is reused in-place for the returned H
/// coefficients (avoiding a second domain-sized allocation); `b_evals` /
/// `c_evals` are dropped at end of call. Short buffers are zero-padded to
/// `domain.size()` internally.
#[instrument(skip_all)]
pub fn compute_h(
    mut a_evals: Vec<Fr>,
    mut b_evals: Vec<Fr>,
    mut c_evals: Vec<Fr>,
    domain: &Radix2EvaluationDomain<Fr>,
) -> Result<Vec<Fr>> {
    let n = domain.size();

    // Pad to domain size
    a_evals.resize(n, Fr::zero());
    b_evals.resize(n, Fr::zero());
    c_evals.resize(n, Fr::zero());

    // IFFT → coset FFT for each buffer. The three pipelines are independent
    // (separate buffers, immutable domain refs), so run them in parallel.
    let coset_domain = domain
        .get_coset(Fr::GENERATOR)
        .ok_or_else(|| anyhow::anyhow!("failed to construct coset domain"))?;
    rayon::join(
        || {
            domain.ifft_in_place(&mut a_evals);
            coset_domain.fft_in_place(&mut a_evals);
        },
        || {
            rayon::join(
                || {
                    domain.ifft_in_place(&mut b_evals);
                    coset_domain.fft_in_place(&mut b_evals);
                },
                || {
                    domain.ifft_in_place(&mut c_evals);
                    coset_domain.fft_in_place(&mut c_evals);
                },
            )
        },
    );

    // Pointwise: a[i] = (a[i] * b[i] - c[i]) / Z(coset), computed in parallel.
    // Reuses a_evals in-place to avoid an extra domain-sized allocation.
    // Z(g·ωⁱ) = (g·ωⁱ)^N - 1 = g^N - 1 (constant on coset)
    let z_inv = {
        let gen_n = Fr::GENERATOR.pow([n as u64]);
        (gen_n - Fr::one())
            .inverse()
            .ok_or_else(|| anyhow::anyhow!("Z(coset) is zero, cannot invert"))?
    };

    a_evals
        .par_iter_mut()
        .zip(b_evals.par_iter())
        .zip(c_evals.par_iter())
        .for_each(|((a, b), c)| {
            *a = (*a * b - c) * z_inv;
        });

    // IFFT on coset: evaluation on coset → coefficient form
    coset_domain.ifft_in_place(&mut a_evals);

    Ok(a_evals)
}

pub fn fr_to_bytes(val: &Fr) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = vec![0u8; FR_BYTES];
    val.serialize_compressed(&mut bytes[..])
        .map_err(|e| anyhow::anyhow!("failed to serialize Fr: {e}"))?;
    Ok(bytes)
}

/// Hash bytes with a domain separator to produce a field element.
///
/// Uses EVM-native Keccak-256 over `dst || msg`, then interprets the 32-byte
/// digest as a big-endian integer reduced mod R.
///
/// Bias note: the result is biased by at most ~2^-126 (R is 254-bit, hash is
/// 256-bit; the modular reduction wraps unevenly over ~4 buckets at the top
/// of the 256-bit range). For BSB22 challenge derivation this is negligible.
///
/// Intentionally diverges from the BSB22-spec hash (RFC 9380
/// `expand_message_xmd-SHA256`) — the trade is ~130 k gas of on-chain
/// SHA-256 + XMD scaffolding for a single `keccak256` opcode.
pub fn hash_to_fr(msg: &[u8], dst: &[u8]) -> Result<Fr> {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(dst);
    h.update(msg);
    let digest: [u8; 32] = h.finalize().into();
    Ok(Fr::from_be_bytes_mod_order(&digest))
}

/// Hash bytes with a domain separator to produce multiple field elements.
///
/// Single-root counter chain:
/// ```text
///   root      = keccak256(dst || msg)
///   out[i]    = keccak256(root || I2OSP(i, 1))   reduced mod R
/// ```
///
/// One outer hash over the (often large) `msg`, then N cheap 33-byte hashes
/// — keeps total work close to a single keccak even for N up to ~32.
pub fn hash_to_fr_multi(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<Fr>> {
    use sha3::{Digest, Keccak256};
    ensure!(count <= 255, "hash_to_fr_multi: count must fit in one byte");

    let root: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(dst);
        h.update(msg);
        h.finalize().into()
    };

    let result = (0..count)
        .map(|i| {
            let mut h = Keccak256::new();
            h.update(root);
            h.update([i as u8]);
            let digest: [u8; 32] = h.finalize().into();
            Fr::from_be_bytes_mod_order(&digest)
        })
        .collect();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_fr_deterministic() {
        let data = b"test data";
        let dst = b"test dst";
        let h1 = hash_to_fr(data, dst).unwrap();
        let h2 = hash_to_fr(data, dst).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_to_fr_different_inputs() {
        let h1 = hash_to_fr(b"input1", b"dst").unwrap();
        let h2 = hash_to_fr(b"input2", b"dst").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_to_fr_produces_nonzero() {
        let h = hash_to_fr(b"test", b"dst").unwrap();
        assert!(!h.is_zero());
    }

    #[test]
    fn test_hash_to_fr_multi() {
        let results = hash_to_fr_multi(b"test", b"dst", 3).unwrap();
        assert_eq!(results.len(), 3);
        // All should be different
        assert_ne!(results[0], results[1]);
        assert_ne!(results[1], results[2]);
    }
}
