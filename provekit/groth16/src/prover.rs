//! Groth16+BSB22 prover building blocks: generates proofs from R1CS + witness.
//!
//! Ported from gnark's `backend/groth16/bn254/prove.go`.
//!
//! The end-to-end proving flow (orchestrated by `provekit_prover::Prove for
//! Groth16Prover` in `provekit/prover/src/lib.rs`) is:
//! 1. (BSB22) Commit to pre-challenge witness values via Pedersen.
//! 2. (BSB22) Derive challenges from commitment hashes.
//! 3. Compute quotient polynomial H via FFT (see [`compute_h`]).
//! 4. Compute proof elements Ar, Bs, Krs via MSM (see [`prove_ar_bs_bs1`] and
//!    [`prove_krs`]).
//! 5. (BSB22) Generate and fold proofs of knowledge (see [`bsb22_pok`]).
//!
//! The caller owns the BSB22 witness-splitting flow (solve w1 → commit →
//! derive challenges → solve w2). Functions in this module take the completed
//! witness and commitments as inputs.

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
    commitment_keys: &[pedersen::ProvingKey],
    committed_values: &[Vec<Fr>],
    challenge_wire_indices: &[usize],
    wire_values: &[Fr],
) -> Result<G1Affine> {
    let poks: Vec<G1Affine> = commitment_keys
        .iter()
        .zip(committed_values.iter())
        .map(|(ck, vals)| ck.prove_knowledge(vals))
        .collect::<Result<Vec<_>>>()?;

    if poks.is_empty() {
        return Ok(G1Affine::zero());
    }

    let mut commitments_serialized = vec![0u8; FR_BYTES * challenge_wire_indices.len()];
    for (j, &wire_idx) in challenge_wire_indices.iter().enumerate() {
        let bytes = fr_to_bytes(&wire_values[wire_idx])?;
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
    infinity_a: &[bool],
    infinity_b: &[bool],
    wire_values: &[Fr],
    g1_alpha: G1Affine,
    g1_beta: G1Affine,
    g2_beta: G2Affine,
    g2_delta: G2Affine,
    r_delta: G1Affine,
    s_delta: G1Affine,
    s_scalar: Fr,
) -> Result<(G1Affine, G2Affine, G1Projective)> {
    let (wire_values_a, wire_values_b) = {
        let _s = info_span!("filter_wires_ab").entered();
        rayon::join(
            || {
                wire_values
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !infinity_a[*i])
                    .map(|(_, v)| *v)
                    .collect::<Vec<Fr>>()
            },
            || {
                wire_values
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !infinity_b[*i])
                    .map(|(_, v)| *v)
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

/// Compute `Krs`, the final Groth16 group element. Depends on the quotient
/// polynomial `H` and the `(A_r, Bs1)` outputs of [`prove_ar_bs_bs1`].
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

/// Filter a slice by removing elements at sorted absolute indices.
///
/// `slice` starts at absolute index `base_offset`. `sorted_indices` contains
/// absolute indices to remove (must be sorted and deduplicated).
/// Returns a new Vec with the matching elements removed.
///
/// Uses a merge-scan which is O(n + k) for pre-sorted indices.
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
/// Given the wire-level evaluations of A·w, B·w, C·w for each constraint,
/// compute H such that A·B - C = H·Z where Z is the vanishing polynomial.
///
/// The buffers are consumed: the `a_evals` allocation is reused in-place
/// for the returned H coefficients (avoiding an extra domain-sized
/// allocation), and `b_evals`/`c_evals` are dropped at the end of the call.
/// Buffers shorter than `domain.size()` are zero-padded internally.
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

/// Convert a field element to its canonical compressed byte form.
pub fn fr_to_bytes(val: &Fr) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = vec![0u8; FR_BYTES];
    val.serialize_compressed(&mut bytes[..])
        .map_err(|e| anyhow::anyhow!("failed to serialize Fr: {e}"))?;
    Ok(bytes)
}

/// RFC 9380 Section 5.3: expand_message_xmd using SHA-256.
///
/// Expands a message and DST into `len_in_bytes` pseudorandom bytes.
/// This is the core building block for hash-to-field.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let b_in_bytes = 32usize; // SHA-256 output size
    let r_in_bytes = 64usize; // SHA-256 block size

    ensure!(dst.len() <= 255, "DST must be at most 255 bytes");
    let ell = len_in_bytes.div_ceil(b_in_bytes);
    ensure!(ell <= 255, "expand_message_xmd: output too large");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, r_in_bytes) — 64 zero bytes
    let z_pad = vec![0u8; r_in_bytes];

    // l_i_b_str = I2OSP(len_in_bytes, 2) — 2-byte big-endian
    let l_i_b_str = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xff) as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(&z_pad);
    h.update(msg);
    h.update(l_i_b_str);
    h.update([0u8]); // I2OSP(0, 1)
    h.update(&dst_prime);
    let b_0: [u8; 32] = h.finalize().into();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(b_0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut b_prev: [u8; 32] = h.finalize().into();

    let mut output = Vec::with_capacity(len_in_bytes);
    output.extend_from_slice(&b_prev);

    // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
    for i in 2..=ell {
        let mut xored = [0u8; 32];
        for j in 0..32 {
            xored[j] = b_0[j] ^ b_prev[j];
        }
        let mut h = Sha256::new();
        h.update(xored);
        h.update([i as u8]);
        h.update(&dst_prime);
        b_prev = h.finalize().into();
        output.extend_from_slice(&b_prev);
    }

    output.truncate(len_in_bytes);
    Ok(output)
}

/// Hash bytes with a domain separator to produce a field element.
///
/// Matches gnark's `fr.Hash(msg, dst, 1)`: uses expand_message_xmd (RFC 9380)
/// with L = 48 bytes (32 byte field + 16 byte security parameter) to produce
/// an unbiased field element.
pub fn hash_to_fr(msg: &[u8], dst: &[u8]) -> Result<Fr> {
    // L = ceil((ceil(log2(p)) + k) / 8) where k=128 (security parameter)
    // For BN254: ceil((254 + 128) / 8) = ceil(382/8) = 48
    const L: usize = 48;

    let pseudo_random_bytes = expand_message_xmd(msg, dst, L)?;

    // Interpret as big-endian integer and reduce mod p
    Ok(Fr::from_be_bytes_mod_order(&pseudo_random_bytes))
}

/// Hash bytes with a domain separator to produce multiple field elements.
///
/// Matches gnark's `fr.Hash(msg, dst, count)`.
pub fn hash_to_fr_multi(msg: &[u8], dst: &[u8], count: usize) -> Result<Vec<Fr>> {
    const L: usize = 48;

    let pseudo_random_bytes = expand_message_xmd(msg, dst, count * L)?;

    let result = (0..count)
        .map(|i| Fr::from_be_bytes_mod_order(&pseudo_random_bytes[i * L..(i + 1) * L]))
        .collect();
    Ok(result)
}

/// Hash a Pedersen commitment to derive a BSB22 challenge.
///
/// Used during witness solving: Hash(C || public_values) → challenge.
/// Matches gnark's commitment hashing with
/// `hash_to_field.New("bsb22-commitment")`.
pub fn derive_commitment_challenge(commitment: &G1Affine, public_values: &[Fr]) -> Result<Fr> {
    use ark_serialize::CanonicalSerialize;

    let mut data = Vec::new();

    // Serialize commitment point
    let mut commitment_bytes = Vec::new();
    commitment.serialize_uncompressed(&mut commitment_bytes)?;
    data.extend_from_slice(&commitment_bytes);

    // Serialize public values
    for val in public_values {
        let bytes = fr_to_bytes(val)?;
        data.extend_from_slice(&bytes);
    }

    hash_to_fr(&data, COMMITMENT_DST)
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
    fn test_expand_message_xmd_basic() {
        // Verify expand_message_xmd produces deterministic output
        let out1 = expand_message_xmd(b"hello", b"dst", 48).unwrap();
        let out2 = expand_message_xmd(b"hello", b"dst", 48).unwrap();
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 48);
    }

    #[test]
    fn test_expand_message_xmd_different_inputs() {
        let out1 = expand_message_xmd(b"hello", b"dst", 48).unwrap();
        let out2 = expand_message_xmd(b"world", b"dst", 48).unwrap();
        assert_ne!(out1, out2);
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
