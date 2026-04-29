/// Groth16+BSB22 prover: generates proofs from R1CS + witness.
///
/// Ported from gnark's `backend/groth16/bn254/prove.go`.
///
/// The proving flow:
/// 1. (BSB22) Commit to pre-challenge witness values via Pedersen
/// 2. (BSB22) Derive challenges from commitment hashes
/// 3. Compute quotient polynomial H via FFT
/// 4. Compute proof elements Ar, Bs, Krs via MSM
/// 5. (BSB22) Generate and fold proofs of knowledge
use anyhow::{ensure, Result};
use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon;
use rayon::prelude::*;
use tracing::{info_span, instrument};

use crate::types::{Proof, ProvingKey};
use crate::{pedersen, CommitmentInfo, BSB22_FOLD_DST, COMMITMENT_DST, FR_BYTES};

/// Prove generates a Groth16+BSB22 proof.
///
/// # Arguments
/// * `pk` - Proving key from trusted setup.
/// * `r1cs_nb_public` - Number of public variables in the R1CS.
/// * `wire_values` - Full witness vector (all wires: constant, public, private).
/// * `commitment_info` - BSB22 commitment metadata.
/// * `committed_values` - For each commitment, the private values that were committed.
/// * `commitments` - Pedersen commitment points (computed during witness solving).
///
/// The caller is responsible for the BSB22 witness-splitting flow:
/// solving w1, computing Pedersen commitments, deriving challenges, then solving w2.
/// This function takes the completed witness and commitments.
/// `challenge_wire_indices` lists ALL wire indices holding challenge values.
/// These are excluded from private wires in the Krs computation (they're public).
#[instrument(skip_all)]
pub fn prove(
    pk: &ProvingKey,
    r1cs_nb_public: usize,
    wire_values: &[Fr],
    h: &[Fr],
    commitment_info: &[CommitmentInfo],
    committed_values: &[Vec<Fr>],
    commitments: &[G1Affine],
    challenge_wire_indices: &[usize],
) -> Result<Proof> {
    let mut rng = ark_std::rand::thread_rng();

    // --- BSB22: Proofs of Knowledge ---
    let commitment_pok = {
        let _s = info_span!("bsb22_pok").entered();
        let poks: Vec<G1Affine> = pk
            .commitment_keys
            .iter()
            .zip(committed_values.iter())
            .map(|(ck, vals)| ck.prove_knowledge(vals))
            .collect::<Result<Vec<_>>>()?;

        if !poks.is_empty() {
            let mut commitments_serialized =
                vec![0u8; FR_BYTES * challenge_wire_indices.len()];
            for (j, &wire_idx) in challenge_wire_indices.iter().enumerate() {
                let bytes = fr_to_bytes(&wire_values[wire_idx]);
                commitments_serialized[FR_BYTES * j..FR_BYTES * (j + 1)]
                    .copy_from_slice(&bytes);
            }

            let challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;
            pedersen::fold(&poks, challenge)?
        } else {
            G1Affine::zero()
        }
    };

    // --- Filter wire values for infinity points (parallel) ---
    let (wire_values_a, wire_values_b, private_wire_values) = {
        let _s = info_span!("filter_wires").entered();
        let (wa, wb) = rayon::join(
            || {
                wire_values
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !pk.infinity_a[*i])
                    .map(|(_, v)| *v)
                    .collect::<Vec<Fr>>()
            },
            || {
                wire_values
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !pk.infinity_b[*i])
                    .map(|(_, v)| *v)
                    .collect::<Vec<Fr>>()
            },
        );

        // Filter private wire values for Krs using sorted-index removal
        let private_wire_values: Vec<Fr> = {
            let mut to_remove: Vec<usize> = Vec::new();
            for ci in commitment_info {
                to_remove.extend_from_slice(&ci.private_committed);
            }
            to_remove.extend_from_slice(challenge_wire_indices);
            to_remove.sort_unstable();
            to_remove.dedup();

            filter_by_sorted_indices(&wire_values[r1cs_nb_public..], &to_remove, r1cs_nb_public)
        };

        (wa, wb, private_wire_values)
    };

    ensure!(
        private_wire_values.len() == pk.g1_k.len(),
        "private wire count mismatch: got {}, expected {}",
        private_wire_values.len(),
        pk.g1_k.len()
    );

    // --- Sample random r, s for zero-knowledge ---
    let r_scalar = Fr::rand(&mut rng);
    let s_scalar = Fr::rand(&mut rng);
    let kr_scalar = -(r_scalar * s_scalar);

    // Batch delta scalar multiplications
    let r_delta = (G1Projective::from(pk.g1_delta) * r_scalar).into_affine();
    let s_delta = (G1Projective::from(pk.g1_delta) * s_scalar).into_affine();
    let kr_delta = (G1Projective::from(pk.g1_delta) * kr_scalar).into_affine();

    // --- Compute Ar, Bs, Bs1 in parallel ---
    let (ar, bs, bs1) = {
        let _s = info_span!("msm_ar_bs").entered();
        let (ar_result, (bs_result, bs1_result)) = rayon::join(
            // Ar = Σ wᵢ·[Aᵢ(τ)]₁ + [α]₁ + r·[δ]₁
            || -> Result<G1Affine> {
                let msm = G1Projective::msm(&pk.g1_a, &wire_values_a).map_err(crate::msm_err)?;
                let mut result = msm;
                result += G1Projective::from(pk.g1_alpha);
                result += G1Projective::from(r_delta);
                Ok(result.into_affine())
            },
            || {
                rayon::join(
                    // Bs (G2) = Σ wᵢ·[Bᵢ(τ)]₂ + [β]₂ + s·[δ]₂
                    || -> Result<G2Affine> {
                        let msm = <G2Projective as VariableBaseMSM>::msm(&pk.g2_b, &wire_values_b)
                            .map_err(crate::msm_err)?;
                        let mut result = msm;
                        result += G2Projective::from(pk.g2_beta);
                        result += G2Projective::from(pk.g2_delta) * s_scalar;
                        Ok(result.into_affine())
                    },
                    // Bs1 (G1) = Σ wᵢ·[Bᵢ(τ)]₁ + [β]₁ + s·[δ]₁
                    || -> Result<G1Projective> {
                        let msm = G1Projective::msm(&pk.g1_b, &wire_values_b)
                            .map_err(crate::msm_err)?;
                        let mut result = msm;
                        result += G1Projective::from(pk.g1_beta);
                        result += G1Projective::from(s_delta);
                        Ok(result)
                    },
                )
            },
        );
        (ar_result?, bs_result?, bs1_result?)
    };

    // --- Compute Krs = Σ wᵢ·[Kᵢ(τ)]₁ + Σ hⱼ·[Zⱼ(τ)]₁ + s·Ar + r·Bs1 - rs·[δ]₁ ---
    let krs = {
        let _s = info_span!("msm_krs").entered();
        let size_h = pk.domain_size as usize - 1;

        let (krs1_result, krs2_result) = rayon::join(
            || G1Projective::msm(&pk.g1_k, &private_wire_values).map_err(crate::msm_err),
            || {
                if !h.is_empty() && !pk.g1_z.is_empty() {
                    let h_slice = &h[..size_h.min(h.len())];
                    let z_slice = &pk.g1_z[..size_h.min(pk.g1_z.len())];
                    let min_len = h_slice.len().min(z_slice.len());
                    G1Projective::msm(&z_slice[..min_len], &h_slice[..min_len])
                        .map_err(crate::msm_err)
                } else {
                    Ok(G1Projective::zero())
                }
            },
        );

        let mut result = krs1_result? + krs2_result?;
        result += G1Projective::from(kr_delta);

        // Cross-terms: s·Ar + r·Bs1
        let (s_ar, r_bs1) = rayon::join(
            || G1Projective::from(ar) * s_scalar,
            || bs1 * r_scalar,
        );
        result += s_ar;
        result += r_bs1;

        result.into_affine()
    };

    Ok(Proof {
        ar,
        bs,
        krs,
        commitments: commitments.to_vec(),
        commitment_pok,
    })
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
#[instrument(skip_all)]
pub fn compute_h(
    a_evals: &mut Vec<Fr>,
    b_evals: &mut Vec<Fr>,
    c_evals: &mut Vec<Fr>,
    domain: &Radix2EvaluationDomain<Fr>,
) -> Vec<Fr> {
    let n = domain.size();

    // Pad to domain size
    a_evals.resize(n, Fr::zero());
    b_evals.resize(n, Fr::zero());
    c_evals.resize(n, Fr::zero());

    // IFFT → coset FFT for each buffer. The three pipelines are independent
    // (separate buffers, immutable domain refs), so run them in parallel.
    let coset_domain = domain.get_coset(Fr::GENERATOR)
        .expect("coset domain");
    rayon::join(
        || {
            domain.ifft_in_place(a_evals);
            coset_domain.fft_in_place(a_evals);
        },
        || rayon::join(
            || {
                domain.ifft_in_place(b_evals);
                coset_domain.fft_in_place(b_evals);
            },
            || {
                domain.ifft_in_place(c_evals);
                coset_domain.fft_in_place(c_evals);
            },
        ),
    );

    // Pointwise: a[i] = (a[i] * b[i] - c[i]) / Z(coset), computed in parallel.
    // Reuses a_evals in-place to avoid an extra domain-sized allocation.
    // Z(g·ωⁱ) = (g·ωⁱ)^N - 1 = g^N - 1 (constant on coset)
    let z_inv = {
        let gen_n = Fr::GENERATOR.pow([n as u64]);
        (gen_n - Fr::one()).inverse().expect("Z(coset) nonzero")
    };

    a_evals
        .par_iter_mut()
        .zip(b_evals.par_iter())
        .zip(c_evals.par_iter())
        .for_each(|((a, b), c)| {
            *a = (*a * b - c) * z_inv;
        });

    // IFFT on coset: evaluation on coset → coefficient form
    coset_domain.ifft_in_place(a_evals);

    // Return the reused buffer (now contains H coefficients)
    std::mem::take(a_evals)
}

/// Convert a field element to big-endian bytes.
pub fn fr_to_bytes(val: &Fr) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = vec![0u8; FR_BYTES];
    val.serialize_compressed(&mut bytes[..]).unwrap_or_default();
    bytes
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
    let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
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
/// Matches gnark's commitment hashing with `hash_to_field.New("bsb22-commitment")`.
pub fn derive_commitment_challenge(
    commitment: &G1Affine,
    public_values: &[Fr],
) -> Result<Fr> {
    use ark_serialize::CanonicalSerialize;

    let mut data = Vec::new();

    // Serialize commitment point
    let mut commitment_bytes = Vec::new();
    commitment.serialize_uncompressed(&mut commitment_bytes)?;
    data.extend_from_slice(&commitment_bytes);

    // Serialize public values
    for val in public_values {
        let bytes = fr_to_bytes(val);
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
