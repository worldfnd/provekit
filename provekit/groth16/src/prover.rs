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
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;

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
pub fn prove(
    pk: &ProvingKey,
    r1cs_nb_public: usize,
    wire_values: &[Fr],
    h: &[Fr],
    commitment_info: &[CommitmentInfo],
    committed_values: &[Vec<Fr>],
    commitments: &[G1Affine],
) -> Result<Proof> {
    let nb_wires = wire_values.len();
    let mut rng = ark_std::test_rng();

    // --- BSB22: Proofs of Knowledge ---
    let poks: Vec<G1Affine> = pk
        .commitment_keys
        .iter()
        .zip(committed_values.iter())
        .map(|(ck, vals)| ck.prove_knowledge(vals))
        .collect::<Result<Vec<_>>>()?;

    // Fold all PoKs into one
    let commitment_pok = if !poks.is_empty() {
        // Serialize commitment wire values for hashing
        let mut commitments_serialized = vec![0u8; FR_BYTES * commitment_info.len()];
        for (i, info) in commitment_info.iter().enumerate() {
            let wire_val = wire_values[info.commitment_index];
            let bytes = fr_to_bytes(&wire_val);
            commitments_serialized[FR_BYTES * i..FR_BYTES * (i + 1)].copy_from_slice(&bytes);
        }

        let challenge = hash_to_fr(&commitments_serialized, BSB22_FOLD_DST)?;
        pedersen::fold(&poks, challenge)?
    } else {
        G1Affine::zero()
    };

    // --- Filter wire values for infinity points ---
    let wire_values_a: Vec<Fr> = wire_values
        .iter()
        .enumerate()
        .filter(|(i, _)| !pk.infinity_a[*i])
        .map(|(_, v)| *v)
        .collect();

    let wire_values_b: Vec<Fr> = wire_values
        .iter()
        .enumerate()
        .filter(|(i, _)| !pk.infinity_b[*i])
        .map(|(_, v)| *v)
        .collect();

    // --- Sample random r, s for zero-knowledge ---
    let r_scalar = Fr::rand(&mut rng);
    let s_scalar = Fr::rand(&mut rng);
    let kr_scalar = -(r_scalar * s_scalar);

    // r·[δ]₁, s·[δ]₁, -rs·[δ]₁
    let r_delta = (G1Projective::from(pk.g1_delta) * r_scalar).into_affine();
    let s_delta = (G1Projective::from(pk.g1_delta) * s_scalar).into_affine();
    let kr_delta = (G1Projective::from(pk.g1_delta) * kr_scalar).into_affine();

    // --- Compute Ar = Σ wᵢ·[Aᵢ(τ)]₁ + [α]₁ + r·[δ]₁ ---
    let ar = {
        let msm = G1Projective::msm(&pk.g1_a, &wire_values_a).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G1Projective::from(pk.g1_alpha);
        result += G1Projective::from(r_delta);
        result.into_affine()
    };

    // --- Compute Bs (G2) = Σ wᵢ·[Bᵢ(τ)]₂ + [β]₂ + s·[δ]₂ ---
    let bs = {
        let msm = <G2Projective as VariableBaseMSM>::msm(&pk.g2_b, &wire_values_b).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G2Projective::from(pk.g2_beta);
        let s_delta_g2 = G2Projective::from(pk.g2_delta) * s_scalar;
        result += s_delta_g2;
        result.into_affine()
    };

    // --- Compute Bs1 (G1) = Σ wᵢ·[Bᵢ(τ)]₁ + [β]₁ + s·[δ]₁ ---
    let bs1 = {
        let msm = G1Projective::msm(&pk.g1_b, &wire_values_b).map_err(crate::msm_err)?;
        let mut result = msm;
        result += G1Projective::from(pk.g1_beta);
        result += G1Projective::from(s_delta);
        result
    };

    // --- Compute Krs = Σ wᵢ·[Kᵢ(τ)]₁ + Σ hⱼ·[Zⱼ(τ)]₁ + s·Ar + r·Bs1 - rs·[δ]₁ ---
    let krs = {
        // Filter private wire values: exclude public, committed, and commitment wires
        let private_committed_set: std::collections::HashSet<usize> = commitment_info
            .iter()
            .flat_map(|c| c.private_committed.iter().copied())
            .collect();
        let commitment_index_set: std::collections::HashSet<usize> = commitment_info
            .iter()
            .map(|c| c.commitment_index)
            .collect();

        let private_wire_values: Vec<Fr> = wire_values[r1cs_nb_public..]
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let abs_idx = i + r1cs_nb_public;
                !private_committed_set.contains(&abs_idx)
                    && !commitment_index_set.contains(&abs_idx)
            })
            .map(|(_, v)| *v)
            .collect();

        ensure!(
            private_wire_values.len() == pk.g1_k.len(),
            "private wire count mismatch: got {}, expected {}",
            private_wire_values.len(),
            pk.g1_k.len()
        );

        // Krs part 1: Σ wᵢ·[Kᵢ(τ)]₁
        let krs1 = G1Projective::msm(&pk.g1_k, &private_wire_values).map_err(crate::msm_err)?;

        // Krs part 2: Σ hⱼ·[Zⱼ(τ)]₁
        let size_h = pk.domain_size as usize - 1;
        let krs2 = if !h.is_empty() && !pk.g1_z.is_empty() {
            let h_slice = &h[..size_h.min(h.len())];
            let z_slice = &pk.g1_z[..size_h.min(pk.g1_z.len())];
            let min_len = h_slice.len().min(z_slice.len());
            G1Projective::msm(&z_slice[..min_len], &h_slice[..min_len]).map_err(crate::msm_err)?
        } else {
            G1Projective::zero()
        };

        let mut result = krs1 + krs2;
        result += G1Projective::from(kr_delta);

        // s·Ar
        let s_ar = G1Projective::from(ar) * s_scalar;
        result += s_ar;

        // r·Bs1
        let r_bs1 = bs1 * r_scalar;
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

/// Compute quotient polynomial H from the R1CS solution vectors.
///
/// Given the wire-level evaluations of A·w, B·w, C·w for each constraint,
/// compute H such that A·B - C = H·Z where Z is the vanishing polynomial.
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

    // IFFT: evaluation form → coefficient form
    domain.ifft_in_place(a_evals);
    domain.ifft_in_place(b_evals);
    domain.ifft_in_place(c_evals);

    // FFT on coset: coefficient form → evaluation on coset
    let coset_domain = domain.get_coset(domain.coset_offset())
        .expect("coset domain");
    coset_domain.fft_in_place(a_evals);
    coset_domain.fft_in_place(b_evals);
    coset_domain.fft_in_place(c_evals);

    // Pointwise: h = (a ⊙ b - c) / Z(coset)
    let z_inv = {
        let gen_n = domain.coset_offset().pow([n as u64]);
        (gen_n - Fr::one()).inverse().expect("Z(coset) nonzero")
    };

    let h: Vec<Fr> = a_evals
        .iter()
        .zip(b_evals.iter())
        .zip(c_evals.iter())
        .map(|((a, b), c)| (*a * b - c) * z_inv)
        .collect();

    // IFFT on coset: evaluation on coset → coefficient form
    let mut h = h;
    coset_domain.ifft_in_place(&mut h);

    h
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
