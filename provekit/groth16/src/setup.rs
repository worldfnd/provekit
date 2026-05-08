/// Groth16 trusted setup: generates ProvingKey and VerifyingKey from R1CS.
///
/// Ported from gnark's `backend/groth16/bn254/setup.go`.
/// Notation follows DIZK paper Figure 4.
use anyhow::Result;
use {
    crate::{pedersen, CommitmentInfo},
    ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{Field, One, UniformRand, Zero},
    ark_poly::{EvaluationDomain, Radix2EvaluationDomain},
    ark_std::rand::Rng,
    provekit_common::R1CS,
    rayon::prelude::*,
};

/// Toxic waste: secret random values used during setup and then destroyed.
///
/// `ZeroizeOnDrop` wipes every secret field when the value goes out of scope,
/// so the trusted-setup secrets can't be recovered from freed memory.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ToxicWaste {
    t:         Fr,
    alpha:     Fr,
    beta:      Fr,
    gamma:     Fr,
    delta:     Fr,
    gamma_inv: Fr,
    delta_inv: Fr,
}

impl ToxicWaste {
    fn sample<R: Rng>(rng: &mut R) -> Result<Self> {
        let sample_nonzero = |rng: &mut R| -> Fr {
            loop {
                let v = Fr::rand(rng);
                if !v.is_zero() {
                    return v;
                }
            }
        };

        let t = sample_nonzero(rng);
        let alpha = sample_nonzero(rng);
        let beta = sample_nonzero(rng);
        let gamma = sample_nonzero(rng);
        let delta = sample_nonzero(rng);

        Ok(ToxicWaste {
            t,
            alpha,
            beta,
            gamma,
            delta,
            gamma_inv: gamma
                .inverse()
                .ok_or_else(|| anyhow::anyhow!("gamma is zero, cannot invert"))?,
            delta_inv: delta
                .inverse()
                .ok_or_else(|| anyhow::anyhow!("delta is zero, cannot invert"))?,
        })
    }
}

/// Run the Groth16 trusted setup.
///
/// Generates a ProvingKey and VerifyingKey from the given R1CS.
/// The toxic waste is sampled internally and dropped at the end of this
/// function. For production use, this should be replaced by an MPC ceremony.
///
/// `challenge_wire_indices` lists ALL wire indices that hold challenge values
/// (treated as public).
///
/// CONTRACT: `challenge_wire_indices` must be flattened across commitments
/// in the same order as `commitment_info`/`num_challenges_per_commitment`,
/// i.e. `[commit0_wire0, commit0_wire1, ..., commit1_wire0, ...]`. Within
/// each commitment, the order must match the order the verifier inserts
/// derived challenges into `extended_public` (the `hash_to_fr_multi` output
/// order for multi-challenge commitments). Violating this contract causes
/// `vk.g1_k` to be paired with the wrong public-input scalars at verify
/// time, producing a silent miscompute for multi-commitment circuits.
pub fn setup(
    r1cs: &R1CS,
    commitment_info: &[CommitmentInfo],
    num_challenges_per_commitment: &[usize],
    challenge_wire_indices: &[usize],
) -> Result<(crate::ProvingKey, crate::VerifyingKey)> {
    let mut rng = ark_std::rand::thread_rng();
    let toxic = ToxicWaste::sample(&mut rng)?;

    let nb_wires = r1cs.num_witnesses();
    // nb_public_variables includes constant-1 wire
    let nb_public_variables = 1 + r1cs.num_public_inputs;
    let private_committed: Vec<Vec<usize>> = commitment_info
        .iter()
        .map(|c| c.private_committed.clone())
        .collect();
    let nb_private_committed: usize = private_committed.iter().map(|v| v.len()).sum();
    let total_challenge_wires = challenge_wire_indices.len();

    // All challenge wire indices are treated as public on the Groth16 level.
    let nb_public = nb_public_variables + total_challenge_wires;
    let nb_private = nb_wires - nb_public_variables - nb_private_committed - total_challenge_wires;

    // FFT domain
    let domain = Radix2EvaluationDomain::<Fr>::new(r1cs.num_constraints())
        .ok_or_else(|| anyhow::anyhow!("failed to create FFT domain"))?;
    let domain_size = domain.size() as u64;

    // Evaluate A, B, C at the toxic waste point t using Lagrange basis.
    let (a_at_t, b_at_t, c_at_t) = evaluate_abc_at_t(r1cs, &domain, &toxic)?;

    // Compute K values: K(i) = (β·A(i) + α·B(i) + C(i)) / γ or / δ
    let mut pk_k = Vec::with_capacity(nb_private); // private wires → divided by δ
    let mut vk_k = Vec::with_capacity(nb_public); // public wires → divided by γ
    let mut ck_k: Vec<Vec<Fr>> = commitment_info
        .iter()
        .map(|c| Vec::with_capacity(c.private_committed.len()))
        .collect();

    // Track which wires are committed (using a merged iterator approach)
    let mut committed_map: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    for (ci, info) in commitment_info.iter().enumerate() {
        for &wire_id in &info.private_committed {
            committed_map.insert(wire_id, ci);
        }
    }

    let commitment_wire_set: std::collections::HashSet<usize> =
        challenge_wire_indices.iter().copied().collect();

    let k_at = |i: usize| -> Fr {
        // K(i) = β·A(i) + α·B(i) + C(i)
        toxic.beta * a_at_t[i] + toxic.alpha * b_at_t[i] + c_at_t[i]
    };

    // Pass 1: public wires (constant + Noir public inputs), in wire-index
    // order. `vk.g1_k[0]` corresponds to the constant-1 wire and is paired
    // with the implicit `1` term in the verifier; `vk.g1_k[1..1+num_public]`
    // is paired with `public_witness` in the same order Noir emits public
    // inputs.
    for i in 0..nb_public_variables {
        vk_k.push(k_at(i) * toxic.gamma_inv);
    }

    // Pass 2: challenge wires in commitment-iteration order. The verifier
    // appends derived challenges to `extended_public` in this same order
    // (`for (i, _) in vk.public_and_commitment_committed.iter().enumerate()`
    // → `extended_public.extend_from_slice(&challenges)`), so the bases
    // emitted here line up with the scalars the verifier produces.
    for &wire_idx in challenge_wire_indices {
        vk_k.push(k_at(wire_idx) * toxic.gamma_inv);
    }

    // Pass 3: private wires. Each goes either to a commitment bucket (if
    // it's in `private_committed` for some commitment) or to `pk_k`.
    // Challenge wires that landed in the private range are skipped — they
    // were already pushed to `vk_k` in pass 2.
    for i in nb_public_variables..nb_wires {
        if commitment_wire_set.contains(&i) {
            continue;
        }
        let k_val = k_at(i);
        if let Some(&ci) = committed_map.get(&i) {
            ck_k[ci].push(k_val * toxic.gamma_inv);
        } else {
            pk_k.push(k_val * toxic.delta_inv);
        }
    }

    // Z(τ) scalars: Z(t)/δ · t^i for i in 0..domain_size
    let z_at_t: Fr = {
        let t_n = toxic.t.pow([domain_size]);
        (t_n - Fr::one()) * toxic.delta_inv
    };
    let mut z_scalars = Vec::with_capacity(domain_size as usize);
    let mut z_cur = z_at_t;
    for _ in 0..domain_size {
        z_scalars.push(z_cur);
        z_cur *= toxic.t;
    }

    // Mark infinity points (where A(τ) or B(τ) is zero)
    let mut infinity_a = vec![false; nb_wires];
    let mut infinity_b = vec![false; nb_wires];
    let mut a_scalars_filtered = Vec::new();
    let mut b_scalars_filtered = Vec::new();

    for i in 0..nb_wires {
        if a_at_t[i] == Fr::zero() {
            infinity_a[i] = true;
        } else {
            a_scalars_filtered.push(a_at_t[i]);
        }
        if b_at_t[i] == Fr::zero() {
            infinity_b[i] = true;
        } else {
            b_scalars_filtered.push(b_at_t[i]);
        }
    }

    let nb_infinity_a = infinity_a.iter().filter(|&&x| x).count() as u64;
    let nb_infinity_b = infinity_b.iter().filter(|&&x| x).count() as u64;

    // Scalar multiplication for G1 points — parallelized via rayon
    let g1_gen = G1Affine::generator();

    let g1_alpha = scalar_mul_g1(&g1_gen, &toxic.alpha);
    let g1_beta = scalar_mul_g1(&g1_gen, &toxic.beta);
    let g1_delta = scalar_mul_g1(&g1_gen, &toxic.delta);

    let g1_a: Vec<G1Affine> = a_scalars_filtered
        .par_iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();

    let g1_b: Vec<G1Affine> = b_scalars_filtered
        .par_iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();

    let mut g1_z: Vec<G1Affine> = z_scalars
        .par_iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();
    // No bit-reverse permutation: arkworks' IFFT outputs H in natural order,
    // so Z points must also be in natural order for the MSM Σ h[i]·Z[i].
    // deg(H) = (n-1)+(n-1)-n = n-2, so we need n-1 Z points
    let size_z = domain_size as usize - 1;
    g1_z.truncate(size_z);

    let g1_vk_k: Vec<G1Affine> = vk_k.par_iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect();
    let g1_pk_k: Vec<G1Affine> = pk_k.par_iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect();

    // Commitment bases in G1
    let g1_ck_k: Vec<Vec<G1Affine>> = ck_k
        .iter()
        .map(|ck| ck.par_iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect())
        .collect();

    // Scalar multiplication for G2 points — parallelized via rayon
    let g2_gen = G2Affine::generator();
    let g2_beta = scalar_mul_g2(&g2_gen, &toxic.beta);
    let g2_delta = scalar_mul_g2(&g2_gen, &toxic.delta);
    let g2_gamma = scalar_mul_g2(&g2_gen, &toxic.gamma);

    let g2_b: Vec<G2Affine> = b_scalars_filtered
        .par_iter()
        .map(|s| scalar_mul_g2(&g2_gen, s))
        .collect();

    // Pedersen commitment setup
    let g2_random = G2Projective::rand(&mut rng).into_affine();
    let mut pk_commitment_keys = Vec::new();
    let mut vk_commitment_keys = Vec::new();

    for ck_bases in &g1_ck_k {
        if ck_bases.is_empty() {
            continue;
        }
        let (pks, vk) = pedersen::setup(&[ck_bases], Some(g2_random))?;
        let pk = pks
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("pedersen::setup returned empty proving key vector"))?;
        pk_commitment_keys.push(pk);
        vk_commitment_keys.push(vk);
    }

    // Public and commitment committed indices for verification
    let public_and_commitment_committed: Vec<Vec<usize>> = commitment_info
        .iter()
        .map(|c| c.public_and_commitment_committed.clone())
        .collect();

    // Build VerifyingKey
    let mut vk = crate::VerifyingKey {
        g1_alpha,
        g1_k: g1_vk_k,
        g2_beta,
        g2_delta,
        g2_gamma,
        g2_delta_neg: G2Affine::zero(), // will be set by precompute
        g2_gamma_neg: G2Affine::zero(),
        e_alpha_beta: ark_ff::AdditiveGroup::ZERO,
        commitment_keys: vk_commitment_keys,
        public_and_commitment_committed,
        num_challenges_per_commitment: num_challenges_per_commitment.to_vec(),
    };
    vk.precompute()?;

    // Build ProvingKey
    let pk = crate::ProvingKey {
        domain_size,
        domain_gen: Fr::from(domain.group_gen()),
        g1_alpha,
        g1_beta,
        g1_delta,
        g1_a,
        g1_b,
        g1_k: g1_pk_k,
        g1_z,
        g2_beta,
        g2_delta,
        g2_b,
        infinity_a,
        infinity_b,
        nb_infinity_a,
        nb_infinity_b,
        commitment_keys: pk_commitment_keys,
    };

    // toxic waste is dropped here — in production this is the MPC ceremony's job.
    // `ToxicWaste` is `ZeroizeOnDrop`, so the secret field elements are wiped
    // from memory when this drop runs.
    drop(toxic);

    Ok((pk, vk))
}

/// Evaluate A(τ), B(τ), C(τ) for each wire using Lagrange interpolation at τ.
///
/// Ported from gnark's `setupABC()`.
fn evaluate_abc_at_t(
    r1cs: &R1CS,
    domain: &Radix2EvaluationDomain<Fr>,
    toxic: &ToxicWaste,
) -> Result<(Vec<Fr>, Vec<Fr>, Vec<Fr>)> {
    let nb_wires = r1cs.num_witnesses();
    let mut a = vec![Fr::zero(); nb_wires];
    let mut b = vec![Fr::zero(); nb_wires];
    let mut c = vec![Fr::zero(); nb_wires];

    let w = domain.group_gen();
    let n = r1cs.num_constraints();

    // Precompute [τ - ω^i] and their inverses
    let mut t_minus_wi = Vec::with_capacity(n + 1);
    let mut wi = Fr::one();
    for _ in 0..=n {
        t_minus_wi.push(toxic.t - wi);
        wi *= w;
    }
    let t_minus_wi_inv = {
        let mut inv = t_minus_wi.clone();
        ark_ff::batch_inversion(&mut inv);
        inv
    };

    // L₀(τ) = (τⁿ - 1) / (n · (τ - ω⁰))
    let t_n = toxic.t.pow([domain.size() as u64]);
    let n_inv = Fr::from(domain.size() as u64)
        .inverse()
        .ok_or_else(|| anyhow::anyhow!("FFT domain size is zero, cannot invert"))?;
    let mut lagrange = (t_n - Fr::one()) * t_minus_wi_inv[0] * n_inv;

    // Accumulate: for each constraint row, add coeff * Lⱼ(τ) to the appropriate
    // wire. Iterates directly over SparseMatrix rows instead of gnark's Term
    // lists.
    let lookup_coeff = |interned| {
        r1cs.interner
            .get(interned)
            .ok_or_else(|| anyhow::anyhow!("R1CS interner missing value for matrix entry"))
    };
    for j in 0..n {
        for (col, interned) in r1cs.a.iter_row(j) {
            a[col] += lookup_coeff(interned)? * lagrange;
        }
        for (col, interned) in r1cs.b.iter_row(j) {
            b[col] += lookup_coeff(interned)? * lagrange;
        }
        for (col, interned) in r1cs.c.iter_row(j) {
            c[col] += lookup_coeff(interned)? * lagrange;
        }

        // Lⱼ₊₁(τ) = ω · Lⱼ(τ) · (τ - ω^j) / (τ - ω^(j+1))
        if j + 1 < n {
            lagrange *= w;
            lagrange *= t_minus_wi[j];
            lagrange *= t_minus_wi_inv[j + 1];
        }
    }

    Ok((a, b, c))
}

/// Scalar multiplication in G1.
fn scalar_mul_g1(base: &G1Affine, scalar: &Fr) -> G1Affine {
    (G1Projective::from(*base) * scalar).into_affine()
}

/// Scalar multiplication in G2.
fn scalar_mul_g2(base: &G2Affine, scalar: &Fr) -> G2Affine {
    (G2Projective::from(*base) * scalar).into_affine()
}

#[cfg(test)]
mod tests {
    use {super::*, provekit_common::FieldElement};

    /// Simple test: setup with a trivial R1CS should not panic.
    #[test]
    fn test_setup_trivial() {
        // x * x = y (where wire 0=constant, wire 1=public output y, wire 2=secret x)
        let mut r1cs = R1CS::new();
        r1cs.num_public_inputs = 1; // one public input (y), excludes constant wire
        r1cs.add_witnesses(3); // wire 0 (const), wire 1 (y), wire 2 (x)

        let one = FieldElement::from(1u64);
        // A: x (wire 2), B: x (wire 2), C: y (wire 1)
        r1cs.add_constraint(
            &[(one, 2)], // A: 1·x
            &[(one, 2)], // B: 1·x
            &[(one, 1)], // C: 1·y
        );

        let (pk, vk) = setup(&r1cs, &[], &[], &[]).unwrap();
        assert!(!pk.g1_a.is_empty());
        assert!(!vk.g1_k.is_empty());
    }
}
