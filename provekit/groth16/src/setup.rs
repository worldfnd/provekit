/// Groth16 trusted setup: generates ProvingKey and VerifyingKey from R1CS.
///
/// Ported from gnark's `backend/groth16/bn254/setup.go`.
/// Notation follows DIZK paper Figure 4.
use anyhow::{ensure, Result};
use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::rand::Rng;

use provekit_common::R1CS;

use crate::{pedersen, CommitmentInfo};

/// Toxic waste: secret random values used during setup and then destroyed.
struct ToxicWaste {
    t: Fr,
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    delta: Fr,
    gamma_inv: Fr,
    delta_inv: Fr,
}

impl ToxicWaste {
    fn sample<R: Rng>(rng: &mut R) -> Result<Self> {
        let mut sample_nonzero = |rng: &mut R| -> Fr {
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
            gamma_inv: gamma.inverse().expect("gamma nonzero"),
            delta_inv: delta.inverse().expect("delta nonzero"),
        })
    }
}

/// Run the Groth16 trusted setup.
///
/// Generates a ProvingKey and VerifyingKey from the given R1CS.
/// The toxic waste is sampled internally and dropped at the end of this function.
///
/// For production use, this should be replaced by an MPC ceremony.
pub fn setup(
    r1cs: &R1CS,
    commitment_info: &[CommitmentInfo],
) -> Result<(crate::ProvingKey, crate::VerifyingKey)> {
    let mut rng = ark_std::test_rng();
    let toxic = ToxicWaste::sample(&mut rng)?;

    let nb_wires = r1cs.num_witnesses();
    // nb_public_variables includes constant-1 wire
    let nb_public_variables = 1 + r1cs.num_public_inputs;
    let commitment_wires: Vec<usize> = commitment_info.iter().map(|c| c.commitment_index).collect();
    let private_committed: Vec<Vec<usize>> = commitment_info.iter().map(|c| c.private_committed.clone()).collect();
    let nb_private_committed: usize = private_committed.iter().map(|v| v.len()).sum();

    // Commitments are treated as public wires on the Groth16 level.
    let nb_public = nb_public_variables + commitment_info.len();
    let nb_private = nb_wires - nb_public_variables
        - nb_private_committed
        - commitment_info.len();

    // FFT domain
    let domain = Radix2EvaluationDomain::<Fr>::new(r1cs.num_constraints())
        .ok_or_else(|| anyhow::anyhow!("failed to create FFT domain"))?;
    let domain_size = domain.size() as u64;

    // Evaluate A, B, C at the toxic waste point t using Lagrange basis.
    let (a_at_t, b_at_t, c_at_t) = evaluate_abc_at_t(r1cs, &domain, &toxic)?;

    // Compute K values: K(i) = (β·A(i) + α·B(i) + C(i)) / γ or / δ
    let mut pk_k = Vec::with_capacity(nb_private); // private wires → divided by δ
    let mut vk_k = Vec::with_capacity(nb_public); // public wires → divided by γ
    let mut ck_k: Vec<Vec<Fr>> = commitment_info.iter().map(|c| Vec::with_capacity(c.private_committed.len())).collect();

    // Track which wires are committed (using a merged iterator approach)
    let mut committed_map: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for (ci, info) in commitment_info.iter().enumerate() {
        for &wire_id in &info.private_committed {
            committed_map.insert(wire_id, ci);
        }
    }

    let mut commitment_wire_set: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for &w in &commitment_wires {
        commitment_wire_set.insert(w);
    }

    let mut vi = 0usize; // public wires seen
    let mut nb_committed_seen = 0usize;

    for i in 0..nb_wires {
        let is_public = i < nb_public_variables;
        let is_commitment = commitment_wire_set.contains(&i);

        // K(i) = β·A(i) + α·B(i) + C(i)
        let k_val = toxic.beta * a_at_t[i] + toxic.alpha * b_at_t[i] + c_at_t[i];

        if is_public || is_commitment {
            // Public/commitment wire → divide by γ
            vk_k.push(k_val * toxic.gamma_inv);
            vi += 1;
            if is_commitment {
                nb_committed_seen += 1;
            }
        } else if let Some(&ci) = committed_map.get(&i) {
            // Private committed wire → goes to commitment bases, divide by γ
            ck_k[ci].push(k_val * toxic.gamma_inv);
            nb_committed_seen += 1;
        } else {
            // Private non-committed wire → divide by δ
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

    // Batch scalar multiplication for G1 points
    let g1_gen = G1Affine::generator();

    // Compute all G1 points via individual scalar multiplications
    // (In production, use batch scalar multiplication for performance)
    let g1_alpha = scalar_mul_g1(&g1_gen, &toxic.alpha);
    let g1_beta = scalar_mul_g1(&g1_gen, &toxic.beta);
    let g1_delta = scalar_mul_g1(&g1_gen, &toxic.delta);

    let g1_a: Vec<G1Affine> = a_scalars_filtered
        .iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();

    let g1_b: Vec<G1Affine> = b_scalars_filtered
        .iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();

    let mut g1_z: Vec<G1Affine> = z_scalars
        .iter()
        .map(|s| scalar_mul_g1(&g1_gen, s))
        .collect();
    // Bit-reverse permutation
    bit_reverse_permutation(&mut g1_z);
    // deg(H) = (n-1)+(n-1)-n = n-2, so we need n-1 Z points
    let size_z = domain_size as usize - 1;
    g1_z.truncate(size_z);

    let g1_vk_k: Vec<G1Affine> = vk_k.iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect();
    let g1_pk_k: Vec<G1Affine> = pk_k.iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect();

    // Commitment bases in G1
    let g1_ck_k: Vec<Vec<G1Affine>> = ck_k
        .iter()
        .map(|ck| ck.iter().map(|s| scalar_mul_g1(&g1_gen, s)).collect())
        .collect();

    // G2 points
    let g2_gen = G2Affine::generator();
    let g2_beta = scalar_mul_g2(&g2_gen, &toxic.beta);
    let g2_delta = scalar_mul_g2(&g2_gen, &toxic.delta);
    let g2_gamma = scalar_mul_g2(&g2_gen, &toxic.gamma);

    let g2_b: Vec<G2Affine> = b_scalars_filtered
        .iter()
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
        pk_commitment_keys.push(pks.into_iter().next().unwrap());
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

    // toxic waste is dropped here — in production this is the MPC ceremony's job
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
    let n_inv = Fr::from(domain.size() as u64).inverse().expect("n nonzero");
    let mut lagrange = (t_n - Fr::one()) * t_minus_wi_inv[0] * n_inv;

    // Accumulate: for each constraint row, add coeff * Lⱼ(τ) to the appropriate wire.
    // Iterates directly over SparseMatrix rows instead of gnark's Term lists.
    for j in 0..n {
        for (col, interned) in r1cs.a.iter_row(j) {
            let coeff = r1cs.interner.get(interned).expect("interned value missing");
            a[col] += coeff * lagrange;
        }
        for (col, interned) in r1cs.b.iter_row(j) {
            let coeff = r1cs.interner.get(interned).expect("interned value missing");
            b[col] += coeff * lagrange;
        }
        for (col, interned) in r1cs.c.iter_row(j) {
            let coeff = r1cs.interner.get(interned).expect("interned value missing");
            c[col] += coeff * lagrange;
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

/// Bit-reverse permutation on a slice (same as FFT bit-reversal).
fn bit_reverse_permutation<T: Copy>(a: &mut [T]) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    let log_n = (n as f64).log2() as u32;
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - log_n);
        if (j as usize) > i {
            a.swap(i, j as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provekit_common::FieldElement;

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

        let (pk, vk) = setup(&r1cs, &[]).unwrap();
        assert!(!pk.g1_a.is_empty());
        assert!(!vk.g1_k.is_empty());
    }
}
