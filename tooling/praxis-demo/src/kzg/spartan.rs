//! 2-round Spartan + HyperKZG prover & verifier directly over ProveKit's
//! `R1CS<Fr>` and `WitnessBuilder::split_and_prepare_layers`.
//!
//! Handles **both** challenge-free circuits (`praxis-satoshi`) and multi-round
//! interactive circuits with LogUp / Spice / spread challenges (`t_attest`,
//! `t_add_*`, `complete_age_check`) using:
//! - Universal BN254 Powers-of-Tau SRS (zero per-circuit setup, zero Groth16,
//!   zero gnark)
//! - ProveKit's own `WitnessBuilder::split_and_prepare_layers` +
//!   `solve_witness_vec`
//! - ProveKit's own `spongefish` transcript (`HashConfig::Skyscraper`)
//! - **Exactly 2 BN254 pairings** in the final verifier check (even in dual
//!   `w1`/`w2` mode!)

use {
    crate::kzg::{
        hyperkzg::{
            self, absorb_fr_prover, absorb_fr_verifier, absorb_g1_prover, absorb_g1_verifier,
            HyperKzgOpening,
        },
        univariate::{self, KzgSrs},
    },
    acir::AcirField,
    anyhow::{ensure, Context, Result},
    ark_bn254::{Fr, G1Affine},
    ark_ff::{Field, One, PrimeField, Zero},
    ark_serialize::CanonicalSerialize,
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    nargo::foreign_calls::DefaultForeignCallBuilder,
    noirc_abi::InputMap,
    noirc_artifacts::program::ProgramArtifact,
    provekit_backend_bn254::{
        solve_witness_vec,
        witness::{SplitWitnessBuilders, WitnessBuilder},
        TranscriptSponge,
    },
    provekit_common::{
        utils::sumcheck::{
            calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq,
            sumcheck_fold_map_reduce,
        },
        HashConfig, R1CS,
    },
    provekit_r1cs_compiler::{noir_to_r1cs, optimize_r1cs},
    rayon::prelude::*,
    std::{
        collections::HashSet,
        time::{Duration, Instant},
    },
    whir::transcript::{DomainSeparator, ProverState, VerifierMessage, VerifierState},
};

/// Compiled ProveKit circuit prepared for 2-round Spartan + HyperKZG proving.
pub struct SpartanKzgCircuit {
    pub program:           ProgramArtifact,
    pub r1cs:              R1CS<Fr>,
    pub split_builders:    SplitWitnessBuilders,
    pub challenge_offsets: Vec<usize>,
    pub m_0:               usize,
    pub m_w1:              usize,
    pub m_w2:              usize,
}

impl SpartanKzgCircuit {
    /// Lower a compiled Noir `ProgramArtifact` through ProveKit's R1CS
    /// compiler, Gaussian-elimination optimizer, and 2-layer witness splitter.
    pub fn prepare(program: ProgramArtifact) -> Result<Self> {
        ensure!(
            program.bytecode.functions.len() == 1,
            "expected single Noir entry point"
        );
        let main_fn = &program.bytecode.functions[0];
        let (mut r1cs, mut witness_map, mut witness_builders) = noir_to_r1cs(main_fn)?;

        let pub_set: HashSet<u32> = main_fn.public_inputs().indices().iter().copied().collect();
        r1cs.num_public_inputs = pub_set.len();

        optimize_r1cs(&mut r1cs, &mut witness_builders, &mut witness_map, &pub_set)?;

        let (split_builders, remapped_r1cs, _remapped_wmap, challenge_offsets) =
            WitnessBuilder::split_and_prepare_layers(
                &witness_builders,
                r1cs,
                witness_map,
                pub_set,
            )?;

        let m_0 = remapped_r1cs
            .num_constraints()
            .max(2)
            .next_power_of_two()
            .ilog2() as usize;
        let m_w1 = split_builders
            .w1_size
            .max(2)
            .next_power_of_two()
            .ilog2() as usize;
        let w2_len = remapped_r1cs
            .num_witnesses()
            .saturating_sub(split_builders.w1_size);
        let m_w2 = if challenge_offsets.is_empty() {
            0
        } else {
            w2_len.max(2).next_power_of_two().ilog2() as usize
        };

        Ok(Self {
            program,
            r1cs: remapped_r1cs,
            split_builders,
            challenge_offsets,
            m_0,
            m_w1,
            m_w2,
        })
    }

    /// Minimum universal KZG SRS size (`max(2^{m_w1}, 2^{m_w2})`) needed for
    /// this circuit.
    #[must_use]
    pub fn required_srs_len(&self) -> usize {
        let s1 = 1usize << self.m_w1;
        let s2 = if self.m_w2 > 0 { 1usize << self.m_w2 } else { 0 };
        s1.max(s2)
    }

    /// Whether this circuit uses 2-round interactive witness challenges
    /// (`w1 -> Challenge -> w2`).
    #[must_use]
    pub fn is_dual_mode(&self) -> bool {
        !self.challenge_offsets.is_empty()
    }
}

/// Complete 2-round Spartan + HyperKZG proof for a ProveKit R1CS instance.
#[derive(Debug, Clone)]
pub struct SpartanKzgProof {
    pub public_inputs:   Vec<Fr>,
    pub c_w1:            G1Affine,
    pub c_w2:            Option<G1Affine>,
    /// Outer sumcheck degree-3 polynomials `[c0, c1, c2, c3]` per round.
    pub outer_sumcheck:  Vec<[Fr; 4]>,
    /// Claimed `[A*w1(alpha), B*w1(alpha), C*w1(alpha)]`.
    pub evals_w1:        [Fr; 3],
    /// Claimed `[A*w2(alpha), B*w2(alpha), C*w2(alpha)]` (dual mode only).
    pub evals_w2:        Option<[Fr; 3]>,
    /// Inner sumcheck 1 degree-2 polynomials `[d0, d1, d2]` per round.
    pub inner_sc_1:      Vec<[Fr; 3]>,
    /// Claimed `w1(r_1)`.
    pub eval_w1_at_r1:   Fr,
    /// Inner sumcheck 2 degree-2 polynomials (dual mode only).
    pub inner_sc_2:      Option<Vec<[Fr; 3]>>,
    /// Claimed `w2(r_2)` (dual mode only).
    pub eval_w2_at_r2:   Option<Fr>,
    /// HyperKZG opening for `w1(r_1)`.
    pub opening_w1:      HyperKzgOpening,
    /// HyperKZG opening for `w2(r_2)` (dual mode only).
    pub opening_w2:      Option<HyperKzgOpening>,
    /// Raw `spongefish` prover transcript bytes (used to replay Fiat-Shamir).
    pub transcript_narg: Vec<u8>,
}

impl SpartanKzgProof {
    /// Exact compressed proof size in bytes (32 B per `G1Affine`, 32 B per
    /// `Fr`, excluding redundant `transcript_narg` which replays the same
    /// messages).
    #[must_use]
    pub fn compressed_bytes(&self) -> usize {
        let mut bytes = 32; // c_w1
        if self.c_w2.is_some() {
            bytes += 32;
        }
        bytes += self.outer_sumcheck.len() * 4 * 32;
        bytes += 3 * 32; // evals_w1
        if self.evals_w2.is_some() {
            bytes += 3 * 32;
        }
        bytes += self.inner_sc_1.len() * 3 * 32 + 32;
        if let Some(ref sc2) = self.inner_sc_2 {
            bytes += sc2.len() * 3 * 32 + 32;
        }
        bytes += self.opening_w1.compressed_bytes();
        if let Some(ref o2) = self.opening_w2 {
            bytes += o2.compressed_bytes();
        }
        bytes
    }

    /// Total number of BN254 pairings executed by `verify` (always **2**!).
    #[must_use]
    pub const fn num_pairings(&self) -> usize {
        2
    }
}

/// Detailed proving timings for Spartan + HyperKZG.
#[derive(Debug, Clone)]
pub struct SpartanKzgProveTimings {
    pub noir_exec_and_solve: Duration,
    pub kzg_commit:          Duration,
    pub sumchecks:           Duration,
    pub hyperkzg_open:       Duration,
    pub total:               Duration,
}

/// Detailed verification timings for Spartan + HyperKZG.
#[derive(Debug, Clone)]
pub struct SpartanKzgVerifyTimings {
    pub sumchecks_and_r1cs: Duration,
    pub kzg_pairings:       Duration,
    pub total:              Duration,
    pub num_pairings:       usize,
}

/// Challenges & intermediate evaluations extracted during verification (used by
/// `bqs_cost` to construct an exact algebraic-verifier BQS).
#[derive(Debug, Clone)]
pub struct VerifiedTranscriptData {
    pub tau:        Vec<Fr>,
    pub alpha:      Vec<Fr>,
    pub x_bind:     Fr,
    pub gamma:      Fr,
    pub challenges: Vec<Fr>,
    pub pub_eval:   Fr,
    pub chal_eval:  Fr,
    pub r1:         Vec<Fr>,
    pub r2:         Option<Vec<Fr>>,
    pub e_l1:       Fr,
    pub e_l2:       Option<Fr>,
    pub kzg_x1:     Fr,
    pub kzg_x2:     Option<Fr>,
}

/// Execute a Noir program on `input_map` and return the ACIR witness map plus
/// sorted public inputs as BN254 `Fr`.
pub fn execute_noir(
    program: &ProgramArtifact,
    input_map: &InputMap,
) -> Result<(acir::native_types::WitnessMap<acir::FieldElement>, Vec<Fr>)> {
    let initial_witness = program.abi.encode(input_map, None)?;
    let solver = Bn254BlackBoxSolver::default();
    let mut output_buf = Vec::new();
    let mut foreign_calls = DefaultForeignCallBuilder {
        output:       &mut output_buf,
        enable_mocks: false,
        resolver_url: None,
        root_path:    None,
        package_name: None,
    }
    .build();

    let mut stack = nargo::ops::execute_program(
        &program.bytecode,
        initial_witness,
        &solver,
        &mut foreign_calls,
    )
    .context("Noir program execution failed")?;

    let acir_map = stack.pop().context("missing ACIR witness stack")?.witness;

    let mut pub_indices = program.bytecode.functions[0].public_inputs().indices();
    pub_indices.sort_unstable();
    let mut public_inputs = Vec::with_capacity(pub_indices.len());
    for &idx in &pub_indices {
        let noir_val = acir_map
            .get(&acir::native_types::Witness::from(idx))
            .with_context(|| format!("missing public input at ACIR index {idx}"))?;
        // Convert Noir FieldElement -> ark_bn254::Fr via canonical LE bytes.
        let bytes = noir_val.to_le_bytes();
        public_inputs.push(Fr::from_le_bytes_mod_order(&bytes));
    }
    Ok((acir_map, public_inputs))
}

/// Compute `M * z` for a hydrated sparse matrix `M` over `Fr`, padded to
/// `padded_rows`.
fn sparse_mat_vec(
    mat: provekit_common::HydratedSparseMatrix<'_, Fr>,
    z: &[Fr],
    padded_rows: usize,
) -> Vec<Fr> {
    let num_rows = mat.matrix.num_rows;
    let mut out: Vec<Fr> = (0..num_rows)
        .into_par_iter()
        .map(|row| {
            let mut acc = Fr::zero();
            for (col, coeff) in mat.iter_row(row) {
                acc += coeff * z[col];
            }
            acc
        })
        .collect();
    out.resize(padded_rows, Fr::zero());
    out
}

/// Compute `M^T * eq_alpha` in one pass over `M`, returning a vector of length
/// `num_cols`.
fn sparse_mat_t_vec(
    mat: provekit_common::HydratedSparseMatrix<'_, Fr>,
    eq_alpha: &[Fr],
    num_cols: usize,
) -> Vec<Fr> {
    let mut out = vec![Fr::zero(); num_cols];
    for row in 0..mat.matrix.num_rows {
        let w = eq_alpha[row];
        if w.is_zero() {
            continue;
        }
        for (col, coeff) in mat.iter_row(row) {
            out[col] += w * coeff;
        }
    }
    out
}

/// Evaluate `sum_row eq_alpha[row] * (M_row . eq_r)` directly without
/// materializing the dense transposed vector.
fn eval_sparse_mat_bilinear(
    mat: provekit_common::HydratedSparseMatrix<'_, Fr>,
    eq_alpha: &[Fr],
    eq_r: &[Fr],
    col_start: usize,
    col_end: usize,
) -> Fr {
    (0..mat.matrix.num_rows)
        .into_par_iter()
        .map(|row| {
            let w = eq_alpha[row];
            if w.is_zero() {
                return Fr::zero();
            }
            let mut row_acc = Fr::zero();
            for (col, coeff) in mat.iter_row(row) {
                if col >= col_start && col < col_end {
                    row_acc += coeff * eq_r[col - col_start];
                }
            }
            w * row_acc
        })
        .sum()
}

/// Interpolate a cubic polynomial `c0 + c1*X + c2*X^2 + c3*X^3` from its values
/// `[y0, y1, y2, y3]` at `X = 0, 1, 2, 3`.
#[inline]
fn interpolate_cubic_0123(y: [Fr; 4]) -> [Fr; 4] {
    let inv2 = Fr::from(2u64).inverse().unwrap();
    let inv3 = Fr::from(3u64).inverse().unwrap();
    let inv6 = Fr::from(6u64).inverse().unwrap();

    let d0 = y[1] - y[0];
    let d1 = y[2] - y[1];
    let d2 = y[3] - y[2];
    let e0 = d1 - d0;
    let e1 = d2 - d1;
    let f0 = e1 - e0;

    let c0 = y[0];
    let c1 = d0 - e0 * inv2 + f0 * inv3;
    let c2 = e0 * inv2 - f0 * inv2;
    let c3 = f0 * inv6;
    [c0, c1, c2, c3]
}

/// Interpolate a quadratic polynomial `d0 + d1*X + d2*X^2` from its values
/// `[y0, y1, y2]` at `X = 0, 1, 2`.
#[inline]
fn interpolate_quad_012(y: [Fr; 3]) -> [Fr; 3] {
    let inv2 = Fr::from(2u64).inverse().unwrap();
    let d0 = y[1] - y[0];
    let d1 = y[2] - y[1];
    let e0 = d1 - d0;
    [y[0], d0 - e0 * inv2, e0 * inv2]
}

/// Evaluate cubic `c0 + c1*x + c2*x^2 + c3*x^3`.
#[inline]
pub fn eval_cubic(c: &[Fr; 4], x: Fr) -> Fr {
    c[0] + x * (c[1] + x * (c[2] + x * c[3]))
}

/// Evaluate quadratic `d0 + d1*x + d2*x^2`.
#[inline]
pub fn eval_quad(d: &[Fr; 3], x: Fr) -> Fr {
    d[0] + x * (d[1] + x * d[2])
}

/// Run a degree-2 inner sumcheck proving `sum_{x in {0,1}^ell} L(x) * W(x) =
/// initial_claim`. Returns `(round_polys, challenges_r, final_w_eval,
/// final_l_eval)`.
fn run_inner_sumcheck_prover(
    mut l_vec: Vec<Fr>,
    mut w_vec: Vec<Fr>,
    ell: usize,
    merlin: &mut ProverState<TranscriptSponge>,
) -> (Vec<[Fr; 3]>, Vec<Fr>, Fr, Fr) {
    assert_eq!(l_vec.len(), 1 << ell);
    assert_eq!(w_vec.len(), 1 << ell);

    let mut polys = Vec::with_capacity(ell);
    let mut challenges = Vec::with_capacity(ell);
    let mut prev_r: Option<Fr> = None;

    for round in 0..ell {
        let active = 1usize << (ell - round + usize::from(prev_r.is_some()));
        let evals = sumcheck_fold_map_reduce(
            [&mut l_vec[..active], &mut w_vec[..active]],
            prev_r,
            |[(l0, l1), (w0, w1)]| {
                let y0 = l0 * w0;
                let y1 = l1 * w1;
                let l2 = l1 + l1 - l0;
                let w2 = w1 + w1 - w0;
                let y2 = l2 * w2;
                [y0, y1, y2]
            },
        );
        let coeffs = interpolate_quad_012(evals);
        for &c in &coeffs {
            absorb_fr_prover(merlin, &c);
        }
        let r: Fr = merlin.verifier_message();
        polys.push(coeffs);
        challenges.push(r);
        prev_r = Some(r);
    }

    // Final fold of length-2 slice into length-1.
    let last_r = prev_r.unwrap();
    let final_l = l_vec[0] + last_r * (l_vec[1] - l_vec[0]);
    let final_w = w_vec[0] + last_r * (w_vec[1] - w_vec[0]);
    (polys, challenges, final_w, final_l)
}

/// Build the canonical 32-byte instance commitment binding R1CS structure +
/// public inputs.
fn build_instance_digest(r1cs: &R1CS<Fr>, public_inputs: &[Fr]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"provekit-spartan-hyperkzg-v1-instance");
    let h = r1cs.hash();
    let h_bytes = postcard::to_stdvec(&h).expect("R1csHash serializes");
    hasher.update(&h_bytes);
    for pi in public_inputs {
        let mut buf = [0u8; 32];
        pi.serialize_compressed(&mut buf[..]).unwrap();
        hasher.update(&buf);
    }
    *hasher.finalize().as_bytes()
}

/// Prove a ProveKit circuit with 2-round Spartan + HyperKZG.
pub fn prove(
    circuit: &SpartanKzgCircuit,
    srs: &KzgSrs,
    input_map: &InputMap,
) -> Result<(SpartanKzgProof, SpartanKzgProveTimings)> {
    let t_total = Instant::now();

    // 1. Execute Noir and solve w1.
    let t_exec = Instant::now();
    let (acir_map, public_inputs) = execute_noir(&circuit.program, input_map)?;
    let instance_digest = build_instance_digest(&circuit.r1cs, &public_inputs);
    let ds = DomainSeparator::protocol(&"provekit-spartan-hyperkzg-v1").instance(&instance_digest);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(HashConfig::Skyscraper));

    let mut witness: Vec<Option<Fr>> = vec![None; circuit.r1cs.num_witnesses_for_solving()];
    solve_witness_vec(
        &mut witness,
        circuit.split_builders.w1_layers.clone(),
        &acir_map,
        &mut merlin,
    )
    .context("solving w1 layers")?;

    let w1_size = circuit.split_builders.w1_size;
    let num_w = circuit.r1cs.num_witnesses();
    let mut w1: Vec<Fr> = witness[..w1_size]
        .iter()
        .map(|v| v.context("missing w1 entry"))
        .collect::<Result<Vec<_>>>()?;
    let t_exec_w1 = t_exec.elapsed();

    // Commit w1.
    let t_comm1 = Instant::now();
    let w1_padded_len = 1usize << circuit.m_w1;
    w1.resize(w1_padded_len, Fr::zero());
    let c_w1 = hyperkzg::commit(srs, &w1)?;
    absorb_g1_prover(&mut merlin, &c_w1);
    let mut kzg_commit = t_comm1.elapsed();

    // Round 2: if dual mode, solve w2 (pulling Fiat-Shamir challenges!) and commit w2.
    let mut noir_exec_and_solve = t_exec_w1;
    let (c_w2, w2_padded, challenges) = if circuit.is_dual_mode() {
        let t_w2 = Instant::now();
        solve_witness_vec(
            &mut witness,
            circuit.split_builders.w2_layers.clone(),
            &acir_map,
            &mut merlin,
        )
        .context("solving w2 layers")?;
        let mut w2: Vec<Fr> = witness[w1_size..num_w]
            .iter()
            .map(|v| v.context("missing w2 entry"))
            .collect::<Result<Vec<_>>>()?;
        let chals: Vec<Fr> = circuit
            .challenge_offsets
            .iter()
            .map(|&off| w2[off])
            .collect();
        noir_exec_and_solve += t_w2.elapsed();

        let t_comm2 = Instant::now();
        let w2_padded_len = 1usize << circuit.m_w2;
        w2.resize(w2_padded_len, Fr::zero());
        let c2 = hyperkzg::commit(srs, &w2)?;
        absorb_g1_prover(&mut merlin, &c2);
        kzg_commit += t_comm2.elapsed();
        (Some(c2), Some(w2), chals)
    } else {
        (None, None, Vec::new())
    };

    // Assemble full real witness z of length num_w.
    let full_z: Vec<Fr> = witness[..num_w]
        .iter()
        .map(|v| v.context("missing real witness entry"))
        .collect::<Result<Vec<_>>>()?;

    // 3. Outer Spartan sumcheck (m_0 rounds, degree-3).
    let t_sc = Instant::now();
    let padded_rows = 1usize << circuit.m_0;
    let mut az = sparse_mat_vec(circuit.r1cs.a(), &full_z, padded_rows);
    let mut bz = sparse_mat_vec(circuit.r1cs.b(), &full_z, padded_rows);
    let mut cz = sparse_mat_vec(circuit.r1cs.c(), &full_z, padded_rows);

    let tau: Vec<Fr> = (0..circuit.m_0).map(|_| merlin.verifier_message()).collect();
    let mut eq_tau = calculate_evaluations_over_boolean_hypercube_for_eq(&tau, padded_rows);

    let mut outer_sumcheck = Vec::with_capacity(circuit.m_0);
    let mut alpha = Vec::with_capacity(circuit.m_0);
    let mut prev_alpha: Option<Fr> = None;

    for round in 0..circuit.m_0 {
        let active = 1usize << (circuit.m_0 - round + usize::from(prev_alpha.is_some()));
        let evals = sumcheck_fold_map_reduce(
            [
                &mut eq_tau[..active],
                &mut az[..active],
                &mut bz[..active],
                &mut cz[..active],
            ],
            prev_alpha,
            |[(e0, e1), (a0, a1), (b0, b1), (c0, c1)]| {
                let de = e1 - e0;
                let da = a1 - a0;
                let db = b1 - b0;
                let dc = c1 - c0;

                let y0 = e0 * (a0 * b0 - c0);
                let y1 = e1 * (a1 * b1 - c1);
                let e2 = e1 + de;
                let a2 = a1 + da;
                let b2 = b1 + db;
                let c2 = c1 + dc;
                let y2 = e2 * (a2 * b2 - c2);
                let e3 = e2 + de;
                let a3 = a2 + da;
                let b3 = b2 + db;
                let c3 = c2 + dc;
                let y3 = e3 * (a3 * b3 - c3);
                [y0, y1, y2, y3]
            },
        );
        let coeffs = interpolate_cubic_0123(evals);
        for &c in &coeffs {
            absorb_fr_prover(&mut merlin, &c);
        }
        let a_i: Fr = merlin.verifier_message();
        outer_sumcheck.push(coeffs);
        alpha.push(a_i);
        prev_alpha = Some(a_i);
    }

    // 4. Compute split row-weighted vectors A^T eq(alpha), B^T eq(alpha), C^T eq(alpha).
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(
        &alpha,
        circuit.r1cs.num_constraints(),
    );
    let alpha_a = sparse_mat_t_vec(circuit.r1cs.a(), &eq_alpha, num_w);
    let alpha_b = sparse_mat_t_vec(circuit.r1cs.b(), &eq_alpha, num_w);
    let alpha_c = sparse_mat_t_vec(circuit.r1cs.c(), &eq_alpha, num_w);

    let dot_slice = |u: &[Fr], v: &[Fr]| -> Fr {
        u.par_iter().zip(v.par_iter()).map(|(&a, &b)| a * b).sum()
    };

    let evals_w1 = [
        dot_slice(&alpha_a[..w1_size], &w1[..w1_size]),
        dot_slice(&alpha_b[..w1_size], &w1[..w1_size]),
        dot_slice(&alpha_c[..w1_size], &w1[..w1_size]),
    ];
    for &e in &evals_w1 {
        absorb_fr_prover(&mut merlin, &e);
    }

    let evals_w2 = if let Some(ref w2) = w2_padded {
        let w2_real = num_w - w1_size;
        let e2 = [
            dot_slice(&alpha_a[w1_size..num_w], &w2[..w2_real]),
            dot_slice(&alpha_b[w1_size..num_w], &w2[..w2_real]),
            dot_slice(&alpha_c[w1_size..num_w], &w2[..w2_real]),
        ];
        for &e in &e2 {
            absorb_fr_prover(&mut merlin, &e);
        }
        Some(e2)
    } else {
        None
    };

    // Squeeze binding challenge x_bind and batching challenge gamma.
    let x_bind: Fr = merlin.verifier_message();
    let gamma: Fr = merlin.verifier_message();
    let gamma2 = gamma * gamma;
    let gamma3 = gamma2 * gamma;

    // Build combined weight vector L_1 for w1 (padded to 2^{m_w1}).
    let mut l1 = vec![Fr::zero(); w1_padded_len];
    for i in 0..w1_size {
        l1[i] = alpha_a[i] + gamma * alpha_b[i] + gamma2 * alpha_c[i];
    }
    // Public input + constant-1 binding: v_pub[0] = 1, v_pub[1+j] = x_bind^{j+1}.
    let mut xp = Fr::one();
    for j in 0..=circuit.r1cs.num_public_inputs {
        l1[j] += gamma3 * xp;
        xp *= x_bind;
    }

    let (inner_sc_1, r1, eval_w1_at_r1, _e_l1) =
        run_inner_sumcheck_prover(l1, w1.clone(), circuit.m_w1, &mut merlin);
    absorb_fr_prover(&mut merlin, &eval_w1_at_r1);

    let (inner_sc_2, r2_opt, eval_w2_at_r2) = if let Some(ref w2) = w2_padded {
        let w2_real = num_w - w1_size;
        let w2_padded_len = 1usize << circuit.m_w2;
        let mut l2 = vec![Fr::zero(); w2_padded_len];
        for i in 0..w2_real {
            l2[i] = alpha_a[w1_size + i]
                + gamma * alpha_b[w1_size + i]
                + gamma2 * alpha_c[w1_size + i];
        }
        // Challenge binding: v_chal[offset_k] = x_bind^k.
        let mut cp = Fr::one();
        for &off in &circuit.challenge_offsets {
            l2[off] += gamma3 * cp;
            cp *= x_bind;
        }
        let (sc2, r2, ew2, _el2) =
            run_inner_sumcheck_prover(l2, w2.clone(), circuit.m_w2, &mut merlin);
        absorb_fr_prover(&mut merlin, &ew2);
        (Some(sc2), Some(r2), Some(ew2))
    } else {
        (None, None, None)
    };
    let sumchecks = t_sc.elapsed();

    // 5. HyperKZG openings (w1 and, if dual mode, w2).
    let t_open = Instant::now();
    let (v1, opening_w1) = hyperkzg::open(srs, &w1, &r1, &mut merlin)?;
    ensure!(v1 == eval_w1_at_r1, "w1 HyperKZG eval mismatch");

    let opening_w2 = if let (Some(ref w2), Some(ref r2), Some(ew2)) =
        (&w2_padded, &r2_opt, eval_w2_at_r2)
    {
        let (v2, o2) = hyperkzg::open(srs, w2, r2, &mut merlin)?;
        ensure!(v2 == ew2, "w2 HyperKZG eval mismatch");
        Some(o2)
    } else {
        None
    };
    let _rho: Fr = merlin.verifier_message();
    let hyperkzg_open = t_open.elapsed();

    // Keep track of unused challenges check in debug.
    debug_assert_eq!(challenges.len(), circuit.challenge_offsets.len());

    let proof_transcript = merlin.proof();
    let proof = SpartanKzgProof {
        public_inputs,
        c_w1,
        c_w2,
        outer_sumcheck,
        evals_w1,
        evals_w2,
        inner_sc_1,
        eval_w1_at_r1,
        inner_sc_2,
        eval_w2_at_r2,
        opening_w1,
        opening_w2,
        transcript_narg: proof_transcript.narg_string,
    };

    let timings = SpartanKzgProveTimings {
        noir_exec_and_solve,
        kzg_commit,
        sumchecks,
        hyperkzg_open,
        total: t_total.elapsed(),
    };
    Ok((proof, timings))
}

/// Verify a 2-round Spartan + HyperKZG proof in **exactly 2 BN254 pairings**.
pub fn verify(
    circuit: &SpartanKzgCircuit,
    srs: &KzgSrs,
    proof: &SpartanKzgProof,
) -> Result<(VerifiedTranscriptData, SpartanKzgVerifyTimings)> {
    let t_total = Instant::now();
    let t_sc = Instant::now();

    ensure!(
        proof.public_inputs.len() == circuit.r1cs.num_public_inputs,
        "public inputs length mismatch"
    );
    ensure!(
        proof.outer_sumcheck.len() == circuit.m_0,
        "outer sumcheck rounds mismatch"
    );
    ensure!(
        proof.inner_sc_1.len() == circuit.m_w1,
        "inner sumcheck 1 rounds mismatch"
    );

    let instance_digest = build_instance_digest(&circuit.r1cs, &proof.public_inputs);
    let ds = DomainSeparator::protocol(&"provekit-spartan-hyperkzg-v1").instance(&instance_digest);
    let whir_proof = whir::transcript::Proof {
        narg_string: proof.transcript_narg.clone(),
        hints: Vec::new(),
        #[cfg(debug_assertions)]
        pattern: Vec::new(),
    };
    let mut arthur = VerifierState::new(
        &ds,
        &whir_proof,
        TranscriptSponge::from_config(HashConfig::Skyscraper),
    );

    // 1. Absorb c_w1.
    absorb_g1_verifier(&mut arthur, &proof.c_w1)?;

    // 2. If dual mode, squeeze challenges and absorb c_w2.
    let challenges: Vec<Fr> = if circuit.is_dual_mode() {
        let chals: Vec<Fr> = (0..circuit.challenge_offsets.len())
            .map(|_| arthur.verifier_message())
            .collect();
        let c_w2 = proof
            .c_w2
            .context("dual-mode circuit requires c_w2 commitment")?;
        absorb_g1_verifier(&mut arthur, &c_w2)?;
        chals
    } else {
        ensure!(proof.c_w2.is_none(), "unexpected c_w2 in single-round mode");
        Vec::new()
    };

    // 3. Verify outer Spartan sumcheck.
    let tau: Vec<Fr> = (0..circuit.m_0).map(|_| arthur.verifier_message()).collect();
    let mut claim = Fr::zero();
    let mut alpha = Vec::with_capacity(circuit.m_0);

    for (round, poly) in proof.outer_sumcheck.iter().enumerate() {
        for &c in poly {
            absorb_fr_verifier(&mut arthur, &c)?;
        }
        let sum_01 = poly[0] + eval_cubic(poly, Fr::one());
        ensure!(
            sum_01 == claim,
            "outer sumcheck round {round} check failed (p(0)+p(1) != claim)"
        );
        let a_i: Fr = arthur.verifier_message();
        claim = eval_cubic(poly, a_i);
        alpha.push(a_i);
    }

    // 4. Absorb split evaluations and verify outer sumcheck final claim.
    for &e in &proof.evals_w1 {
        absorb_fr_verifier(&mut arthur, &e)?;
    }
    let (az_alpha, bz_alpha, cz_alpha) = if circuit.is_dual_mode() {
        let e2 = proof
            .evals_w2
            .context("dual-mode circuit requires evals_w2")?;
        for &e in &e2 {
            absorb_fr_verifier(&mut arthur, &e)?;
        }
        (
            proof.evals_w1[0] + e2[0],
            proof.evals_w1[1] + e2[1],
            proof.evals_w1[2] + e2[2],
        )
    } else {
        (proof.evals_w1[0], proof.evals_w1[1], proof.evals_w1[2])
    };

    let eq_tau_alpha = calculate_eq(&tau, &alpha);
    ensure!(
        eq_tau_alpha * (az_alpha * bz_alpha - cz_alpha) == claim,
        "outer Spartan sumcheck final claim mismatch"
    );

    // 5. Public-input + challenge binding and inner sumcheck(s).
    let x_bind: Fr = arthur.verifier_message();
    let gamma: Fr = arthur.verifier_message();
    let gamma2 = gamma * gamma;
    let gamma3 = gamma2 * gamma;

    // Expected public_eval = 1 + sum_{j=0}^{n_pub-1} x_bind^{j+1} * pi[j].
    let mut pub_eval = Fr::one();
    let mut xp = x_bind;
    for &pi in &proof.public_inputs {
        pub_eval += xp * pi;
        xp *= x_bind;
    }

    let mut claim_1 = proof.evals_w1[0]
        + gamma * proof.evals_w1[1]
        + gamma2 * proof.evals_w1[2]
        + gamma3 * pub_eval;
    let mut r1 = Vec::with_capacity(circuit.m_w1);
    for (round, poly) in proof.inner_sc_1.iter().enumerate() {
        for &c in poly {
            absorb_fr_verifier(&mut arthur, &c)?;
        }
        let sum_01 = poly[0] + eval_quad(poly, Fr::one());
        ensure!(
            sum_01 == claim_1,
            "inner sumcheck 1 round {round} check failed"
        );
        let r_i: Fr = arthur.verifier_message();
        claim_1 = eval_quad(poly, r_i);
        r1.push(r_i);
    }
    absorb_fr_verifier(&mut arthur, &proof.eval_w1_at_r1)?;

    // Evaluate L_1(r1) via sparse R1CS MLE evaluation + public-input weight MLE.
    let w1_size = circuit.split_builders.w1_size;
    let num_w = circuit.r1cs.num_witnesses();
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(
        &alpha,
        circuit.r1cs.num_constraints(),
    );
    let eq_r1 = calculate_evaluations_over_boolean_hypercube_for_eq(&r1, w1_size);

    let a1_r1 = eval_sparse_mat_bilinear(circuit.r1cs.a(), &eq_alpha, &eq_r1, 0, w1_size);
    let b1_r1 = eval_sparse_mat_bilinear(circuit.r1cs.b(), &eq_alpha, &eq_r1, 0, w1_size);
    let c1_r1 = eval_sparse_mat_bilinear(circuit.r1cs.c(), &eq_alpha, &eq_r1, 0, w1_size);
    let mut pub_r1 = Fr::zero();
    let mut xp2 = Fr::one();
    for j in 0..=circuit.r1cs.num_public_inputs {
        pub_r1 += xp2 * eq_r1[j];
        xp2 *= x_bind;
    }
    let e_l1 = a1_r1 + gamma * b1_r1 + gamma2 * c1_r1 + gamma3 * pub_r1;
    ensure!(
        e_l1 * proof.eval_w1_at_r1 == claim_1,
        "inner sumcheck 1 final claim mismatch (L_1(r_1) * w_1(r_1) != claim)"
    );

    // Dual-mode inner sumcheck 2 + challenge binding.
    let mut chal_eval = Fr::zero();
    let (r2_opt, e_l2_opt) = if circuit.is_dual_mode() {
        let e2 = proof.evals_w2.unwrap();
        let sc2 = proof
            .inner_sc_2
            .as_ref()
            .context("missing inner_sc_2 in dual mode")?;
        let ew2 = proof
            .eval_w2_at_r2
            .context("missing eval_w2_at_r2 in dual mode")?;
        ensure!(sc2.len() == circuit.m_w2, "inner sumcheck 2 rounds mismatch");

        let mut cp = Fr::one();
        for &ch in &challenges {
            chal_eval += cp * ch;
            cp *= x_bind;
        }

        let mut claim_2 = e2[0] + gamma * e2[1] + gamma2 * e2[2] + gamma3 * chal_eval;
        let mut r2 = Vec::with_capacity(circuit.m_w2);
        for (round, poly) in sc2.iter().enumerate() {
            for &c in poly {
                absorb_fr_verifier(&mut arthur, &c)?;
            }
            let sum_01 = poly[0] + eval_quad(poly, Fr::one());
            ensure!(
                sum_01 == claim_2,
                "inner sumcheck 2 round {round} check failed"
            );
            let r_i: Fr = arthur.verifier_message();
            claim_2 = eval_quad(poly, r_i);
            r2.push(r_i);
        }
        absorb_fr_verifier(&mut arthur, &ew2)?;

        let eq_r2 =
            calculate_evaluations_over_boolean_hypercube_for_eq(&r2, num_w - w1_size);
        let a2_r2 = eval_sparse_mat_bilinear(circuit.r1cs.a(), &eq_alpha, &eq_r2, w1_size, num_w);
        let b2_r2 = eval_sparse_mat_bilinear(circuit.r1cs.b(), &eq_alpha, &eq_r2, w1_size, num_w);
        let c2_r2 = eval_sparse_mat_bilinear(circuit.r1cs.c(), &eq_alpha, &eq_r2, w1_size, num_w);
        let mut chal_r2 = Fr::zero();
        let mut cp2 = Fr::one();
        for &off in &circuit.challenge_offsets {
            chal_r2 += cp2 * eq_r2[off];
            cp2 *= x_bind;
        }
        let e_l2 = a2_r2 + gamma * b2_r2 + gamma2 * c2_r2 + gamma3 * chal_r2;
        ensure!(
            e_l2 * ew2 == claim_2,
            "inner sumcheck 2 final claim mismatch (L_2(r_2) * w_2(r_2) != claim)"
        );
        (Some(r2), Some(e_l2))
    } else {
        (None, None)
    };
    let sumchecks_and_r1cs = t_sc.elapsed();

    // 6. HyperKZG algebraic checks + single batched 2-pairing BN254 check.
    let t_pair = Instant::now();
    let mut kzg_claims = hyperkzg::verify_to_kzg_claims(
        proof.c_w1,
        &r1,
        proof.eval_w1_at_r1,
        &proof.opening_w1,
        &mut arthur,
    )?;
    let kzg_x1 = kzg_claims[0].point;

    let kzg_x2 = if let (Some(c_w2), Some(ref r2), Some(ew2), Some(ref o2)) = (
        proof.c_w2,
        &r2_opt,
        proof.eval_w2_at_r2,
        &proof.opening_w2,
    ) {
        let claims2 = hyperkzg::verify_to_kzg_claims(c_w2, r2, ew2, o2, &mut arthur)?;
        let x2 = claims2[0].point;
        kzg_claims.extend(claims2);
        Some(x2)
    } else {
        None
    };

    let rho: Fr = arthur.verifier_message();
    let ok = univariate::verify_batched(srs, &kzg_claims, rho)?;
    ensure!(ok, "batched 2-pairing KZG verification failed");
    let kzg_pairings = t_pair.elapsed();

    let data = VerifiedTranscriptData {
        tau,
        alpha,
        x_bind,
        gamma,
        challenges,
        pub_eval,
        chal_eval,
        r1,
        r2: r2_opt,
        e_l1,
        e_l2: e_l2_opt,
        kzg_x1,
        kzg_x2,
    };
    let timings = SpartanKzgVerifyTimings {
        sumchecks_and_r1cs,
        kzg_pairings,
        total: t_total.elapsed(),
        num_pairings: 2,
    };
    Ok((data, timings))
}
