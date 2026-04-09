use {
    crate::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    ark_ff::{PrimeField, Zero},
    provekit_common::{
        file::read,
        FieldElement, NoirProof, Verifier, WhirR1CSScheme,
    },
    provekit_verifier::Verify,
    sha3::{Digest, Sha3_512},
    std::{
        fmt::Write as FmtWrite,
        fs::File,
        io::Write,
        path::PathBuf,
    },
    tracing::{info, instrument},
    whir::protocols::proof_of_work,
};

/// Generate input files for the Noir recursive verifier circuit.
///
/// Extracts WHIR configuration constants and proof data needed by the
/// Noir recursive verifier. Outputs a JSON config file and a partial
/// Prover.toml with Spartan-level data and R1CS matrices.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-noir-inputs")]
pub struct Args {
    /// path to the verifier data file (.pkp)
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file (.np or .json)
    #[argh(positional)]
    proof_path: PathBuf,

    /// output path for the Noir Prover.toml
    #[argh(
        option,
        long = "output",
        default = "String::from(\"./Prover.toml\")"
    )]
    output_path: String,

    /// output path for supplementary JSON data
    #[argh(
        option,
        long = "json",
        default = "String::from(\"./noir_verifier_data.json\")"
    )]
    json_path: String,
}

/// SHA3-512(CBOR(WhirR1CSScheme)) -- matches whir::transcript::DomainSeparator::protocol().
fn compute_protocol_id(scheme: &WhirR1CSScheme) -> [u8; 64] {
    let mut hash = Sha3_512::default();
    ciborium::into_writer(scheme, &mut hash).expect("CBOR serialization of scheme failed");
    hash.finalize().into()
}

fn field_str(f: &FieldElement) -> String {
    format!("{f}")
}

/// Parse a 32-byte LE field element from a byte slice at the given offset.
fn parse_field(narg: &[u8], offset: usize) -> FieldElement {
    let bytes: [u8; 32] = narg[offset..offset + 32].try_into().unwrap();
    FieldElement::from_le_bytes_mod_order(&bytes)
}

/// Parse a 32-byte hash from a byte slice at the given offset.
fn parse_hash(narg: &[u8], offset: usize) -> [u8; 32] {
    narg[offset..offset + 32].try_into().unwrap()
}

/// Parse a u64 (LE 8 bytes) from a byte slice at the given offset.
fn parse_u64_le(narg: &[u8], offset: usize) -> u64 {
    let bytes: [u8; 8] = narg[offset..offset + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Parse a WHIR quadratic sumcheck section from the narg_string.
/// Returns (coefficients, pow_nonces, bytes_consumed).
fn parse_whir_sumcheck(
    narg: &[u8],
    pos: usize,
    num_rounds: usize,
    pow_active: bool,
) -> (Vec<[FieldElement; 2]>, Vec<u64>, usize) {
    let mut offset = pos;
    let mut coeffs = Vec::with_capacity(num_rounds);
    let mut pow_nonces = Vec::new();

    for _ in 0..num_rounds {
        let c0 = parse_field(narg, offset);
        offset += 32;
        let c2 = parse_field(narg, offset);
        offset += 32;
        coeffs.push([c0, c2]);

        if pow_active {
            pow_nonces.push(parse_u64_le(narg, offset));
            offset += 8;
        }
    }

    (coeffs, pow_nonces, offset - pos)
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier =
            read(&self.verifier_path).context("while reading Verifier data")?;
        let proof: NoirProof = read(&self.proof_path).context("while reading proof")?;

        let wfw = verifier
            .whir_for_witness
            .as_ref()
            .context("verifier is missing whir_for_witness config")?;

        info!(
            m_0 = wfw.m_0,
            m = wfw.m,
            num_challenges = wfw.num_challenges,
            "Generating Noir verifier inputs"
        );

        // Verify the proof passes (sanity check)
        info!("Running Rust verifier as sanity check...");
        let mut verifier_clone = verifier.clone();
        verifier_clone
            .verify(&proof)
            .context("Proof verification failed")?;
        info!("Proof verified successfully");

        let protocol_id = compute_protocol_id(wfw);
        let instance = proof.public_inputs.hash_bytes();

        // === Extract WHIR config parameters ===
        let blinded = &wfw.whir_witness.blinded_commitment;
        let blinding = &wfw.whir_witness.blinding_commitment;

        let m = wfw.m;
        let m_0 = wfw.m_0;
        let initial_ff = blinded.initial_sumcheck.num_rounds;
        let num_whir_rounds = blinded.round_configs.len();
        let final_sumcheck_rounds = blinded.final_sumcheck.num_rounds;
        let final_poly_size = blinded.final_sumcheck.initial_size;
        let ood_samples = blinded.initial_committer.out_domain_samples;
        let num_vectors = blinded.initial_committer.num_vectors;
        let max_queries = blinded.initial_committer.in_domain_samples;
        let tree_height = {
            let cl = blinded.initial_committer.codeword_length;
            let il = blinded.initial_committer.interleaving_depth;
            (cl / il).ilog2() as usize
        };
        let pow_bits = f64::from(proof_of_work::difficulty(blinded.final_pow.threshold));

        let blinding_ood = blinding.initial_committer.out_domain_samples;
        let blinding_num_vectors = blinding.initial_committer.num_vectors;
        let blinding_whir_rounds = blinding.round_configs.len();
        let blinding_tree_height = {
            let cl = blinding.initial_committer.codeword_length;
            let il = blinding.initial_committer.interleaving_depth;
            (cl / il).ilog2() as usize
        };
        let blinding_queries = blinding.initial_committer.in_domain_samples;

        let interleaving_depth = blinded.initial_committer.interleaving_depth;
        let blinding_interleaving_depth = blinding.initial_committer.interleaving_depth;
        let num_witness_variables = m;
        let _num_blinding_variables = blinding.initial_sumcheck.num_rounds
            + blinding.round_configs.len() * blinding.initial_sumcheck.num_rounds
            + blinding.final_sumcheck.num_rounds;

        let has_public_inputs = !proof.public_inputs.0.is_empty();
        let num_linear_forms =
            if has_public_inputs { 4 + 1 } else { 3 + 1 }; // evals(3) + blinding(1) + optional public(1)
        let num_gammas = max_queries * interleaving_depth;
        let num_w_folded_evals = num_linear_forms * 1 * (num_witness_variables + 1);

        let initial_sc_pow_active =
            blinded.initial_sumcheck.round_pow.threshold != u64::MAX;
        let final_sc_pow_active =
            blinded.final_sumcheck.round_pow.threshold != u64::MAX;
        let final_pow_active = blinded.final_pow.threshold != u64::MAX;

        let blinding_initial_sc_pow_active =
            blinding.initial_sumcheck.round_pow.threshold != u64::MAX;
        let blinding_final_sc_pow_active =
            blinding.final_sumcheck.round_pow.threshold != u64::MAX;
        let blinding_final_pow_active = blinding.final_pow.threshold != u64::MAX;

        let blinding_ff = blinding.initial_sumcheck.num_rounds;
        let blinding_final_sc_rounds = blinding.final_sumcheck.num_rounds;
        let blinding_final_poly_size = blinding.final_sumcheck.initial_size;

        // Per-round config extraction (inner WHIR)
        let round_sc_rounds: Vec<usize> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.num_rounds)
            .collect();
        let round_ood_samples: Vec<usize> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.out_domain_samples)
            .collect();
        let round_pow_active: Vec<bool> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.pow.threshold != u64::MAX)
            .collect();
        let round_sc_pow_active: Vec<bool> = blinded
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.round_pow.threshold != u64::MAX)
            .collect();

        // Per-round config extraction (blinding WHIR)
        let blinding_round_sc_rounds: Vec<usize> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.num_rounds)
            .collect();
        let blinding_round_ood_samples: Vec<usize> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.irs_committer.out_domain_samples)
            .collect();
        let blinding_round_pow_active: Vec<bool> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.pow.threshold != u64::MAX)
            .collect();
        let blinding_round_sc_pow_active: Vec<bool> = blinding
            .round_configs
            .iter()
            .map(|rc| rc.sumcheck.round_pow.threshold != u64::MAX)
            .collect();

        info!(
            initial_ff,
            num_whir_rounds,
            final_sumcheck_rounds,
            final_poly_size,
            tree_height,
            ood_samples,
            num_vectors,
            max_queries,
            pow_bits,
            interleaving_depth,
            num_gammas,
            num_w_folded_evals,
            num_witness_variables,
            initial_sc_pow_active,
            final_sc_pow_active,
            final_pow_active,
            "Extracted WHIR config"
        );

        // === Output constants JSON ===
        let mut constants = serde_json::Map::new();
        constants.insert("LOG_NUM_CONSTRAINTS".into(), m_0.into());
        constants.insert("LOG_NUM_VARIABLES".into(), m.into());
        constants.insert("NUM_WHIR_ROUNDS".into(), num_whir_rounds.into());
        constants.insert("FOLDING_FACTOR".into(), initial_ff.into());
        constants.insert("MAX_QUERIES_PER_ROUND".into(), max_queries.into());
        constants.insert("TREE_HEIGHT".into(), tree_height.into());
        constants.insert("OOD_SAMPLES".into(), ood_samples.into());
        constants.insert("FINAL_POLY_SIZE".into(), final_poly_size.into());
        constants.insert("FINAL_SUMCHECK_ROUNDS".into(), final_sumcheck_rounds.into());
        constants.insert("FOLD_SIZE".into(), (1usize << initial_ff).into());
        constants.insert("POW_BITS".into(), (pow_bits as u32).into());
        constants.insert("MAX_PUBLIC_INPUTS".into(), proof.public_inputs.0.len().into());
        constants.insert("W1_SIZE".into(), wfw.w1_size.into());
        constants.insert("NUM_CHALLENGES".into(), wfw.num_challenges.into());
        constants.insert("BATCH_SIZE".into(), num_vectors.into());
        constants.insert("NUM_VECTORS".into(), num_vectors.into());
        constants.insert("INTERLEAVING_DEPTH".into(), interleaving_depth.into());
        constants.insert("NUM_WITNESS_VARIABLES".into(), num_witness_variables.into());
        constants.insert("NUM_LINEAR_FORMS".into(), num_linear_forms.into());
        constants.insert("NUM_W_FOLDED_EVALS".into(), num_w_folded_evals.into());
        constants.insert("NUM_GAMMAS".into(), num_gammas.into());
        constants.insert("BLINDING_OOD_SAMPLES".into(), blinding_ood.into());
        constants.insert("BLINDING_WHIR_ROUNDS".into(), blinding_whir_rounds.into());
        constants.insert("BLINDING_TREE_HEIGHT".into(), blinding_tree_height.into());
        constants.insert("BLINDING_MAX_QUERIES".into(), blinding_queries.into());
        constants.insert("BLINDING_NUM_VECTORS".into(), blinding_num_vectors.into());
        constants.insert("BLINDING_INTERLEAVING_DEPTH".into(), blinding_interleaving_depth.into());
        constants.insert("BLINDING_FOLDING_FACTOR".into(), blinding_ff.into());
        constants.insert("BLINDING_FINAL_SUMCHECK_ROUNDS".into(), blinding_final_sc_rounds.into());
        constants.insert("BLINDING_FINAL_POLY_SIZE".into(), blinding_final_poly_size.into());
        constants.insert("INITIAL_SUMCHECK_POW_ACTIVE".into(), initial_sc_pow_active.into());
        constants.insert("FINAL_SUMCHECK_POW_ACTIVE".into(), final_sc_pow_active.into());
        constants.insert("FINAL_POW_ACTIVE".into(), final_pow_active.into());
        constants.insert("BLINDING_INITIAL_SC_POW_ACTIVE".into(), blinding_initial_sc_pow_active.into());
        constants.insert("BLINDING_FINAL_SC_POW_ACTIVE".into(), blinding_final_sc_pow_active.into());
        constants.insert("BLINDING_FINAL_POW_ACTIVE".into(), blinding_final_pow_active.into());
        constants.insert("ROUND_SC_ROUNDS".into(), serde_json::to_value(&round_sc_rounds).unwrap());
        constants.insert("ROUND_OOD_SAMPLES".into(), serde_json::to_value(&round_ood_samples).unwrap());
        constants.insert("ROUND_POW_ACTIVE".into(), serde_json::to_value(&round_pow_active).unwrap());
        constants.insert("ROUND_SC_POW_ACTIVE".into(), serde_json::to_value(&round_sc_pow_active).unwrap());
        constants.insert("BLINDING_ROUND_SC_ROUNDS".into(), serde_json::to_value(&blinding_round_sc_rounds).unwrap());
        constants.insert("BLINDING_ROUND_OOD_SAMPLES".into(), serde_json::to_value(&blinding_round_ood_samples).unwrap());
        constants.insert("BLINDING_ROUND_POW_ACTIVE".into(), serde_json::to_value(&blinding_round_pow_active).unwrap());
        constants.insert("BLINDING_ROUND_SC_POW_ACTIVE".into(), serde_json::to_value(&blinding_round_sc_pow_active).unwrap());
        constants.insert("protocol_id_hex".into(), hex::encode(protocol_id).into());
        constants.insert("instance_hex".into(), hex::encode(instance).into());
        constants.insert("narg_string_len".into(), proof.whir_r1cs_proof.narg_string.len().into());
        constants.insert("hints_len".into(), proof.whir_r1cs_proof.hints.len().into());
        let constants = serde_json::Value::Object(constants);

        let mut json_file =
            File::create(&self.json_path).context("while creating JSON output")?;
        json_file
            .write_all(serde_json::to_string_pretty(&constants)?.as_bytes())
            .context("while writing JSON")?;
        info!(path = %self.json_path, "Wrote constants JSON");

        // === Parse narg_string to extract commitment data ===
        // The narg_string contains all prover messages in protocol order.
        // Format: Hash(32B) + OOD_answers(32B*ood*nvec) + Hash(32B) + blinding_OOD(32B*...) + ...
        let narg = &proof.whir_r1cs_proof.narg_string;
        let mut pos: usize = 0;

        // Initial f_hat root hash (1 polynomial)
        let initial_root_hash = parse_hash(narg, pos);
        pos += 32;

        // OOD answers: ood_samples * num_vectors field elements
        let mut initial_ood_answers = Vec::with_capacity(ood_samples * num_vectors);
        for _ in 0..(ood_samples * num_vectors) {
            initial_ood_answers.push(parse_field(narg, pos));
            pos += 32;
        }

        // Blinding root hash
        let blinding_root_hash = parse_hash(narg, pos);
        pos += 32;

        // Blinding OOD answers
        let mut blinding_ood_answers =
            Vec::with_capacity(blinding_ood * blinding_num_vectors);
        for _ in 0..(blinding_ood * blinding_num_vectors) {
            blinding_ood_answers.push(parse_field(narg, pos));
            pos += 32;
        }

        // sum_g
        let sum_g = parse_field(narg, pos);
        pos += 32;

        // Spartan sumcheck: m_0 rounds, 4 coefficients each
        let mut sumcheck_coeffs = Vec::with_capacity(m_0);
        for _ in 0..m_0 {
            let c: [FieldElement; 4] = [
                parse_field(narg, pos),
                parse_field(narg, pos + 32),
                parse_field(narg, pos + 64),
                parse_field(narg, pos + 96),
            ];
            sumcheck_coeffs.push(c);
            pos += 128;
        }

        // blinding_eval
        let blinding_eval = parse_field(narg, pos);
        pos += 32;

        // public_inputs_hash
        let public_inputs_hash = parse_field(narg, pos);
        pos += 32;

        // evals: Az, Bz, Cz
        let evals_az = parse_field(narg, pos);
        pos += 32;
        let evals_bz = parse_field(narg, pos);
        pos += 32;
        let evals_cz = parse_field(narg, pos);
        pos += 32;

        // public_eval (if applicable)
        let public_eval = if !proof.public_inputs.0.is_empty() {
            let pe = parse_field(narg, pos);
            pos += 32;
            pe
        } else {
            FieldElement::zero()
        };

        info!(
            narg_offset_after_spartan = pos,
            narg_total = narg.len(),
            remaining = narg.len() - pos,
            "Parsed Spartan-level data from narg_string"
        );

        // === Parse zkWHIR prover messages ===

        // w_folded_blinding_evals
        let mut w_folded_evals = Vec::with_capacity(num_w_folded_evals);
        for _ in 0..num_w_folded_evals {
            w_folded_evals.push(parse_field(narg, pos));
            pos += 32;
        }

        // Per-gamma block: for each gamma, for each polynomial (=1):
        //   m_eval (1 field) + g_hat_evals (num_witness_variables fields)
        let mut gamma_m_evals = Vec::with_capacity(num_gammas);
        let mut gamma_g_hat_evals = Vec::with_capacity(num_gammas * num_witness_variables);
        for _ in 0..num_gammas {
            gamma_m_evals.push(parse_field(narg, pos));
            pos += 32;
            for _ in 0..num_witness_variables {
                gamma_g_hat_evals.push(parse_field(narg, pos));
                pos += 32;
            }
        }

        // combined_claims and batched_h_claims (1 each for single polynomial)
        let combined_claims = parse_field(narg, pos);
        pos += 32;
        let batched_h_claims = parse_field(narg, pos);
        pos += 32;

        info!(
            narg_offset_after_zkwhir_claims = pos,
            "Parsed zkWHIR claims from narg_string"
        );

        // === Parse inner WHIR prover messages (blinded commitment) ===

        // Initial sumcheck: initial_ff rounds of (c0, c2) + optional PoW nonces
        let (initial_whir_coeffs, _initial_sc_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, initial_ff, initial_sc_pow_active);
        pos += consumed;

        // Per-round WHIR data
        // For each round: receive_commitment (root + OOD answers) + PoW + sumcheck
        // STIR challenges and Merkle proofs are verifier-side / in hints
        let mut round_root_hashes = Vec::with_capacity(num_whir_rounds);
        let mut round_ood_answers: Vec<Vec<FieldElement>> = Vec::with_capacity(num_whir_rounds);
        let mut round_pow_nonces = Vec::with_capacity(num_whir_rounds);
        let mut round_sumcheck_coeffs: Vec<Vec<[FieldElement; 2]>> =
            Vec::with_capacity(num_whir_rounds);

        for r in 0..num_whir_rounds {
            // receive_commitment: root hash
            round_root_hashes.push(parse_hash(narg, pos));
            pos += 32;

            // receive_commitment: OOD answers
            let mut ood_ans = Vec::with_capacity(round_ood_samples[r]);
            for _ in 0..round_ood_samples[r] {
                ood_ans.push(parse_field(narg, pos));
                pos += 32;
            }
            round_ood_answers.push(ood_ans);

            // Round PoW nonce
            let nonce = if round_pow_active[r] {
                let n = parse_u64_le(narg, pos);
                pos += 8;
                n
            } else {
                0u64
            };
            round_pow_nonces.push(nonce);

            // Round sumcheck coefficients
            let (coeffs, _round_sc_nonces, consumed) =
                parse_whir_sumcheck(narg, pos, round_sc_rounds[r], round_sc_pow_active[r]);
            pos += consumed;
            round_sumcheck_coeffs.push(coeffs);
        }

        info!(
            narg_offset_after_inner_whir_rounds = pos,
            inner_rounds_parsed = num_whir_rounds,
            "Parsed inner WHIR per-round data"
        );

        // Final vector
        let mut final_coefficients = Vec::with_capacity(final_poly_size);
        for _ in 0..final_poly_size {
            final_coefficients.push(parse_field(narg, pos));
            pos += 32;
        }

        // Final PoW nonce
        let final_pow_nonce = if final_pow_active {
            let n = parse_u64_le(narg, pos);
            pos += 8;
            n
        } else {
            0u64
        };

        // Final sumcheck
        let (final_whir_coeffs, _final_sc_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, final_sumcheck_rounds, final_sc_pow_active);
        pos += consumed;

        info!(
            narg_offset_after_inner_whir = pos,
            remaining = narg.len() - pos,
            "Parsed inner WHIR data from narg_string"
        );

        // === Parse blinding WHIR prover messages ===

        // Blinding initial sumcheck
        let (blinding_initial_coeffs, _blinding_initial_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, blinding_ff, blinding_initial_sc_pow_active);
        pos += consumed;

        // Blinding per-round data
        let mut blinding_round_root_hashes = Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_ood_ans: Vec<Vec<FieldElement>> =
            Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_pow_nonce_vec = Vec::with_capacity(blinding_whir_rounds);
        let mut blinding_round_sumcheck_coeffs_vec: Vec<Vec<[FieldElement; 2]>> =
            Vec::with_capacity(blinding_whir_rounds);

        for r in 0..blinding_whir_rounds {
            blinding_round_root_hashes.push(parse_hash(narg, pos));
            pos += 32;

            let mut ood_ans = Vec::with_capacity(blinding_round_ood_samples[r]);
            for _ in 0..blinding_round_ood_samples[r] {
                ood_ans.push(parse_field(narg, pos));
                pos += 32;
            }
            blinding_round_ood_ans.push(ood_ans);

            let nonce = if blinding_round_pow_active[r] {
                let n = parse_u64_le(narg, pos);
                pos += 8;
                n
            } else {
                0u64
            };
            blinding_round_pow_nonce_vec.push(nonce);

            let (coeffs, _nonces, consumed) = parse_whir_sumcheck(
                narg,
                pos,
                blinding_round_sc_rounds[r],
                blinding_round_sc_pow_active[r],
            );
            pos += consumed;
            blinding_round_sumcheck_coeffs_vec.push(coeffs);
        }

        info!(
            narg_offset_after_blinding_whir_rounds = pos,
            blinding_rounds_parsed = blinding_whir_rounds,
            "Parsed blinding WHIR per-round data"
        );

        // Blinding final vector
        let mut blinding_final_coefficients = Vec::with_capacity(blinding_final_poly_size);
        for _ in 0..blinding_final_poly_size {
            blinding_final_coefficients.push(parse_field(narg, pos));
            pos += 32;
        }

        // Blinding final PoW nonce
        let blinding_final_pow_nonce = if blinding_final_pow_active {
            let n = parse_u64_le(narg, pos);
            pos += 8;
            n
        } else {
            0u64
        };

        // Blinding final sumcheck
        let (blinding_final_coeffs, _blinding_final_pow_nonces, consumed) =
            parse_whir_sumcheck(narg, pos, blinding_final_sc_rounds, blinding_final_sc_pow_active);
        pos += consumed;

        info!(
            narg_offset_after_blinding_whir = pos,
            narg_total = narg.len(),
            remaining_bytes = narg.len().saturating_sub(pos),
            "Parsed blinding WHIR data from narg_string"
        );

        if pos != narg.len() {
            info!(
                unparsed_bytes = narg.len() - pos,
                "Warning: {} unparsed bytes remain in narg_string",
                narg.len() - pos
            );
        }

        // === Extract R1CS matrices ===
        let r1cs = &verifier.r1cs;
        let ha = r1cs.a();
        let hb = r1cs.b();
        let hc = r1cs.c();

        let mut a_cells: Vec<(u32, u32, FieldElement)> = Vec::new();
        let mut b_cells: Vec<(u32, u32, FieldElement)> = Vec::new();
        let mut c_cells: Vec<(u32, u32, FieldElement)> = Vec::new();

        for row in 0..r1cs.a.num_rows {
            for (col, val) in ha.iter_row(row) {
                a_cells.push((row as u32, col as u32, val));
            }
        }
        for row in 0..r1cs.b.num_rows {
            for (col, val) in hb.iter_row(row) {
                b_cells.push((row as u32, col as u32, val));
            }
        }
        for row in 0..r1cs.c.num_rows {
            for (col, val) in hc.iter_row(row) {
                c_cells.push((row as u32, col as u32, val));
            }
        }

        info!(
            a_nnz = a_cells.len(),
            b_nnz = b_cells.len(),
            c_nnz = c_cells.len(),
            "Extracted R1CS matrices"
        );

        // === Write Prover.toml ===
        let mut out = String::new();
        writeln!(out, "# ProveKit Noir Recursive Verifier Inputs")?;
        writeln!(out, "# Generated by `provekit generate-noir-inputs`")?;
        writeln!(out, "# Config: m_0={m_0}, m={m}, rounds={num_whir_rounds}")?;
        writeln!(out)?;

        write_byte_array(&mut out, "protocol_id", &protocol_id)?;
        write_byte_array(&mut out, "instance", &instance)?;
        writeln!(out)?;

        write_byte_array(&mut out, "initial_root_hash", &initial_root_hash)?;
        write_field_array(&mut out, "initial_ood_answers", &initial_ood_answers)?;
        write_byte_array(&mut out, "blinding_root_hash", &blinding_root_hash)?;
        write_field_array(&mut out, "blinding_ood_answers", &blinding_ood_answers)?;
        writeln!(out)?;

        writeln!(out, "sum_g = \"{}\"", field_str(&sum_g))?;
        writeln!(out, "blinding_eval = \"{}\"", field_str(&blinding_eval))?;
        writeln!(out)?;

        writeln!(out, "sumcheck_coeffs = [")?;
        for (i, coeffs) in sumcheck_coeffs.iter().enumerate() {
            let comma = if i < sumcheck_coeffs.len() - 1 { "," } else { "" };
            writeln!(
                out,
                "  [\"{}\", \"{}\", \"{}\", \"{}\"]{}",
                field_str(&coeffs[0]),
                field_str(&coeffs[1]),
                field_str(&coeffs[2]),
                field_str(&coeffs[3]),
                comma
            )?;
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        writeln!(out, "num_public_inputs = {}", proof.public_inputs.0.len())?;
        if proof.public_inputs.0.is_empty() {
            writeln!(out, "public_inputs = [\"0\"]")?;
        } else {
            write_field_array(&mut out, "public_inputs", &proof.public_inputs.0)?;
        }
        writeln!(out, "public_inputs_hash_from_prover = \"{}\"", field_str(&public_inputs_hash))?;
        writeln!(out, "evals_az = \"{}\"", field_str(&evals_az))?;
        writeln!(out, "evals_bz = \"{}\"", field_str(&evals_bz))?;
        writeln!(out, "evals_cz = \"{}\"", field_str(&evals_cz))?;
        writeln!(out, "public_eval = \"{}\"", field_str(&public_eval))?;
        writeln!(out)?;

        // === zkWHIR data ===
        writeln!(out, "# --- Phase 4: zkWHIR ---")?;
        write_field_array(&mut out, "w_folded_evals", &w_folded_evals)?;
        writeln!(out)?;

        writeln!(out, "num_gammas = {num_gammas}")?;
        write_field_array(&mut out, "gamma_m_evals", &gamma_m_evals)?;
        // gamma_g_hat_evals is a 2D array: [MAX_GAMMAS][NUM_WITNESS_VARIABLES]
        writeln!(out, "gamma_g_hat_evals = [")?;
        for g in 0..num_gammas {
            let start = g * num_witness_variables;
            let end = start + num_witness_variables;
            let row: Vec<String> = gamma_g_hat_evals[start..end]
                .iter()
                .map(|f| format!("\"{}\"", field_str(f)))
                .collect();
            let comma = if g < num_gammas - 1 { "," } else { "" };
            writeln!(out, "  [{}]{comma}", row.join(", "))?;
        }
        writeln!(out, "]")?;
        writeln!(out, "combined_claims = \"{}\"", field_str(&combined_claims))?;
        writeln!(out, "batched_h_claims = \"{}\"", field_str(&batched_h_claims))?;
        writeln!(out)?;

        // === Inner WHIR data ===
        writeln!(out, "# --- Phase 4a: Inner WHIR (blinded) ---")?;
        writeln!(out, "initial_whir_sumcheck_coeffs = [")?;
        for (i, c) in initial_whir_coeffs.iter().enumerate() {
            let comma = if i < initial_whir_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;

        write_field_array(&mut out, "final_coefficients", &final_coefficients)?;
        writeln!(out, "final_pow_nonce = {final_pow_nonce}")?;
        writeln!(out, "final_num_queries = {max_queries}")?;

        writeln!(out, "final_whir_sumcheck_coeffs = [")?;
        for (i, c) in final_whir_coeffs.iter().enumerate() {
            let comma = if i < final_whir_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        // Per-round WHIR data
        writeln!(out, "# Per-round WHIR data ({num_whir_rounds} rounds)")?;
        writeln!(out, "round_root_hashes = [")?;
        for (r, rh) in round_root_hashes.iter().enumerate() {
            let comma = if r < num_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "  {:?}{comma}", rh)?;
        }
        writeln!(out, "]")?;

        writeln!(out, "round_ood_answers = [")?;
        for (r, answers) in round_ood_answers.iter().enumerate() {
            let vals: Vec<String> = answers.iter().map(|f| format!("\"{}\"", field_str(f))).collect();
            let comma = if r < num_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "  [{}]{comma}", vals.join(", "))?;
        }
        writeln!(out, "]")?;

        writeln!(out, "round_whir_sumcheck_coeffs = [")?;
        for (r, coeffs) in round_sumcheck_coeffs.iter().enumerate() {
            write!(out, "  [")?;
            for (i, c) in coeffs.iter().enumerate() {
                let comma = if i < coeffs.len() - 1 { ", " } else { "" };
                write!(out, "[\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
            }
            let comma = if r < num_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;

        writeln!(
            out,
            "round_pow_nonces = [{}]",
            round_pow_nonces.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
        )?;
        writeln!(out)?;

        // Final Merkle proofs (TODO: extract from proof hints)
        writeln!(out, "# Final Merkle proofs (TODO: extract from proof hints)")?;
        writeln!(out)?;

        // === Blinding WHIR data ===
        writeln!(out, "# --- Phase 4b: Blinding WHIR ---")?;
        writeln!(out, "blinding_whir_initial_coeffs = [")?;
        for (i, c) in blinding_initial_coeffs.iter().enumerate() {
            let comma = if i < blinding_initial_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;

        write_field_array(&mut out, "blinding_final_coefficients", &blinding_final_coefficients)?;
        writeln!(out, "blinding_final_pow_nonce = {blinding_final_pow_nonce}")?;
        writeln!(out, "blinding_final_num_queries = {blinding_queries}")?;

        writeln!(out, "blinding_final_sumcheck_coeffs = [")?;
        for (i, c) in blinding_final_coeffs.iter().enumerate() {
            let comma = if i < blinding_final_coeffs.len() - 1 { "," } else { "" };
            writeln!(out, "  [\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
        }
        writeln!(out, "]")?;
        writeln!(out)?;

        // Blinding per-round data
        writeln!(out, "# Blinding per-round data ({blinding_whir_rounds} rounds)")?;
        writeln!(out, "blinding_round_root_hashes = [")?;
        for (r, rh) in blinding_round_root_hashes.iter().enumerate() {
            let comma = if r < blinding_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "  {:?}{comma}", rh)?;
        }
        writeln!(out, "]")?;

        writeln!(out, "blinding_round_ood_answers = [")?;
        for (r, answers) in blinding_round_ood_ans.iter().enumerate() {
            let vals: Vec<String> = answers.iter().map(|f| format!("\"{}\"", field_str(f))).collect();
            let comma = if r < blinding_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "  [{}]{comma}", vals.join(", "))?;
        }
        writeln!(out, "]")?;

        writeln!(out, "blinding_round_sumcheck_coeffs = [")?;
        for (r, coeffs) in blinding_round_sumcheck_coeffs_vec.iter().enumerate() {
            write!(out, "  [")?;
            for (i, c) in coeffs.iter().enumerate() {
                let comma = if i < coeffs.len() - 1 { ", " } else { "" };
                write!(out, "[\"{}\", \"{}\"]{comma}", field_str(&c[0]), field_str(&c[1]))?;
            }
            let comma = if r < blinding_whir_rounds - 1 { "," } else { "" };
            writeln!(out, "]{comma}")?;
        }
        writeln!(out, "]")?;

        writeln!(
            out,
            "blinding_round_pow_nonces = [{}]",
            blinding_round_pow_nonce_vec.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
        )?;
        writeln!(out)?;

        // Blinding final Merkle proofs (TODO: extract from proof hints)
        writeln!(out, "# Blinding final Merkle proofs (TODO: extract from proof hints)")?;
        writeln!(out)?;

        // === R1CS matrices ===
        writeln!(out, "# --- Phase 5: R1CS matrices ---")?;
        write_matrix_cells(&mut out, "matrix_a", &a_cells)?;
        write_matrix_cells(&mut out, "matrix_b", &b_cells)?;
        write_matrix_cells(&mut out, "matrix_c", &c_cells)?;

        let mut toml_file =
            File::create(&self.output_path).context("while creating Prover.toml")?;
        toml_file
            .write_all(out.as_bytes())
            .context("while writing Prover.toml")?;

        info!(
            toml_path = %self.output_path,
            json_path = %self.json_path,
            "Noir verifier inputs generated"
        );

        Ok(())
    }
}

fn write_byte_array(out: &mut String, name: &str, bytes: &[u8]) -> std::fmt::Result {
    write!(out, "{name} = [")?;
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{b}")?;
    }
    writeln!(out, "]")
}

fn write_field_array(out: &mut String, name: &str, fields: &[FieldElement]) -> std::fmt::Result {
    write!(out, "{name} = [")?;
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "\"{}\"", field_str(f))?;
    }
    writeln!(out, "]")
}

fn write_matrix_cells(
    out: &mut String,
    prefix: &str,
    cells: &[(u32, u32, FieldElement)],
) -> std::fmt::Result {
    write!(out, "{prefix}_rows = [")?;
    for (i, (r, _, _)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{r}")?;
    }
    writeln!(out, "]")?;

    write!(out, "{prefix}_cols = [")?;
    for (i, (_, c, _)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "{c}")?;
    }
    writeln!(out, "]")?;

    write!(out, "{prefix}_vals = [")?;
    for (i, (_, _, v)) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, ", ")?;
        }
        write!(out, "\"{}\"", field_str(v))?;
    }
    writeln!(out, "]")?;

    writeln!(out, "{}_len = {}", prefix.replace("matrix_", ""), cells.len())
}
