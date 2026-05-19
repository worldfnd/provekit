use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    ark_bn254::Fr,
    ark_ff::PrimeField,
    provekit_common::{
        file::read, poseidon2::Poseidon2Sponge, FieldElement, NoirProof, Verifier,
    },
    spongefish::DuplexSpongeInterface,
    std::{
        cell::RefCell,
        collections::BTreeMap,
        path::PathBuf,
        rc::Rc,
    },
    tracing::instrument,
};

/// Emit Noir verifier inputs (types.nr / matrices.nr / Prover.toml) from a
/// `.pkv` (ProveKit Verifier) and a `.np` (Noir proof) file generated under
/// `HashConfig::Poseidon2`.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-noir-inputs")]
pub struct Args {
    /// path to the ProveKit Verifier (PKV) file
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the Noir proof (.np) file
    #[argh(positional)]
    proof_path: PathBuf,

    /// output directory for the generated Noir crate inputs
    /// (default: `provekit/verifier-noir`)
    #[argh(option, default = "PathBuf::from(\"provekit/verifier-noir\")")]
    out_dir: PathBuf,

    /// dump the byte-grain transcript trace produced by replaying the Rust
    /// verifier with a logging sponge, then exit. No codegen output is
    /// written. Used for diagnosing desyncs against the Noir verifier.
    #[argh(switch)]
    trace: bool,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier = read(&self.verifier_path)
            .with_context(|| format!("reading PKV from {}", self.verifier_path.display()))?;
        let proof: NoirProof = read(&self.proof_path)
            .with_context(|| format!("reading NP from {}", self.proof_path.display()))?;

        let scheme = verifier
            .whir_for_witness
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PKV has no WHIR scheme (Mavros only?)"))?;

        let nonzeros = nonzero_counts(&verifier.r1cs);

        println!("scheme summary:");
        println!("  hash_config       = {}", verifier.hash_config);
        println!("  m                 = {}", scheme.m);
        println!("  m_0               = {}", scheme.m_0);
        println!("  w1_size           = {}", scheme.w1_size);
        println!("  num_challenges    = {}", scheme.num_challenges);
        println!("  has_public_inputs = {}", scheme.has_public_inputs);
        println!("  num_constraints   = {}", verifier.r1cs.num_constraints());
        println!("  num_witnesses     = {}", verifier.r1cs.num_witnesses());
        println!("  num_public_inputs = {}", verifier.r1cs.num_public_inputs);
        println!("  nonzeros A/B/C    = {}/{}/{}", nonzeros.0, nonzeros.1, nonzeros.2);
        println!("  proof narg bytes  = {}", proof.whir_r1cs_proof.narg_string.len());
        println!("  proof hint bytes  = {}", proof.whir_r1cs_proof.hints.len());
        println!("  public inputs len = {}", proof.public_inputs.len());

        // WHIR config summary (blinded_commitment = witness-side WHIR).
        let wc = &scheme.whir_witness.blinded_commitment;
        println!("  WHIR config (witness-side):");
        println!(
            "    num_witness_variables    = {}",
            scheme.whir_witness.num_witness_variables()
        );
        println!(
            "    num_blinding_variables   = {}",
            scheme.whir_witness.num_blinding_variables()
        );
        println!(
            "    initial folding_factor   = {} (interleaving_depth={})",
            wc.initial_committer.interleaving_depth.trailing_zeros(),
            wc.initial_committer.interleaving_depth,
        );
        println!(
            "    initial codeword_length  = {}",
            wc.initial_committer.codeword_length,
        );
        println!(
            "    initial num_vectors      = {}",
            wc.initial_committer.num_vectors,
        );
        println!(
            "    initial OOD samples      = {}",
            wc.initial_committer.out_domain_samples,
        );
        println!(
            "    initial in-domain samples= {}",
            wc.initial_committer.in_domain_samples,
        );
        println!(
            "    initial sumcheck rounds  = {}",
            wc.initial_sumcheck.num_rounds,
        );
        println!(
            "    initial sumcheck PoW     = {:.2}",
            wc.initial_sumcheck.round_pow.difficulty(),
        );
        println!("    num WHIR rounds          = {}", wc.round_configs.len());
        for (i, rc) in wc.round_configs.iter().enumerate() {
            println!(
                "    round[{i}] folding_factor  = {} (interleaving_depth={})",
                rc.irs_committer.interleaving_depth.trailing_zeros(),
                rc.irs_committer.interleaving_depth,
            );
            println!(
                "    round[{i}] codeword_length = {}",
                rc.irs_committer.codeword_length,
            );
            println!(
                "    round[{i}] OOD samples     = {}",
                rc.irs_committer.out_domain_samples,
            );
            println!(
                "    round[{i}] in-domain samp  = {}",
                rc.irs_committer.in_domain_samples,
            );
            println!(
                "    round[{i}] query PoW       = {:.2}",
                rc.pow.difficulty(),
            );
            println!(
                "    round[{i}] sumcheck rounds = {}",
                rc.sumcheck.num_rounds,
            );
            println!(
                "    round[{i}] sumcheck PoW    = {:.2}",
                rc.sumcheck.round_pow.difficulty(),
            );
        }
        // Blinding-side WHIR config summary
        let bc = &scheme.whir_witness.blinding_commitment;
        println!("  WHIR config (blinding-side):");
        println!(
            "    initial folding_factor   = {} (interleaving_depth={})",
            bc.initial_committer.interleaving_depth.trailing_zeros(),
            bc.initial_committer.interleaving_depth,
        );
        println!(
            "    initial codeword_length  = {}",
            bc.initial_committer.codeword_length,
        );
        println!(
            "    initial OOD samples      = {}",
            bc.initial_committer.out_domain_samples,
        );
        println!(
            "    initial in-domain samples= {}",
            bc.initial_committer.in_domain_samples,
        );
        println!(
            "    initial sumcheck rounds  = {}",
            bc.initial_sumcheck.num_rounds,
        );
        println!("    num WHIR rounds          = {}", bc.round_configs.len());
        for (i, rc) in bc.round_configs.iter().enumerate() {
            println!(
                "    round[{i}] folding_factor  = {} (interleaving_depth={})",
                rc.irs_committer.interleaving_depth.trailing_zeros(),
                rc.irs_committer.interleaving_depth,
            );
            println!(
                "    round[{i}] codeword_length = {}",
                rc.irs_committer.codeword_length,
            );
            println!(
                "    round[{i}] OOD samples     = {}",
                rc.irs_committer.out_domain_samples,
            );
            println!(
                "    round[{i}] in-domain samp  = {}",
                rc.irs_committer.in_domain_samples,
            );
            println!(
                "    round[{i}] query PoW       = {:.2}",
                rc.pow.difficulty(),
            );
            println!(
                "    round[{i}] sumcheck rounds = {}",
                rc.sumcheck.num_rounds,
            );
        }
        println!(
            "    final sumcheck rounds    = {}",
            bc.final_sumcheck.num_rounds,
        );
        println!("    final PoW                = {:.2}", bc.final_pow.difficulty());
        println!(
            "    initial codeword_length (witness)  = {}",
            wc.initial_committer.codeword_length,
        );
        println!(
            "    final sumcheck rounds    = {}",
            wc.final_sumcheck.num_rounds,
        );
        println!(
            "    final sumcheck PoW       = {:.2}",
            wc.final_sumcheck.round_pow.difficulty(),
        );
        println!("    final PoW                = {:.2}", wc.final_pow.difficulty());

        anyhow::ensure!(
            verifier.hash_config == provekit_common::HashConfig::Poseidon2,
            "PKV hash_config is {}, but generate-noir-inputs only supports Poseidon2 for v0",
            verifier.hash_config
        );

        anyhow::ensure!(
            scheme.num_challenges == 0,
            "generate-noir-inputs v0 does not support multi-commit circuits (num_challenges = {})",
            scheme.num_challenges
        );

        // --trace mode: dump the byte-grain transcript trace by re-running the
        // verifier with a LoggingSponge and exit before any file output.
        if self.trace {
            return dump_transcript_trace(&verifier, scheme, &proof);
        }

        // Emit types.nr
        let src_dir = self.out_dir.join("src");
        std::fs::create_dir_all(&src_dir)
            .with_context(|| format!("creating {}", src_dir.display()))?;
        let types_path = src_dir.join("types.nr");
        let types_src = emit_types_nr(&verifier, scheme);
        std::fs::write(&types_path, &types_src)
            .with_context(|| format!("writing {}", types_path.display()))?;
        eprintln!("wrote {}", types_path.display());

        let matrices_path = src_dir.join("matrices.nr");
        let matrices_src = emit_matrices_nr(&verifier);
        std::fs::write(&matrices_path, &matrices_src)
            .with_context(|| format!("writing {}", matrices_path.display()))?;
        eprintln!("wrote {}", matrices_path.display());

        // Emit Prover.toml by walking the proof's narg_string field-by-field
        // in the documented verifier order.
        let prover_toml_path = self.out_dir.join("Prover.toml");
        let prover_toml = emit_prover_toml(&verifier, scheme, &proof)
            .context("emitting Prover.toml from proof bytes")?;
        std::fs::write(&prover_toml_path, &prover_toml)
            .with_context(|| format!("writing {}", prover_toml_path.display()))?;
        eprintln!("wrote {}", prover_toml_path.display());

        Ok(())
    }
}

/// Walks `proof.narg_string` field-element-by-field-element in the same order
/// as `WhirR1CSVerifier::verify` consumes them, and emits a Prover.toml that
/// `main.nr` accepts.
///
/// Approach: the narg_string contains only `prover_message` bytes (each
/// `Fr` is 32 LE bytes; each `U64` is 8 LE bytes). `verifier_message`
/// values are squeezed from the sponge so they do not appear in narg_string,
/// and we don't need to recompute them here (main.nr re-derives them).
///
/// Merkle openings and other `prover_hint_ark` data live in `proof.hints`,
/// not narg_string, so they're naturally skipped here.
///
/// For basic-2 the verifier's narg consumption order (see
/// `provekit/verifier/src/whir_r1cs.rs` and `whir_zk::Config::verify`):
///
/// 1. Witness-side initial commitment (`receive_commitments(_, 1)`):
///    - 1 Merkle root          (Hash, 32 bytes)
///    - INITIAL_OOD_COUNT OOD evals (Fr each)
/// 2. Outer-Spartan sumcheck (`run_sumcheck_verifier`, m_0=1):
///    - 1 sum_g  (Fr)
///    - For each of m_0 rounds: 4 cubic-polynomial coeffs (Fr)
///    - 1 blinding_eval (Fr)
/// 3. Public-inputs hash: absent for basic-2 (no public inputs).
/// 4. A/B/C eval hints: 3 Fr (`evals_az`, `evals_bz`, `evals_cz`).
/// 5. zkWHIR `verify` (the big one):
///    - 14 w_folded_blinding_evals (Fr each)
///    - Witness-side initial WHIR commitment:
///      - 1 root (Hash)
///      - INITIAL_OOD_COUNT OOD evals (Fr)
///    - Per h_gamma per polynomial (1 gamma * 1 poly for basic-2):
///      - 1 m_eval (Fr) + NUM_WITNESS_VARIABLES g_hat_evals (Fr)
///    - combined_claims (1 Fr) + batched_h_claims (1 Fr)
///    - witness-side WHIR LDT (`blinded_commitment.verify`):
///      - per round:
///        - 1 root + OOD evals + sumcheck round polys + PoW nonce
///      - final round: final_vector + PoW nonce + final sumcheck
///    - blinding-side WHIR LDT (`blinding_commitment.verify`): also consumed
///      but emitted only as needed.
fn emit_prover_toml(
    verifier: &Verifier,
    scheme: &provekit_common::WhirR1CSScheme,
    proof: &NoirProof,
) -> Result<String> {
    let wc = &scheme.whir_witness.blinded_commitment;
    let bc = &scheme.whir_witness.blinding_commitment;
    let initial_ood_count = wc.initial_committer.out_domain_samples;
    let initial_sumcheck_rounds = wc.initial_sumcheck.num_rounds;
    let final_sumcheck_rounds = wc.final_sumcheck.num_rounds;
    let num_witness_variables = scheme.whir_witness.num_witness_variables();
    let num_polynomials = 1usize; // basic-2: single committed polynomial
    let num_witness_variables_plus_1 = num_witness_variables + 1;

    let interleaving_depth = wc.initial_committer.interleaving_depth;
    let num_gammas = initial_ood_count * interleaving_depth;
    // Number of weights inside the inner WHIR call. For basic-2 with no
    // public inputs and no challenges: 3 covectors (alpha_A, alpha_B,
    // alpha_C) + 1 blinding_covector = 4.
    //
    // TODO(generalize): derive `num_weights` from the same logic
    // `whir_r1cs.rs` uses to build `weight_refs`. For basic-2 we hardcode 4
    // and pin it via assertion below.
    let num_weights = 4usize;
    let w_folded_evals_len = num_weights * num_polynomials * num_witness_variables_plus_1;

    let final_polynomial_len = wc.final_sumcheck.initial_size;

    // Inner-WHIR sumcheck mask_length (basic-2 => 0). With mask_length=0
    // and num_rounds>0, the inner-sumcheck verifier reads `1 + max(3, ml) - 2 = max(1, ml-1)`
    // fields per round. For ml=0: that's 1 + 1 = 2 fields per round. We pin
    // INNER_SUMCHECK_FIELDS_PER_ROUND = 2 below; if the scheme ever requires
    // non-zero mask_length, regenerate.
    let initial_sumcheck_mask_len = wc.initial_sumcheck.mask_length;
    anyhow::ensure!(
        initial_sumcheck_mask_len == 0,
        "generate-noir-inputs v0 only supports mask_length=0 inner sumcheck \
         (got initial_sumcheck.mask_length = {initial_sumcheck_mask_len})"
    );
    // Same constraint for each round's sumcheck and the final sumcheck.
    for (i, rc) in wc.round_configs.iter().enumerate() {
        anyhow::ensure!(
            rc.sumcheck.mask_length == 0,
            "round[{i}].sumcheck.mask_length must be 0 (got {})",
            rc.sumcheck.mask_length
        );
        anyhow::ensure!(
            rc.sumcheck.round_pow.threshold == u64::MAX,
            "round[{i}].sumcheck.round_pow must be disabled (threshold = u64::MAX); \
             got threshold = {}",
            rc.sumcheck.round_pow.threshold
        );
    }
    anyhow::ensure!(
        wc.final_sumcheck.mask_length == 0,
        "final_sumcheck.mask_length must be 0 (got {})",
        wc.final_sumcheck.mask_length
    );
    anyhow::ensure!(
        wc.initial_sumcheck.round_pow.threshold == u64::MAX,
        "initial_sumcheck.round_pow must be disabled; got threshold = {}",
        wc.initial_sumcheck.round_pow.threshold
    );
    anyhow::ensure!(
        wc.final_sumcheck.round_pow.threshold == u64::MAX,
        "final_sumcheck.round_pow must be disabled; got threshold = {}",
        wc.final_sumcheck.round_pow.threshold
    );

    let mut p = NargParser::new(&proof.whir_r1cs_proof.narg_string);
    let mut values: BTreeMap<String, TomlValue> = BTreeMap::new();

    // Pre-absorbed sponge state: compute the exact sponge state after the
    // domain-separator absorbs (protocol_id || session_id || instance) so the
    // Noir verifier's transcript starts at the same state as the Rust prover.
    let (pre_state, pre_absorb_pos, pre_squeeze_pos) =
        compute_pre_absorbed_state(verifier, scheme, proof)
            .context("computing pre-absorbed sponge state")?;
    values.insert(
        "pre_absorbed_state".to_string(),
        TomlValue::FieldArray(pre_state.to_vec()),
    );
    values.insert(
        "pre_absorbed_absorb_pos".to_string(),
        TomlValue::U32String(pre_absorb_pos),
    );
    values.insert(
        "pre_absorbed_squeeze_pos".to_string(),
        TomlValue::U32String(pre_squeeze_pos),
    );

    // Step 1: receive_commitments(_, 1) which calls:
    //   (a) blinded_commitment.receive_commitment  -> 1 root + INITIAL_OOD_COUNT OOD evals
    //   (b) blinding_commitment.receive_commitment -> 1 root + BLINDING_OOD_COUNT OOD evals
    // Both commitments are absorbed into the transcript before the sumcheck.

    // Step 1a: witness-side blinded IRS commitment.
    let initial_root = p.read_hash_as_field()?;
    values.insert("initial_root".to_string(), TomlValue::Field(initial_root));
    let initial_ood_evals = p.read_field_vec(initial_ood_count)?;
    values.insert(
        "initial_ood_evals".to_string(),
        TomlValue::FieldArray(initial_ood_evals),
    );

    // Step 1b: blinding-side commitment (root + OOD evals).
    // Also consumed by the Noir circuit to keep the transcript in sync.
    // Total OOD eval fields = out_domain_samples * num_vectors.
    let blinding_ood_eval_count =
        bc.initial_committer.out_domain_samples * bc.initial_committer.num_vectors;
    let blinding_initial_root = p.read_hash_as_field()?;
    values.insert(
        "blinding_initial_root".to_string(),
        TomlValue::Field(blinding_initial_root),
    );
    let blinding_initial_ood_evals = p.read_field_vec(blinding_ood_eval_count)?;
    values.insert(
        "blinding_initial_ood_evals".to_string(),
        TomlValue::FieldArray(blinding_initial_ood_evals),
    );

    // Step 2: outer-Spartan sumcheck.
    let sum_g = p.read_field()?;
    values.insert("sum_g".to_string(), TomlValue::Field(sum_g));
    let mut sumcheck_h_polys: Vec<Vec<Fr>> = Vec::with_capacity(scheme.m_0);
    for _ in 0..scheme.m_0 {
        sumcheck_h_polys.push(p.read_field_vec(4)?);
    }
    values.insert(
        "sumcheck_h_polys".to_string(),
        TomlValue::FieldMatrix(sumcheck_h_polys),
    );
    let blinding_eval = p.read_field()?;
    values.insert("blinding_eval".to_string(), TomlValue::Field(blinding_eval));

    // Step 3 (no challenges).
    // Step 4: public-inputs hash. The Rust prover UNCONDITIONALLY writes a
    // public_inputs_hash field via `merlin.prover_message(&public_inputs_hash)`
    // (see `prover/src/whir_r1cs.rs::get_public_weights`), so the verifier
    // UNCONDITIONALLY reads it via `arthur.prover_message()?`. Even for
    // shapes with NUM_PUBLIC_INPUTS = 0 the field is present in the narg
    // stream and must be absorbed into the transcript -- skipping it causes
    // every downstream absorb to use the wrong bytes (off-by-32 desync).
    let public_inputs_hash = p.read_field()?;
    values.insert(
        "public_inputs_hash".to_string(),
        TomlValue::Field(public_inputs_hash),
    );

    // Step 5: A/B/C evals.
    let evals_az = p.read_field()?;
    let evals_bz = p.read_field()?;
    let evals_cz = p.read_field()?;
    values.insert("evals_az".to_string(), TomlValue::Field(evals_az));
    values.insert("evals_bz".to_string(), TomlValue::Field(evals_bz));
    values.insert("evals_cz".to_string(), TomlValue::Field(evals_cz));

    // Step 6: zkWHIR verify.
    //   6a. w_folded_blinding_evals
    let w_folded_blinding_evals = p.read_field_vec(w_folded_evals_len)?;
    values.insert(
        "w_folded_blinding_evals".to_string(),
        TomlValue::FieldArray(w_folded_blinding_evals),
    );

    //   6b. The Rust `whir_zk::Config::verify` calls
    //       `blinded_commitment.initial_committer.verify(...)` here, which
    //       squeezes 254 query-index bytes from the transcript (handled in
    //       main.nr via stub_prev_commit_open) and reads only `hints` for the
    //       Merkle openings. **No narg bytes are consumed at this point.**
    //
    //   Previously this codegen emitted phantom `witness_initial_root` and
    //   `witness_initial_ood_evals` fields, mis-aligning the parse by 64
    //   bytes (32 for the bogus root + 32 for the bogus OOD). That has been
    //   removed.

    //   6c. Per h_gamma per polynomial: m_eval + g_hat_evals.
    let mut witness_m_evals: Vec<Fr> = Vec::with_capacity(num_gammas * num_polynomials);
    let mut witness_g_hat_evals: Vec<Fr> =
        Vec::with_capacity(num_gammas * num_polynomials * num_witness_variables);
    for _ in 0..num_gammas {
        for _ in 0..num_polynomials {
            witness_m_evals.push(p.read_field()?);
            for _ in 0..num_witness_variables {
                witness_g_hat_evals.push(p.read_field()?);
            }
        }
    }
    values.insert(
        "witness_m_evals".to_string(),
        TomlValue::FieldArray(witness_m_evals),
    );
    values.insert(
        "witness_g_hat_evals".to_string(),
        TomlValue::FieldArray(witness_g_hat_evals),
    );

    //   6d. combined_claims + batched_h_claims.
    let combined_claims = p.read_field_vec(num_polynomials)?;
    values.insert(
        "combined_claims".to_string(),
        TomlValue::FieldArray(combined_claims),
    );
    let batched_h_claims = p.read_field_vec(num_polynomials)?;
    values.insert(
        "batched_h_claims".to_string(),
        TomlValue::FieldArray(batched_h_claims),
    );

    //   6e. Witness-side WHIR LDT (blinded_commitment.verify), see
    //       `~/.cargo/git/checkouts/whir-…/src/protocols/whir/verifier.rs`.
    //
    //   Inner-WHIR sumcheck is quadratic: each round writes 2 fields (c0, c2)
    //   when mask_length=0 (basic-2). The verifier derives c1 from
    //   `sum - 2*c0 - c2`. No per-round PoW nonces (sumcheck.round_pow=none for
    //   basic-2).
    //
    //   Per-WHIR-round shape (the round loop):
    //     1. receive_commitment(this round): root + OOD evals (no narg reads
    //        for the squeezed OOD points)
    //     2. round_config.pow.verify: nonce (8 bytes)
    //     3. open prev commit: NO narg reads (Merkle hints live in `hints`)
    //     4. sumcheck (num_rounds rounds): each round 2 fields, no nonce.
    //
    //   Final round shape:
    //     1. final_vector: final_sumcheck.initial_size fields
    //     2. final_pow.verify: nonce (8 bytes)
    //     3. open last commit: NO narg reads
    //     4. final_sumcheck (num_rounds rounds): each round 2 fields, no nonce.

    // -- Initial-sumcheck round polynomials (executed BEFORE the round loop
    //    in whir::Config::verify). Each round reads 2 fields (c0, c2).
    let mut initial_sumcheck_polys: Vec<Vec<Fr>> = Vec::with_capacity(initial_sumcheck_rounds);
    for _ in 0..initial_sumcheck_rounds {
        let pair = p.read_field_vec(2)?;
        initial_sumcheck_polys.push(pair);
    }
    values.insert(
        "initial_sumcheck_polys".to_string(),
        TomlValue::FieldMatrix(initial_sumcheck_polys),
    );

    // -- Subsequent WHIR rounds.
    let mut whir_round_roots: Vec<Fr> = Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_ood_evals: Vec<Vec<Fr>> = Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_pow_nonces: Vec<[u8; 8]> = Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_sumcheck_polys: Vec<Vec<Vec<Fr>>> =
        Vec::with_capacity(wc.round_configs.len());

    for round_config in &wc.round_configs {
        // receive_commitment(this round): root + OOD evals.
        let root = p.read_hash_as_field()?;
        whir_round_roots.push(root);
        let ood = p
            .read_field_vec(round_config.irs_committer.out_domain_samples)?;
        whir_round_ood_evals.push(ood);

        // round_config.pow.verify: 8-byte nonce.
        let nonce = p.read_u64_bytes()?;
        whir_round_pow_nonces.push(nonce);

        // sumcheck for this round: num_rounds rounds, each 2 fields.
        let mut per_round_polys: Vec<Vec<Fr>> =
            Vec::with_capacity(round_config.sumcheck.num_rounds);
        for _ in 0..round_config.sumcheck.num_rounds {
            let pair = p.read_field_vec(2)?;
            per_round_polys.push(pair);
        }
        whir_round_sumcheck_polys.push(per_round_polys);
    }

    values.insert(
        "whir_round_roots".to_string(),
        TomlValue::FieldArray(whir_round_roots),
    );
    values.insert(
        "whir_round_ood_evals".to_string(),
        TomlValue::FieldMatrix(whir_round_ood_evals),
    );
    values.insert(
        "whir_round_sumcheck_polys".to_string(),
        TomlValue::FieldCube(whir_round_sumcheck_polys),
    );
    values.insert(
        "whir_round_pow_nonces".to_string(),
        TomlValue::U8Matrix(
            whir_round_pow_nonces
                .into_iter()
                .map(|arr| arr.to_vec())
                .collect(),
        ),
    );

    // -- Final round of the witness-side WHIR LDT.
    // final_vector first (size = final_sumcheck.initial_size), then PoW nonce.
    let final_vector = p.read_field_vec(final_polynomial_len)?;
    values.insert(
        "whir_final_vector".to_string(),
        TomlValue::FieldArray(final_vector.clone()),
    );

    let final_pow_nonce = p.read_u64_bytes()?;
    values.insert(
        "whir_final_pow_nonce".to_string(),
        TomlValue::U8Array(final_pow_nonce.to_vec()),
    );

    // Final sumcheck (FINAL_SUMCHECK_ROUNDS rounds, each 2 fields).
    let mut whir_final_sumcheck_polys: Vec<Vec<Fr>> =
        Vec::with_capacity(final_sumcheck_rounds);
    for _ in 0..final_sumcheck_rounds {
        let pair = p.read_field_vec(2)?;
        whir_final_sumcheck_polys.push(pair);
    }
    values.insert(
        "whir_final_sumcheck_polys".to_string(),
        TomlValue::FieldMatrix(whir_final_sumcheck_polys),
    );

    // The blinding-side WHIR LDT messages also follow (mirror structure)
    // but main.nr doesn't expose them yet. We do NOT need to parse them
    // here -- the unused trailing bytes are tolerated since we stop at our
    // current position and `nargo execute` won't see them.

    let _ = bc; // suppress unused warning when shape inspection is skipped.

    // Format Prover.toml: emit in deterministic (alphabetical) order.
    let mut out = String::new();
    for (k, v) in &values {
        out.push_str(&format!("{} = {}\n", k, v.format()));
    }
    Ok(out)
}

/// Replay the Rust verify flow against the basic-2 proof with a `LoggingSponge`
/// and dump every absorb/squeeze op to stdout in order. Used as a diagnostic
/// for transcript desyncs between the Rust verifier and the Noir verifier.
///
/// Scope: only the v0 path (single commitment, Poseidon2, no challenges). The
/// implementation mirrors `WhirR1CSScheme::verify` step by step but stops at
/// the witness-side WHIR LDT round-0 PoW (where the current Noir verifier
/// fails). All earlier ops are dumped so a desync can be located by diff
/// against an analogous Noir-side replay.
fn dump_transcript_trace(
    verifier: &Verifier,
    scheme: &provekit_common::WhirR1CSScheme,
    proof: &NoirProof,
) -> Result<()> {
    use whir::transcript::{Proof, VerifierMessage, VerifierState};

    provekit_common::register_ntt();

    let instance = proof.public_inputs.hash_bytes(verifier.hash_config);
    let ds = scheme.create_domain_separator().instance(&instance);
    let whir_proof = Proof {
        narg_string: proof.whir_r1cs_proof.narg_string.clone(),
        hints:       proof.whir_r1cs_proof.hints.clone(),
        #[cfg(debug_assertions)]
        pattern:     proof.whir_r1cs_proof.pattern.clone(),
    };

    let logging = LoggingSponge::default();
    let log_handle = logging.log.clone();
    let mut arthur = VerifierState::new(&ds, &whir_proof, logging);

    let mut op_index = 0usize;
    let mut dump = |label: &str, log: &Rc<RefCell<Vec<SpongeOp>>>| {
        let mut log_mut = log.borrow_mut();
        while op_index < log_mut.len() {
            let op = log_mut[op_index].clone();
            let prefix = if op_index == 0 {
                format!("[{}]", label)
            } else {
                "         ".to_string()
            };
            match &op {
                SpongeOp::Absorb(bytes) => {
                    println!(
                        "op {:>4} {} ABSORB ({:>3} bytes) {}",
                        op_index,
                        prefix,
                        bytes.len(),
                        hex_short(bytes),
                    );
                }
                SpongeOp::Squeeze(n) => {
                    println!("op {:>4} {} SQUEEZE ({:>3} bytes)", op_index, prefix, n);
                }
                SpongeOp::Ratchet => {
                    println!("op {:>4} {} RATCHET", op_index, prefix);
                }
            }
            op_index += 1;
        }
        let _ = label;
        drop(log_mut);
    };

    println!("=== Transcript trace for basic-2 verify flow ===");
    dump("DS_INIT", &log_handle);

    // Step 1: receive_commitments(1).
    let commitment_1 = scheme
        .whir_witness
        .receive_commitments(&mut arthur, 1)
        .map_err(|_| anyhow::anyhow!("failed receive_commitments(1)"))?;
    dump("receive_commitments(1)", &log_handle);

    // Step 2: Spartan sumcheck (inline replay of run_sumcheck_verifier).
    let _r: Vec<ark_bn254::Fr> = arthur.verifier_message_vec(scheme.m_0);
    let _sum_g: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read sum_g"))?;
    let _rho: ark_bn254::Fr = arthur.verifier_message();
    for _ in 0..scheme.m_0 {
        let _h0: ark_bn254::Fr = arthur.prover_message().unwrap();
        let _h1: ark_bn254::Fr = arthur.prover_message().unwrap();
        let _h2: ark_bn254::Fr = arthur.prover_message().unwrap();
        let _h3: ark_bn254::Fr = arthur.prover_message().unwrap();
        let _alpha: ark_bn254::Fr = arthur.verifier_message();
    }
    let _blinding_eval: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read blinding_eval"))?;
    dump("spartan_sumcheck", &log_handle);

    // Step 3: public_inputs_hash absorb (unconditional).
    let _pih: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read public_inputs_hash"))?;
    dump("public_inputs_hash", &log_handle);

    // Step 4: squeeze x.
    let _x: ark_bn254::Fr = arthur.verifier_message();
    dump("squeeze_x", &log_handle);

    // Step 5: 3 evals (az, bz, cz).
    let az: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read evals_az"))?;
    let bz: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read evals_bz"))?;
    let cz: ark_bn254::Fr = arthur
        .prover_message()
        .map_err(|_| anyhow::anyhow!("failed to read evals_cz"))?;
    dump("evals_az_bz_cz", &log_handle);

    // Step 6+: call the real zkWHIR verify with our logging sponge. We need
    // valid `weights` and `evaluations`. Build them as the real verifier does.
    use provekit_common::{
        prefix_covector::{build_prefix_covectors, expand_powers, OffsetCovector},
        utils::sumcheck::{multiply_transposed_by_eq_alpha, transpose_r1cs_matrices},
    };
    use whir::algebra::linear_form::LinearForm;

    // Re-do Spartan to get `alpha` since we need it; we already consumed the
    // narg, so we need to redo. Actually we already squeezed `alpha_0` from the
    // verifier. Let's reconstruct it by replaying narg bytes:
    // This is a hack -- we don't bother reconstructing. We just call the real
    // whir_witness.verify here using DUMMY weights/evaluations.
    //
    // Since whir.verify consumes the transcript regardless of weight
    // correctness, the trace will still capture all ops. The final assertion
    // (linear form matching) might fail but we just want the trace.

    // Build alphas (3 vectors) from Spartan's alpha (which we discarded but we
    // need to reconstruct). Simplest: just provide empty/zero alphas. The
    // result evaluations won't match but the transcript flow is the same.

    let (at, bt, ct) = transpose_r1cs_matrices(&verifier.r1cs);
    let dummy_alpha = vec![ark_bn254::Fr::from(0u64); scheme.m_0];
    let alphas = multiply_transposed_by_eq_alpha(&at, &bt, &ct, &dummy_alpha, &verifier.r1cs);
    let blinding_eval = ark_bn254::Fr::from(0u64);
    let blinding_weights = expand_powers::<4>(&dummy_alpha);
    let domain_size = 1usize << scheme.m;
    let blinding_covector = OffsetCovector::new(blinding_weights, scheme.w1_size, domain_size);
    let mut weights = build_prefix_covectors(scheme.m, alphas);
    // No public inputs for basic-2.
    let mut evaluations = vec![az, bz, cz];
    evaluations.push(blinding_eval);
    let mut weight_refs: Vec<&dyn LinearForm<ark_bn254::Fr>> = weights
        .iter()
        .map(|w| w as &dyn LinearForm<ark_bn254::Fr>)
        .collect();
    weight_refs.push(&blinding_covector as &dyn LinearForm<ark_bn254::Fr>);

    eprintln!("about to call whir_witness.verify...");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scheme.whir_witness.verify(&mut arthur, &weight_refs, &evaluations, &commitment_1)
    }));
    match &result {
        Ok(Ok(_)) => eprintln!("whir_witness.verify OK"),
        Ok(Err(_)) => eprintln!("whir_witness.verify returned Err"),
        Err(_) => eprintln!("whir_witness.verify PANICKED"),
    }
    dump("whir_witness.verify", &log_handle);

    // Continue replaying the blinding-side WHIR LDT manually with fresh
    // dummy weights/evaluations to capture transcript ops.
    // (Actually: since `whir_zk::verify` consumes commitments.blinding
    // internally, we don't repeat that here. The trace already includes
    // anything `verify` performed up to its early-exit Err point.)

    println!("=== trace stopped after full zkWHIR verify ===");
    println!("ops captured: {}", op_index);
    drop(weights);

    Ok(())
}

/// Render the first up-to-16 bytes of a byte slice as ASCII hex for the trace.
fn hex_short(bytes: &[u8]) -> String {
    let n = bytes.len().min(16);
    let mut out = String::with_capacity(n * 2 + 4);
    for b in &bytes[..n] {
        out.push_str(&format!("{:02x}", b));
    }
    if bytes.len() > n {
        out.push_str("...");
    }
    out
}

/// A logging wrapper around `Poseidon2Sponge` that records every byte
/// absorbed, squeezed, and ratchet event in order. We use this to capture the
/// exact byte sequence spongefish drives through the sponge during
/// `VerifierState::new` (which only ever calls `absorb`, but the wrapper still
/// records other operations defensively in case spongefish evolves).
#[derive(Clone)]
struct LoggingSponge {
    inner: Poseidon2Sponge,
    log:   Rc<RefCell<Vec<SpongeOp>>>,
}

#[derive(Clone, Debug)]
enum SpongeOp {
    Absorb(Vec<u8>),
    Squeeze(usize),
    Ratchet,
}

impl Default for LoggingSponge {
    fn default() -> Self {
        Self {
            inner: Poseidon2Sponge::default(),
            log:   Rc::new(RefCell::new(Vec::new())),
        }
    }
}

impl DuplexSpongeInterface for LoggingSponge {
    type U = u8;

    fn absorb(&mut self, input: &[u8]) -> &mut Self {
        self.log.borrow_mut().push(SpongeOp::Absorb(input.to_vec()));
        self.inner.absorb(input);
        self
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        self.log.borrow_mut().push(SpongeOp::Squeeze(output.len()));
        self.inner.squeeze(output);
        self
    }

    fn ratchet(&mut self) -> &mut Self {
        self.log.borrow_mut().push(SpongeOp::Ratchet);
        self.inner.ratchet();
        self
    }
}

/// Byte-grain sponge replay over the BN254 Poseidon2 permutation, mirroring
/// spongefish's `DuplexSponge<Poseidon2Wrapper, 128, 96>` state machine
/// exactly (see
/// `~/.cargo/git/checkouts/spongefish-…/spongefish/src/duplex_sponge.rs`).
///
/// We can't read spongefish's private state directly, but we can deterministically
/// reproduce it by replaying the same byte ops on our own copy of the state
/// machine. This is the same approach as `byte_sponge_replay` in
/// `provekit-verifier-noir-test`, generalised to also support absorbs and to
/// return the final state + positions.
///
/// Returns `(state_bytes, absorb_pos, squeeze_pos)`.
fn byte_grain_sponge_replay(ops: &[SpongeOp]) -> ([u8; 128], usize, usize) {
    use poseidon2::permutation::poseidon2_permutation;

    const WIDTH: usize = 128;
    const RATE: usize = 96;

    let mut state = [0u8; WIDTH];
    let mut absorb_pos: usize = 0;
    let mut squeeze_pos: usize = RATE;

    fn permute(state: &mut [u8; 128]) {
        // Interpret state as 4 lanes of 32 bytes each, reduce LE mod p, permute,
        // re-encode canonical LE. Mirrors `Poseidon2Wrapper::permute`.
        let inputs: [Fr; 4] = std::array::from_fn(|i| {
            Fr::from_le_bytes_mod_order(&state[i * 32..(i + 1) * 32])
        });
        let output = poseidon2_permutation(&inputs);
        for (i, fe) in output.iter().enumerate() {
            let bi = fe.into_bigint();
            for (limb_i, limb) in bi.0.iter().enumerate() {
                state[i * 32 + limb_i * 8..i * 32 + (limb_i + 1) * 8]
                    .copy_from_slice(&limb.to_le_bytes());
            }
        }
    }

    for op in ops {
        match op {
            SpongeOp::Absorb(input) => {
                // Mirrors spongefish duplex_sponge.rs `absorb`.
                squeeze_pos = RATE;
                let mut remaining: &[u8] = input;
                while !remaining.is_empty() {
                    if absorb_pos == RATE {
                        permute(&mut state);
                        absorb_pos = 0;
                    } else {
                        let chunk_len = (remaining.len()).min(RATE - absorb_pos);
                        state[absorb_pos..absorb_pos + chunk_len]
                            .copy_from_slice(&remaining[..chunk_len]);
                        absorb_pos += chunk_len;
                        remaining = &remaining[chunk_len..];
                    }
                }
            }
            SpongeOp::Squeeze(len) => {
                // Mirrors spongefish duplex_sponge.rs `squeeze`.
                let mut remaining = *len;
                if remaining == 0 {
                    continue;
                }
                absorb_pos = 0;
                while remaining > 0 {
                    if squeeze_pos == RATE {
                        squeeze_pos = 0;
                        permute(&mut state);
                    }
                    let chunk_len = remaining.min(RATE - squeeze_pos);
                    squeeze_pos += chunk_len;
                    remaining -= chunk_len;
                }
            }
            SpongeOp::Ratchet => {
                // Mirrors spongefish duplex_sponge.rs `ratchet`.
                absorb_pos = RATE;
                squeeze_pos = RATE;
                state[0..RATE].fill(0);
                permute(&mut state);
            }
        }
    }

    (state, absorb_pos, squeeze_pos)
}

/// Reconstructs the Fiat-Shamir sponge state after the domain-separator
/// initialisation done by `WhirR1CSVerifier::verify` (i.e. after spongefish's
/// `DomainSeparator::new(protocol).session(s).instance(i).to_verifier(...)`)
/// and returns `(state_lanes, absorb_pos_lanes, squeeze_pos_lanes)` in the
/// lane-grain units the Noir verifier consumes.
///
/// Requires `hash_config == Poseidon2`; bails on any byte-misalignment that
/// cannot be expressed in lane units.
fn compute_pre_absorbed_state(
    verifier: &Verifier,
    scheme: &provekit_common::WhirR1CSScheme,
    proof: &NoirProof,
) -> Result<([Fr; 4], u32, u32)> {
    use whir::transcript::{DomainSeparator, Proof, VerifierState};

    anyhow::ensure!(
        verifier.hash_config == provekit_common::HashConfig::Poseidon2,
        "compute_pre_absorbed_state currently supports only Poseidon2"
    );

    // Reconstruct the exact byte sequence the Rust verifier feeds the sponge.
    let instance = proof.public_inputs.hash_bytes(verifier.hash_config);

    // Spongefish's DomainSeparator::new/session/instance just packages the
    // ids; the actual byte absorbs happen inside `to_verifier` (via
    // public_message → absorb).
    let logging = LoggingSponge::default();
    let log_handle = logging.log.clone();

    // Build whir's DomainSeparator for the scheme, then bind it to the
    // instance bytes.
    let ds = scheme.create_domain_separator();
    let ds_with_instance: DomainSeparator<'_, [u8; 32]> = ds.instance(&instance);

    // Construct a synthetic Proof: VerifierState::new only consumes the proof
    // bytes from `narg_string` later (we only care about the DS-init absorbs
    // here). An empty narg_string is fine because we never call `prover_message`.
    let synthetic_proof = Proof {
        narg_string: Vec::new(),
        hints:       Vec::new(),
        #[cfg(debug_assertions)]
        pattern:     Vec::new(),
    };

    let _verifier_state: VerifierState<'_, LoggingSponge> =
        VerifierState::new(&ds_with_instance, &synthetic_proof, logging);

    let ops_snapshot = log_handle.borrow().clone();

    // Sanity check: the proof's narg_string is not used here. The variable
    // `proof` is kept in the signature for forward compatibility (and in case
    // we later want to validate the pre-state against absorbs the verifier
    // would do next).
    let _ = proof;

    // Replay through our byte-grain state machine to extract the final
    // (state, absorb_pos, squeeze_pos) in BYTES.
    let (state_bytes, absorb_pos_bytes, squeeze_pos_bytes) =
        byte_grain_sponge_replay(&ops_snapshot);

    // Convert byte positions to lane positions (RATE = 96 bytes = 3 lanes).
    anyhow::ensure!(
        absorb_pos_bytes.is_multiple_of(32),
        "pre-absorbed sponge state is byte-misaligned (absorb_pos_bytes = {}); \
         the Noir lane sponge cannot represent this. Consider redesigning the \
         Noir sponge to track byte-grain positions.",
        absorb_pos_bytes
    );
    anyhow::ensure!(
        squeeze_pos_bytes.is_multiple_of(32),
        "pre-absorbed sponge state is byte-misaligned (squeeze_pos_bytes = {}); \
         the Noir lane sponge cannot represent this.",
        squeeze_pos_bytes
    );

    let absorb_pos_lanes = (absorb_pos_bytes / 32) as u32;
    let squeeze_pos_lanes = (squeeze_pos_bytes / 32) as u32;

    // Decode state lanes from their canonical LE-byte encoding.
    let state_lanes: [Fr; 4] = std::array::from_fn(|i| {
        Fr::from_le_bytes_mod_order(&state_bytes[i * 32..(i + 1) * 32])
    });

    Ok((state_lanes, absorb_pos_lanes, squeeze_pos_lanes))
}

/// A byte parser over the `narg_string` that reads field elements and U64s
/// in spongefish's wire encoding.
struct NargParser<'a> {
    bytes: &'a [u8],
    pos:   usize,
}

impl<'a> NargParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<()> {
        if self.pos + n > self.bytes.len() {
            anyhow::bail!(
                "narg_string overrun: need {n} bytes at pos {}, len={}",
                self.pos,
                self.bytes.len(),
            );
        }
        Ok(())
    }

    /// Read a field element. BN254 Fr is 32 bytes little-endian
    /// (`from_le_bytes_mod_order`).
    fn read_field(&mut self) -> Result<Fr> {
        self.ensure(32)?;
        let slice = &self.bytes[self.pos..self.pos + 32];
        self.pos += 32;
        Ok(Fr::from_le_bytes_mod_order(slice))
    }

    fn read_field_vec(&mut self, n: usize) -> Result<Vec<Fr>> {
        (0..n).map(|_| self.read_field()).collect()
    }

    /// Read a 32-byte Merkle root as a field element (interpret LE).
    fn read_hash_as_field(&mut self) -> Result<Fr> {
        self.ensure(32)?;
        let slice = &self.bytes[self.pos..self.pos + 32];
        self.pos += 32;
        Ok(Fr::from_le_bytes_mod_order(slice))
    }

    /// Read 8 bytes as a U64 PoW nonce, returned as an 8-byte little-endian
    /// array.
    fn read_u64_bytes(&mut self) -> Result<[u8; 8]> {
        self.ensure(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(buf)
    }
}

/// Minimal TOML value representation for the inputs we emit.
enum TomlValue {
    Field(Fr),
    FieldArray(Vec<Fr>),
    FieldMatrix(Vec<Vec<Fr>>),
    FieldCube(Vec<Vec<Vec<Fr>>>),
    U32String(u32),
    U8Array(Vec<u8>),
    U8Matrix(Vec<Vec<u8>>),
}

impl TomlValue {
    fn format(&self) -> String {
        match self {
            Self::Field(f) => format!("\"{}\"", fr_to_decimal(*f)),
            Self::FieldArray(v) => {
                let inner: Vec<String> =
                    v.iter().map(|f| format!("\"{}\"", fr_to_decimal(*f))).collect();
                format!("[{}]", inner.join(", "))
            }
            Self::FieldMatrix(m) => {
                let rows: Vec<String> = m
                    .iter()
                    .map(|row| {
                        let inner: Vec<String> = row
                            .iter()
                            .map(|f| format!("\"{}\"", fr_to_decimal(*f)))
                            .collect();
                        format!("[{}]", inner.join(", "))
                    })
                    .collect();
                format!("[{}]", rows.join(", "))
            }
            Self::FieldCube(c) => {
                let mats: Vec<String> = c
                    .iter()
                    .map(|m| {
                        let rows: Vec<String> = m
                            .iter()
                            .map(|row| {
                                let inner: Vec<String> = row
                                    .iter()
                                    .map(|f| format!("\"{}\"", fr_to_decimal(*f)))
                                    .collect();
                                format!("[{}]", inner.join(", "))
                            })
                            .collect();
                        format!("[{}]", rows.join(", "))
                    })
                    .collect();
                format!("[{}]", mats.join(", "))
            }
            Self::U32String(n) => format!("\"{}\"", n),
            Self::U8Array(v) => {
                let inner: Vec<String> = v.iter().map(|b| format!("\"{}\"", b)).collect();
                format!("[{}]", inner.join(", "))
            }
            Self::U8Matrix(m) => {
                let rows: Vec<String> = m
                    .iter()
                    .map(|row| {
                        let inner: Vec<String> =
                            row.iter().map(|b| format!("\"{}\"", b)).collect();
                        format!("[{}]", inner.join(", "))
                    })
                    .collect();
                format!("[{}]", rows.join(", "))
            }
        }
    }
}

fn fr_to_decimal(fe: Fr) -> String {
    fe.into_bigint().to_string()
}

/// Convert a `provekit_common::FieldElement` to an `ark_bn254::Fr`. Both are
/// the BN254 scalar field, so the underlying bigint representation is the
/// same — we just go through the canonical byte representation.
#[allow(dead_code)]
fn fe_to_fr(fe: FieldElement) -> Fr {
    let big = fe.into_bigint();
    Fr::from(big)
}

/// Count non-zero entries in each of the R1CS A, B, C matrices.
fn nonzero_counts(r1cs: &provekit_common::R1CS) -> (usize, usize, usize) {
    let num_rows = r1cs.num_constraints();
    let a = (0..num_rows).map(|row| r1cs.a().iter_row(row).count()).sum();
    let b = (0..num_rows).map(|row| r1cs.b().iter_row(row).count()).sum();
    let c = (0..num_rows).map(|row| r1cs.c().iter_row(row).count()).sum();
    (a, b, c)
}

/// Emit the `types.nr` source string for the given verifier/scheme.
fn emit_types_nr(verifier: &Verifier, scheme: &provekit_common::WhirR1CSScheme) -> String {
    let num_constraints = verifier.r1cs.num_constraints();
    let num_witnesses = verifier.r1cs.num_witnesses();
    let num_public_inputs = verifier.r1cs.num_public_inputs;
    let log_constraints = num_constraints.next_power_of_two().trailing_zeros();
    let log_witnesses = num_witnesses.next_power_of_two().trailing_zeros();

    // WHIR-specific constants from the blinded (witness-side) commitment.
    let wc = &scheme.whir_witness.blinded_commitment;
    let bc = &scheme.whir_witness.blinding_commitment;
    let num_whir_rounds = wc.round_configs.len();
    // folding_factor = log2(interleaving_depth)
    let initial_folding_factor = wc.initial_committer.interleaving_depth.trailing_zeros();
    let initial_ood_count = wc.initial_committer.out_domain_samples;
    let initial_query_count = wc.initial_committer.in_domain_samples;
    let initial_sumcheck_rounds = wc.initial_sumcheck.num_rounds;
    let final_sumcheck_rounds = wc.final_sumcheck.num_rounds;
    // PoW difficulty as an integer (ceiling); 0 means PoW disabled.
    let final_pow_bits = f64::from(wc.final_pow.difficulty()).ceil() as u32;
    let num_witness_variables = scheme.whir_witness.num_witness_variables();
    let num_blinding_variables = scheme.whir_witness.num_blinding_variables();
    // For zkWHIR: weights.len() * num_polynomials * (num_witness_variables + 1).
    // Per whir_zk verifier:
    //   num_w_folded_evals = weights.len() * num_polynomials * (nwv + 1)
    // For basic-2 (no public, no challenges): weights.len() = 3 covectors +
    // 1 blinding_covector = 4. num_polynomials = 1. nwv = 13. → 4*1*14 = 56.
    let num_weights_basic_2 = 4;
    let w_folded_blinding_evals_len =
        num_weights_basic_2 * 1 * (num_witness_variables + 1);
    // Per-round query PoW threshold (raw u64) so the verifier matches the
    // Rust `proof_of_work::threshold(difficulty)` value exactly, including
    // fractional-bit difficulties (e.g. 9.94 → 2^54.06 ≈ 1.89e16).
    let round_pow_thresholds: Vec<u64> = wc.round_configs.iter()
        .map(|rc| rc.pow.threshold)
        .collect();
    let final_pow_threshold: u64 = wc.final_pow.threshold;
    let round_pow_bits_str = round_pow_thresholds.iter().enumerate()
        .map(|(i, t)| format!("pub global ROUND_POW_THRESHOLD_{i}: u64 = {t};"))
        .collect::<Vec<_>>().join("\n");
    // Keep ROUND_POW_BITS_k as integer-ceil bits for diagnostic/back-compat.
    let round_pow_bits_compat: Vec<u32> = wc.round_configs.iter()
        .map(|rc| f64::from(rc.pow.difficulty()).ceil() as u32)
        .collect();
    let round_pow_bits_compat_str = round_pow_bits_compat.iter().enumerate()
        .map(|(i, b)| format!("pub global ROUND_POW_BITS_{i}: u32 = {b};"))
        .collect::<Vec<_>>().join("\n");
    // Blinding-side OOD point count (number of challenge points squeezed).
    let blinding_ood_points = bc.initial_committer.out_domain_samples;
    // Blinding-side OOD eval count: out_domain_samples * num_vectors field
    // elements are sent by the prover (one eval per OOD point per vector).
    let blinding_ood_count =
        bc.initial_committer.out_domain_samples * bc.initial_committer.num_vectors;

    // -- Per-round query counts and bytes-per-index for in-domain sampling.
    //
    // The verifier squeezes `count * size_bytes` raw bytes per round to
    // sample query indices, where `count = prev_round.in_domain_samples`
    // and `size_bytes = ceil(log2(prev_round.codeword_length) / 8)`.
    //
    // Round k (k in 0..NUM_WHIR_ROUNDS) opens the previous round's commit:
    //   k = 0 opens the initial committer
    //   k > 0 opens round_configs[k-1]
    //
    // The final round opens round_configs[NUM_WHIR_ROUNDS-1].
    let query_count_per_round: Vec<usize> = (0..num_whir_rounds)
        .map(|k| if k == 0 {
            wc.initial_committer.in_domain_samples
        } else {
            wc.round_configs[k - 1].irs_committer.in_domain_samples
        })
        .collect();
    let query_bytes_per_round: Vec<usize> = (0..num_whir_rounds)
        .map(|k| {
            let cl = if k == 0 {
                wc.initial_committer.codeword_length
            } else {
                wc.round_configs[k - 1].irs_committer.codeword_length
            };
            ((cl.ilog2() as usize).div_ceil(8)).max(1)
        })
        .collect();
    let query_final_count = if num_whir_rounds == 0 {
        wc.initial_committer.in_domain_samples
    } else {
        wc.round_configs[num_whir_rounds - 1].irs_committer.in_domain_samples
    };
    let query_final_bytes = {
        let cl = if num_whir_rounds == 0 {
            wc.initial_committer.codeword_length
        } else {
            wc.round_configs[num_whir_rounds - 1].irs_committer.codeword_length
        };
        ((cl.ilog2() as usize).div_ceil(8)).max(1)
    };

    let per_round_query_str = (0..num_whir_rounds)
        .map(|k| {
            format!(
                "pub global QUERY_COUNT_{k}: u32 = {};\npub global QUERY_BYTES_{k}: u32 = {};\npub global QUERY_BYTES_TOTAL_{k}: u32 = {};",
                query_count_per_round[k],
                query_bytes_per_round[k],
                query_count_per_round[k] * query_bytes_per_round[k],
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let final_vector_len = wc.final_sumcheck.initial_size;

    format!(
        "// AUTO-GENERATED by `provekit-cli generate-noir-inputs`.
// DO NOT EDIT - re-run the codegen tool to regenerate.
//
// Compile-time constants for the v0 inner circuit. Tied to a specific
// `.pkv` (verifier key) shape; regenerate after any scheme change.

pub global M: u32 = {m};
pub global M_0: u32 = {m_0};
pub global W1_SIZE: u32 = {w1_size};
pub global NUM_CHALLENGES: u32 = {num_challenges};
pub global NUM_PUBLIC_INPUTS: u32 = {num_public_inputs};
pub global NUM_CONSTRAINTS: u32 = {num_constraints};
pub global NUM_WITNESSES: u32 = {num_witnesses};
pub global LOG_NUM_CONSTRAINTS: u32 = {log_constraints};
pub global LOG_NUM_WITNESSES: u32 = {log_witnesses};

// WHIR protocol shape (witness-side blinded commitment).
pub global NUM_WITNESS_VARIABLES: u32 = {num_witness_variables};
pub global NUM_BLINDING_VARIABLES: u32 = {num_blinding_variables};
pub global NUM_WHIR_ROUNDS: u32 = {num_whir_rounds};
pub global INITIAL_FOLDING_FACTOR: u32 = {initial_folding_factor};
pub global INITIAL_OOD_COUNT: u32 = {initial_ood_count};
// OOD challenge points squeezed for the blinding-side initial commitment
// (= out_domain_samples; part of the zkWHIR outer receive_commitments call
// before the Spartan sumcheck).
pub global BLINDING_OOD_POINTS: u32 = {blinding_ood_points};
// OOD evaluations absorbed for the blinding-side initial commitment
// (= out_domain_samples * num_vectors).
pub global BLINDING_OOD_COUNT: u32 = {blinding_ood_count};
pub global INITIAL_QUERY_COUNT: u32 = {initial_query_count};
pub global INITIAL_SUMCHECK_ROUNDS: u32 = {initial_sumcheck_rounds};
pub global FINAL_SUMCHECK_ROUNDS: u32 = {final_sumcheck_rounds};
pub global FINAL_POW_BITS: u32 = {final_pow_bits};
pub global FINAL_POW_THRESHOLD: u64 = {final_pow_threshold};
{round_pow_bits_compat_str}
{round_pow_bits_str}

// Per-round in-domain query counts and per-index byte widths, used by the
// (stubbed) Merkle-opening transcript advance step. The verifier squeezes
// QUERY_COUNT_k * QUERY_BYTES_k raw bytes from the transcript before
// verifying round-k's open of the previous commit.
{per_round_query_str}
pub global QUERY_COUNT_FINAL: u32 = {query_final_count};
pub global QUERY_BYTES_FINAL: u32 = {query_final_bytes};
pub global QUERY_BYTES_TOTAL_FINAL: u32 = {query_final_total};

// WHIR's inner (quadratic) sumcheck sends 2 fields per round (c0, c2). The
// missing c1 coefficient is derived as `sum - 2*c0 - c2`. Contrast with the
// outer Spartan sumcheck which is cubic (SUMCHECK_POLY_COEFFS = 4).
pub global INNER_SUMCHECK_FIELDS_PER_ROUND: u32 = 2;

// Length of the final committed vector absorbed at the start of the final
// WHIR round (= final_sumcheck.initial_size).
pub global FINAL_VECTOR_LEN: u32 = {final_vector_len};

// Universal constants.
pub global SUMCHECK_POLY_COEFFS: u32 = 4;
// W_FOLDED_BLINDING_EVALS_LEN = weights * polynomials * (num_witness_variables + 1).
// For basic-2: 1 * 1 * 14 = 14.
pub global W_FOLDED_BLINDING_EVALS_LEN: u32 = {w_folded_blinding_evals_len};
",
        m = scheme.m,
        m_0 = scheme.m_0,
        w1_size = scheme.w1_size,
        num_challenges = scheme.num_challenges,
        num_public_inputs = num_public_inputs,
        num_constraints = num_constraints,
        num_witnesses = num_witnesses,
        log_constraints = log_constraints,
        log_witnesses = log_witnesses,
        num_witness_variables = num_witness_variables,
        num_blinding_variables = num_blinding_variables,
        num_whir_rounds = num_whir_rounds,
        initial_folding_factor = initial_folding_factor,
        initial_ood_count = initial_ood_count,
        blinding_ood_points = blinding_ood_points,
        blinding_ood_count = blinding_ood_count,
        initial_query_count = initial_query_count,
        initial_sumcheck_rounds = initial_sumcheck_rounds,
        final_sumcheck_rounds = final_sumcheck_rounds,
        final_pow_bits = final_pow_bits,
        round_pow_bits_str = round_pow_bits_str,
        round_pow_bits_compat_str = round_pow_bits_compat_str,
        final_pow_threshold = final_pow_threshold,
        w_folded_blinding_evals_len = w_folded_blinding_evals_len,
        per_round_query_str = per_round_query_str,
        query_final_count = query_final_count,
        query_final_bytes = query_final_bytes,
        query_final_total = query_final_count * query_final_bytes,
        final_vector_len = final_vector_len,
    )
}

fn emit_matrices_nr(verifier: &Verifier) -> String {
    let mut out = String::new();
    out.push_str(
        "// AUTO-GENERATED by `provekit-cli generate-noir-inputs`.
// DO NOT EDIT - re-run the codegen tool to regenerate.
//
// Sparse triples for the v0 inner circuit's R1CS A/B/C matrices.

use crate::matrix_eval::SparseTriple;

",
    );

    emit_matrix(&mut out, "A_TRIPLES", &verifier.r1cs.a, &verifier.r1cs);
    out.push('\n');
    emit_matrix(&mut out, "B_TRIPLES", &verifier.r1cs.b, &verifier.r1cs);
    out.push('\n');
    emit_matrix(&mut out, "C_TRIPLES", &verifier.r1cs.c, &verifier.r1cs);

    out
}

fn emit_matrix(
    out: &mut String,
    name: &str,
    matrix: &provekit_common::sparse_matrix::SparseMatrix,
    r1cs: &provekit_common::R1CS,
) {
    let hydrated = matrix.hydrate(&r1cs.interner);
    let mut triples: Vec<(usize, usize, provekit_common::FieldElement)> = Vec::new();
    for row in 0..matrix.num_rows {
        for (col, val) in hydrated.iter_row(row) {
            triples.push((row, col, val));
        }
    }

    out.push_str(&format!(
        "pub global {name}: [SparseTriple; {n}] = [\n",
        n = triples.len()
    ));
    for (row, col, val) in &triples {
        out.push_str(&format!(
            "    SparseTriple {{ row: {row}, col: {col}, val: {val_dec} }},\n",
            val_dec = field_to_decimal(*val)
        ));
    }
    out.push_str("];\n");
}

fn field_to_decimal(fe: provekit_common::FieldElement) -> String {
    use ark_ff::PrimeField;
    fe.into_bigint().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_fails_on_missing_files() {
        let args = Args {
            verifier_path: PathBuf::from("/tmp/does-not-exist.pkv"),
            proof_path:    PathBuf::from("/tmp/does-not-exist.np"),
            out_dir:       PathBuf::from("/tmp/out"),
        };
        assert!(args.run().is_err());
    }
}
