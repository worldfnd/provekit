use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    ark_bn254::Fr,
    ark_ff::PrimeField,
    provekit_common::{file::read, FieldElement, NoirProof, Verifier},
    std::{collections::BTreeMap, path::PathBuf},
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
    let w_folded_evals_len = num_polynomials * num_witness_variables_plus_1;

    let final_polynomial_len = wc.final_sumcheck.initial_size;

    let mut p = NargParser::new(&proof.whir_r1cs_proof.narg_string);
    let mut values: BTreeMap<String, TomlValue> = BTreeMap::new();

    // Pre-absorbed sponge state: kept as the previous behaviour (zeros).
    // TODO(soundness): replay the domain separator + instance through the
    // byte-faithful sponge to compute real (state, absorb_pos, squeeze_pos)
    // values, then bind them in-circuit.
    values.insert(
        "pre_absorbed_state".to_string(),
        TomlValue::FieldArray(vec![Fr::from(0u64); 4]),
    );
    values.insert(
        "pre_absorbed_absorb_pos".to_string(),
        TomlValue::U32String(0),
    );
    values.insert(
        "pre_absorbed_squeeze_pos".to_string(),
        TomlValue::U32String(3),
    );

    // Step 1: receive witness-side initial IRS commitment.
    let initial_root = p.read_hash_as_field()?;
    values.insert("initial_root".to_string(), TomlValue::Field(initial_root));
    let initial_ood_evals = p.read_field_vec(initial_ood_count)?;
    values.insert(
        "initial_ood_evals".to_string(),
        TomlValue::FieldArray(initial_ood_evals),
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
    // Step 4: public-inputs hash absorbed only when public_inputs.len() > 0.
    if !proof.public_inputs.is_empty() {
        let _public_hash = p.read_field()?;
        // Not exposed to main.nr today; placeholder for future codegen.
    }

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

    //   6b. initial_committer.verify -> matrix_commit.receive_commitment +
    //       OOD evals.
    let witness_initial_root = p.read_hash_as_field()?;
    values.insert(
        "witness_initial_root".to_string(),
        TomlValue::Field(witness_initial_root),
    );
    let witness_initial_ood_evals =
        p.read_field_vec(initial_ood_count * wc.initial_committer.num_vectors)?;
    values.insert(
        "witness_initial_ood_evals".to_string(),
        TomlValue::FieldArray(witness_initial_ood_evals),
    );

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

    //   6e. Witness-side WHIR LDT (blinded_commitment.verify):
    //       For commitments=1 and num_linear_forms = evaluations.len() / num_vectors,
    //       the verifier first reads cross-term OODs for OFF-diagonal entries.
    //       For basic-2 (single commitment), the diagonal block is filled from
    //       the commitment's OOD evals; no extra cross-terms are read here.
    //
    //       Then initial_sumcheck.verify runs INITIAL_SUMCHECK_ROUNDS rounds,
    //       each reading 4 cubic-polynomial coefficients (we use mask_length=0
    //       so no mask_sum is read).
    //
    //       NOTE: When num_linear_forms > 0 (we have constraints to enforce),
    //       sumcheck.verify reads (4 coeffs + PoW nonce) per round. When the
    //       constraint_rlc is empty, it just squeezes folding_randomness and
    //       verifies the skip_pow nonce. For basic-2 we have constraints, so
    //       the standard path applies.
    let mut whir_round_roots: Vec<Fr> = Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_ood_evals: Vec<Vec<Fr>> = Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_sumcheck_polys: Vec<Vec<Vec<Fr>>> =
        Vec::with_capacity(wc.round_configs.len());
    let mut whir_round_pow_nonces: Vec<[u8; 8]> = Vec::with_capacity(wc.round_configs.len());

    // Initial-sumcheck round polynomials (executed BEFORE the round loop in
    // whir::Config::verify). Each round reads 4 cubic coeffs + per-round PoW
    // nonce. We absorb-only in main.nr so the PoW nonces go into the
    // "initial-sumcheck PoW" bucket -- but main.nr today expects the PoW
    // nonces in whir_round_pow_nonces[round]. For basic-2 we have
    // initial_sumcheck_rounds = 3 (same as INITIAL_SUMCHECK_ROUNDS) which
    // matches; we capture those polys + PoW nonces and emit them at the
    // appropriate buckets.
    //
    // For shape clarity:
    //   initial_sumcheck: INITIAL_SUMCHECK_ROUNDS rounds, each (4 coeffs + 8-byte nonce)
    //   per round (in round_configs): 1 root + ood_evals + INITIAL_SUMCHECK_ROUNDS rounds of (4 coeffs + nonce) + 1 PoW
    //
    // The current Noir main.nr's expectations are coarse: it wants
    //   whir_round_sumcheck_polys[round][s][j]  for round in [0,NUM_WHIR_ROUNDS), s in [0,INITIAL_SUMCHECK_ROUNDS)
    //   whir_round_pow_nonces[round]
    // We capture, for each WHIR round (initial+rounds), the same shape.
    let mut initial_sumcheck_polys: Vec<Vec<Fr>> = Vec::with_capacity(initial_sumcheck_rounds);
    for _ in 0..initial_sumcheck_rounds {
        let coeffs = p.read_field_vec(4)?;
        initial_sumcheck_polys.push(coeffs);
        // per-round PoW nonce (8 bytes)
        let _nonce = p.read_u64_bytes()?;
    }

    // Subsequent WHIR rounds.
    for round_config in &wc.round_configs {
        // receive_commitment(round): root (Hash, 32 bytes) + OOD evals.
        let root = p.read_hash_as_field()?;
        whir_round_roots.push(root);
        let ood = p
            .read_field_vec(round_config.irs_committer.out_domain_samples)?;
        whir_round_ood_evals.push(ood);
        // round-level PoW nonce.
        let nonce = p.read_u64_bytes()?;
        whir_round_pow_nonces.push(nonce);
        // sumcheck for this round: INITIAL_SUMCHECK_ROUNDS rounds of (4 coeffs + nonce).
        let mut per_round_polys: Vec<Vec<Fr>> =
            Vec::with_capacity(round_config.sumcheck.num_rounds);
        for _ in 0..round_config.sumcheck.num_rounds {
            let coeffs = p.read_field_vec(4)?;
            per_round_polys.push(coeffs);
            let _round_nonce = p.read_u64_bytes()?;
        }
        whir_round_sumcheck_polys.push(per_round_polys);
    }

    // main.nr expects exactly NUM_WHIR_ROUNDS round buckets of size
    // (INITIAL_SUMCHECK_ROUNDS, SUMCHECK_POLY_COEFFS). Use the initial
    // sumcheck polys as the first WHIR round's sumcheck polys, then append
    // the rest. For basic-2 NUM_WHIR_ROUNDS = round_configs.len() = 3 and
    // there are also 3 round_configs, so we use round_configs' polys
    // directly.
    let _ = initial_sumcheck_polys;

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

    // Final round of the witness-side WHIR LDT.
    // final_vector first (size = final_sumcheck.initial_size), then PoW nonce.
    let _final_vector = p.read_field_vec(final_polynomial_len)?;
    let _final_pow_nonce = p.read_u64_bytes()?;

    // Final sumcheck (FINAL_SUMCHECK_ROUNDS rounds, each 4 coeffs + nonce).
    let mut whir_final_sumcheck_polys: Vec<Vec<Fr>> =
        Vec::with_capacity(final_sumcheck_rounds);
    for _ in 0..final_sumcheck_rounds {
        let coeffs = p.read_field_vec(4)?;
        whir_final_sumcheck_polys.push(coeffs);
        let _round_nonce = p.read_u64_bytes()?;
    }
    values.insert(
        "whir_final_sumcheck_polys".to_string(),
        TomlValue::FieldMatrix(whir_final_sumcheck_polys),
    );

    // Emit the final polynomial vector consumed by main.nr (length = 2 for
    // basic-2; this is the final folded polynomial after all folds).
    // Reuse the first two coefficients of `_final_vector` (which is the
    // final-round committed vector). When final_sumcheck.initial_size matches
    // 2 these are exactly what main.nr absorbs.
    let final_poly_for_noir: Vec<Fr> = if _final_vector.len() >= 2 {
        _final_vector.iter().copied().take(2).collect()
    } else {
        vec![Fr::from(0u64); 2]
    };
    values.insert(
        "whir_final_polynomial".to_string(),
        TomlValue::FieldArray(final_poly_for_noir),
    );
    values.insert(
        "whir_final_pow_nonce".to_string(),
        TomlValue::U8Array(_final_pow_nonce.to_vec()),
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
    // For zkWHIR: weights * polynomials * (num_witness_variables + 1).
    // Following the same formula the proof parser uses (polynomials * (nwv+1)).
    let w_folded_blinding_evals_len =
        wc.initial_committer.num_vectors * (num_witness_variables + 1);
    // Per-round query PoW bits (basic-2 has 3 rounds).
    let round_pow_bits: Vec<u32> = wc.round_configs.iter()
        .map(|rc| f64::from(rc.pow.difficulty()).ceil() as u32)
        .collect();
    let round_pow_bits_str = round_pow_bits.iter().enumerate()
        .map(|(i, b)| format!("pub global ROUND_POW_BITS_{i}: u32 = {b};"))
        .collect::<Vec<_>>().join("\n");

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
pub global INITIAL_QUERY_COUNT: u32 = {initial_query_count};
pub global INITIAL_SUMCHECK_ROUNDS: u32 = {initial_sumcheck_rounds};
pub global FINAL_SUMCHECK_ROUNDS: u32 = {final_sumcheck_rounds};
pub global FINAL_POW_BITS: u32 = {final_pow_bits};
{round_pow_bits_str}

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
        initial_query_count = initial_query_count,
        initial_sumcheck_rounds = initial_sumcheck_rounds,
        final_sumcheck_rounds = final_sumcheck_rounds,
        final_pow_bits = final_pow_bits,
        round_pow_bits_str = round_pow_bits_str,
        w_folded_blinding_evals_len = w_folded_blinding_evals_len,
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
