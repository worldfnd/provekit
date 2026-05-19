use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Verifier},
    std::path::PathBuf,
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

        Ok(())
    }
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

    format!(
        "// AUTO-GENERATED by `provekit-cli generate-noir-inputs`.
// DO NOT EDIT - re-run the codegen tool to regenerate.
//
// Compile-time constants for the v0 inner circuit. Tied to a specific
// `.pkv` (verifier key) shape; regenerate after any scheme change.

global M: u32 = {m};
global M_0: u32 = {m_0};
global W1_SIZE: u32 = {w1_size};
global NUM_CHALLENGES: u32 = {num_challenges};
global NUM_PUBLIC_INPUTS: u32 = {num_public_inputs};
global NUM_CONSTRAINTS: u32 = {num_constraints};
global NUM_WITNESSES: u32 = {num_witnesses};
global LOG_NUM_CONSTRAINTS: u32 = {log_constraints};
global LOG_NUM_WITNESSES: u32 = {log_witnesses};

// WHIR protocol shape (witness-side blinded commitment).
global NUM_WITNESS_VARIABLES: u32 = {num_witness_variables};
global NUM_BLINDING_VARIABLES: u32 = {num_blinding_variables};
global NUM_WHIR_ROUNDS: u32 = {num_whir_rounds};
global INITIAL_FOLDING_FACTOR: u32 = {initial_folding_factor};
global INITIAL_OOD_COUNT: u32 = {initial_ood_count};
global INITIAL_QUERY_COUNT: u32 = {initial_query_count};
global INITIAL_SUMCHECK_ROUNDS: u32 = {initial_sumcheck_rounds};
global FINAL_SUMCHECK_ROUNDS: u32 = {final_sumcheck_rounds};
global FINAL_POW_BITS: u32 = {final_pow_bits};
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
