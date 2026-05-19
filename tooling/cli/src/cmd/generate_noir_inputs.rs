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

        anyhow::ensure!(
            verifier.hash_config == provekit_common::HashConfig::Poseidon2,
            "PKV hash_config is {}, but generate-noir-inputs only supports Poseidon2 for v0",
            verifier.hash_config
        );

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
