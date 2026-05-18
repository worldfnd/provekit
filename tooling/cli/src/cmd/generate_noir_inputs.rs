use {
    super::Command,
    anyhow::Result,
    argh::FromArgs,
    std::path::PathBuf,
    tracing::instrument,
};

/// Emit Noir verifier inputs (types.nr / matrices.nr / Prover.toml) from a
/// `.pkv` (ProveKit Verifier) and a `.np` (Noir proof) file generated under
/// `HashConfig::Poseidon2`.
///
/// Phase 1A: argument-parsing scaffold only. Codegen logic lands in Phase 2.
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
        eprintln!(
            "generate-noir-inputs: scaffold ready (codegen logic lands in Phase 2). \
             pkv={} np={} out_dir={}",
            self.verifier_path.display(),
            self.proof_path.display(),
            self.out_dir.display()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_run_returns_ok() {
        let args = Args {
            verifier_path: PathBuf::from("/tmp/does-not-exist.pkv"),
            proof_path: PathBuf::from("/tmp/does-not-exist.np"),
            out_dir: PathBuf::from("/tmp/out"),
        };
        assert!(args.run().is_ok());
    }
}
