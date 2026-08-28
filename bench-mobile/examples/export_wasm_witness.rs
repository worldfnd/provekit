//! Generate a deterministic witness outside browser benchmark measurement.

use {
    anyhow::{bail, Context, Result},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{Format, NoirProofScheme, Prover},
    provekit_prover::Prove,
    provekit_r1cs_compiler::NoirProofSchemeBuilder,
    std::{env, fs, path::PathBuf},
};

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let program_path = PathBuf::from(args.next().context("missing compiled program path")?);
    let input_path = PathBuf::from(args.next().context("missing Prover.toml path")?);
    let output_path = PathBuf::from(args.next().context("missing witness output path")?);
    if args.next().is_some() {
        bail!("expected exactly three paths");
    }

    let program: ProgramArtifact =
        serde_json::from_slice(&fs::read(&program_path)?).context("deserializing Noir program")?;
    let scheme = NoirProofScheme::from_program(program).context("preparing proof scheme")?;
    let input = fs::read_to_string(&input_path).context("reading Prover.toml")?;
    let input_map = Format::Toml
        .parse(&input, &scheme.witness_generator.abi)
        .context("parsing Prover.toml")?;
    let mut prover = Prover::from_noir_proof_scheme(scheme);
    let witness = prover
        .generate_witness(input_map)
        .context("generating witness")?;
    let encoded = postcard::to_stdvec(&witness).context("serializing witness")?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, encoded)?;
    Ok(())
}
