use {
    crate::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, NoirProofScheme},
    provekit_gnark::write_gnark_parameters_to_file,
    std::{fs::File, io::Write, path::PathBuf},
    tracing::{info, instrument},
};

/// Generate input compatible with gnark.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-gnark-inputs")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    scheme_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the proof file for gnark recursive verifier
    #[argh(
        option,
        long = "proof",
        default = "String::from(\"./proof_for_recursive_verifier\")"
    )]
    proof_for_recursive_verifier: String,

    /// path to the parameters file for gnark recursive verifier
    #[argh(
        option,
        long = "params",
        default = "String::from(\"./params_for_recursive_verifier\")"
    )]
    params_for_recursive_verifier: String,

    /// path to the r1cs file
    #[argh(option, long = "r1cs", default = "String::from(\"./r1cs.json\")")]
    r1cs_path: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        // Read the scheme
        let scheme: NoirProofScheme =
            read(&self.scheme_path).context("while reading Noir proof scheme")?;
        let (constraints, witnesses) = scheme.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Read the proof
        let proof: NoirProof = read(&self.proof_path).context("while reading proof")?;

        write_gnark_parameters_to_file(
            &scheme.whir_for_witness.whir_witness,
            &scheme.whir_for_witness.whir_for_hiding_spartan,
            &proof.whir_r1cs_proof.transcript,
            &scheme.whir_for_witness.create_io_pattern(),
            scheme.whir_for_witness.m_0,
            scheme.whir_for_witness.m,
            scheme.whir_for_witness.a_num_terms,
            &self.params_for_recursive_verifier,
        );

        let json = serde_json::to_string_pretty(&scheme.r1cs).unwrap(); // Or `to_string` for compact
        let mut file = File::create(&self.r1cs_path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }
}
