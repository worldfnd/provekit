use {
    crate::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    ark_serialize::CanonicalSerialize,
    noir_r1cs::{
        create_io_pattern, read, write_gnark_parameters_to_file, NoirProof, NoirProofScheme,
    },
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
            &scheme.whir.whir_config,
            &proof.whir_r1cs_proof.transcript,
            &create_io_pattern(scheme.whir.m_0, &scheme.whir.whir_config),
            proof.whir_r1cs_proof.whir_query_answer_sums,
            scheme.whir.m_0,
            scheme.whir.m,
            &self.params_for_recursive_verifier,
        );

        let json = serde_json::to_string_pretty(&scheme.r1cs).unwrap(); // Or `to_string` for compact
        let mut file = File::create("r1cs.json")?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }
}
