use {
    crate::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    provekit_common::{file::read, NoirProof, Verifier},
    provekit_gnark::write_gnark_parameters_to_file,
    std::{fs::File, io::Write, path::PathBuf},
    tracing::{info, instrument},
};

/// Generate input compatible with gnark.
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "generate-gnark-inputs")]
pub struct Args {
    /// path to the verifier data file
    #[argh(positional)]
    verifier_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,

    /// path to the parameters file for gnark recursive verifier
    #[argh(
        option,
        long = "params",
        default = "String::from(\"./params_for_recursive_verifier\")"
    )]
    params_for_recursive_verifier: String,

    /// path to the r1cs output file
    #[argh(option, long = "r1cs", default = "String::from(\"./r1cs.json\")")]
    r1cs_path: String,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let verifier: Verifier =
            read(&self.verifier_path).context("while reading Verifier data")?;
        let (constraints, witnesses) = (
            verifier.r1cs.num_constraints(),
            verifier.r1cs.num_witnesses(),
        );
        info!(constraints, witnesses, "Read verifier data");

        // Read the proof
        let proof: NoirProof = read(&self.proof_path).context("while reading proof")?;

        let wfw = verifier
            .whir_for_witness
            .as_ref()
            .context("verifier is missing whir_for_witness config")?;

        write_gnark_parameters_to_file(
            &wfw.whir_witness.blinded_commitment,
            &proof.whir_r1cs_proof,
            wfw.m_0,
            wfw.m,
            wfw.a_num_terms,
            wfw.num_challenges,
            wfw.w1_size,
            &proof.public_inputs,
            &self.params_for_recursive_verifier,
        );

        let json =
            serde_json::to_string(&verifier.r1cs).context("while serializing R1CS to JSON")?;
        let mut file = File::create(&self.r1cs_path).context("while creating R1CS file")?;
        file.write_all(json.as_bytes())
            .context("while writing R1CS file")?;

        Ok(())
    }
}
