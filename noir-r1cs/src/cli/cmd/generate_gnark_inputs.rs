use {
    crate::Command, 
    anyhow::{Context, Result}, 
    argh::FromArgs, 
    noir_r1cs::{
        create_io_pattern, 
        read, 
        write_gnark_parameters_to_file, 
        NoirProof, 
        NoirProofScheme
    }, 
    std::{
        fs::File, 
        path::PathBuf, 
        io::Write,
    }, 
    tracing::{info, instrument},
    ark_serialize::CanonicalSerialize,
};


/// Generate input compatible with gnark.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "generate-gnark-inputs")]
pub struct Args {
    /// path to the compiled Noir program
    #[argh(positional)]
    scheme_path: PathBuf,

    /// path to the proof file
    #[argh(positional)]
    proof_path: PathBuf,
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
        );

        let mut file = File::create("./prover/proof").unwrap();
        let mut proof_bytes = vec![];
        proof.whir_r1cs_proof.whir_proof.serialize_compressed(&mut proof_bytes).unwrap();
        file.write_all(&proof_bytes).expect("Writing proof bytes to a file failed");

        let json = serde_json::to_string_pretty(&scheme.r1cs).unwrap(); // Or `to_string` for compact
        let mut file = File::create("r1cs.json")?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }
}