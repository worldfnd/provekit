use {
    crate::whir_r1cs::WhirR1CSSchemeBuilder,
    anyhow::{ensure, Context as _, Result},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{utils::{convert_spartan_r1cs_to_provekit, PrintAbi}, NoirProofScheme, WhirR1CSScheme},
    spartan_vm::api as spartan_api,
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

pub trait NoirProofSchemeBuilder {
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<Self>
    where
        Self: Sized;

    fn from_program(program: ProgramArtifact, project_path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}

impl NoirProofSchemeBuilder for NoirProofScheme {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).context("while opening Noir program")?;
        let program = serde_json::from_reader(file).context("while reading Noir program")?;

        // Derive the project directory from the JSON file path.
        // The JSON file is typically at `project/target/name.json`, so we go up 2 levels.
        let project_path = path
            .parent()
            .and_then(|p| p.parent())
            .context("Could not derive project path from JSON file path")?;

        Self::from_program(program, project_path)
    }

    fn from_program(program: ProgramArtifact, project_path: impl AsRef<Path>) -> Result<Self> {
        info!("Program noir version: {}", program.noir_version);
        info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        let artifacts = spartan_api::compile_to_artifacts(project_path.as_ref().to_path_buf(), false)?;

        let whir_for_witness = WhirR1CSScheme::new_from_spartan_r1cs(&artifacts.r1cs);
        let r1cs = convert_spartan_r1cs_to_provekit(&artifacts.r1cs);

        Ok(Self {
            whir_for_witness,
            artifacts,
            r1cs,
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::NoirProofSchemeBuilder,
        ark_std::One,
        provekit_common::{
            witness::{ConstantTerm, SumTerm, WitnessBuilder},
            FieldElement, NoirProofScheme,
        },
        serde::{Deserialize, Serialize},
        std::path::PathBuf,
    };

    #[track_caller]
    fn test_serde<T>(value: &T)
    where
        T: std::fmt::Debug + PartialEq + Serialize + for<'a> Deserialize<'a>,
    {
        // Test JSON
        let json = serde_json::to_string(value).unwrap();
        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(value, &deserialized);

        // Test Postcard
        let bin = postcard::to_allocvec(value).unwrap();
        let deserialized = postcard::from_bytes(&bin).unwrap();
        assert_eq!(value, &deserialized);
    }

    #[test]
    fn test_noir_proof_scheme_serde() {
        let path = PathBuf::from("../../tooling/provekit-bench/benches/poseidon_rounds.json");
        let proof_schema = NoirProofScheme::from_file(path).unwrap();

        test_serde(&proof_schema.whir_for_witness);
    }

    #[test]
    fn test_witness_builder_serde() {
        let sum_term = SumTerm(Some(FieldElement::one()), 2);
        test_serde(&sum_term);
        let constant_term = ConstantTerm(2, FieldElement::one());
        test_serde(&constant_term);
        let witness_builder = WitnessBuilder::Constant(constant_term);
        test_serde(&witness_builder);
    }
}
