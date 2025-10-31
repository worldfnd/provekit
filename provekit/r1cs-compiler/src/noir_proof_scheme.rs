use {
    crate::{
        noir_to_r1cs, whir_r1cs::WhirR1CSSchemeBuilder,
        witness_generator::NoirWitnessGeneratorBuilder,
    },
    anyhow::{ensure, Context as _, Result},
    noirc_artifacts::program::ProgramArtifact,
    provekit_common::{
        utils::PrintAbi,
        witness::{NoirWitnessGenerator, WitnessBuilder},
        NoirProofScheme, WhirR1CSScheme,
    },
    std::{fs::File, path::Path},
    tracing::{info, instrument},
};

pub trait NoirProofSchemeBuilder {
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<Self>
    where
        Self: Sized;

    fn from_program(program: ProgramArtifact) -> Result<Self>
    where
        Self: Sized;
}

impl NoirProofSchemeBuilder for NoirProofScheme {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<Self> {
        let file = File::open(path).context("while opening Noir program")?;
        let program = serde_json::from_reader(file).context("while reading Noir program")?;

        Self::from_program(program)
    }

    #[instrument(skip_all)]
    fn from_program(program: ProgramArtifact) -> Result<Self> {
        info!("Program noir version: {}", program.noir_version);
        info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        // Extract bits from Program Artifact.
        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        // Compile to R1CS schemes
        let (r1cs, witness_map, witness_builders) = noir_to_r1cs(main)?;
        info!(
            "R1CS {} constraints, {} witnesses, A {} entries, B {} entries, C {} entries",
            r1cs.num_constraints(),
            r1cs.num_witnesses(),
            r1cs.a.num_entries(),
            r1cs.b.num_entries(),
            r1cs.c.num_entries()
        );

        // Split witness builders and remap indices for sound challenge generation
        let (split_witness_builders, remapped_r1cs, remapped_witness_map) =
            WitnessBuilder::split_and_prepare_layers(&witness_builders, r1cs, witness_map);
        info!(
            "Witness split: w1 size = {}, w2 size = {}",
            split_witness_builders.w1_size,
            remapped_r1cs.num_witnesses() - split_witness_builders.w1_size
        );

        // Configure witness generator with remapped witness map
        let witness_generator = NoirWitnessGenerator::new(
            &program,
            remapped_witness_map,
            remapped_r1cs.num_witnesses(),
        );

        // Configure Whir for full witness
        let whir_for_witness = WhirR1CSScheme::new_for_r1cs(&remapped_r1cs);

        Ok(Self {
            program: program.bytecode,
            r1cs: remapped_r1cs,
            split_witness_builders,
            witness_generator,
            whir_for_witness,
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

        test_serde(&proof_schema.r1cs);
        test_serde(&proof_schema.split_witness_builders);
        test_serde(&proof_schema.witness_generator);
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
