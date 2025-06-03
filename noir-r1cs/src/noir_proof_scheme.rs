use {
    crate::{
        noir_to_r1cs,
        r1cs_solver::{MockTranscript, WitnessBuilder},
        utils::PrintAbi,
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        FieldElement, NoirWitnessGenerator, R1CS,
    },
    acir::{native_types::WitnessMap, FieldElement as NoirFieldElement},
    anyhow::{ensure, Context as _, Result},
    noirc_artifacts::program::ProgramArtifact,
    rand::{rng, Rng as _},
    serde::{Deserialize, Serialize},
    std::{fs::File, path::Path},
    tracing::{info, instrument, span, Level},
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub r1cs:              R1CS,
    pub witness_builders:  Vec<WitnessBuilder>,
    pub witness_generator: NoirWitnessGenerator,
    pub whir:              WhirR1CSScheme,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[instrument(fields(size = path.as_ref().metadata().map(|m| m.len()).ok()))]
    pub fn from_file(path: impl AsRef<Path> + std::fmt::Debug) -> Result<Self> {
        let program = {
            let file = File::open(path).context("while opening Noir program")?;
            let _span = span!(
                Level::INFO,
                "serde_json",
                size = file.metadata().map(|m| m.len()).ok(),
            )
            .entered();

            serde_json::from_reader(file).context("while reading Noir program")?
        };
        Self::from_program(&program)
    }

    #[instrument(skip_all)]
    pub fn from_program(program: &ProgramArtifact) -> Result<Self> {
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

        // Configure witness generator
        let witness_generator =
            NoirWitnessGenerator::new(program, witness_map, r1cs.num_witnesses());

        // Configure Whir
        let whir = WhirR1CSScheme::new_for_r1cs(&r1cs);

        Ok(Self {
            r1cs,
            witness_builders,
            witness_generator,
            whir,
        })
    }

    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    #[instrument(skip_all)]
    pub fn prove(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
    ) -> Result<NoirProof> {
        let span = span!(Level::INFO, "generate_witness").entered();

        // Solve R1CS instance
        let mut transcript = MockTranscript::new();
        let partial_witness = self.r1cs.solve_witness_vec(
            &self.witness_builders,
            acir_witness_idx_to_value_map,
            &mut transcript,
        );
        let witness = fill_witness(partial_witness).context("while filling witness")?;

        // Verify witness (redudant with solve)
        #[cfg(test)]
        self.r1cs
            .test_witness_satisfaction(&witness)
            .context("While verifying R1CS instance")?;
        drop(span);

        // Prove R1CS instance
        let whir_r1cs_proof = self
            .whir
            .prove(&self.r1cs, witness)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }

    #[instrument(skip_all)]
    pub fn verify(&self, proof: &NoirProof) -> Result<()> {
        self.whir.verify(&proof.whir_r1cs_proof)?;
        Ok(())
    }
}

/// Complete a partial witness with random values.
#[instrument(skip_all, fields(size = witness.len()))]
fn fill_witness(witness: Vec<Option<FieldElement>>) -> Result<Vec<FieldElement>> {
    // TODO: Use better entropy source and proper sampling.
    let mut rng = rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                FieldElement::from(rng.random::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use {
        super::NoirProofScheme,
        crate::{
            r1cs_solver::{ConstantTerm, SumTerm, WitnessBuilder},
            FieldElement,
        },
        ark_std::One,
        noir_tools::compile_workspace,
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
        println!("working directory: {:?}", std::env::current_dir().unwrap());
        let directory = "../noir-examples/poseidon-rounds";

        compile_workspace(directory).expect("Compiling workspace");

        let path = PathBuf::from(directory).join("target/basic.json");
        let proof_schema = NoirProofScheme::from_file(path).unwrap();

        test_serde(&proof_schema.r1cs);
        test_serde(&proof_schema.witness_builders);
        test_serde(&proof_schema.witness_generator);
        test_serde(&proof_schema.whir);
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
