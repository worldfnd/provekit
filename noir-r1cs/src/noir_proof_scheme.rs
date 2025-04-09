use {
    crate::{
        noir_to_r1cs,
        utils::PrintAbi,
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        FieldElement, NoirWitnessGenerator, R1CS,
    },
    anyhow::{ensure, Context as _, Result},
    noirc_artifacts::program::ProgramArtifact,
    rand::{thread_rng, Rng as _},
    serde::{Deserialize, Serialize},
    std::{fs::File, path::Path},
    tracing::{info, instrument, span, Level},
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProofScheme {
    r1cs:              R1CS,
    witness_generator: NoirWitnessGenerator,
    whir:              WhirR1CSScheme,
}

pub struct NoirProof {
    // TODO:
    whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[instrument(fields(size = path.metadata().map(|m| m.len()).ok()))]
    pub fn from_file(path: &Path) -> Result<Self> {
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
        let (r1cs, witness_map) = noir_to_r1cs(&main)?;
        info!(
            "R1CS {} constraints, {} witnesses, A {} entries, B {} entries, C {} entries",
            r1cs.constraints,
            r1cs.witnesses,
            r1cs.a.iter().count(),
            r1cs.b.iter().count(),
            r1cs.c.iter().count()
        );

        // Configure witness generator
        let witness_generator = NoirWitnessGenerator::new(&program, witness_map, r1cs.witnesses);

        // Configure Whir
        let whir = WhirR1CSScheme::new_for_r1cs(&r1cs);

        Ok(Self {
            r1cs,
            witness_generator,
            whir,
        })
    }

    #[instrument(skip_all, fields(size=input_toml.len()))]
    pub fn prove(&self, input_toml: &str) -> Result<NoirProof> {
        let span = span!(Level::INFO, "generate_witness").entered();

        // Create witness for provided input
        let input = self
            .witness_generator
            .input_from_toml(input_toml)
            .context("while reading input from toml")?;
        let mut partial_witness = self
            .witness_generator
            .generate_partial_witness(input)
            .context("while generating partial witness")?;

        // Solve R1CS instance
        self.r1cs
            .solve_witness(&mut partial_witness)
            .context("while solving R1CS witness")?;
        let witness = fill_witness(partial_witness).context("while filling witness")?;

        // Verify witness
        self.r1cs
            .verify_witness(&witness)
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
    let mut rng = thread_rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                FieldElement::from(rng.gen::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use {super::NoirProofScheme, crate::test_serde, std::path::PathBuf};

    #[test]
    fn test_noir_proof_scheme_serde() {
        let proof_schema = NoirProofScheme::from_file(&PathBuf::from(
            "../noir-examples/poseidon-rounds/target/basic.json",
        ))
        .unwrap();
        test_serde(&proof_schema.r1cs);
        test_serde(&proof_schema.witness_generator);
        test_serde(&proof_schema.whir);
    }
}
