use {
    crate::{
        utils::{noir_to_native, serde_jsonify},
        FieldElement, NoirElement,
    },
    acir::{
        brillig::ForeignCallResult,
        circuit::{brillig::BrilligBytecode, Circuit as NoirCircuit},
        native_types::{Witness, WitnessMap},
    },
    acvm::pwg::{ACVMStatus, ACVM},
    anyhow::{anyhow, Context, Result},
    ark_std::One,
    bn254_blackbox_solver::Bn254BlackBoxSolver,
    noirc_abi::{input_parser::Format, Abi},
    noirc_artifacts::program::ProgramArtifact,
    serde::{Deserialize, Serialize},
    std::num::NonZeroU32,
    tracing::{info, instrument},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirWitnessGenerator {
    // Note: Abi uses an [internally tagged] enum format in Serde, which is not compatible
    // with some schemaless formats like Postcard.
    // [internally-tagged]: https://serde.rs/enum-representations.html
    #[serde(with = "serde_jsonify")]
    abi:     Abi,
    brillig: Vec<BrilligBytecode<NoirElement>>,
    circuit: NoirCircuit<NoirElement>,

    /// ACIR witness index to R1CS witness index
    /// Index zero is reserved for constant one, so we can use NonZeroU32
    witness_map:    Vec<Option<NonZeroU32>>,
    r1cs_witnesses: usize,
}

impl NoirWitnessGenerator {
    pub fn new(
        program: &ProgramArtifact,
        witness_map: Vec<Option<NonZeroU32>>,
        r1cs_witnesses: usize,
    ) -> Self {
        let abi = program.abi.clone();
        let brillig = program.bytecode.unconstrained_functions.clone();
        let circuit = program.bytecode.functions[0].clone();
        assert!(witness_map
            .iter()
            .filter_map(|n| *n)
            .all(|n| (n.get() as usize) < r1cs_witnesses));
        Self {
            abi,
            brillig,
            circuit,
            witness_map,
            r1cs_witnesses,
        }
    }

    #[instrument(skip_all, fields(size = toml.len()))]
    pub fn input_from_toml(&self, toml: &str) -> Result<WitnessMap<NoirElement>> {
        let input = Format::Toml
            .parse(toml, &self.abi)
            .context("while parsing input toml")?;
        let map = self
            .abi
            .encode(&input, None)
            .context("while encoding input toml to witness map")?;
        Ok(map)
    }

    #[instrument(skip_all)]
    pub fn generate_partial_witness(
        &self,
        input: WitnessMap<NoirElement>,
    ) -> Result<Vec<Option<FieldElement>>> {
        let noir_witness = input;
        let witness = noir_to_r1cs_witness(noir_witness, &self.witness_map, self.r1cs_witnesses)
            .context("while converting noir witness to r1cs")?;
        Ok(witness)
    }
}

impl PartialEq for NoirWitnessGenerator {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.abi) == format!("{:?}", other.abi)
            && self.brillig == other.brillig
            && self.circuit == other.circuit
            && self.witness_map == other.witness_map
            && self.r1cs_witnesses == other.r1cs_witnesses
    }
}

#[instrument(skip_all, fields(size = circuit.opcodes.len(), witnesses = circuit.current_witness_index))]
fn generate_noir_witness(
    brillig: &[BrilligBytecode<NoirElement>],
    circuit: &NoirCircuit<NoirElement>,
    input: WitnessMap<NoirElement>,
) -> Result<WitnessMap<NoirElement>> {
    let solver = Bn254BlackBoxSolver::default();
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        input,
        brillig,
        &circuit.assert_messages,
    );
    loop {
        match acvm.solve() {
            ACVMStatus::Solved => break,
            ACVMStatus::InProgress => Err(anyhow!("Execution halted unexpectedly")),
            ACVMStatus::RequiresForeignCall(info) => {
                let result = match info.function.as_str() {
                    "print" => {
                        info!("NOIR PRINT: {:?}", info.inputs);
                        Ok(ForeignCallResult::default())
                    }
                    name => Err(anyhow!(
                        "Execution requires unimplemented foreign call to {name}"
                    )),
                }?;
                acvm.resolve_pending_foreign_call(result);
                Ok(())
            }
            ACVMStatus::RequiresAcirCall(_) => Err(anyhow!("Execution requires acir call")),
            ACVMStatus::Failure(error) => Err(error.into()),
        }
        .context("while running ACVM")?
    }
    Ok(acvm.finalize())
}

#[instrument(skip_all)]
fn noir_to_r1cs_witness(
    noir_witness: WitnessMap<NoirElement>,
    remap: &[Option<NonZeroU32>],
    r1cs_witnesses: usize,
) -> Result<Vec<Option<FieldElement>>> {
    // Compute a satisfying witness
    let mut witness = vec![None; r1cs_witnesses];
    witness[0] = Some(FieldElement::one()); // Constant at index 1

    // Fill in R1CS witness values with the pre-computed ACIR witness values
    for (Witness(index), value) in noir_witness.into_iter() {
        let index = remap
            .get(index as usize)
            .ok_or_else(|| anyhow!("ACIR witness index out of range"))?
            .ok_or_else(|| anyhow!("ACIR witness index unmapped"))?
            .get() as usize;
        witness[index] = Some(noir_to_native(value));
    }

    Ok(witness)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_serde,
        std::{fs::File, path::PathBuf},
    };

    #[test]
    fn test_noir_witness_generator_serde() {
        let path = &PathBuf::from("../noir-examples/poseidon-rounds/target/basic.json");
        let program = {
            let file = File::open(path).unwrap();
            serde_json::from_reader(file).unwrap()
        };

        let witness_generator = NoirWitnessGenerator::new(&program, BTreeMap::new(), 0);
        test_serde(&witness_generator.brillig);
        test_serde(&witness_generator.circuit);
        test_serde(&witness_generator.witness_map);
        test_serde(&witness_generator.r1cs_witnesses);
    }
}
