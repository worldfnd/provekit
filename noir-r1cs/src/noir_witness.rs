use {
    crate::{utils::noir_to_native, FieldElement, NoirElement},
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
    std::collections::BTreeMap,
    tracing::{info, instrument},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirWitnessGenerator {
    abi:            Abi,
    brillig:        Vec<BrilligBytecode<NoirElement>>,
    circuit:        NoirCircuit<NoirElement>,
    witness_map:    BTreeMap<usize, usize>,
    r1cs_witnesses: usize,
}

impl NoirWitnessGenerator {
    pub fn new(
        program: &ProgramArtifact,
        witness_map: BTreeMap<usize, usize>,
        r1cs_witnesses: usize,
    ) -> Self {
        let abi = program.abi.clone();
        let brillig = program.bytecode.unconstrained_functions.clone();
        let circuit = program.bytecode.functions[0].clone();
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
        let noir_witness = generate_noir_witness(&self.brillig, &self.circuit, input)
            .context("while generating noir witness")?;
        let witness = noir_to_r1cs_witness(noir_witness, &self.witness_map, self.r1cs_witnesses)
            .context("while converting noir witness to r1cs")?;
        Ok(witness)
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
    remap: &BTreeMap<usize, usize>,
    r1cs_witnesses: usize,
) -> Result<Vec<Option<FieldElement>>> {
    // Compute a satisfying witness
    let mut witness = vec![None; r1cs_witnesses];
    witness[0] = Some(FieldElement::one()); // Constant at index 1

    // Fill in R1CS witness values with the pre-computed ACIR witness values
    for (acir_witness_idx, witness_idx) in remap {
        witness[*witness_idx] = Some(noir_to_native(
            noir_witness[&Witness(*acir_witness_idx as u32)],
        ));
    }

    Ok(witness)
}
