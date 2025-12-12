use {
    crate::{whir_r1cs::WhirR1CSProver, witness::witness_io_pattern::WitnessIOPattern},
    anyhow::{Context, Result},
    provekit_common::{
        skyscraper::SkyscraperSponge, utils::convert_spartan_r1cs_to_provekit, FieldElement,
        IOPattern, NoirProof, Prover,
    },
    spartan_vm::api as spartan_api,
    spongefish::ProverState,
    std::path::Path,
};

mod whir_r1cs;
mod witness;

pub trait Prove {
    fn prove(self, prover_toml: impl AsRef<Path>) -> Result<NoirProof>;

    fn create_witness_io_pattern(&self) -> IOPattern;

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        witness: &Vec<FieldElement>,
    ) -> Result<()>;
}

impl Prove for Prover {
    fn prove(mut self, prover_toml: impl AsRef<Path>) -> Result<NoirProof> {
        // Derive the project directory from the Prover.toml path.
        let project_path = prover_toml
            .as_ref()
            .parent()
            .context("Could not derive project path from Prover.toml path")?;

        let (driver, _) = spartan_api::compile_to_r1cs(project_path.to_path_buf(), false)?;

        let params = spartan_api::read_prover_inputs(&project_path.to_path_buf(), driver.abi())?;

        let witgen_result = spartan_api::run_witgen_from_binary(
            &mut self.artifacts.witgen_binary,
            &self.artifacts.r1cs,
            &params,
        );
        let witness: Vec<FieldElement> = [
            witgen_result.out_wit_pre_comm.clone(),
            witgen_result.out_wit_post_comm.clone(),
        ]
        .concat();

        // TODO: Implement witness splitting and commitments
        // let witness_io = self.create_witness_io_pattern();
        // let mut witness_merlin = witness_io.to_prover_state();
        // self.seed_witness_merlin(&mut witness_merlin,
        // &acir_witness_idx_to_value_map)?;

        #[cfg(test)]
        assert!(spartan_api::check_witgen(
            &self.artifacts.r1cs,
            &witgen_result
        ));

        let converted_r1cs = convert_spartan_r1cs_to_provekit(&self.artifacts.r1cs);

        let whir_r1cs_proof = self
            .whir_for_witness
            .prove(converted_r1cs, witness, &mut self.artifacts)
            .context("While proving R1CS instance")?;

        Ok(NoirProof { whir_r1cs_proof })
    }

    fn create_witness_io_pattern(&self) -> IOPattern {
        // let circuit = &self.program.functions[0];
        // let public_idxs = circuit.public_inputs().indices();
        // let num_challenges = self
        //     .layered_witness_builders
        //     .layers
        //     .iter()
        //     .flat_map(|layer| &layer.witness_builders)
        //     .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
        //     .count();

        // // Create witness IO pattern
        IOPattern::new("📜")
        //     .add_shape()
        //     .add_public_inputs(public_idxs.len())
        //     .add_logup_challenges(num_challenges)
    }

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        public_inputs: &Vec<FieldElement>,
    ) -> Result<()> {
        // // Absorb circuit shape
        // let _ = merlin.add_scalars(&[
        //     FieldElement::from(self.r1cs.num_constraints() as u64),
        //     FieldElement::from(self.r1cs.num_witnesses() as u64),
        // ]);

        // // Absorb public inputs (values) in canonical order
        // let circuit = &self.program.functions[0];
        // let public_idxs = circuit.public_inputs().indices();
        // if !public_idxs.is_empty() {
        //     let pub_vals: Vec<FieldElement> = public_idxs
        //         .iter()
        //         .map(|&i| noir_to_native(*witness.get_index(i).expect("missing public
        // input")))         .collect();
        //     let _ = merlin.add_scalars(&pub_vals);
        // }

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
