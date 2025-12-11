use {
    crate::{
        whir_r1cs::WhirR1CSProver,
        witness::{witness_io_pattern::WitnessIOPattern},
    }, provekit_common::{
        FieldElement, IOPattern,  NoirProof, Prover, skyscraper::SkyscraperSponge, utils::convert_spartan_r1cs_to_provekit,
    }, spartan_vm::api as spartan_api, spongefish::ProverState, std::path::Path,
    anyhow::{Context, Result},
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
        
        let witgen_result = spartan_api::run_witgen_from_binary(&mut self.artifacts.witgen_binary, &self.artifacts.r1cs, &params);
        let witness: Vec<FieldElement> = [witgen_result.out_wit_pre_comm.clone(), witgen_result.out_wit_post_comm.clone()].concat();

        #[cfg(test)]
        assert!(spartan_api::check_witgen(&self.artifacts.r1cs, &witgen_result));

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
        // println!("Number of challenges: {:?} public inputs: {:?}", num_challenges, public_idxs.len());

        // Create witness IO pattern
        IOPattern::new("📜")
            .add_shape()
            .add_public_inputs(self.artifacts.r1cs.witness_layout.challenges_size + 1)
            .add_logup_challenges(self.artifacts.r1cs.witness_layout.lookups_data_size)
    }

    fn seed_witness_merlin(
        &mut self,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        public_inputs: &Vec<FieldElement>,
    ) -> Result<()> {
        // Absorb circuit shape
        // let _ = merlin.add_scalars(&[
        //     FieldElement::from(self.artifacts.r1cs.constraints.len() as u64),
        //     FieldElement::from(self.artifacts.r1cs.witness_layout.algebraic_size as u64),
        // ]);

        // Absorb public inputs (values) in canonical order
        // let circuit = &self.program.functions[0];
        // if !public_inputs.is_empty() {
        //     let _ = merlin.add_scalars(&public_inputs);
        // }

        Ok(())
    }
}

#[cfg(test)]
mod tests {}
