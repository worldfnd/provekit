#[macro_export]
macro_rules! prove {
    ($self:ident, $hash_type:expr, $H:ty) => {{
        // Load the Prover
        let prover: Prover<$H> =
            read(&$self.prover_path).context("while reading Provekit Prover")?;

        let (constraints, witnesses) = prover.size();
        info!(constraints, witnesses, "Read Noir proof scheme");

        // Generate the proof
        let proof = prover
            .prove(&$self.input_path)
            .context("While proving Noir program statement")?;

        // Verify the proof (only in test/debug if needed)
        #[cfg(test)]
        {
            let verifier: Verifier<$H> =
                read(&$self.verifier_path).context("while reading Provekit Verifier")?;
            verifier
                .verify(&proof)
                .context("While verifying Noir proof")?;
        }

        // Store the proof to file
        write(&proof, &$self.proof_path, $hash_type).context("while writing proof")?;
    }};
}

#[macro_export]
macro_rules! verify {
    ($self:ident, $H:ty) => {{
        // Load the specialized Verifier
        let mut verifier: Verifier<$H> =
            read(&$self.verifier_path).context("while reading Provekit Verifier")?;

        // Load the proof
        let proof = read(&$self.proof_path).context("while reading proof")?;

        // Perform the verification
        verifier
            .verify(&proof)
            .context("While verifying Noir proof")?;

        info!("Verification successful using {}", stringify!($H));
    }};
}
