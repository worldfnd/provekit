use {
    crate::{
        prover::SparkProverScheme,
        types::{SparkMatrix, SparkSetup, SparkWitnesses},
    },
    anyhow::Result,
    provekit_common::{FieldElement, HashConfig, TranscriptSponge, WhirR1CSProof},
    tracing::instrument,
    whir::{
        protocols::irs_commit::Commitment,
        transcript::{codecs::Empty, DomainSeparator, Proof, ProverState, VerifierState},
    },
};

pub(crate) struct PrecomputedCommitments {
    pub vals_rsws:     Commitment<FieldElement>,
    pub a_row_finalts: Commitment<FieldElement>,
    pub a_col_finalts: Commitment<FieldElement>,
}

#[instrument(skip_all)]
pub fn preprocess_spark(
    matrix: &SparkMatrix,
    hash_config: HashConfig,
) -> (SparkSetup, SparkWitnesses) {
    let num_rows = matrix.timestamps.final_row.len();
    let num_cols = matrix.timestamps.final_col.len();
    let nonzero_terms = matrix.coo.val.len();
    let scheme = SparkProverScheme::new(num_rows, num_cols, nonzero_terms, hash_config);

    let ds = DomainSeparator::protocol(&scheme.whir_configs).instance(&Empty);
    let mut merlin = ProverState::new(&ds, TranscriptSponge::from_config(hash_config));

    let row_field = matrix.coo.row_field();
    let col_field = matrix.coo.col_field();
    let read_row_field = matrix.timestamps.read_row_field();
    let read_col_field = matrix.timestamps.read_col_field();
    let vals_rs_ws_witness = scheme
        .whir_configs
        .num_terms_5batched
        .commit(&mut merlin, &[
            &matrix.coo.val,
            &row_field,
            &read_row_field,
            &col_field,
            &read_col_field,
        ]);
    drop((row_field, col_field, read_row_field, read_col_field));
    let final_row_field = matrix.timestamps.final_row_field();
    let final_row_ts_witness = scheme
        .whir_configs
        .row
        .commit(&mut merlin, &[&final_row_field]);
    drop(final_row_field);
    let final_col_field = matrix.timestamps.final_col_field();
    let final_col_ts_witness = scheme
        .whir_configs
        .col
        .commit(&mut merlin, &[&final_col_field]);
    drop(final_col_field);

    let proof = merlin.proof();
    let setup = SparkSetup {
        whir_configs: scheme.whir_configs,
        matrix_dimensions: scheme.matrix_dimensions,
        transcript: WhirR1CSProof {
            narg_string: proof.narg_string,
            hints: proof.hints,
            #[cfg(debug_assertions)]
            pattern: proof.pattern,
        },
        hash_config,
    };
    let witnesses = SparkWitnesses {
        vals_rs_ws_witness,
        final_row_ts_witness,
        final_col_ts_witness,
    };
    (setup, witnesses)
}

impl SparkSetup {
    pub(crate) fn extract_commitments(&self) -> Result<PrecomputedCommitments> {
        let setup_ds = DomainSeparator::protocol(&self.whir_configs).instance(&Empty);
        let setup_proof = Proof {
            narg_string: self.transcript.narg_string.clone(),
            hints: self.transcript.hints.clone(),
            #[cfg(debug_assertions)]
            pattern: self.transcript.pattern.clone(),
        };
        let mut side = VerifierState::new(
            &setup_ds,
            &setup_proof,
            TranscriptSponge::from_config(self.hash_config),
        );

        let vals_rsws = self
            .whir_configs
            .num_terms_5batched
            .receive_commitment(&mut side)
            .map_err(|e| anyhow::anyhow!("Failed to reconstruct vals_rsws commitment: {e}"))?;
        let a_row_finalts = self
            .whir_configs
            .row
            .receive_commitment(&mut side)
            .map_err(|e| anyhow::anyhow!("Failed to reconstruct row finalts commitment: {e}"))?;
        let a_col_finalts = self
            .whir_configs
            .col
            .receive_commitment(&mut side)
            .map_err(|e| anyhow::anyhow!("Failed to reconstruct col finalts commitment: {e}"))?;

        Ok(PrecomputedCommitments {
            vals_rsws,
            a_row_finalts,
            a_col_finalts,
        })
    }
}
