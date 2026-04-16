use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        NoirElement, PublicInputs, R1CS,
    },
    acir::circuit::Program,
    anyhow::{Context, Result},
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    serde::{Deserialize, Serialize},
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoirProof {
    pub public_inputs:   PublicInputs,
    pub whir_r1cs_proof: WhirR1CSProof,
}

impl NoirProofScheme {
    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }
}

impl NoirProof {
    /// Encode to a portable text form: CBOR, wrapped in base64url (no padding).
    pub fn encode(&self) -> Result<String> {
        let mut cbor = Vec::new();
        ciborium::into_writer(self, &mut cbor).context("CBOR encode NoirProof")?;
        Ok(URL_SAFE_NO_PAD.encode(cbor))
    }

    /// Inverse of [`encode`](Self::encode).
    pub fn decode(s: &str) -> Result<Self> {
        let cbor = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .context("base64url decode NoirProof")?;
        ciborium::from_reader(cbor.as_slice()).context("CBOR decode NoirProof")
    }
}
