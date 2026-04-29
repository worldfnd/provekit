use {
    crate::{
        whir_r1cs::{WhirR1CSProof, WhirR1CSScheme},
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, MavrosSchemeData, NoirElement, PublicInputs, R1CS,
    },
    acir::circuit::Program,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirSchemeData {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
    pub hash_config:            HashConfig,
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoirProofScheme {
    Noir(NoirSchemeData),
    Mavros(MavrosSchemeData),
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NoirProof {
    Whir {
        public_inputs:   PublicInputs,
        whir_r1cs_proof: WhirR1CSProof,
    },
    Groth16 {
        public_inputs: PublicInputs,
        /// CanonicalSerialize'd `provekit_groth16::Proof`.
        groth16_proof: Vec<u8>,
    },
}

impl NoirProof {
    /// Access public inputs regardless of proof variant.
    pub fn public_inputs(&self) -> &PublicInputs {
        match self {
            NoirProof::Whir { public_inputs, .. } => public_inputs,
            NoirProof::Groth16 { public_inputs, .. } => public_inputs,
        }
    }

    /// Mutably access public inputs regardless of proof variant.
    pub fn public_inputs_mut(&mut self) -> &mut PublicInputs {
        match self {
            NoirProof::Whir { public_inputs, .. } => public_inputs,
            NoirProof::Groth16 { public_inputs, .. } => public_inputs,
        }
    }

    /// Access the WHIR proof, panics if this is a Groth16 proof.
    pub fn whir_r1cs_proof(&self) -> &WhirR1CSProof {
        match self {
            NoirProof::Whir {
                whir_r1cs_proof, ..
            } => whir_r1cs_proof,
            NoirProof::Groth16 { .. } => panic!("called whir_r1cs_proof() on a Groth16 proof"),
        }
    }
}

impl NoirProofScheme {
    #[must_use]
    pub fn r1cs(&self) -> &R1CS {
        match self {
            NoirProofScheme::Noir(d) => &d.r1cs,
            NoirProofScheme::Mavros(d) => &d.r1cs,
        }
    }

    #[must_use]
    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            NoirProofScheme::Noir(d) => &d.whir_for_witness,
            NoirProofScheme::Mavros(d) => &d.whir_for_witness,
        }
    }

    #[must_use]
    pub fn size(&self) -> (usize, usize) {
        let r1cs = self.r1cs();
        (r1cs.num_constraints(), r1cs.num_witnesses())
    }

    #[must_use]
    pub fn abi(&self) -> &noirc_abi::Abi {
        match self {
            NoirProofScheme::Noir(d) => d.witness_generator.abi(),
            NoirProofScheme::Mavros(d) => &d.abi,
        }
    }
}
