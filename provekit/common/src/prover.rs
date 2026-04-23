use {
    crate::{
        noir_proof_scheme::NoirProofScheme,
        whir_r1cs::WhirR1CSScheme,
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        HashConfig, MavrosProver, NoirElement, R1CS,
    },
    acir::circuit::Program,
    noirc_abi::Abi,
    serde::{Deserialize, Serialize},
};

/// Information about a single BSB22 commitment within the R1CS.
///
/// This is the serde-serializable version stored in `Groth16Prover`.
/// Mirrors `provekit_groth16::CommitmentInfo` (which has the same fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Groth16CommitmentInfo {
    /// Indices of public wires and other commitment wires hashed with this
    /// commitment.
    pub public_and_commitment_committed: Vec<usize>,
    /// Indices of private/internal wires committed to.
    pub private_committed: Vec<usize>,
    /// Wire index where the commitment challenge value is stored.
    pub commitment_index: usize,
    /// Number of entries in `public_and_commitment_committed` that are public
    /// (as opposed to other commitment indices).
    pub nb_public_committed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProver {
    pub hash_config:            HashConfig,
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    pub whir_for_witness:       WhirR1CSScheme,
}

/// Groth16 prover: holds R1CS, witness builders, and the serialized proving key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Prover {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    /// CanonicalSerialize'd `provekit_groth16::ProvingKey`.
    pub groth16_pk:             Vec<u8>,
    /// BSB22 commitment metadata (empty if circuit has no commitments).
    pub commitment_info:        Vec<Groth16CommitmentInfo>,
}

// INVARIANT: Variant order is wire-format-critical (postcard uses positional
// discriminants). Do not reorder, cfg-gate, or insert variants without
// verifying cross-target deserialization (native <-> WASM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Prover {
    Noir(NoirProver),
    Mavros(MavrosProver),
    Groth16(Groth16Prover),
}

impl Prover {
    /// Convert a compilation output into the on-disk prover format.
    pub fn from_noir_proof_scheme(scheme: NoirProofScheme) -> Self {
        match scheme {
            NoirProofScheme::Noir(d) => Prover::Noir(NoirProver {
                hash_config:            d.hash_config,
                program:                d.program,
                r1cs:                   d.r1cs,
                split_witness_builders: d.split_witness_builders,
                witness_generator:      d.witness_generator,
                whir_for_witness:       d.whir_for_witness,
            }),
            NoirProofScheme::Mavros(d) => Prover::Mavros(MavrosProver {
                abi:                d.abi,
                num_public_inputs:  d.num_public_inputs,
                whir_for_witness:   d.whir_for_witness,
                witgen_binary:      d.witgen_binary,
                ad_binary:          d.ad_binary,
                constraints_layout: d.constraints_layout,
                witness_layout:     d.witness_layout,
                hash_config:        d.hash_config,
            }),
        }
    }

    pub fn abi(&self) -> &Abi {
        match self {
            Prover::Noir(p) => p.witness_generator.abi(),
            Prover::Mavros(p) => &p.abi,
            Prover::Groth16(p) => p.witness_generator.abi(),
        }
    }

    pub fn size(&self) -> (usize, usize) {
        match self {
            Prover::Noir(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
            Prover::Mavros(p) => (
                p.constraints_layout.algebraic_size,
                p.witness_layout.algebraic_size,
            ),
            Prover::Groth16(p) => (p.r1cs.num_constraints(), p.r1cs.num_witnesses()),
        }
    }

    pub fn whir_for_witness(&self) -> &WhirR1CSScheme {
        match self {
            Prover::Noir(p) => &p.whir_for_witness,
            Prover::Mavros(p) => &p.whir_for_witness,
            Prover::Groth16(_) => panic!("Groth16 prover does not use WHIR"),
        }
    }
}
