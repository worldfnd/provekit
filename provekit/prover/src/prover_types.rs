//! Backend-aware Prover enum.
//!
//! Lives in `provekit_prover` (not `provekit_common`) so the Groth16 variant
//! can hold a typed `provekit_groth16::ProvingKey` directly. Common cannot
//! import `provekit_groth16` without creating a dependency cycle, so the union
//! type that knows about every backend is rooted here.

// `MaybeHashAware` lives behind `provekit_common::file::io`, which is gated to
// non-wasm targets. The only consumer of the `MaybeHashAware for Prover` impl
// is `pkp_io`, which is itself non-wasm-gated, so confine both to that target.
#[cfg(not(target_arch = "wasm32"))]
use provekit_common::{file::MaybeHashAware, HashConfig};
use {
    acir::circuit::Program,
    provekit_common::{
        witness::{NoirWitnessGenerator, SplitWitnessBuilders},
        MavrosProver, NoirElement, NoirProver, R1CS,
    },
    serde::{Deserialize, Serialize},
};

/// BSB22 commitment info for ProveKit's Groth16 backend.
///
/// One Pedersen commitment over all private w1 wires,
/// producing multiple challenges via `hash_to_fr_multi`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Groth16CommitmentInfo {
    /// Indices of public wires hashed with the commitment.
    pub public_committed:  Vec<usize>,
    /// Indices of private/internal wires committed to via Pedersen.
    pub private_committed: Vec<usize>,
    /// Wire indices where the derived challenge values are stored.
    pub challenge_indices: Vec<usize>,
}

/// Groth16 prover: holds R1CS, witness builders, and the typed proving key.
///
/// `groth16_pk` is the deserialized [`provekit_groth16::ProvingKey`] — no
/// `Vec<u8>` round-trip on each prove. Serialization round-trips the PK
/// through arkworks `CanonicalSerialize` via the custom serde impl in the
/// groth16 crate, so the .pkp wire format is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Prover {
    pub program:                Program<NoirElement>,
    pub r1cs:                   R1CS,
    pub split_witness_builders: SplitWitnessBuilders,
    pub witness_generator:      NoirWitnessGenerator,
    /// Typed Groth16 proving key. Serialized via arkworks bytes.
    pub groth16_pk:             provekit_groth16::ProvingKey,
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
    pub fn from_noir_proof_scheme(scheme: provekit_common::NoirProofScheme) -> Self {
        use provekit_common::NoirProofScheme;
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

    pub fn abi(&self) -> &noirc_abi::Abi {
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

    /// Returns the WHIR scheme for backends that use it (Noir, Mavros).
    /// Returns `None` for Groth16, which doesn't use WHIR.
    pub fn whir_for_witness(&self) -> Option<&provekit_common::WhirR1CSScheme> {
        match self {
            Prover::Noir(p) => Some(&p.whir_for_witness),
            Prover::Mavros(p) => Some(&p.whir_for_witness),
            Prover::Groth16(_) => None,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl MaybeHashAware for Prover {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            Prover::Noir(p) => Some(p.hash_config),
            Prover::Mavros(p) => Some(p.hash_config),
            Prover::Groth16(_) => None,
        }
    }
}
