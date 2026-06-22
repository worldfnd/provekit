//! BN254 instantiation of the ProveKit spine (`Identity<Fr>`, base == ext),
//! plus the bn254-welded Noir/Mavros frontend: scheme types, file-format glue,
//! and the Noir↔native field bridge.

#[cfg(not(target_arch = "wasm32"))]
mod file_format;
mod mavros;
mod noir_proof_scheme;
mod print_abi;
mod prover;
mod verifier;
mod witness_generator;

pub use {
    acir::FieldElement as NoirElement,
    mavros::{MavrosProver, MavrosSchemeData},
    noir_proof_scheme::{NoirProof, NoirProofScheme, NoirSchemeData},
    print_abi::PrintAbi,
    prover::{NoirProver, Prover},
    verifier::Verifier,
    witness_generator::NoirWitnessGenerator,
};
use {
    ark_ff::{BigInt, PrimeField},
    provekit_common::FieldElement,
};

/// Convert a Noir field element to a native `FieldElement`.
#[inline(always)]
pub fn noir_to_native(n: NoirElement) -> FieldElement {
    let limbs = n.into_repr().into_bigint().0;
    FieldElement::from(BigInt(limbs))
}
