//! BN254 instantiation of the ProveKit spine (`Identity<Fr>`, base == ext),
//! plus the bn254-welded Noir/Mavros frontend: scheme types, the prove/verify
//! glue and witness solver, file-format glue, and the Noir↔native field bridge.

mod bigint_mod;
mod ec_arith;
#[cfg(not(target_arch = "wasm32"))]
mod file_format;
#[cfg(not(target_arch = "wasm32"))]
mod input_utils;
mod logging;
mod mavros;
mod noir_proof_scheme;
mod print_abi;
mod prove;
mod prover;
mod r1cs;
mod verifier;
mod verify;
mod witness;
mod witness_generator;

pub use {
    acir::FieldElement as NoirElement,
    ec_arith::ec_scalar_mul,
    mavros::{MavrosProver, MavrosSchemeData},
    noir_proof_scheme::{NoirProofScheme, NoirSchemeData},
    print_abi::PrintAbi,
    prove::Prove,
    provekit_common::{Bn254Field, ProvekitProof},
    prover::{NoirProver, Prover},
    r1cs::solve_witness_vec,
    verifier::Verifier,
    verify::Verify,
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
