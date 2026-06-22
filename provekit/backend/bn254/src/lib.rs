//! BN254 instantiation of the ProveKit spine (`Identity<Fr>`, base == ext),
//! plus the bn254-welded Noir/Mavros frontend. Organized into `scheme` (the
//! serialized PKP/PKV/proof types), `frontend` (the Noir/ACIR bridge),
//! `solver` (witness solving), and the `prove`/`verify` orchestration.

mod field;
mod field_hash;
mod frontend;
#[cfg(not(target_arch = "wasm32"))]
mod mavros_prove;
mod prove;
mod scheme;
mod solver;
mod verify;

pub use {
    acir::FieldElement as NoirElement,
    field::{Bn254Field, WhirConfig, WhirZkConfig},
    frontend::{noir_to_native, NoirWitnessGenerator, PrintAbi},
    prove::Prove,
    provekit_common::{ec_arith::ec_scalar_mul, ProvekitProof},
    scheme::{
        MavrosProver, MavrosSchemeData, NoirProofScheme, NoirProver, NoirSchemeData, Prover,
        Verifier,
    },
    solver::solve_witness_vec,
    verify::Verify,
};
