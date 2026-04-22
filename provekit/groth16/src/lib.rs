/// Groth16 proof system with BSB22 commitment extension for BN254.
///
/// This is a Rust port of gnark's Groth16 BN254 backend, using arkworks
/// primitives for elliptic curve operations, pairings, FFT, and MSM.
///
/// Reference: DIZK paper <https://eprint.iacr.org/2018/691.pdf> (Figure 4)
/// BSB22 extension: <https://eprint.iacr.org/2022/1072>
pub mod pedersen;
pub mod prover;
pub mod setup;
pub mod types;
pub mod verifier;

pub use types::{Proof, ProvingKey, VerifyingKey};

use ark_bn254::Fr;

/// Domain separator for BSB22 commitment hashing.
pub const COMMITMENT_DST: &[u8] = b"bsb22-commitment";

/// Domain separator for folding PoKs.
pub const BSB22_FOLD_DST: &[u8] = b"G16-BSB22";

/// Field element byte length for BN254.
pub const FR_BYTES: usize = 32;

/// Information about a single BSB22 commitment within the R1CS.
#[derive(Clone, Debug, Default)]
pub struct CommitmentInfo {
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

impl CommitmentInfo {
    /// Returns the public wire indices committed to.
    pub fn public_committed(&self) -> &[usize] {
        &self.public_and_commitment_committed[..self.nb_public_committed]
    }

    /// Returns the commitment wire indices committed to.
    pub fn commitment_committed(&self) -> &[usize] {
        &self.public_and_commitment_committed[self.nb_public_committed..]
    }
}

/// R1CS input for Groth16 setup and proving.
///
/// This is an adapter type that holds the constraint system in a form
/// suitable for Groth16. ProveKit's native `R1CS` (SparseMatrix-based)
/// must be converted into this form before use.
#[derive(Clone, Debug)]
pub struct R1CSMatrices {
    /// Number of public variables (including the constant 1 wire).
    pub nb_public_variables: usize,
    /// Number of secret (private) variables.
    pub nb_secret_variables: usize,
    /// Number of internal variables.
    pub nb_internal_variables: usize,
    /// Number of constraints.
    pub nb_constraints: usize,
    /// Constraint terms: for each constraint, the L (A), R (B), O (C) terms.
    /// Each term is (wire_id, coefficient).
    pub constraints: Vec<R1CConstraint>,
    /// BSB22 commitment information.
    pub commitment_info: Vec<CommitmentInfo>,
    /// Coefficient table (interned field elements).
    pub coefficients: Vec<Fr>,
}

impl R1CSMatrices {
    /// Total number of wires.
    pub fn nb_wires(&self) -> usize {
        self.nb_public_variables + self.nb_secret_variables + self.nb_internal_variables
    }

    /// Returns the commitment wire indices.
    pub fn commitment_indexes(&self) -> Vec<usize> {
        self.commitment_info
            .iter()
            .map(|c| c.commitment_index)
            .collect()
    }

    /// Returns private committed wire indices per commitment.
    pub fn private_committed(&self) -> Vec<Vec<usize>> {
        self.commitment_info
            .iter()
            .map(|c| c.private_committed.clone())
            .collect()
    }
}

/// A single R1CS constraint: L * R = O, where L, R, O are linear combinations.
#[derive(Clone, Debug)]
pub struct R1CConstraint {
    /// Left (A) terms: Vec<(wire_id, coeff_id)>.
    pub l: Vec<Term>,
    /// Right (B) terms: Vec<(wire_id, coeff_id)>.
    pub r: Vec<Term>,
    /// Output (C) terms: Vec<(wire_id, coeff_id)>.
    pub o: Vec<Term>,
}

/// A term in a linear combination: references a wire and a coefficient.
#[derive(Clone, Copy, Debug)]
pub struct Term {
    pub wire_id: usize,
    pub coeff_id: usize,
}

/// Well-known coefficient IDs (matching gnark's convention).
pub const COEFF_ID_ZERO: usize = 0;
pub const COEFF_ID_ONE: usize = 1;
pub const COEFF_ID_MINUS_ONE: usize = 2;
pub const COEFF_ID_TWO: usize = 3;

/// Helper to convert arkworks MSM errors (which are just `usize`) into anyhow errors.
pub(crate) fn msm_err(e: usize) -> anyhow::Error {
    anyhow::anyhow!("MSM error: bases/scalars length mismatch ({})", e)
}
