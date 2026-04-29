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
    pub private_committed:               Vec<usize>,
    /// Wire index where the commitment challenge value is stored.
    pub commitment_index:                usize,
    /// Number of entries in `public_and_commitment_committed` that are public
    /// (as opposed to other commitment indices).
    pub nb_public_committed:             usize,
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

/// Helper to convert arkworks MSM errors (which are just `usize`) into anyhow
/// errors.
pub(crate) fn msm_err(e: usize) -> anyhow::Error {
    anyhow::anyhow!("MSM error: bases/scalars length mismatch ({})", e)
}
