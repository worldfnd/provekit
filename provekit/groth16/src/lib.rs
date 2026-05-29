/// Groth16 proof system with BSB22 commitment extension for BN254.
///
/// Built on arkworks primitives for elliptic curve operations, pairings,
/// FFT, and MSM.
///
/// Reference: DIZK paper <https://eprint.iacr.org/2018/691.pdf> (Figure 4)
/// BSB22 extension: <https://eprint.iacr.org/2022/1072>
pub mod pedersen;
pub mod prover;
pub mod setup;
pub mod types;
pub mod verifier;

#[cfg(not(target_arch = "wasm32"))]
pub mod mmap_pk;

#[cfg(not(target_arch = "wasm32"))]
pub use mmap_pk::{MmapProvingKey, MMAP_SENTINEL};
pub use types::{Proof, ProvingKey, VerifyingKey};

/// Extension trait for [`provekit_common::Verifier`] that decodes the
/// `groth16_vk: Option<Vec<u8>>` field into a typed [`VerifyingKey`] in one
/// place — so consumers don't each repeat the
/// `CanonicalDeserialize::deserialize_uncompressed(&bytes[..])` dance.
pub trait VerifierGroth16Ext {
    /// Decode the embedded Groth16 verifying key, if present.
    ///
    /// `Ok(None)` means this PKV is for the WHIR backend; `Err` means a VK
    /// was present but failed to deserialize.
    fn groth16_vk_typed(&self) -> anyhow::Result<Option<VerifyingKey>>;
}

impl VerifierGroth16Ext for provekit_common::Verifier {
    fn groth16_vk_typed(&self) -> anyhow::Result<Option<VerifyingKey>> {
        use {anyhow::Context, ark_serialize::CanonicalDeserialize};
        self.groth16_vk
            .as_ref()
            .map(|bytes| {
                VerifyingKey::deserialize_uncompressed(&bytes[..]).context("decoding groth16_vk")
            })
            .transpose()
    }
}

/// Domain separator for BSB22 commitment hashing.
pub const COMMITMENT_DST: &[u8] = b"bsb22-commitment";

/// Domain separator for folding PoKs.
pub const BSB22_FOLD_DST: &[u8] = b"G16-BSB22";

/// Field element byte length for BN254.
pub const FR_BYTES: usize = 32;

/// Information about a single BSB22 commitment within the R1CS.
///
/// All wire indices in this struct are **absolute witness indices**: position
/// 0 is the constant-1 ONE_WIRE, public input `i` lives at index `1 + i`, and
/// private/challenge wires follow. The verifier subtracts 1 when looking up
/// values in its `extended_public` vector (which excludes the ONE_WIRE), so
/// index 0 is never a valid entry in `public_and_commitment_committed`.
#[derive(Clone, Debug, Default)]
pub struct CommitmentInfo {
    /// Indices of public wires and other commitment wires hashed with this
    /// commitment. See struct-level docs for index convention.
    pub public_and_commitment_committed: Vec<usize>,
    /// Indices of private/internal wires committed to.
    pub private_committed:               Vec<usize>,
    /// Wire indices that hold derived challenge values for this commitment,
    /// in the order the verifier inserts them into `extended_public`.
    /// `setup()` flattens these across `commitment_info` to know which wires
    /// belong to `vk.g1_k`; the prover writes derived challenges into the
    /// witness at these positions.
    pub challenge_indices:               Vec<usize>,
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

pub(crate) fn msm_err(e: usize) -> anyhow::Error {
    anyhow::anyhow!("MSM error: bases/scalars length mismatch ({})", e)
}
