//! Memory-saving postcard compression of the R1CS.
//!
//! The R1CS is only needed during specific proving phases; serializing it to a
//! compact blob frees that memory in between. Field-agnostic: the blob is raw
//! bytes, only (de)serialization is typed.

use {
    crate::R1CS,
    anyhow::{Context, Result},
    ark_ff::Field,
};

/// Serialized R1CS matrices held as a compact postcard blob.
///
/// The R1CS is only needed during the sumcheck phase. Compressing it
/// into a serialized blob frees that memory during the commit phase,
/// then decompresses when the sumcheck begins.
pub struct CompressedR1CS {
    num_constraints: usize,
    num_witnesses:   usize,
    num_virtual:     usize,
    blob:            Vec<u8>,
}

impl CompressedR1CS {
    pub fn compress<F: Field>(r1cs: R1CS<F>) -> Result<Self> {
        let num_constraints = r1cs.num_constraints();
        let num_witnesses = r1cs.num_witnesses();
        let num_virtual = r1cs.num_virtual;
        let blob = postcard::to_allocvec(&r1cs).context("R1CS serialization failed")?;
        drop(r1cs);
        Ok(Self {
            num_constraints,
            num_witnesses,
            num_virtual,
            blob,
        })
    }

    pub fn decompress<F: Field>(self) -> Result<R1CS<F>> {
        postcard::from_bytes(&self.blob).context("R1CS deserialization failed")
    }

    pub const fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    pub const fn num_witnesses(&self) -> usize {
        self.num_witnesses
    }

    /// Total witnesses needed for solving: real witnesses (matrix columns)
    /// plus virtual witnesses (computation-only).
    pub const fn num_witnesses_for_solving(&self) -> usize {
        self.num_witnesses + self.num_virtual
    }

    pub fn blob_len(&self) -> usize {
        self.blob.len()
    }
}
