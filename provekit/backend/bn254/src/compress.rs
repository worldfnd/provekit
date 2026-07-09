//! Memory-saving postcard compression of the witness-builder layers.
//!
//! Mirrors [`provekit_common::CompressedR1CS`]: the w2 layers are not needed
//! until challenge-dependent witness solving, so we compress them to a compact
//! blob to free memory during the w1 commit.

use {
    crate::witness::LayeredWitnessBuilders,
    anyhow::{Context, Result},
};

/// Serialized witness builder layers held as a compact postcard blob.
pub struct CompressedLayers {
    blob: Vec<u8>,
}

impl CompressedLayers {
    pub fn compress(layers: LayeredWitnessBuilders) -> Result<Self> {
        let blob = postcard::to_allocvec(&layers)
            .context("LayeredWitnessBuilders serialization failed")?;
        Ok(Self { blob })
    }

    pub fn decompress(self) -> Result<LayeredWitnessBuilders> {
        postcard::from_bytes(&self.blob).context("LayeredWitnessBuilders deserialization failed")
    }
}
