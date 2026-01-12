//! WHIR integration for BLAKE3-based Merkle trees.
//!
//! Implements the necessary traits to use BLAKE3 Merkle trees with WHIR's proof
//! system.
//!
//! Provides two implementations:
//! 1. **Hybrid**: BLAKE3 Merkle + Skyscraper Fiat-Shamir (field-native
//!    operations)
//! 2. **Pure**: BLAKE3 Merkle + BLAKE3 Fiat-Shamir (pure cryptographic hash)

use {
    crate::{
        blake3::{Blake3Digest, Blake3MerkleConfig, Blake3Sponge},
        skyscraper::SkyscraperSponge,
        FieldElement,
    },
    ark_ff::PrimeField,
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        BytesToUnitDeserialize, BytesToUnitSerialize, DomainSeparator, ProofResult, ProverState,
        VerifierState,
    },
};

// ============================================================================
// BLAKE3 Hybrid Implementation
// ============================================================================
// BLAKE3 for Merkle commitments + Skyscraper for Fiat-Shamir transcript
// This is the standard approach used in production ZK systems.

/// Implementation of DigestDomainSeparator for BLAKE3 Merkle with Skyscraper
/// Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Blake3MerkleConfig>
    for DomainSeparator<SkyscraperSponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        // Convert BLAKE3 digest (32 bytes) to 4 field elements (8 bytes each)
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 4, label)
    }
}

/// Implementation of DigestToUnitSerialize for BLAKE3 Merkle with Skyscraper
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitSerialize<Blake3MerkleConfig>
    for ProverState<SkyscraperSponge, FieldElement>
{
    fn add_digest(&mut self, digest: Blake3Digest) -> ProofResult<()> {
        // Convert 32-byte digest to 4 field elements (8 bytes each)
        let mut field_elements = Vec::new();
        for chunk in digest.0.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(bytes);
            field_elements.push(FieldElement::from(value));
        }
        self.add_scalars(&field_elements)
    }
}

/// Implementation of DigestToUnitDeserialize for BLAKE3 Merkle with Skyscraper
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Blake3MerkleConfig>
    for VerifierState<'_, SkyscraperSponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<Blake3Digest> {
        // Read 4 field elements and convert back to 32 bytes
        let field_elements = self.next_scalars::<4>()?;
        let mut bytes = [0u8; 32];

        for (i, elem) in field_elements.iter().enumerate() {
            let bigint = elem.into_bigint();
            let limbs = bigint.as_ref();
            let chunk_bytes = limbs[0].to_le_bytes();
            let start: usize = i * 8;
            let end: usize = (start + 8).min(32);
            bytes[start..end].copy_from_slice(&chunk_bytes[..(end - start)]);
        }

        Ok(bytes.into())
    }
}

// ============================================================================
// BLAKE3 Pure Implementation
// ============================================================================
// BLAKE3 for both Merkle commitments AND Fiat-Shamir transcript
// Uses byte serialization for field elements through spongefish codecs.

/// Implementation of DigestDomainSeparator for BLAKE3 Merkle with BLAKE3
/// Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Blake3MerkleConfig>
    for DomainSeparator<Blake3Sponge, u8>
{
    fn add_digest(self, label: &str) -> Self {
        // BLAKE3 digest is 32 bytes
        self.absorb(32, label)
    }
}

/// Implementation of DigestToUnitSerialize for BLAKE3 Merkle with BLAKE3
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitSerialize<Blake3MerkleConfig>
    for ProverState<Blake3Sponge, u8>
{
    fn add_digest(&mut self, digest: Blake3Digest) -> ProofResult<()> {
        // Add the 32-byte digest directly to the BLAKE3 sponge
        self.add_bytes(&digest.0)
            .map_err(|_| spongefish::ProofError::SerializationError)
    }
}

/// Implementation of DigestToUnitDeserialize for BLAKE3 Merkle with BLAKE3
/// Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Blake3MerkleConfig>
    for VerifierState<'_, Blake3Sponge, u8>
{
    fn read_digest(&mut self) -> ProofResult<Blake3Digest> {
        // Read 32 bytes from the BLAKE3 sponge
        let bytes: [u8; 32] = self.next_bytes()?;
        Ok(bytes.into())
    }
}
