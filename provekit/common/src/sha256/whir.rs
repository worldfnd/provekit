use {
    crate::{
        sha256::{Sha256Digest, Sha256MerkleConfig, Sha256Sponge},
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
// SHA256 Hybrid Implementation
// ============================================================================
// SHA256 for Merkle commitments + Skyscraper for Fiat-Shamir transcript
// This is the standard approach used in production ZK systems.

/// Implementation of DigestDomainSeparator for SHA256 Merkle with Skyscraper Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Sha256MerkleConfig>
    for DomainSeparator<SkyscraperSponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        // Convert SHA256 digest (32 bytes) to 4 field elements (8 bytes each)
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 4, label)
    }
}

/// Implementation of DigestToUnitSerialize for SHA256 Merkle with Skyscraper Fiat-Shamir.
impl whir::whir::utils::DigestToUnitSerialize<Sha256MerkleConfig>
    for ProverState<SkyscraperSponge, FieldElement>
{
    fn add_digest(&mut self, digest: Sha256Digest) -> ProofResult<()> {
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

/// Implementation of DigestToUnitDeserialize for SHA256 Merkle with Skyscraper Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Sha256MerkleConfig>
    for VerifierState<'_, SkyscraperSponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<Sha256Digest> {
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

        Ok(Sha256Digest(bytes))
    }
}

// ============================================================================
// SHA256 Pure Implementation
// ============================================================================
// SHA256 for both Merkle commitments AND Fiat-Shamir transcript
// Uses byte serialization for field elements through spongefish codecs.

/// Implementation of DigestDomainSeparator for SHA256 Merkle with SHA256 Fiat-Shamir.
impl whir::whir::domainsep::DigestDomainSeparator<Sha256MerkleConfig>
    for DomainSeparator<Sha256Sponge, u8>
{
    fn add_digest(self, label: &str) -> Self {
        // SHA256 digest is 32 bytes
        self.absorb(32, label)
    }
}

/// Implementation of DigestToUnitSerialize for SHA256 Merkle with SHA256 Fiat-Shamir.
impl whir::whir::utils::DigestToUnitSerialize<Sha256MerkleConfig>
    for ProverState<Sha256Sponge, u8>
{
    fn add_digest(&mut self, digest: Sha256Digest) -> ProofResult<()> {
        // Add the 32-byte digest directly to the SHA256 sponge
        self.add_bytes(&digest.0)
            .map_err(|_| spongefish::ProofError::SerializationError)
    }
}

/// Implementation of DigestToUnitDeserialize for SHA256 Merkle with SHA256 Fiat-Shamir.
impl whir::whir::utils::DigestToUnitDeserialize<Sha256MerkleConfig>
    for VerifierState<'_, Sha256Sponge, u8>
{
    fn read_digest(&mut self) -> ProofResult<Sha256Digest> {
        // Read 32 bytes from the SHA256 sponge
        let bytes: [u8; 32] = self.next_bytes()?;
        Ok(Sha256Digest(bytes))
    }
}
