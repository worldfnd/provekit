use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        sponge::Absorb,
        Error,
    },
    ark_ff::{Field, PrimeField},
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        borrow::Borrow,
        io::{Read, Write},
    },
};

/// Wrapper type for SHA256 digest that implements `Absorb` trait.
///
/// This allows SHA256 digests to be absorbed into Fiat-Shamir transcripts
/// required by WHIR's spongefish integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Digest(pub [u8; 32]);

impl Default for Sha256Digest {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl Absorb for Sha256Digest {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.0);
    }

    fn to_sponge_field_elements<F: Field>(&self, dest: &mut Vec<F>) {
        // Convert 32 bytes to field elements by chunking into 8-byte (u64) pieces
        // This gives us 4 field elements for the 32-byte digest
        for chunk in self.0.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let value = u64::from_le_bytes(bytes);
            dest.push(F::from(value));
        }
    }
}

impl CanonicalSerialize for Sha256Digest {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        32
    }
}

impl ark_serialize::Valid for Sha256Digest {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        // SHA256 digests are always valid - they're just 32 bytes
        Ok(())
    }
}

impl CanonicalDeserialize for Sha256Digest {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for Sha256Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Sha256Digest> for [u8; 32] {
    fn from(digest: Sha256Digest) -> Self {
        digest.0
    }
}

impl AsRef<[u8; 32]> for Sha256Digest {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA256-based collision-resistant hash for Merkle tree leaves
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256CRH;

impl CRHScheme for Sha256CRH {
    type Input = [FieldElement];
    type Output = Sha256Digest;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 32];

        for elem in input.borrow() {
            let bigint = elem.into_bigint();
            for (i, limb) in bigint.0.iter().enumerate() {
                buf[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
            }
            hasher.update(&buf);
        }

        Ok(Sha256Digest(hasher.finalize().into()))
    }
}

/// SHA256-based 2-to-1 hash for Merkle tree internal nodes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256TwoToOne;

impl TwoToOneCRHScheme for Sha256TwoToOne {
    type Input = Sha256Digest;
    type Output = Sha256Digest;
    type Parameters = ();

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        // sha2 crate with "asm" feature uses hardware acceleration on aarch64
        let mut hasher = Sha256::new();
        hasher.update(&left.borrow().0);
        hasher.update(&right.borrow().0);
        Ok(Sha256Digest(hasher.finalize().into()))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left: T,
        right: T,
    ) -> Result<Self::Output, Error> {
        Self::evaluate(parameters, left, right)
    }
}

/// SHA256-based Merkle tree configuration
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256MerkleConfig;

impl Config for Sha256MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = Sha256Digest;
    type LeafInnerDigestConverter = IdentityDigestConverter<Sha256Digest>;
    type InnerDigest = Sha256Digest;
    type LeafHash = Sha256CRH;
    type TwoToOneHash = Sha256TwoToOne;
}

impl crate::hash_config::TypedHashConfig for Sha256MerkleConfig {
    const HASH_CONFIG: crate::HashConfig = crate::HashConfig::Sha256;
    type Sponge = crate::sha256::Sha256Sponge;
    type Unit = u8;
}
