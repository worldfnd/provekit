//! Keccak256 hash implementations for Merkle tree construction.

use {
    crate::FieldElement,
    ark_crypto_primitives::{crh::CRHScheme, Error},
    ark_serialize::CanonicalSerialize,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha3::Digest,
    std::{borrow::Borrow, io::Write},
    whir::crypto::merkle_tree::digest::GenericDigest,
};

pub type Keccak256Digest = GenericDigest<32>;

/// 8-byte length prefix + up to 16 field elements (16 * 32 = 512 bytes).
const LEAF_BUFFER_SIZE: usize = 528;

struct StackBuffer {
    buf: [u8; LEAF_BUFFER_SIZE],
    pos: usize,
}

impl StackBuffer {
    fn new() -> Self {
        Self {
            buf: [0u8; LEAF_BUFFER_SIZE],
            pos: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl Write for StackBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let available = LEAF_BUFFER_SIZE - self.pos;
        if data.len() > available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "buffer overflow",
            ));
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keccak256LeafHash;

impl CRHScheme for Keccak256LeafHash {
    type Input = [FieldElement];
    type Output = Keccak256Digest;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();
        let required_size = 8 + input.len() * 32;

        if required_size <= LEAF_BUFFER_SIZE {
            let mut buf = StackBuffer::new();
            input.serialize_compressed(&mut buf)?;
            let output: [u8; 32] = sha3::Keccak256::digest(buf.as_slice()).into();
            Ok(output.into())
        } else {
            let mut buf = Vec::with_capacity(required_size);
            input.serialize_compressed(&mut buf)?;
            let output: [u8; 32] = sha3::Keccak256::digest(&buf).into();
            Ok(output.into())
        }
    }
}

pub use whir::crypto::merkle_tree::keccak::KeccakCompress as Keccak256Compress;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_ff::One;
    use whir::crypto::merkle_tree::keccak::KeccakLeafHash;

    #[test]
    fn leaf_hash_matches_whir() {
        let input = vec![
            FieldElement::one(),
            FieldElement::from(42u64),
            FieldElement::from(123456u64),
            FieldElement::from(999999u64),
        ];
        let whir = KeccakLeafHash::<FieldElement>::evaluate(&(), input.as_slice()).unwrap();
        let ours = Keccak256LeafHash::evaluate(&(), input.as_slice()).unwrap();
        assert_eq!(whir, ours);
    }

    #[test]
    fn leaf_hash_all_sizes() {
        for n in 1..=20 {
            let input: Vec<FieldElement> = (0..n).map(|i| FieldElement::from(i as u64)).collect();
            let whir = KeccakLeafHash::<FieldElement>::evaluate(&(), input.as_slice()).unwrap();
            let ours = Keccak256LeafHash::evaluate(&(), input.as_slice()).unwrap();
            assert_eq!(whir, ours, "mismatch at n={}", n);
        }
    }
}
