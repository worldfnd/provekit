//! BLAKE3 hash implementations for Merkle tree construction.

use {
    crate::FieldElement,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        Error,
    },
    ark_serialize::CanonicalSerialize,
    rand08::Rng,
    serde::{Deserialize, Serialize},
    std::{borrow::Borrow, io::Write},
    whir::crypto::merkle_tree::digest::GenericDigest,
};

pub type Blake3Digest = GenericDigest<32>;

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
pub struct Blake3LeafHash;

impl CRHScheme for Blake3LeafHash {
    type Input = [FieldElement];
    type Output = Blake3Digest;
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
            let output: [u8; 32] = blake3::hash(buf.as_slice()).into();
            Ok(output.into())
        } else {
            let mut buf = Vec::with_capacity(required_size);
            input.serialize_compressed(&mut buf)?;
            let output: [u8; 32] = blake3::hash(&buf).into();
            Ok(output.into())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake3Compress;

impl TwoToOneCRHScheme for Blake3Compress {
    type Input = Blake3Digest;
    type Output = Blake3Digest;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left_input.borrow().0);
        buf[32..].copy_from_slice(&right_input.borrow().0);
        let output: [u8; 32] = blake3::hash(&buf).into();
        Ok(output.into())
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme},
        ark_ff::One,
        whir::crypto::merkle_tree::blake3::{
            Blake3Compress as WhirCompress, Blake3LeafHash as WhirLeafHash,
        },
    };

    #[test]
    fn leaf_hash_matches_whir() {
        let input = vec![
            FieldElement::one(),
            FieldElement::from(42u64),
            FieldElement::from(123456u64),
            FieldElement::from(999999u64),
        ];
        let whir = WhirLeafHash::<FieldElement>::evaluate(&(), input.as_slice()).unwrap();
        let ours = Blake3LeafHash::evaluate(&(), input.as_slice()).unwrap();
        assert_eq!(whir, ours);
    }

    #[test]
    fn compress_matches_whir() {
        let left: Blake3Digest = [1u8; 32].into();
        let right: Blake3Digest = [2u8; 32].into();
        let whir = WhirCompress::evaluate(&(), &left, &right).unwrap();
        let ours = Blake3Compress::evaluate(&(), &left, &right).unwrap();
        assert_eq!(whir, ours);
    }
}
