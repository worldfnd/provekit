#[allow(missing_docs)]
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{
        Config,
        IdentityDigestConverter,
    },
    Error,
};
use crate::skyscraper::skyscraper::SkyscraperSponge;
use nimue::{Arthur, IOPattern, Merlin, ProofResult};
use nimue::plugins::ark::{FieldIOPattern, FieldReader, FieldWriter};
use rand::Rng;
use std::borrow::Borrow;
use whir::{
    crypto::fields::Field256,
    whir::{
        iopattern::DigestIOPattern,
        fs_utils::{DigestReader, DigestWriter},
    },
};
/// TODO: Add documentation
pub struct SkyscraperCRH;

impl CRHScheme for SkyscraperCRH {
    type Input = [Field256];
    type Output = Field256;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let elems = input.borrow();
        elems
            .iter()
            .cloned()
            .reduce(crate::skyscraper::skyscraper::compress)
            .ok_or(Error::IncorrectInputLength(0))
    }
}
/// TODO: Add documentation
pub struct SkyscraperTwoToOne;

impl TwoToOneCRHScheme for SkyscraperTwoToOne {
    type Input = Field256;
    type Output = Field256;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Ok(crate::skyscraper::skyscraper::compress(
            left_input.borrow().clone(),
            right_input.borrow().clone(),
        ))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}

#[derive(Clone, Copy)]
/// Skyscraper configuration for the Merkle hash
pub struct SkyscraperMerkleConfig;

impl Config for SkyscraperMerkleConfig {
    type Leaf = [Field256];
    type LeafDigest = Field256;
    type LeafInnerDigestConverter = IdentityDigestConverter<Field256>;
    type InnerDigest = Field256;
    type LeafHash = SkyscraperCRH;
    type TwoToOneHash = SkyscraperTwoToOne;
}

impl DigestIOPattern<SkyscraperMerkleConfig> for IOPattern<SkyscraperSponge, Field256> {
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldIOPattern<Field256>>::add_scalars(self, 1, label)
    }
}

impl DigestWriter<SkyscraperMerkleConfig> for Merlin<SkyscraperSponge, Field256> {
    fn add_digest(&mut self, digest: Field256) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl <'a> DigestReader<SkyscraperMerkleConfig> for Arthur<'a, SkyscraperSponge, Field256> {
    fn read_digest(&mut self) -> ProofResult<Field256> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}