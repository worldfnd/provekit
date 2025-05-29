use {
    crate::skyscraper::skyscraper_impl::{compress, SkyscraperSponge},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    whir::{
        crypto::fields::Field256,
        whir::{
            domainsep::DigestDomainSeparator,
            utils::{DigestToUnitDeserialize, DigestToUnitSerialize},
        },
    },
};

/// Skyscraper collision-resistant hash
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            .copied()
            .reduce(compress)
            .ok_or(Error::IncorrectInputLength(0))
    }
}
/// Skyscraper collision-resistant hash for merkle inner hash

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperTwoToOne;

impl TwoToOneCRHScheme for SkyscraperTwoToOne {
    type Input = Field256;
    type Output = Field256;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Ok(compress(*left_input.borrow(), *right_input.borrow()))
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
    }
}

/// Skyscraper configuration for the Merkle hash
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperMerkleConfig;

impl Config for SkyscraperMerkleConfig {
    type Leaf = [Field256];
    type LeafDigest = Field256;
    type LeafInnerDigestConverter = IdentityDigestConverter<Field256>;
    type InnerDigest = Field256;
    type LeafHash = SkyscraperCRH;
    type TwoToOneHash = SkyscraperTwoToOne;
}

impl DigestDomainSeparator<SkyscraperMerkleConfig> for DomainSeparator<SkyscraperSponge, Field256> {
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<Field256>>::add_scalars(self, 1, label)
    }
}

impl DigestToUnitSerialize<SkyscraperMerkleConfig> for ProverState<SkyscraperSponge, Field256> {
    fn add_digest(&mut self, digest: Field256) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl DigestToUnitDeserialize<SkyscraperMerkleConfig>
    for VerifierState<'_, SkyscraperSponge, Field256>
{
    fn read_digest(&mut self) -> ProofResult<Field256> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
