use {
    crate::{skyscraper::SkyscraperSponge, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    core::mem::size_of,
    std::borrow::Borrow, whir::merkle_tree::{Hasher, Hash},
};


fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let l64 = l.into_bigint().0;
    let r64 = r.into_bigint().0;
    let out = skyscraper::simple::compress(l64, r64);
    FieldElement::new(BigInt(out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperCRH;

impl CRHScheme for SkyscraperCRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();
    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }
    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        input
            .borrow()
            .iter()
            .copied()
            .reduce(compress)
            .ok_or(Error::IncorrectInputLength(0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperTwoToOne;

impl TwoToOneCRHScheme for SkyscraperTwoToOne {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();
    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }
    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        Ok(compress(*l.borrow(), *r.borrow()))
    }
    fn compress<T: Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(p, l, r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperMerkleConfig;

impl Config for SkyscraperMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = SkyscraperCRH;
    type TwoToOneHash = SkyscraperTwoToOne;
}

impl whir::whir::domainsep::DigestDomainSeparator<SkyscraperMerkleConfig>
    for DomainSeparator<SkyscraperSponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<SkyscraperMerkleConfig>
    for ProverState<SkyscraperSponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<SkyscraperMerkleConfig>
    for VerifierState<'_, SkyscraperSponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}

pub struct SkyscraperHasher;

impl SkyscraperHasher {
    pub fn new() -> Self {
        // Skyscraper outputs 32 bytes (one field element)
        assert_eq!(size_of::<Hash>(), 32);
        Self
    }
}

impl Hasher for SkyscraperHasher {
    fn hash_many(&self, size: usize, input: &[u8], output: &mut [Hash]) {
        assert_eq!(input.len() % size, 0, "Input length not a multiple of message size.");
        assert_eq!(input.len() / 2, output.len() * 32, "Output length mismatch.");

        // Reinterpret `&mut [Hash]` as a flat `&mut [u8]`
        let out_bytes_len = output.len() * size_of::<Hash>();
        let out_bytes = unsafe {
            core::slice::from_raw_parts_mut(output.as_mut_ptr().cast::<u8>(), out_bytes_len)
        };

        // Choose the implementation you want:
        // skyscraper::reference::compress_many(input, out_bytes);
        // skyscraper::v1::compress_many(input, out_bytes);
        // skyscraper::block3::compress_many(input, out_bytes);
        skyscraper::block4::compress_many(input, out_bytes);
        // skyscraper::simple::compress_many(input, out_bytes);
    }
}