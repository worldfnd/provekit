use {
    crate::{
        hash::{
            hash::{CompressionScheme, PermutationScheme},
            Sponge,
        },
        FieldElement,
    },
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
        DomainSeparator as SpongeDomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    whir::whir::{
        domainsep::DigestDomainSeparator,
        utils::{DigestToUnitDeserialize, DigestToUnitSerialize},
    },
};

fn compress<C: CompressionScheme>(l: FieldElement, r: FieldElement) -> FieldElement {
    let l64 = l.into_bigint().0;
    let r64 = r.into_bigint().0;
    let out = C::compress(l64, r64);
    FieldElement::new(BigInt(out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CRH<C: CompressionScheme>(std::marker::PhantomData<C>);

impl<C: CompressionScheme> CRHScheme for CRH<C> {
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
            .reduce(compress::<C>)
            .ok_or(Error::IncorrectInputLength(0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoToOne<C: CompressionScheme>(std::marker::PhantomData<C>);

impl<C: CompressionScheme> TwoToOneCRHScheme for TwoToOne<C> {
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
        Ok(compress::<C>(*l.borrow(), *r.borrow()))
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
pub struct MerkleConfig<C: CompressionScheme> {
    _marker: std::marker::PhantomData<C>,
}

impl<C: CompressionScheme> Config for MerkleConfig<C> {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = CRH<C>;
    type TwoToOneHash = TwoToOne<C>;
}

impl<C: CompressionScheme, P: PermutationScheme> DigestDomainSeparator<MerkleConfig<C>>
    for SpongeDomainSeparator<Sponge<P>, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl<C: CompressionScheme, P: PermutationScheme> DigestToUnitSerialize<MerkleConfig<C>>
    for ProverState<Sponge<P>, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<C: CompressionScheme, P: PermutationScheme> DigestToUnitDeserialize<MerkleConfig<C>>
    for VerifierState<'_, Sponge<P>, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
