/// Macro to generate WHIR-compatible types (CRH, TwoToOne, MerkleConfig) and trait impls.
///
/// Requires the calling module to have `FieldElement` and the hasher type in scope.
/// The hasher must implement `HashCore`.
#[macro_export]
macro_rules! impl_hash_whir {
    ($name:ident, $hasher:ty) => {
        use {
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
        };

        paste::paste! {
            #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
            pub struct [<$name CRH>];

            impl CRHScheme for [<$name CRH>] {
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
                        .reduce(<$hasher as HashCore>::compress)
                        .ok_or(Error::IncorrectInputLength(0))
                }
            }

            #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
            pub struct [<$name TwoToOne>];

            impl TwoToOneCRHScheme for [<$name TwoToOne>] {
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
                    Ok(<$hasher as HashCore>::compress(*l.borrow(), *r.borrow()))
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
            pub struct [<$name MerkleConfig>];

            impl Config for [<$name MerkleConfig>] {
                type Leaf = [FieldElement];
                type LeafDigest = FieldElement;
                type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
                type InnerDigest = FieldElement;
                type LeafHash = [<$name CRH>];
                type TwoToOneHash = [<$name TwoToOne>];
            }

            impl whir::whir::domainsep::DigestDomainSeparator<[<$name MerkleConfig>]>
                for DomainSeparator<[<$name Sponge>], FieldElement>
            {
                fn add_digest(self, label: &str) -> Self {
                    <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
                }
            }

            impl whir::whir::utils::DigestToUnitSerialize<[<$name MerkleConfig>]>
                for ProverState<[<$name Sponge>], FieldElement>
            {
                fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
                    self.add_scalars(&[digest])
                }
            }

            impl whir::whir::utils::DigestToUnitDeserialize<[<$name MerkleConfig>]>
                for VerifierState<'_, [<$name Sponge>], FieldElement>
            {
                fn read_digest(&mut self) -> ProofResult<FieldElement> {
                    let [r] = self.next_scalars()?;
                    Ok(r)
                }
            }
        }
    };
}
