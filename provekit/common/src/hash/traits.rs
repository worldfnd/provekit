use {
    crate::FieldElement, ark_crypto_primitives::merkle_tree::Config,
    spongefish::duplex_sponge::Permutation, spongefish_pow::PowStrategy,
};

pub trait HashCore: Clone + Send + Sync + 'static {
    fn compress(left: FieldElement, right: FieldElement) -> FieldElement;
    fn permute(left: FieldElement, right: FieldElement) -> (FieldElement, FieldElement);
    fn solve_pow(challenge: [u8; 32], bits: f64) -> Option<u64>;
    fn check_pow(challenge: [u8; 32], bits: f64, nonce: u64) -> bool;
}

pub trait ProtocolHash: Clone + Send + Sync + 'static {
    type Permutation: Permutation<U = FieldElement> + Clone + Default + Send + Sync;
    type Sponge: Clone + Default + Send + Sync;
    type MerkleConfig: Config<Leaf = [FieldElement], LeafDigest = FieldElement, InnerDigest = FieldElement>
        + Clone
        + Send
        + Sync;
    type PoW: PowStrategy;

    fn compress(left: FieldElement, right: FieldElement) -> FieldElement;

    fn hash_slice(input: &[FieldElement]) -> FieldElement {
        input
            .iter()
            .copied()
            .reduce(Self::compress)
            .unwrap_or_else(|| FieldElement::from(0u64))
    }

    fn name() -> &'static str;
}
