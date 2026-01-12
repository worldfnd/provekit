use ark_bn254::Fr;

pub trait PowScheme: Clone + Send + Sync + 'static {
    fn check(challenge: [u64; 4], bits: f64, nonce: u64) -> bool;
    fn solve(challenge: [u64; 4], bits: f64) -> Option<u64>;
}

pub trait PermutationScheme: Clone + Send + Sync + 'static {
    fn permute(l: Fr, r: Fr) -> (Fr, Fr);
}

pub trait CompressionScheme: Clone + Send + Sync + 'static {
    fn compress(l: [u64; 4], r: [u64; 4]) -> [u64; 4];
}
