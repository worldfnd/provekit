pub mod backends;

#[cfg(target_os = "macos")]
pub use backends::MetalBn254Ntt;
pub use backends::RSFr;

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use {
        super::{MetalBn254Ntt, RSFr},
        ark_bn254::Fr,
        ark_ff::UniformRand,
        whir::algebra::ntt::ReedSolomon,
    };

    #[test]
    fn metal_matches_cpu_for_small_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        eprintln!(
            "using Metal device: {}",
            gpu.runtime().unwrap().device.name()
        );

        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let messages = [&coeffs[..1 << 11], &coeffs[1 << 11..]];
        let cpu = RSFr.interleaved_encode(&messages, &[], 1 << 11);
        let gpu = gpu.interleaved_encode(&messages, &[], 1 << 11);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn metal_matches_cpu_for_small_codeword_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let messages_storage: Vec<_> = (0..2)
            .map(|_| (0..16).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>())
            .collect();
        let messages = messages_storage
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let masks: Vec<_> = (0..(2 * 4)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = RSFr.interleaved_encode(&messages, &masks, 32);
        let gpu = gpu.interleaved_encode(&messages, &masks, 32);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn metal_matches_cpu_for_multi_poly_case() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let messages_storage: Vec<_> = (0..4)
            .map(|_| (0..16).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>())
            .collect();
        let messages = messages_storage
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let cpu = RSFr.interleaved_encode(&messages, &[], 32);
        let gpu = gpu.interleaved_encode(&messages, &[], 32);
        assert_eq!(cpu, gpu);
    }
}
