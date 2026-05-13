pub mod backends;

#[cfg(target_os = "linux")]
pub use backends::CudaBn254Ntt;
#[cfg(target_os = "macos")]
pub use backends::MetalBn254Ntt;
pub use backends::RSFr;

#[cfg(all(test, target_os = "linux"))]
mod cuda_tests {
    use {
        super::{CudaBn254Ntt, RSFr},
        ark_bn254::Fr,
        ark_ff::UniformRand,
        whir::algebra::ntt::ReedSolomon,
    };

    fn try_init() -> Option<CudaBn254Ntt> {
        match CudaBn254Ntt::new() {
            Ok(gpu) => Some(gpu),
            Err(err) => {
                eprintln!("skipping CUDA test: {err}");
                None
            }
        }
    }

    #[test]
    fn cuda_matches_cpu_for_large_case() {
        let Some(gpu) = try_init() else { return };
        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let messages = [&coeffs[..1 << 11], &coeffs[1 << 11..]];
        let cpu = RSFr.interleaved_encode(&messages, &[], 1 << 11);
        let actual = gpu.interleaved_encode(&messages, &[], 1 << 11);
        assert_eq!(cpu, actual);
    }

    #[test]
    fn cuda_matches_cpu_for_multi_poly_case() {
        let Some(gpu) = try_init() else { return };
        let mut rng = ark_std::test_rng();
        let storage: Vec<Vec<Fr>> = (0..64)
            .map(|_| (0..16).map(|_| Fr::rand(&mut rng)).collect())
            .collect();
        let messages: Vec<&[Fr]> = storage.iter().map(Vec::as_slice).collect();
        let cpu = RSFr.interleaved_encode(&messages, &[], 32);
        let actual = gpu.interleaved_encode(&messages, &[], 32);
        assert_eq!(cpu, actual);
    }

    #[test]
    fn cuda_matches_cpu_with_masks() {
        let Some(gpu) = try_init() else { return };
        let mut rng = ark_std::test_rng();
        let storage: Vec<Vec<Fr>> = (0..64)
            .map(|_| (0..16).map(|_| Fr::rand(&mut rng)).collect())
            .collect();
        let messages: Vec<&[Fr]> = storage.iter().map(Vec::as_slice).collect();
        let masks: Vec<Fr> = (0..(64 * 4)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = RSFr.interleaved_encode(&messages, &masks, 32);
        let actual = gpu.interleaved_encode(&messages, &masks, 32);
        assert_eq!(cpu, actual);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use {
        super::{MetalBn254Ntt, RSFr},
        ark_bn254::Fr,
        ark_ff::UniformRand,
        objc2_metal::MTLDevice,
        std::sync::Arc,
        whir::{
            algebra::ntt::ReedSolomon,
            hash::SHA2,
            protocols::{
                irs_commit::{CpuIrsCommitter, IrsCommitter},
                matrix_commit::Config as MatrixCommitConfig,
                whir_accelerator::WhirProverAccelerator,
            },
        },
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

    #[test]
    fn metal_commit_gathers_rows_and_merkle_nodes() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let messages_storage: Vec<_> = (0..64)
            .map(|_| (0..16).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>())
            .collect();
        let messages = messages_storage
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let matrix_commit = MatrixCommitConfig::with_hash(SHA2, 32, messages.len());
        let cpu = CpuIrsCommitter::new(Arc::new(RSFr)).commit(&messages, &[], 32, &matrix_commit);
        let metal = gpu.commit(&messages, &[], 32, &matrix_commit);

        assert_eq!(cpu.root, metal.root);

        let row_indices = [0, 1, 5, 17, 31, 0];
        assert_eq!(
            cpu.rows.read_rows(&row_indices),
            metal.rows.read_rows(&row_indices)
        );

        let root_index = matrix_commit.merkle_tree.num_nodes() - 1;
        let node_indices = [0, 3, 31, 32, root_index];
        assert_eq!(
            cpu.matrix_witness.read_nodes(&node_indices),
            metal.matrix_witness.read_nodes(&node_indices)
        );
    }

    #[test]
    fn metal_whir_accelerator_matches_cpu_primitives() {
        let gpu = MetalBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let mut a: Vec<_> = (0..1024).map(|_| Fr::rand(&mut rng)).collect();
        let mut b: Vec<_> = (0..1024).map(|_| Fr::rand(&mut rng)).collect();

        let mut gpu_a = gpu.upload(&a);
        let mut gpu_b = gpu.upload(&b);
        assert_eq!(
            whir::algebra::sumcheck::compute_sumcheck_polynomial(&a, &b),
            gpu.sumcheck_polynomial(&*gpu_a, &*gpu_b)
        );
        assert_eq!(whir::algebra::dot(&a, &b), gpu.dot(&*gpu_a, &*gpu_b));

        let weight = Fr::rand(&mut rng);
        whir::algebra::sumcheck::fold(&mut a, weight);
        whir::algebra::sumcheck::fold(&mut b, weight);
        gpu.fold(&mut *gpu_a, weight);
        gpu.fold(&mut *gpu_b, weight);
        assert_eq!(a, gpu.download(&*gpu_a));
        assert_eq!(b, gpu.download(&*gpu_b));

        let points: Vec<_> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let scalars: Vec<_> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        let mut cpu_accum = a.clone();
        whir::algebra::linear_form::UnivariateEvaluation::accumulate_many(
            &points
                .iter()
                .map(|&point| {
                    whir::algebra::linear_form::UnivariateEvaluation::new(point, cpu_accum.len())
                })
                .collect::<Vec<_>>(),
            &mut cpu_accum,
            &scalars,
        );
        gpu.accumulate_univariate_evaluations(&mut *gpu_a, &points, &scalars);
        assert_eq!(cpu_accum, gpu.download(&*gpu_a));

        let evals = gpu.evaluate_univariate_many(&*gpu_a, &points);
        let cpu = gpu.download(&*gpu_a);
        let expected = points
            .iter()
            .map(|&point| whir::algebra::univariate_evaluate(&cpu, point))
            .collect::<Vec<_>>();
        assert_eq!(expected, evals);
    }
}
