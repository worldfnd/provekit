//! Hash function benchmarks for ProveKit.

use {
    ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme},
    core::hint::black_box,
    divan::Bencher,
    provekit_common::FieldElement,
    spongefish::duplex_sponge::DuplexSpongeInterface,
    std::{
        fmt::{self, Display, Formatter},
        time::{Duration, Instant},
    },
};

fn random_field_elements(count: usize) -> Vec<FieldElement> {
    use ark_ff::UniformRand;
    let mut rng = ark_std::test_rng();
    (0..count).map(|_| FieldElement::rand(&mut rng)).collect()
}

fn random_bytes(count: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; count];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn measure<A, F: FnMut() -> A>(duration: Duration, mut f: F) -> f64 {
    let total = Instant::now();
    let mut aggregate = f64::INFINITY;
    let mut repeats = 1;
    while total.elapsed() < duration {
        let start = Instant::now();
        for _ in 0..repeats {
            black_box(f());
        }
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed < 1.0e-6 {
            repeats *= 10;
        } else {
            aggregate = aggregate.min(elapsed / repeats as f64);
        }
    }
    aggregate
}

fn human(value: f64) -> impl Display {
    struct Human(f64);
    impl Display for Human {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            let log10 = if self.0.is_normal() {
                self.0.abs().log10()
            } else {
                0.0
            };
            let si_power = ((log10 / 3.0).floor() as isize).clamp(-10, 10);
            let value = self.0 * 10_f64.powi((-si_power * 3) as i32);
            let digits = f.precision().unwrap_or(3) - 1 - (log10 - 3.0 * si_power as f64) as usize;
            write!(f, "{value:.digits$} ")?;
            let suffix = "qryzafpnum kMGTPEZYRQ"
                .chars()
                .nth((si_power + 10) as usize)
                .unwrap();
            if suffix != ' ' {
                write!(f, "{suffix}")?;
            }
            Ok(())
        }
    }
    Human(value)
}

mod blake3_bench {
    use {
        super::*,
        provekit_common::blake3::{Blake3Compress, Blake3LeafHash, Blake3Sponge},
    };

    #[divan::bench(args = [4, 16, 64, 256, 1024])]
    fn leaf_hash(bencher: Bencher, count: usize) {
        let input = random_field_elements(count);
        bencher.bench_local(|| Blake3LeafHash::evaluate(&(), black_box(input.as_slice())));
    }

    #[divan::bench(args = [100, 1000, 10000])]
    fn two_to_one_compress(bencher: Bencher, iterations: usize) {
        use provekit_common::blake3::Blake3Digest;
        let start: Blake3Digest = [1u8; 32].into();
        let right: Blake3Digest = [2u8; 32].into();
        bencher.bench_local(|| {
            let mut result = start.clone();
            for _ in 0..iterations {
                result =
                    Blake3Compress::evaluate(&(), black_box(&result), black_box(&right)).unwrap();
            }
            result
        });
    }

    #[divan::bench(args = [64, 256, 1024, 4096])]
    fn sponge_absorb(bencher: Bencher, bytes: usize) {
        let input = random_bytes(bytes);
        bencher.bench_local(|| {
            let mut sponge = Blake3Sponge::new([0u8; 32]);
            sponge.absorb_unchecked(black_box(&input));
            sponge
        });
    }

    #[divan::bench(args = [32, 128, 512, 2048])]
    fn sponge_squeeze(bencher: Bencher, bytes: usize) {
        let input = random_bytes(64);
        let mut output = vec![0u8; bytes];
        bencher.bench_local(|| {
            let mut sponge = Blake3Sponge::new([0u8; 32]);
            sponge.absorb_unchecked(&input);
            sponge.squeeze_unchecked(black_box(&mut output));
        });
    }

    #[divan::bench]
    fn sponge_ratchet() {
        let mut sponge = Blake3Sponge::new([0u8; 32]);
        sponge.absorb_unchecked(&[1u8; 64]);
        divan::black_box_drop(sponge.ratchet_unchecked());
    }
}

mod sha256_bench {
    use {
        super::*,
        provekit_common::sha256::{Sha256CRH, Sha256Sponge, Sha256TwoToOne},
    };

    #[divan::bench(args = [4, 16, 64, 256, 1024])]
    fn leaf_hash(bencher: Bencher, count: usize) {
        let input = random_field_elements(count);
        bencher.bench_local(|| Sha256CRH::evaluate(&(), black_box(input.as_slice())));
    }

    #[divan::bench(args = [100, 1000, 10000])]
    fn two_to_one_compress(bencher: Bencher, iterations: usize) {
        use provekit_common::sha256::Sha256Digest;
        let left = Sha256Digest::default();
        let right = Sha256Digest::default();
        bencher.bench_local(|| {
            let mut result = left.clone();
            for _ in 0..iterations {
                result =
                    Sha256TwoToOne::evaluate(&(), black_box(&result), black_box(&right)).unwrap();
            }
            result
        });
    }

    #[divan::bench(args = [64, 256, 1024, 4096])]
    fn sponge_absorb(bencher: Bencher, bytes: usize) {
        let input = random_bytes(bytes);
        bencher.bench_local(|| {
            let mut sponge = Sha256Sponge::new([0u8; 32]);
            sponge.absorb_unchecked(black_box(&input));
            sponge
        });
    }

    #[divan::bench(args = [32, 128, 512, 2048])]
    fn sponge_squeeze(bencher: Bencher, bytes: usize) {
        let input = random_bytes(64);
        let mut output = vec![0u8; bytes];
        bencher.bench_local(|| {
            let mut sponge = Sha256Sponge::new([0u8; 32]);
            sponge.absorb_unchecked(&input);
            sponge.squeeze_unchecked(black_box(&mut output));
        });
    }

    #[divan::bench]
    fn sponge_ratchet() {
        let mut sponge = Sha256Sponge::new([0u8; 32]);
        sponge.absorb_unchecked(&[1u8; 64]);
        divan::black_box_drop(sponge.ratchet_unchecked());
    }
}

mod keccak_bench {
    use {
        super::*,
        provekit_common::keccak::{Keccak256Compress, Keccak256LeafHash, KeccakSponge},
    };

    #[divan::bench(args = [4, 16, 64, 256, 1024])]
    fn leaf_hash(bencher: Bencher, count: usize) {
        let input = random_field_elements(count);
        bencher.bench_local(|| Keccak256LeafHash::evaluate(&(), black_box(input.as_slice())));
    }

    #[divan::bench(args = [100, 1000, 10000])]
    fn two_to_one_compress(bencher: Bencher, iterations: usize) {
        use provekit_common::keccak::KeccakDigest;
        let start: KeccakDigest = [1u8; 32].into();
        let right: KeccakDigest = [2u8; 32].into();
        bencher.bench_local(|| {
            let mut result = start.clone();
            for _ in 0..iterations {
                result = Keccak256Compress::evaluate(&(), black_box(&result), black_box(&right))
                    .unwrap();
            }
            result
        });
    }

    #[divan::bench(args = [64, 256, 1024, 4096])]
    fn sponge_absorb(bencher: Bencher, bytes: usize) {
        let input = random_bytes(bytes);
        bencher.bench_local(|| {
            let mut sponge = KeccakSponge::new([0u8; 32]);
            sponge.absorb_unchecked(black_box(&input));
            sponge
        });
    }

    #[divan::bench(args = [32, 128, 512, 2048])]
    fn sponge_squeeze(bencher: Bencher, bytes: usize) {
        let input = random_bytes(64);
        let mut output = vec![0u8; bytes];
        bencher.bench_local(|| {
            let mut sponge = KeccakSponge::new([0u8; 32]);
            sponge.absorb_unchecked(&input);
            sponge.squeeze_unchecked(black_box(&mut output));
        });
    }

    #[divan::bench]
    fn sponge_ratchet() {
        let mut sponge = KeccakSponge::new([0u8; 32]);
        sponge.absorb_unchecked(&[1u8; 64]);
        divan::black_box_drop(sponge.ratchet_unchecked());
    }
}

mod skyscraper_bench {
    use {
        super::*,
        provekit_common::skyscraper::{SkyscraperCRH, SkyscraperSponge, SkyscraperTwoToOne},
    };

    #[divan::bench(args = [4, 16, 64, 256, 1024])]
    fn leaf_hash(bencher: Bencher, count: usize) {
        let input = random_field_elements(count);
        bencher.bench_local(|| SkyscraperCRH::evaluate(&(), black_box(input.as_slice())));
    }

    #[divan::bench(args = [100, 1000, 10000])]
    fn two_to_one_compress(bencher: Bencher, iterations: usize) {
        let left = FieldElement::from(1u64);
        let right = FieldElement::from(2u64);
        bencher.bench_local(|| {
            let mut result = left;
            for _ in 0..iterations {
                result = SkyscraperTwoToOne::evaluate(&(), black_box(&result), black_box(&right))
                    .unwrap();
            }
            result
        });
    }

    #[divan::bench(args = [4, 16, 64, 256])]
    fn sponge_absorb_field_elements(bencher: Bencher, count: usize) {
        let input = random_field_elements(count);
        bencher.bench_local(|| {
            let mut sponge = SkyscraperSponge::new([0u8; 32]);
            sponge.absorb_unchecked(black_box(&input));
            sponge
        });
    }

    #[divan::bench(args = [4, 16, 64, 256])]
    fn sponge_squeeze_field_elements(bencher: Bencher, count: usize) {
        let input = random_field_elements(4);
        let mut output = vec![FieldElement::from(0u64); count];
        bencher.bench_local(|| {
            let mut sponge = SkyscraperSponge::new([0u8; 32]);
            sponge.absorb_unchecked(&input);
            sponge.squeeze_unchecked(black_box(&mut output));
        });
    }

    #[divan::bench]
    fn sponge_ratchet() {
        let input = random_field_elements(4);
        let mut sponge = SkyscraperSponge::new([0u8; 32]);
        sponge.absorb_unchecked(&input);
        divan::black_box_drop(sponge.ratchet_unchecked());
    }
}

mod comparison {
    use {super::*, ark_crypto_primitives::crh::CRHScheme};

    const LEAF_SIZE: usize = 16;

    #[divan::bench]
    fn blake3_leaf_16() {
        use provekit_common::blake3::Blake3LeafHash;
        let input = random_field_elements(LEAF_SIZE);
        divan::black_box_drop(Blake3LeafHash::evaluate(&(), input.as_slice()));
    }

    #[divan::bench]
    fn sha256_leaf_16() {
        use provekit_common::sha256::Sha256CRH;
        let input = random_field_elements(LEAF_SIZE);
        divan::black_box_drop(Sha256CRH::evaluate(&(), input.as_slice()));
    }

    #[divan::bench]
    fn keccak_leaf_16() {
        use provekit_common::keccak::Keccak256LeafHash;
        let input = random_field_elements(LEAF_SIZE);
        divan::black_box_drop(Keccak256LeafHash::evaluate(&(), input.as_slice()));
    }

    #[divan::bench]
    fn skyscraper_leaf_16() {
        use provekit_common::skyscraper::SkyscraperCRH;
        let input = random_field_elements(LEAF_SIZE);
        divan::black_box_drop(SkyscraperCRH::evaluate(&(), input.as_slice()));
    }
}

mod merkle_tree_sim {
    use super::*;

    #[divan::bench(args = [256, 1024, 4096])]
    fn blake3_merkle_layer(bencher: Bencher, num_leaves: usize) {
        use provekit_common::blake3::{Blake3Compress, Blake3Digest};
        let leaves: Vec<Blake3Digest> = (0..num_leaves)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                arr.into()
            })
            .collect();

        bencher.bench_local(|| {
            let mut layer = leaves.clone();
            while layer.len() > 1 {
                layer = layer
                    .chunks(2)
                    .map(|pair| Blake3Compress::evaluate(&(), &pair[0], &pair[1]).unwrap())
                    .collect();
            }
            layer[0].clone()
        });
    }

    #[divan::bench(args = [256, 1024, 4096])]
    fn sha256_merkle_layer(bencher: Bencher, num_leaves: usize) {
        use provekit_common::sha256::{Sha256Digest, Sha256TwoToOne};
        let leaves: Vec<Sha256Digest> = (0..num_leaves).map(|_| Sha256Digest::default()).collect();

        bencher.bench_local(|| {
            let mut layer = leaves.clone();
            while layer.len() > 1 {
                layer = layer
                    .chunks(2)
                    .map(|pair| Sha256TwoToOne::evaluate(&(), &pair[0], &pair[1]).unwrap())
                    .collect();
            }
            layer[0].clone()
        });
    }

    #[divan::bench(args = [256, 1024, 4096])]
    fn keccak_merkle_layer(bencher: Bencher, num_leaves: usize) {
        use provekit_common::keccak::{Keccak256Compress, KeccakDigest};
        let leaves: Vec<KeccakDigest> = (0..num_leaves)
            .map(|i| {
                let mut arr = [0u8; 32];
                arr[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                arr.into()
            })
            .collect();

        bencher.bench_local(|| {
            let mut layer = leaves.clone();
            while layer.len() > 1 {
                layer = layer
                    .chunks(2)
                    .map(|pair| Keccak256Compress::evaluate(&(), &pair[0], &pair[1]).unwrap())
                    .collect();
            }
            layer[0].clone()
        });
    }

    #[divan::bench(args = [256, 1024, 4096])]
    fn skyscraper_merkle_layer(bencher: Bencher, num_leaves: usize) {
        use provekit_common::skyscraper::SkyscraperTwoToOne;
        let leaves: Vec<FieldElement> = (0..num_leaves)
            .map(|i| FieldElement::from(i as u64))
            .collect();

        bencher.bench_local(|| {
            let mut layer = leaves.clone();
            while layer.len() > 1 {
                layer = layer
                    .chunks(2)
                    .map(|pair| SkyscraperTwoToOne::evaluate(&(), &pair[0], &pair[1]).unwrap())
                    .collect();
            }
            layer[0]
        });
    }
}

fn print_comparison_table() {
    use provekit_common::{
        blake3::{Blake3Compress, Blake3Digest, Blake3LeafHash},
        keccak::{Keccak256Compress, Keccak256LeafHash, KeccakDigest},
        sha256::{Sha256CRH, Sha256Digest, Sha256TwoToOne},
        skyscraper::{SkyscraperCRH, SkyscraperTwoToOne},
    };

    let duration = Duration::from_millis(100);
    let input = random_field_elements(16);

    println!("\n============================================================");
    println!("                   COMPARISON TABLE");
    println!("============================================================");
    println!("{:<12} {:>15} {:>15}", "Hash", "Leaf(16)", "Compress");
    println!("------------------------------------------------------------");

    // Blake3
    let leaf = measure(duration, || Blake3LeafHash::evaluate(&(), input.as_slice()));
    let start: Blake3Digest = [1u8; 32].into();
    let right: Blake3Digest = [2u8; 32].into();
    let compress = measure(duration, || {
        let mut r = start.clone();
        for _ in 0..1000 {
            r = Blake3Compress::evaluate(&(), &r, &right).unwrap();
        }
        r
    }) / 1000.0;
    println!(
        "{:<12} {:>15} {:>15}",
        "blake3",
        format!("{:#}s", human(leaf)),
        format!("{:#}s", human(compress))
    );

    // SHA256
    let leaf = measure(duration, || Sha256CRH::evaluate(&(), input.as_slice()));
    let start = Sha256Digest::default();
    let right = Sha256Digest::default();
    let compress = measure(duration, || {
        let mut r = start;
        for _ in 0..1000 {
            r = Sha256TwoToOne::evaluate(&(), &r, &right).unwrap();
        }
        r
    }) / 1000.0;
    println!(
        "{:<12} {:>15} {:>15}",
        "sha256",
        format!("{:#}s", human(leaf)),
        format!("{:#}s", human(compress))
    );

    // Keccak
    let leaf = measure(duration, || {
        Keccak256LeafHash::evaluate(&(), input.as_slice())
    });
    let start: KeccakDigest = [1u8; 32].into();
    let right: KeccakDigest = [2u8; 32].into();
    let compress = measure(duration, || {
        let mut r = start.clone();
        for _ in 0..1000 {
            r = Keccak256Compress::evaluate(&(), &r, &right).unwrap();
        }
        r
    }) / 1000.0;
    println!(
        "{:<12} {:>15} {:>15}",
        "keccak",
        format!("{:#}s", human(leaf)),
        format!("{:#}s", human(compress))
    );

    // Skyscraper
    let leaf = measure(duration, || SkyscraperCRH::evaluate(&(), input.as_slice()));
    let start = FieldElement::from(1u64);
    let right = FieldElement::from(2u64);
    let compress = measure(duration, || {
        let mut r = start;
        for _ in 0..1000 {
            r = SkyscraperTwoToOne::evaluate(&(), &r, &right).unwrap();
        }
        r
    }) / 1000.0;
    println!(
        "{:<12} {:>15} {:>15}",
        "skyscraper",
        format!("{:#}s", human(leaf)),
        format!("{:#}s", human(compress))
    );

    println!("============================================================\n");
}

fn main() {
    divan::main();
    print_comparison_table();
}
