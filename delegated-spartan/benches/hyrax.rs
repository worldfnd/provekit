mod allocator;
mod utils;

use {
    self::utils::{human, time},
    allocator::ALLOCATOR,
    ark_bn254::Fr,
    delegated_spartan::{
        pcs::hyrax::{compute_contraction, HyraxCommiter},
        transcript::Prover,
    },
    rand::{Rng, SeedableRng},
    rand_chacha::ChaCha20Rng,
    std::hint::black_box,
};

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut transcript = Prover::new();

    println!("Hyrax commitment and opening:");
    for size_log2 in 10..24 {
        let size: usize = 1 << size_log2;
        let cols = 1 << (size.ilog2() / 2);
        let rows = size / cols;
        let hyrax = HyraxCommiter::new(cols);
        let f = (0..size).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let a = (0..rows).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let b = (0..cols).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let c = compute_contraction(&f, &a, &b);
        let mut mem = (0, 0);

        let duration = time({
            let mem = &mut mem;
            let transcript = &mut transcript;
            || {
                transcript.proof.clear();
                ALLOCATOR.reset();
                let before = (ALLOCATOR.count(), ALLOCATOR.max());
                let s = hyrax.commit(&mut rng, transcript, black_box(&f));
                let (sc, cc) = hyrax.pedersen.commit(&mut rng, &[c]);
                transcript.write_g1(cc);
                hyrax.proof_contraction(&mut rng, transcript, (&s, &f), &a, &b, sc);
                mem.0 = ALLOCATOR.count() - before.0;
                mem.1 = ALLOCATOR.max();
            }
        });
        let proof_size = transcript.proof.len() * size_of::<Fr>();

        println!(
            "size: 2^{size_log2} = {}𝔽, prover time: {}s, througput: {}𝔽/s, proof size: {}B, \
             memory: {}B, allocs: {}",
            human(size),
            human(duration),
            human(size as f64 / duration),
            human(proof_size),
            human(mem.1),
            human(mem.0)
        );
    }
}
