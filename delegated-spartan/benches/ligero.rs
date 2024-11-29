mod allocator;
mod utils;

use {
    self::{
        allocator::ALLOCATOR,
        utils::{human, time},
    },
    ark_bn254::Fr,
    delegated_spartan::{
        pcs::{hyrax::compute_contraction, ligero::LigeroCommitter},
        poseidon,
        transcript::Prover,
    },
    rand::{Rng, SeedableRng},
    rand_chacha::ChaCha20Rng,
    std::{hint::black_box, sync::atomic::Ordering},
};

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut transcript = Prover::new();

    println!("Ligero commitment and opening:");
    for size_log2 in 10..24 {
        let size: usize = 1 << size_log2;

        let committer = LigeroCommitter::new(128.0, size);
        let f = (0..size).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let a = (0..committer.rows).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let b = (0..committer.cols).map(|_| rng.gen()).collect::<Vec<Fr>>();
        let c = compute_contraction(&f, &a, &b);
        let mut num_hashes = (0, 0);
        let mut mem = (0, 0);

        let duration = time({
            let transcript = &mut transcript;
            let mem = &mut mem;
            let num_hashes = &mut num_hashes;
            || {
                let before = (
                    poseidon::COUNT_3.load(Ordering::SeqCst),
                    poseidon::COUNT_16.load(Ordering::SeqCst),
                    ALLOCATOR.count(),
                    ALLOCATOR.max(),
                );
                transcript.proof.clear();
                let s = committer.commit(transcript, black_box(&f));
                transcript.write(c);
                s.prove_contraction(transcript, &a, &b);
                *num_hashes = (
                    poseidon::COUNT_3.load(Ordering::SeqCst) - before.0,
                    poseidon::COUNT_16.load(Ordering::SeqCst) - before.1,
                );
                *mem = (ALLOCATOR.count() - before.2, ALLOCATOR.max());
            }
        });
        let proof_size = transcript.proof.len() * size_of::<Fr>();

        println!(
            "size: 2^{size_log2} = {}𝔽 = {:#}x{:#}, prover time: {}s, througput: {}𝔽/s, proof \
             size: {}B, permute_3: {:#}, permute_16: {:#}, memory: {}B, allocs: {:#}",
            human(size),
            human(committer.rows),
            human(committer.cols),
            human(duration),
            human(size as f64 / duration),
            human(proof_size),
            human(num_hashes.0),
            human(num_hashes.1),
            human(mem.1),
            human(mem.0)
        );
    }
}
