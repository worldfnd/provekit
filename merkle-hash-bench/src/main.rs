mod blake2_icicle;
mod blake3;
mod blake3_naive;
mod keccak_icicle;
mod keccak_neon;
mod mod_ring;
mod poseidon2_bn254_plonky3;
mod poseidon2_bn254_ruint;
mod poseidon2_bn254_zkhash;
mod poseidon_icicle;
mod sha256_neon;
// mod skyscraper_bn254_portable;
mod skyscraper_bn254_ref;
mod skyscraper_bn254_ruint;
mod skyscraper_neon;

use {
    core::{
        f64,
        fmt::{self, Display, Formatter},
        hint::black_box,
        time::Duration,
    },
    rand::RngCore,
    std::{
        io::{stdout, Write},
        time::Instant,
    },
};

pub trait SmolHasher: Display {
    /// `messages` will be a multiple of 64 bytes, `hashes` a multiple of 32.
    fn hash(&self, messages: &[u8], hashes: &mut [u8]);
}

/// Measure a function for the given minimum duration.
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

pub fn human(value: f64) -> impl Display {
    pub struct Human(f64);

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
            let separator = if f.alternate() { "" } else { "\u{202F}" };
            write!(f, "{value:.digits$}{separator}")?;
            let suffix = "qryzafpnμm kMGTPEZYRQ"
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

fn main() {
    let mut rng = rand::thread_rng();
    let hashers: Vec<Box<dyn SmolHasher>> = vec![
        Box::new(blake2_icicle::Blake2Icicle::new()),
        Box::new(blake3_naive::Blake3Naive),
        Box::new(blake3::Blake3::new()),
        Box::new(keccak_icicle::KeccakIcicle::new()),
        Box::new(keccak_neon::Keccak),
        Box::new(keccak_neon::K12),
        Box::new(sha256_neon::Sha256),
        Box::new(poseidon_icicle::PoseidonIcicle::new()),
        Box::new(poseidon2_bn254_plonky3::Poseidon2Bn254Plonky3::new()),
        Box::new(poseidon2_bn254_ruint::Poseidon2::new()),
        Box::new(poseidon2_bn254_zkhash::Poseidon2Zkhash::new()),
        Box::new(skyscraper_bn254_ref::Skyscraper),
        Box::new(skyscraper_bn254_ruint::Skyscraper),
    ];
    println!("seconds per hash for batches of 512 bit messages.");
    print!("hash \\ batch size              ");
    let lengths = [4, 16, 64, 256, 1 << 20];
    for length in lengths {
        print!("\t{length}");
    }
    println!();
    for hash in &hashers {
        print!("{hash:25}");
        stdout().flush().unwrap();
        for length in lengths {
            let mut input = vec![0_u8; length * 64];
            let mut output = vec![0_u8; length * 32];
            rng.fill_bytes(&mut input);
            let duration = measure(Duration::from_secs(1), || {
                hash.hash(black_box(&input), black_box(&mut output));
            });
            let hashes_per_sec = human(length as f64 / duration);
            let sec_per_hash = human(duration / length as f64);
            print!("\t{sec_per_hash:#}");
            stdout().flush().unwrap();
        }
        println!();
    }
}
