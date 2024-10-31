mod blake3;
mod blake3_naive;
mod keccak_neon;
mod poseidon2_bn254_plonky3;
mod sha256_neon;

use {
    core::{
        f64,
        fmt::{self, Display, Formatter},
        hint::black_box,
        time::Duration,
    },
    rand::RngCore,
    std::time::Instant,
};

pub trait SmolHasher: Display {
    /// `messages` will be a multiple of 64 bytes, `hashes` a multiple of 32.
    fn hash(&self, messages: &[u8], hashes: &mut [u8]);
}

/// Measure a function for the given minimum duration.
fn measure<F: FnMut()>(duration: Duration, mut f: F) -> f64 {
    let total = Instant::now();
    let mut aggregate = f64::INFINITY;
    while total.elapsed() < duration {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed();
        aggregate = aggregate.min(elapsed.as_secs_f64());
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
        Box::new(blake3_naive::Blake3Naive),
        Box::new(blake3::Blake3::new()),
        Box::new(keccak_neon::Keccak),
        Box::new(keccak_neon::K12),
        Box::new(sha256_neon::Sha256),
        Box::new(poseidon2_bn254_plonky3::Poseidon2Bn254PLonky3::new()),
    ];
    for hash in &hashers {
        for length in [4, 16, 1024] {
            let mut input = vec![0_u8; length * 64];
            let mut output = vec![0_u8; length * 32];
            rng.fill_bytes(&mut input);
            let duration = measure(Duration::from_secs(1), || {
                hash.hash(black_box(&input), black_box(&mut output));
            });
            let hashes_per_sec = human(length as f64 / duration);
            println!("{hash} at {length} = {hashes_per_sec}hashes/sec");
        }
    }
}
