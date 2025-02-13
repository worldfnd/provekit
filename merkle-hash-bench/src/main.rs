#![feature(portable_simd)] // Required for Stwo
#![allow(unsafe_code)]
#![allow(missing_docs)]

mod hashes;
mod mod_ring;

use {
    anyhow::Result,
    argh::FromArgs,
    core::{
        f64,
        fmt::{self, Display, Formatter},
        hint::black_box,
        time::Duration,
    },
    linkme::distributed_slice,
    rand::RngCore,
    std::{
        io::{stdout, Write},
        time::Instant,
    },
};

/// Linker magic to collect all hash constructors.
#[distributed_slice]
pub static HASHES: [fn() -> Box<dyn SmolHasher>];

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

/// Pretty print a float using SI-prefixes.
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

fn print_table<'a>(duration: Duration, hashers: impl Iterator<Item = &'a dyn SmolHasher>) {
    let mut rng = rand::thread_rng();
    println!("seconds per hash for batches of 512 bit messages.");
    print!("hash \\ batch size              ");
    let lengths = [4, 16, 64, 256, 1 << 15];
    for length in lengths {
        print!("\t{length}");
    }
    println!();
    for hash in hashers {
        print!("{hash:25}");
        stdout().flush().unwrap();
        for length in lengths {
            let mut input = vec![0_u8; length * 64];
            let mut output = vec![0_u8; length * 32];
            rng.fill_bytes(&mut input);
            let duration = measure(duration, || {
                hash.hash(black_box(&input), black_box(&mut output));
            });
            let _hashes_per_sec = human(length as f64 / duration);
            let sec_per_hash = human(duration / length as f64);
            print!("\t{sec_per_hash:#}");
            stdout().flush().unwrap();
        }
        println!();
    }
    println!();
}

#[derive(FromArgs)]
/// Benchmark various regular and zk-firendly hash functions for batches of
/// 512-bit messages.
struct Args {
    /// duration of the benchmark in seconds.
    #[argh(option)]
    duration: Option<f64>,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();
    let duration = Duration::from_secs_f64(args.duration.unwrap_or(0.01));

    // Consrtuct all hashers.
    let hashes = HASHES.iter().map(|ctor| ctor()).collect::<Vec<_>>();

    print_table(duration, hashes.iter().map(|hasher| &**hasher));
    Ok(())
}
