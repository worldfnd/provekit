#![feature(portable_simd)] // Required for Stwo
// #![allow(unsafe_code)]
#![allow(missing_docs)]

mod hashes;
mod mod_ring;
mod registery;
mod utils;

use {
    self::{
        registery::HASHES,
        utils::{human, measure},
    },
    anyhow::Result,
    argh::FromArgs,
    rand::RngCore,
    std::{
        f64,
        fmt::Display,
        hint::black_box,
        io::{stdout, Write},
        time::Duration,
    },
};

pub trait SmolHasher: Display {
    /// `messages` will be a multiple of 64 bytes, `hashes` a multiple of 32.
    fn hash(&self, messages: &[u8], hashes: &mut [u8]);
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
