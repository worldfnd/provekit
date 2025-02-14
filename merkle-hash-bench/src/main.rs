#![feature(portable_simd)] // Required for Stwo
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
        fmt::{Display, Formatter},
        hint::black_box,
        io::{stdout, Write},
        time::Duration,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Field {
    None,
    Bn254,
    Goldilocks,
    M31,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashFn {
    Sha256,
    Blake2s,
    Blake3,
    Poseidon(usize),
    Poseidon2(usize),
    Skyscraper(usize),
    Keccak(usize),
}

pub trait SmolHasher {
    fn hash_fn(&self) -> HashFn;

    fn implementation(&self) -> &str {
        ""
    }

    fn field(&self) -> Field {
        Field::None
    }

    /// `messages` will be a multiple of 64 bytes, `hashes` a multiple of 32.
    fn hash(&self, messages: &[u8], hashes: &mut [u8]);
}

impl Display for Field {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::None => f.pad("none"),
            Self::Bn254 => f.pad("bn254"),
            Self::Goldilocks => f.pad("goldilocks"),
            Self::M31 => f.pad("m31"),
        }
    }
}

impl Display for HashFn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::Sha256 => f.pad("sha256"),
            Self::Blake2s => f.pad("blake2s"),
            Self::Blake3 => f.pad("blake3"),
            Self::Poseidon(t) => f.pad(&format!("poseidon:{t}")),
            Self::Poseidon2(t) => f.pad(&format!("poseidon2:{t}")),
            Self::Skyscraper(t) => f.pad(&format!("skyscraper:{t}")),
            Self::Keccak(t) => f.pad(&format!("keccak:{t}")),
        }
    }
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
        print!(
            "{:14}{:10}{:7}",
            hash.hash_fn(),
            hash.implementation(),
            hash.field()
        );
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
