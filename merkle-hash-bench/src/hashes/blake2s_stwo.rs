#![cfg(feature = "stwo")]
use {
    crate::{register_hash, HashFn, SmolHasher},
    std::{iter::zip, mem::transmute, simd::u32x16},
    stwo_prover::core::backend::simd::blake2s::compress16,
};

register_hash!(Blake2Stwo);

pub struct Blake2Stwo;

impl SmolHasher for Blake2Stwo {
    fn hash_fn(&self) -> HashFn {
        HashFn::Blake2s
    }

    fn implementation(&self) -> &str {
        "stwo"
    }

    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (msg, out) in zip(messages.chunks_exact(1024), hashes.chunks_exact_mut(512)) {
            compress(msg.try_into().unwrap(), out.try_into().unwrap());
        }
    }
}

// TODO: There has to be a better way of doing the tranmutes. Maybe `bytemuck`?
/// Compress 16x64 bytes into 16x32 bytes
#[allow(clippy::missing_transmute_annotations)]
fn compress(msg: &[u8; 1024], out: &mut [u8; 512]) {
    let mut state: [u32x16; 8] = [u32x16::splat(0); 8];
    let zeros = u32x16::splat(0);
    let msgs: &[u32x16; 16] = unsafe { transmute(msg) };
    state = compress16(state, transpose_msgs(*msgs), zeros, zeros, zeros, zeros);
    *out = unsafe { transmute(state) };
}

/// Transposes input chunks (16 chunks of 16 `u32`s each), to get 16 `u32x16`,
/// each representing 16 packed instances of a message word.
fn transpose_msgs(mut data: [u32x16; 16]) -> [u32x16; 16] {
    // Index abcd:xyzw, refers to a specific word in data as follows:
    //   abcd - chunk index (in base 2)
    //   xyzw - word offset (in base 2)
    // Transpose by applying 4 times the index permutation:
    //   abcd:xyzw => wabc:dxyz
    // In other words, rotate the index to the right by 1.
    for _ in 0..4 {
        let (d0, d8) = data[0].deinterleave(data[1]);
        let (d1, d9) = data[2].deinterleave(data[3]);
        let (d2, d10) = data[4].deinterleave(data[5]);
        let (d3, d11) = data[6].deinterleave(data[7]);
        let (d4, d12) = data[8].deinterleave(data[9]);
        let (d5, d13) = data[10].deinterleave(data[11]);
        let (d6, d14) = data[12].deinterleave(data[13]);
        let (d7, d15) = data[14].deinterleave(data[15]);
        data = [
            d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15,
        ];
    }

    data
}
