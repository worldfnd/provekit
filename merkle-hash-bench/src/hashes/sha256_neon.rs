//! Adapted from: https://github.com/RustCrypto/hashes/blob/a467ac63d85f31d4bdd67a28ba0d61939df86dbd/sha2/src/sha256/aarch64.rs#L22
//! Which itself is adapted from mbed-tls.
use {
    crate::{SmolHasher, HASHES},
    core::{arch::aarch64::*, fmt::Display},
    linkme::distributed_slice,
};

#[allow(unsafe_code)] // Squelch the warning about using link_section
#[distributed_slice(HASHES)]
static HASH: fn() -> Box<dyn SmolHasher> = || Box::new(Sha256);

/// Round constants for SHA-256 family of digests
pub static K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256;

impl Display for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("SHA256-NEON")
    }
}

impl SmolHasher for Sha256 {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (message, hash) in messages.chunks_exact(64).zip(hashes.chunks_exact_mut(32)) {
            unsafe { sha256_compress(message, hash) }
        }
    }
}

#[target_feature(enable = "sha2")]
unsafe fn sha256_compress(input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len(), 64);
    debug_assert_eq!(output.len(), 32);

    // Initialize state to zero.
    let mut abcd = vdupq_n_u32(0);
    let mut efgh = vdupq_n_u32(0);

    // Load the message block into vectors, assuming little endianness.
    let mut s0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(input[0..16].as_ptr())));
    let mut s1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(input[16..32].as_ptr())));
    let mut s2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(input[32..48].as_ptr())));
    let mut s3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(input[48..64].as_ptr())));

    // Rounds 0 to 3
    let mut tmp = vaddq_u32(s0, vld1q_u32(&K32[0]));
    let mut abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    // Rounds 4 to 7
    tmp = vaddq_u32(s1, vld1q_u32(&K32[4]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    // Rounds 8 to 11
    tmp = vaddq_u32(s2, vld1q_u32(&K32[8]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    // Rounds 12 to 15
    tmp = vaddq_u32(s3, vld1q_u32(&K32[12]));
    abcd_prev = abcd;
    abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
    efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

    for t in (16..64).step_by(16) {
        // Rounds t to t + 3
        s0 = vsha256su1q_u32(vsha256su0q_u32(s0, s1), s2, s3);
        tmp = vaddq_u32(s0, vld1q_u32(&K32[t]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds t + 4 to t + 7
        s1 = vsha256su1q_u32(vsha256su0q_u32(s1, s2), s3, s0);
        tmp = vaddq_u32(s1, vld1q_u32(&K32[t + 4]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds t + 8 to t + 11
        s2 = vsha256su1q_u32(vsha256su0q_u32(s2, s3), s0, s1);
        tmp = vaddq_u32(s2, vld1q_u32(&K32[t + 8]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds t + 12 to t + 15
        s3 = vsha256su1q_u32(vsha256su0q_u32(s3, s0), s1, s2);
        tmp = vaddq_u32(s3, vld1q_u32(&K32[t + 12]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);
    }

    // Store vectors into state.
    vst1q_u8(output[0..4].as_mut_ptr(), vreinterpretq_u8_u32(abcd));
    vst1q_u8(output[4..8].as_mut_ptr(), vreinterpretq_u8_u32(abcd));
}
