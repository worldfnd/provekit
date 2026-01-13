//! ARM NEON + SHA3 optimized Keccak-f1600 permutation.
//!
//! This module provides hardware-accelerated Keccak permutation using
//! ARMv8 SHA3 cryptographic extensions. It processes two Keccak states
//! in parallel using 128-bit NEON registers.
//!
//! Adapted from merkle-hash-bench implementation.
//!
//! # Requirements
//!
//! - ARMv8.2-A or later with SHA3 extensions
//! - Only available on `aarch64` targets

#![cfg(all(target_arch = "aarch64", target_feature = "sha3"))]

/// Keccak round constants for f1600 permutation.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Keccak-f1600 permutation with 24 rounds (standard Keccak-256).
///
/// Hashes two 64-byte messages in parallel, producing two 32-byte outputs.
///
/// # Safety
///
/// Requires ARMv8 SHA3 extensions to be available.
///
/// # Panics
///
/// Panics if input is not exactly 128 bytes or output is not exactly 64 bytes.
#[target_feature(enable = "sha3")]
pub unsafe fn keccak_f1600_x2(input: &[u8], output: &mut [u8]) {
    keccak_f1600::<24>(input, output);
}

/// Keccak-f1600 permutation with 12 rounds (KangarooTwelve style).
///
/// Hashes two 64-byte messages in parallel, producing two 32-byte outputs.
///
/// # Safety
///
/// Requires ARMv8 SHA3 extensions to be available.
#[target_feature(enable = "sha3")]
pub unsafe fn keccak_f1600_x2_k12(input: &[u8], output: &mut [u8]) {
    keccak_f1600::<12>(input, output);
}

/// Internal Keccak-f1600 implementation with configurable rounds.
///
/// This function computes two f1600 permutations in parallel using
/// ARMv8 NEON 128-bit registers with SHA3 extensions.
#[target_feature(enable = "sha3")]
unsafe fn keccak_f1600<const ROUNDS: usize>(input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(
        input.len(),
        128,
        "Expecting 128 bytes (two messages) of input."
    );
    debug_assert_eq!(
        output.len(),
        64,
        "Expecting 64 bytes (two hashes) of output."
    );

    core::arch::asm!(
        // Load input state
        // A single Keccak state is 25 u64s (200 bytes).
        // We load 8 u64s from each message (64 bytes) into v0-v7.
        // Lower and upper 64-bit halves contain two separate states.
        "ld4.2d {{ v0- v3}}, [{input}], #64",
        "ld4.2d {{ v4- v7}}, [{input}], #64",

        // Zero remainder of the state (lanes 8-24)
        "movi v8.16b, #0",
        "movi v9.16b, #0",
        "movi v10.16b, #0",
        "movi v11.16b, #0",
        "movi v12.16b, #0",
        "movi v13.16b, #0",
        "movi v14.16b, #0",
        "movi v15.16b, #0",
        "movi v16.16b, #0",
        "movi v17.16b, #0",
        "movi v18.16b, #0",
        "movi v19.16b, #0",
        "movi v20.16b, #0",
        "movi v21.16b, #0",
        "movi v22.16b, #0",
        "movi v23.16b, #0",
        "movi v24.16b, #0",

        // Reset input pointer
        "sub {input}, {input}, #64",

        // Main permutation loop
        // Computes two f1600 functions in parallel
        "0:",
        "sub {rounds}, {rounds}, #1",

        // === Theta step ===
        // Column parity: C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
        "eor3.16b   v25, v20, v15, v10",
        "eor3.16b   v26, v21, v16, v11",
        "eor3.16b   v27, v22, v17, v12",
        "eor3.16b   v28, v23, v18, v13",
        "eor3.16b   v29, v24, v19, v14",
        "eor3.16b   v25, v25,  v5,  v0",
        "eor3.16b   v26, v26,  v6,  v1",
        "eor3.16b   v27, v27,  v7,  v2",
        "eor3.16b   v28, v28,  v8,  v3",
        "eor3.16b   v29, v29,  v9,  v4",

        // D[x] = C[x-1] ^ ROT(C[x+1], 1)
        "rax1.2d    v30, v25, v27",
        "rax1.2d    v31, v26, v28",
        "rax1.2d    v27, v27, v29",
        "rax1.2d    v28, v28, v25",
        "rax1.2d    v29, v29, v26",

        // === Rho and Pi steps ===
        // Combined rotation and permutation
        "eor.16b     v0,  v0, v29",
        "xar.2d     v25,  v1, v30, #64 -  1",
        "xar.2d      v1,  v6, v30, #64 - 44",
        "xar.2d      v6,  v9, v28, #64 - 20",
        "xar.2d      v9, v22, v31, #64 - 61",
        "xar.2d     v22, v14, v28, #64 - 39",
        "xar.2d     v14, v20, v29, #64 - 18",
        "xar.2d     v26,  v2, v31, #64 - 62",
        "xar.2d      v2, v12, v31, #64 - 43",
        "xar.2d     v12, v13, v27, #64 - 25",
        "xar.2d     v13, v19, v28, #64 -  8",
        "xar.2d     v19, v23, v27, #64 - 56",
        "xar.2d     v23, v15, v29, #64 - 41",
        "xar.2d     v15,  v4, v28, #64 - 27",
        "xar.2d     v28, v24, v28, #64 - 14",
        "xar.2d     v24, v21, v30, #64 -  2",
        "xar.2d      v8,  v8, v27, #64 - 55",
        "xar.2d      v4, v16, v30, #64 - 45",
        "xar.2d     v16,  v5, v29, #64 - 36",
        "xar.2d      v5,  v3, v27, #64 - 28",
        "xar.2d     v27, v18, v27, #64 - 21",
        "xar.2d      v3, v17, v31, #64 - 15",
        "xar.2d     v30, v11, v30, #64 - 10",
        "xar.2d     v31,  v7, v31, #64 -  6",
        "xar.2d     v29, v10, v29, #64 -  3",

        // === Chi step ===
        // A[x] = B[x] ^ ((~B[x+1]) & B[x+2])
        "bcax.16b   v20, v26, v22,  v8",
        "bcax.16b   v21,  v8, v23, v22",
        "bcax.16b   v22, v22, v24, v23",
        "bcax.16b   v23, v23, v26, v24",
        "bcax.16b   v24, v24,  v8, v26",

        // === Iota step ===
        // Load and XOR round constant
        "ld1r.2d    {{v26}}, [{rc}], #8",

        "bcax.16b   v17, v30, v19,  v3",
        "bcax.16b   v18,  v3, v15, v19",
        "bcax.16b   v19, v19, v16, v15",
        "bcax.16b   v15, v15, v30, v16",
        "bcax.16b   v16, v16,  v3, v30",

        "bcax.16b   v10, v25, v12, v31",
        "bcax.16b   v11, v31, v13, v12",
        "bcax.16b   v12, v12, v14, v13",
        "bcax.16b   v13, v13, v25, v14",
        "bcax.16b   v14, v14, v31, v25",

        "bcax.16b    v7, v29,  v9,  v4",
        "bcax.16b    v8,  v4,  v5,  v9",
        "bcax.16b    v9,  v9,  v6,  v5",
        "bcax.16b    v5,  v5, v29,  v6",
        "bcax.16b    v6,  v6,  v4, v29",

        "bcax.16b    v3, v27,  v0, v28",
        "bcax.16b    v4, v28,  v1,  v0",
        "bcax.16b    v0,  v0,  v2,  v1",
        "bcax.16b    v1,  v1, v27,  v2",
        "bcax.16b    v2,  v2, v28, v27",

        // Apply round constant to lane 0
        "eor.16b v0, v0, v26",

        // Loop until all rounds complete
        "cbnz    {rounds:w}, 0b",

        // Store first 32 bytes of state (4 lanes) as output
        "st4.2d	{{ v0- v3}}, [{output}], #64",

        input = inout(reg) input.as_ptr() => _,
        rc = inout(reg) RC[24-ROUNDS..].as_ptr() => _,
        output = inout(reg) output.as_mut_ptr() => _,
        rounds = inout(reg) ROUNDS => _,
        out("v0") _, out("v1") _, out("v2") _, out("v3") _,
        out("v4") _, out("v5") _, out("v6") _, out("v7") _,
        out("v8") _, out("v9") _, out("v10") _, out("v11") _,
        out("v12") _, out("v13") _, out("v14") _, out("v15") _,
        out("v16") _, out("v17") _, out("v18") _, out("v19") _,
        out("v20") _, out("v21") _, out("v22") _, out("v23") _,
        out("v24") _, out("v25") _, out("v26") _, out("v27") _,
        out("v28") _, out("v29") _, out("v30") _, out("v31") _,
        options(nostack)
    );
}

/// Batch compress multiple pairs of 32-byte inputs using Keccak-f1600.
///
/// Processes inputs two at a time using SIMD parallelism.
///
/// # Safety
///
/// Requires ARMv8 SHA3 extensions to be available.
///
/// # Panics
///
/// Panics if input/output sizes don't match expected multiples.
#[target_feature(enable = "sha3")]
pub unsafe fn keccak_compress_many(inputs: &[u8], outputs: &mut [u8]) {
    assert_eq!(inputs.len() % 64, 0, "Input must be multiple of 64 bytes");
    assert_eq!(outputs.len() % 32, 0, "Output must be multiple of 32 bytes");
    assert_eq!(
        inputs.len() / 64,
        outputs.len() / 32,
        "Input/output count mismatch"
    );

    let count = inputs.len() / 64;

    // Process pairs of messages
    let pairs = count / 2;
    for i in 0..pairs {
        let in_offset = i * 128;
        let out_offset = i * 64;
        keccak_f1600::<24>(
            &inputs[in_offset..in_offset + 128],
            &mut outputs[out_offset..out_offset + 64],
        );
    }

    // Handle odd message if present
    if count % 2 == 1 {
        let last_idx = count - 1;
        let in_offset = last_idx * 64;
        let out_offset = last_idx * 32;

        // Pad with zeros for the second message slot
        let mut padded_input = [0u8; 128];
        padded_input[..64].copy_from_slice(&inputs[in_offset..in_offset + 64]);

        let mut padded_output = [0u8; 64];
        keccak_f1600::<24>(&padded_input, &mut padded_output);

        outputs[out_offset..out_offset + 32].copy_from_slice(&padded_output[..32]);
    }
}

/// Check if SHA3 NEON extensions are available at runtime.
#[cfg(target_arch = "aarch64")]
pub fn is_sha3_available() -> bool {
    #[cfg(target_feature = "sha3")]
    {
        true
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        // Could use runtime detection here if needed
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(target_arch = "aarch64", target_feature = "sha3"))]
    fn test_keccak_f1600_x2() {
        let input = [0xABu8; 128];
        let mut output = [0u8; 64];

        unsafe {
            keccak_f1600_x2(&input, &mut output);
        }

        // Verify we got non-trivial output
        assert!(output.iter().any(|&b| b != 0));
        assert!(output.iter().any(|&b| b != 0xAB));

        // Both halves should be the same (same input)
        assert_eq!(&output[..32], &output[32..]);
    }
}
