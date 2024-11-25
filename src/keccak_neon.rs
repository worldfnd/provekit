use {crate::SmolHasher, std::fmt::Display};

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

pub struct Keccak;

pub struct K12;

impl Display for Keccak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("keccak-NEON")
    }
}

impl Display for K12 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("K12-NEON")
    }
}

impl SmolHasher for Keccak {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (messages, hashes) in messages.chunks_exact(128).zip(hashes.chunks_exact_mut(64)) {
            unsafe {
                keccak_f1600::<24>(messages, hashes);
            }
        }
    }
}

impl SmolHasher for K12 {
    fn hash(&self, messages: &[u8], hashes: &mut [u8]) {
        for (messages, hashes) in messages.chunks_exact(128).zip(hashes.chunks_exact_mut(64)) {
            unsafe {
                keccak_f1600::<12>(messages, hashes);
            }
        }
    }
}

/// ARMv8+SHA3 optimized double-hasher.
#[target_feature(enable = "sha3")]
pub unsafe fn keccak_f1600<const ROUNDS: usize>(input: &[u8], output: &mut [u8]) {
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
    core::arch::asm!("
        // Construct state
        // A single state is 25 u64s:
        // [0..7 input, 8..24: zero] loaded to v0..v24.
        // Lower and upper half contain two separate instances of the hash.
        // There's also some padding that should be applied and differs for Keccak and SHA3.
        // I'm ignoring this entirely for now. I should not impact performance.

        // TODO: Fix data ordering.
        ld4.2d {{ v0- v3}}, [x0], #64
        ld4.2d {{ v4- v7}}, [x0], #64

        // Zero remainder of the state
        movi v8.16b, #0
        movi v9.16b, #0
        movi v10.16b, #0
        movi v11.16b, #0
        movi v12.16b, #0
        movi v13.16b, #0
        movi v14.16b, #0
        movi v15.16b, #0
        movi v16.16b, #0
        movi v17.16b, #0
        movi v18.16b, #0
        movi v19.16b, #0
        movi v20.16b, #0
        movi v21.16b, #0
        movi v22.16b, #0
        movi v23.16b, #0
        movi v24.16b, #0
        sub x0, x0, #64

        // NOTE: This loop actually computes two f1600 functions in
        // parallel, in both the lower and the upper 64-bit of the
        // 128-bit registers v0-v24.
    0:  sub	x8, x8, #1

        // Theta Calculations
        eor3.16b   v25, v20, v15, v10
        eor3.16b   v26, v21, v16, v11
        eor3.16b   v27, v22, v17, v12
        eor3.16b   v28, v23, v18, v13
        eor3.16b   v29, v24, v19, v14
        eor3.16b   v25, v25,  v5,  v0
        eor3.16b   v26, v26,  v6,  v1
        eor3.16b   v27, v27,  v7,  v2
        eor3.16b   v28, v28,  v8,  v3
        eor3.16b   v29, v29,  v9,  v4
        rax1.2d    v30, v25, v27
        rax1.2d    v31, v26, v28
        rax1.2d    v27, v27, v29
        rax1.2d    v28, v28, v25
        rax1.2d    v29, v29, v26

        // Rho and Phi
        eor.16b     v0,  v0, v29
        xar.2d     v25,  v1, v30, #64 -  1
        xar.2d      v1,  v6, v30, #64 - 44
        xar.2d      v6,  v9, v28, #64 - 20
        xar.2d      v9, v22, v31, #64 - 61
        xar.2d     v22, v14, v28, #64 - 39
        xar.2d     v14, v20, v29, #64 - 18
        xar.2d     v26,  v2, v31, #64 - 62
        xar.2d      v2, v12, v31, #64 - 43
        xar.2d     v12, v13, v27, #64 - 25
        xar.2d     v13, v19, v28, #64 -  8
        xar.2d     v19, v23, v27, #64 - 56
        xar.2d     v23, v15, v29, #64 - 41
        xar.2d     v15,  v4, v28, #64 - 27
        xar.2d     v28, v24, v28, #64 - 14
        xar.2d     v24, v21, v30, #64 -  2
        xar.2d      v8,  v8, v27, #64 - 55
        xar.2d      v4, v16, v30, #64 - 45
        xar.2d     v16,  v5, v29, #64 - 36
        xar.2d      v5,  v3, v27, #64 - 28
        xar.2d     v27, v18, v27, #64 - 21
        xar.2d      v3, v17, v31, #64 - 15
        xar.2d     v30, v11, v30, #64 - 10
        xar.2d     v31,  v7, v31, #64 -  6
        xar.2d     v29, v10, v29, #64 -  3

        // Chi and Iota
        bcax.16b   v20, v26, v22,  v8
        bcax.16b   v21,  v8, v23, v22
        bcax.16b   v22, v22, v24, v23
        bcax.16b   v23, v23, v26, v24
        bcax.16b   v24, v24,  v8, v26

        ld1r.2d    {{v26}}, [x1], #8 // Load round constant

        bcax.16b   v17, v30, v19,  v3
        bcax.16b   v18,  v3, v15, v19
        bcax.16b   v19, v19, v16, v15
        bcax.16b   v15, v15, v30, v16
        bcax.16b   v16, v16,  v3, v30

        bcax.16b   v10, v25, v12, v31
        bcax.16b   v11, v31, v13, v12
        bcax.16b   v12, v12, v14, v13
        bcax.16b   v13, v13, v25, v14
        bcax.16b   v14, v14, v31, v25

        bcax.16b    v7, v29,  v9,  v4
        bcax.16b    v8,  v4,  v5,  v9
        bcax.16b    v9,  v9,  v6,  v5
        bcax.16b    v5,  v5, v29,  v6
        bcax.16b    v6,  v6,  v4, v29

        bcax.16b    v3, v27,  v0, v28
        bcax.16b    v4, v28,  v1,  v0
        bcax.16b    v0,  v0,  v2,  v1
        bcax.16b    v1,  v1, v27,  v2
        bcax.16b    v2,  v2, v28, v27

        eor.16b v0,v0,v26

        // Rounds loop
        cbnz    w8, 0b

        // First 32 bytes of state is the output hash
        // TODO: Fix data ordering.
        st4.2d	{{ v0- v3}}, [x2], #64
    ",
        in("x0") input.as_ptr(),
        in("x1") RC[24-ROUNDS..].as_ptr(),
        in("x2") output.as_mut_ptr(),
        in("x8") ROUNDS,
        clobber_abi("C"),
        options(nostack)
    );
}
