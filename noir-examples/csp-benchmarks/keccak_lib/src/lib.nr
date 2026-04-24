// Keccak-256 sponge used by the Ethproofs CSP benchmark fixtures.
//
// Kept as explicit Noir code instead of std::hash::keccakf1600 because
// ProveKit does not lower the Keccak blackbox to R1CS in this change.
// Uses native u64 operations; the permutation is implemented in Noir.

global ROUND_CONSTANTS: [u64; 24] = [
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

fn rotl(x: u64, n: u8) -> u64 {
    if n == 0 {
        x
    } else {
        let n64 = n as u64;
        (x << n64) ^ (x >> (64 - n64))
    }
}

// Keccak-f[1600] permutation: 24 rounds of theta, rho, pi, chi, iota.
fn keccakf1600(mut a: [u64; 25]) -> [u64; 25] {
    for round in 0..24 {
        // Theta: column parity mixing.
        let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

        let d0 = c4 ^ rotl(c1, 1);
        let d1 = c0 ^ rotl(c2, 1);
        let d2 = c1 ^ rotl(c3, 1);
        let d3 = c2 ^ rotl(c4, 1);
        let d4 = c3 ^ rotl(c0, 1);

        a[0] = a[0] ^ d0;
        a[1] = a[1] ^ d1;
        a[2] = a[2] ^ d2;
        a[3] = a[3] ^ d3;
        a[4] = a[4] ^ d4;
        a[5] = a[5] ^ d0;
        a[6] = a[6] ^ d1;
        a[7] = a[7] ^ d2;
        a[8] = a[8] ^ d3;
        a[9] = a[9] ^ d4;
        a[10] = a[10] ^ d0;
        a[11] = a[11] ^ d1;
        a[12] = a[12] ^ d2;
        a[13] = a[13] ^ d3;
        a[14] = a[14] ^ d4;
        a[15] = a[15] ^ d0;
        a[16] = a[16] ^ d1;
        a[17] = a[17] ^ d2;
        a[18] = a[18] ^ d3;
        a[19] = a[19] ^ d4;
        a[20] = a[20] ^ d0;
        a[21] = a[21] ^ d1;
        a[22] = a[22] ^ d2;
        a[23] = a[23] ^ d3;
        a[24] = a[24] ^ d4;

        // Rho + Pi.
        let mut b: [u64; 25] = [0; 25];
        b[0] = a[0];
        b[10] = rotl(a[1], 1);
        b[7] = rotl(a[10], 3);
        b[11] = rotl(a[7], 6);
        b[17] = rotl(a[11], 10);
        b[18] = rotl(a[17], 15);
        b[3] = rotl(a[18], 21);
        b[5] = rotl(a[3], 28);
        b[16] = rotl(a[5], 36);
        b[8] = rotl(a[16], 45);
        b[21] = rotl(a[8], 55);
        b[24] = rotl(a[21], 2);
        b[4] = rotl(a[24], 14);
        b[15] = rotl(a[4], 27);
        b[23] = rotl(a[15], 41);
        b[19] = rotl(a[23], 56);
        b[13] = rotl(a[19], 8);
        b[12] = rotl(a[13], 25);
        b[2] = rotl(a[12], 43);
        b[20] = rotl(a[2], 62);
        b[14] = rotl(a[20], 18);
        b[22] = rotl(a[14], 39);
        b[9] = rotl(a[22], 61);
        b[6] = rotl(a[9], 20);
        b[1] = rotl(a[6], 44);
        a = b;

        // Chi: row-local nonlinear layer.
        let s = a;
        a[0] = s[0] ^ ((!s[1]) & s[2]);
        a[1] = s[1] ^ ((!s[2]) & s[3]);
        a[2] = s[2] ^ ((!s[3]) & s[4]);
        a[3] = s[3] ^ ((!s[4]) & s[0]);
        a[4] = s[4] ^ ((!s[0]) & s[1]);
        a[5] = s[5] ^ ((!s[6]) & s[7]);
        a[6] = s[6] ^ ((!s[7]) & s[8]);
        a[7] = s[7] ^ ((!s[8]) & s[9]);
        a[8] = s[8] ^ ((!s[9]) & s[5]);
        a[9] = s[9] ^ ((!s[5]) & s[6]);
        a[10] = s[10] ^ ((!s[11]) & s[12]);
        a[11] = s[11] ^ ((!s[12]) & s[13]);
        a[12] = s[12] ^ ((!s[13]) & s[14]);
        a[13] = s[13] ^ ((!s[14]) & s[10]);
        a[14] = s[14] ^ ((!s[10]) & s[11]);
        a[15] = s[15] ^ ((!s[16]) & s[17]);
        a[16] = s[16] ^ ((!s[17]) & s[18]);
        a[17] = s[17] ^ ((!s[18]) & s[19]);
        a[18] = s[18] ^ ((!s[19]) & s[15]);
        a[19] = s[19] ^ ((!s[15]) & s[16]);
        a[20] = s[20] ^ ((!s[21]) & s[22]);
        a[21] = s[21] ^ ((!s[22]) & s[23]);
        a[22] = s[22] ^ ((!s[23]) & s[24]);
        a[23] = s[23] ^ ((!s[24]) & s[20]);
        a[24] = s[24] ^ ((!s[20]) & s[21]);

        // Iota.
        a[0] = a[0] ^ ROUND_CONSTANTS[round];
    }

    a
}

fn le_bytes_to_lane(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8, b5: u8, b6: u8, b7: u8) -> u64 {
    (b0 as u64)
        + ((b1 as u64) * 256)
        + ((b2 as u64) * 65536)
        + ((b3 as u64) * 16777216)
        + ((b4 as u64) * 4294967296)
        + ((b5 as u64) * 1099511627776)
        + ((b6 as u64) * 281474976710656)
        + ((b7 as u64) * 72057594037927936)
}

fn state_to_32_bytes(state: [u64; 25]) -> [u8; 32] {
    let mut result = [0; 32];
    for lane in 0..4 {
        let bytes: [u8; 8] = (state[lane] as Field).to_le_bytes();
        for byte in 0..8 {
            result[8 * lane + byte] = bytes[byte];
        }
    }
    result
}

fn absorb_block(state: [u64; 25], block: [u8; 136]) -> [u64; 25] {
    let mut st = state;
    for lane in 0..17 {
        let base = lane * 8;
        let lane_val = le_bytes_to_lane(
            block[base],
            block[base + 1],
            block[base + 2],
            block[base + 3],
            block[base + 4],
            block[base + 5],
            block[base + 6],
            block[base + 7],
        );
        st[lane] = st[lane] ^ lane_val;
    }
    keccakf1600(st)
}

// Sponge construction: absorb message in 136-byte blocks, squeeze 32 bytes.
// Padding: append 0x01 after message, 0x80 at end of block.
pub fn keccak256<let N: u32>(msg: [u8; N], message_size: u32) -> [u8; 32] {
    assert(message_size == N);

    let mut state = [0; 25];

    // Keccak-256 has rate 136 bytes. With pad10*1, any message of length N needs
    // exactly (N / 136) + 1 absorb+permute steps (including the final padded block).
    let num_blocks = (N / 136) + 1;

    for block_idx in 0..num_blocks {
        let bidx = block_idx as u32;
        let mut block: [u8; 136] = [0; 136];
        let base = bidx * 136;

        // Copy the (potentially partial) message block.
        for i in 0..136 {
            let idx = base + (i as u32);
            if idx < N {
                block[i] = msg[idx];
            }
        }

        // Apply padding to the final block.
        if bidx == (num_blocks - 1) {
            let pad_pos = N - base;
            block[pad_pos] ^= 0x01;
            block[135] ^= 0x80;
        }

        state = absorb_block(state, block);
    }

    state_to_32_bytes(state)
}
