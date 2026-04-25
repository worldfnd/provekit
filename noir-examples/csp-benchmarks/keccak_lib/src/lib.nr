// Keccak-256 sponge used by the Ethproofs CSP benchmark fixtures.
//
// Kept as explicit Noir code instead of std::hash::keccakf1600 because
// ProveKit does not lower the Keccak blackbox to R1CS in this change.
// Uses a witness-focused u32 split-lane representation.

// 64-bit lane split into two u32 halves (little-endian)
struct Lane {
    lo: u32,
    hi: u32,
}

impl Lane {
    fn zero() -> Self {
        Lane { lo: 0, hi: 0 }
    }

    fn xor(self, other: Self) -> Self {
        Lane { lo: self.lo ^ other.lo, hi: self.hi ^ other.hi }
    }

    fn and(self, other: Self) -> Self {
        Lane { lo: self.lo & other.lo, hi: self.hi & other.hi }
    }

    fn not(self) -> Self {
        Lane { lo: !self.lo, hi: !self.hi }
    }

    fn rotl(self, n: u8) -> Self {
        if n == 0 {
            self
        } else if n == 32 {
            Lane { lo: self.hi, hi: self.lo }
        } else if n < 32 {
            let n32 = n as u32;
            let complement = 32 - n32;
            // The shifted halves occupy disjoint bit ranges, so addition is
            // equivalent to XOR/OR while avoiding an extra bitwise operation.
            Lane {
                lo: (self.lo << n32) + (self.hi >> complement),
                hi: (self.hi << n32) + (self.lo >> complement),
            }
        } else {
            let m = n - 32;
            let m32 = m as u32;
            let complement = 32 - m32;
            // The shifted halves occupy disjoint bit ranges, so addition is
            // equivalent to XOR/OR while avoiding an extra bitwise operation.
            Lane {
                lo: (self.hi << m32) + (self.lo >> complement),
                hi: (self.lo << m32) + (self.hi >> complement),
            }
        }
    }
}

// 5x5 grid of 64-bit lanes = 1600-bit state
struct State {
    lanes: [Lane; 25],
}

impl State {
    fn zero() -> Self {
        State { lanes: [Lane::zero(); 25] }
    }
}

global ROUND_CONSTANTS: [Lane; 24] = [
    Lane { lo: 0x00000001, hi: 0x00000000 },
    Lane { lo: 0x00008082, hi: 0x00000000 },
    Lane { lo: 0x0000808A, hi: 0x80000000 },
    Lane { lo: 0x80008000, hi: 0x80000000 },
    Lane { lo: 0x0000808B, hi: 0x00000000 },
    Lane { lo: 0x80000001, hi: 0x00000000 },
    Lane { lo: 0x80008081, hi: 0x80000000 },
    Lane { lo: 0x00008009, hi: 0x80000000 },
    Lane { lo: 0x0000008A, hi: 0x00000000 },
    Lane { lo: 0x00000088, hi: 0x00000000 },
    Lane { lo: 0x80008009, hi: 0x00000000 },
    Lane { lo: 0x8000000A, hi: 0x00000000 },
    Lane { lo: 0x8000808B, hi: 0x00000000 },
    Lane { lo: 0x0000008B, hi: 0x80000000 },
    Lane { lo: 0x00008089, hi: 0x80000000 },
    Lane { lo: 0x00008003, hi: 0x80000000 },
    Lane { lo: 0x00008002, hi: 0x80000000 },
    Lane { lo: 0x00000080, hi: 0x80000000 },
    Lane { lo: 0x0000800A, hi: 0x00000000 },
    Lane { lo: 0x8000000A, hi: 0x80000000 },
    Lane { lo: 0x80008081, hi: 0x80000000 },
    Lane { lo: 0x00008080, hi: 0x80000000 },
    Lane { lo: 0x80000001, hi: 0x00000000 },
    Lane { lo: 0x80008008, hi: 0x80000000 },
];

// Keccak-f[1600] permutation: 24 rounds of theta, rho, pi, chi, iota
fn keccakf1600(state: State) -> State {
    let mut a = state.lanes;

    for round in 0..24 {
        // theta: column parity mixing
        let c0 = a[0].xor(a[5]).xor(a[10]).xor(a[15]).xor(a[20]);
        let c1 = a[1].xor(a[6]).xor(a[11]).xor(a[16]).xor(a[21]);
        let c2 = a[2].xor(a[7]).xor(a[12]).xor(a[17]).xor(a[22]);
        let c3 = a[3].xor(a[8]).xor(a[13]).xor(a[18]).xor(a[23]);
        let c4 = a[4].xor(a[9]).xor(a[14]).xor(a[19]).xor(a[24]);

        let d0 = c4.xor(c1.rotl(1));
        let d1 = c0.xor(c2.rotl(1));
        let d2 = c1.xor(c3.rotl(1));
        let d3 = c2.xor(c4.rotl(1));
        let d4 = c3.xor(c0.rotl(1));

        a[0] = a[0].xor(d0);
        a[1] = a[1].xor(d1);
        a[2] = a[2].xor(d2);
        a[3] = a[3].xor(d3);
        a[4] = a[4].xor(d4);
        a[5] = a[5].xor(d0);
        a[6] = a[6].xor(d1);
        a[7] = a[7].xor(d2);
        a[8] = a[8].xor(d3);
        a[9] = a[9].xor(d4);
        a[10] = a[10].xor(d0);
        a[11] = a[11].xor(d1);
        a[12] = a[12].xor(d2);
        a[13] = a[13].xor(d3);
        a[14] = a[14].xor(d4);
        a[15] = a[15].xor(d0);
        a[16] = a[16].xor(d1);
        a[17] = a[17].xor(d2);
        a[18] = a[18].xor(d3);
        a[19] = a[19].xor(d4);
        a[20] = a[20].xor(d0);
        a[21] = a[21].xor(d1);
        a[22] = a[22].xor(d2);
        a[23] = a[23].xor(d3);
        a[24] = a[24].xor(d4);

        // rho: rotate each lane, pi: permute lane positions
        let mut b: [Lane; 25] = [Lane::zero(); 25];
        b[0] = a[0];
        b[10] = a[1].rotl(1);
        b[7] = a[10].rotl(3);
        b[11] = a[7].rotl(6);
        b[17] = a[11].rotl(10);
        b[18] = a[17].rotl(15);
        b[3] = a[18].rotl(21);
        b[5] = a[3].rotl(28);
        b[16] = a[5].rotl(36);
        b[8] = a[16].rotl(45);
        b[21] = a[8].rotl(55);
        b[24] = a[21].rotl(2);
        b[4] = a[24].rotl(14);
        b[15] = a[4].rotl(27);
        b[23] = a[15].rotl(41);
        b[19] = a[23].rotl(56);
        b[13] = a[19].rotl(8);
        b[12] = a[13].rotl(25);
        b[2] = a[12].rotl(43);
        b[20] = a[2].rotl(62);
        b[14] = a[20].rotl(18);
        b[22] = a[14].rotl(39);
        b[9] = a[22].rotl(61);
        b[6] = a[9].rotl(20);
        b[1] = a[6].rotl(44);
        a = b;

        // chi: non-linear mixing (a[i] ^= ~a[i+1] & a[i+2])
        let s = a;
        a[0] = s[0].xor(s[1].not().and(s[2]));
        a[1] = s[1].xor(s[2].not().and(s[3]));
        a[2] = s[2].xor(s[3].not().and(s[4]));
        a[3] = s[3].xor(s[4].not().and(s[0]));
        a[4] = s[4].xor(s[0].not().and(s[1]));
        a[5] = s[5].xor(s[6].not().and(s[7]));
        a[6] = s[6].xor(s[7].not().and(s[8]));
        a[7] = s[7].xor(s[8].not().and(s[9]));
        a[8] = s[8].xor(s[9].not().and(s[5]));
        a[9] = s[9].xor(s[5].not().and(s[6]));
        a[10] = s[10].xor(s[11].not().and(s[12]));
        a[11] = s[11].xor(s[12].not().and(s[13]));
        a[12] = s[12].xor(s[13].not().and(s[14]));
        a[13] = s[13].xor(s[14].not().and(s[10]));
        a[14] = s[14].xor(s[10].not().and(s[11]));
        a[15] = s[15].xor(s[16].not().and(s[17]));
        a[16] = s[16].xor(s[17].not().and(s[18]));
        a[17] = s[17].xor(s[18].not().and(s[19]));
        a[18] = s[18].xor(s[19].not().and(s[15]));
        a[19] = s[19].xor(s[15].not().and(s[16]));
        a[20] = s[20].xor(s[21].not().and(s[22]));
        a[21] = s[21].xor(s[22].not().and(s[23]));
        a[22] = s[22].xor(s[23].not().and(s[24]));
        a[23] = s[23].xor(s[24].not().and(s[20]));
        a[24] = s[24].xor(s[20].not().and(s[21]));

        // iota: XOR round constant into lane 0
        a[0] = a[0].xor(ROUND_CONSTANTS[round]);
    }

    State { lanes: a }
}

fn le_bytes_to_lane(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8, b5: u8, b6: u8, b7: u8) -> Lane {
    let lo = (b0 as u32) + ((b1 as u32) * 256) + ((b2 as u32) * 65536) + ((b3 as u32) * 16777216);
    let hi = (b4 as u32) + ((b5 as u32) * 256) + ((b6 as u32) * 65536) + ((b7 as u32) * 16777216);
    Lane { lo, hi }
}

// XOR 136-byte block into state and apply permutation (rate = 1088 bits)
fn absorb_block(state: State, block: [u8; 136]) -> State {
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
        st.lanes[lane] = st.lanes[lane].xor(lane_val);
    }
    keccakf1600(st)
}

fn state_to_32_bytes(state: State) -> [u8; 32] {
    let lanes = state.lanes;
    let mut result = [0; 32];
    for lane in 0..4 {
        let lo_bytes: [u8; 4] = (lanes[lane].lo as Field).to_le_bytes();
        let hi_bytes: [u8; 4] = (lanes[lane].hi as Field).to_le_bytes();
        for byte in 0..4 {
            result[8 * lane + byte] = lo_bytes[byte];
            result[8 * lane + 4 + byte] = hi_bytes[byte];
        }
    }
    result
}

// Sponge construction: absorb message in 136-byte blocks, squeeze 32 bytes.
// Padding: append 0x01 after message, 0x80 at end of block.
pub fn keccak256<let N: u32>(msg: [u8; N], message_size: u32) -> [u8; 32] {
    assert(message_size == N);

    let mut state = State::zero();

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
            if pad_pos == 135 {
                block[135] = 0x81;
            } else {
                block[pad_pos] = 0x01;
                block[135] = 0x80;
            }
        }

        state = absorb_block(state, block);
    }

    state_to_32_bytes(state)
}
