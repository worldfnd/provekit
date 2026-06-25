use std::hash::sha256_compression;

global H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn main(input: [u8; 5]) {
    let mut block: [u32; 16] = [0; 16];
    block[0] = (input[0] as u32) * 16777216
        + (input[1] as u32) * 65536
        + (input[2] as u32) * 256
        + (input[3] as u32);
    block[1] = (input[4] as u32) * 16777216 + 0x800000;
    block[15] = 40;

    let mut state = H;
    for _ in 0..35 {
        state = sha256_compression(block, state);
    }

    assert(state[0] == 0x2b431f1f);
    assert(state[1] == 0x9f7ccc65);
    assert(state[2] == 0xb39b5188);
    assert(state[3] == 0x8b7e8689);
    assert(state[4] == 0x8ad1bc84);
    assert(state[5] == 0x09f78be6);
    assert(state[6] == 0xf0431b8d);
    assert(state[7] == 0x97fcfb9c);
}
