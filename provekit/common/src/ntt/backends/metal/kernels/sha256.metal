inline uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

inline uint ch(uint x, uint y, uint z) {
    return (x & y) ^ ((~x) & z);
}

inline uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint big_sigma0(uint x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

inline uint big_sigma1(uint x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

inline uint small_sigma0(uint x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

inline uint small_sigma1(uint x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

inline uchar field_byte(Fe value, uint byte_index) {
    ulong limb = value.limbs[byte_index >> 3u];
    uint shift = (byte_index & 7u) << 3u;
    return uchar((limb >> shift) & 0xfful);
}

inline void sha256_init(thread uint state[8]) {
    state[0] = 0x6a09e667u;
    state[1] = 0xbb67ae85u;
    state[2] = 0x3c6ef372u;
    state[3] = 0xa54ff53au;
    state[4] = 0x510e527fu;
    state[5] = 0x9b05688cu;
    state[6] = 0x1f83d9abu;
    state[7] = 0x5be0cd19u;
}

inline uchar sha256_padding_byte(uint idx, uint size, uint total_padded_len, uint bit_len) {
    if (idx == size) {
        return 0x80u;
    }
    if (idx >= total_padded_len - 8u) {
        uint shift = (total_padded_len - 1u - idx) * 8u;
        return shift >= 32u ? 0u : uchar((bit_len >> shift) & 0xffu);
    }
    return 0u;
}

inline uint sha256_load_field_word(
    Fe field0,
    Fe field1,
    uint block_base,
    uint word_index,
    uint size,
    uint total_padded_len,
    uint bit_len
) {
    uint word = 0u;
#pragma clang loop unroll(enable)
    for (uint j = 0; j < 4; ++j) {
        uint idx = block_base + word_index * 4u + j;
        uchar byte = 0u;
        if (idx < size) {
            uint byte_in_block = idx - block_base;
            byte = byte_in_block < 32u
                ? field_byte(field0, byte_in_block)
                : field_byte(field1, byte_in_block - 32u);
        } else {
            byte = sha256_padding_byte(idx, size, total_padded_len, bit_len);
        }
        word = (word << 8) | uint(byte);
    }
    return word;
}

inline uint sha256_load_byte_word(
    device const uchar *input,
    uint offset,
    uint block_base,
    uint word_index,
    uint size,
    uint total_padded_len,
    uint bit_len
) {
    uint word = 0u;
#pragma clang loop unroll(enable)
    for (uint j = 0; j < 4; ++j) {
        uint idx = block_base + word_index * 4u + j;
        uchar byte = idx < size
            ? input[offset + idx]
            : sha256_padding_byte(idx, size, total_padded_len, bit_len);
        word = (word << 8) | uint(byte);
    }
    return word;
}

inline void sha256_extend_schedule(thread uint w[64]) {
    for (uint i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }
}

inline void sha256_compress(thread uint state[8], thread const uint w[64]) {
    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint i = 0; i < 64; ++i) {
        uint t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
        uint t2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline void sha256_write_digest(device uchar *out, thread const uint state[8]) {
#pragma clang loop unroll(enable)
    for (uint i = 0; i < 8; ++i) {
        out[i * 4 + 0] = uchar((state[i] >> 24) & 0xffu);
        out[i * 4 + 1] = uchar((state[i] >> 16) & 0xffu);
        out[i * 4 + 2] = uchar((state[i] >> 8) & 0xffu);
        out[i * 4 + 3] = uchar(state[i] & 0xffu);
    }
}

[[kernel]]
void sha256_field_rows(
    device const Fe *input [[buffer(0)]],
    device uchar *output [[buffer(1)]],
    constant HashManyParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    uint field_count = params.size >> 5u;
    uint row_offset = gid * field_count;
    uint total_blocks = (params.size + 9u + 63u) / 64u;
    uint total_padded_len = total_blocks * 64u;
    uint bit_len = params.size * 8u;
    uint state[8];
    sha256_init(state);

    for (uint block = 0; block < total_blocks; ++block) {
        uint block_base = block * 64u;
        uint field_base = block << 1u;
        bool has_field0 = block_base < params.size;
        bool has_field1 = block_base + 32u < params.size;
        Fe field0 = has_field0 ? from_mont(input[row_offset + field_base]) : FE_ONE;
        Fe field1 = has_field1 ? from_mont(input[row_offset + field_base + 1u]) : FE_ONE;
        uint w[64];

#pragma clang loop unroll(enable)
        for (uint i = 0; i < 16; ++i) {
            w[i] = sha256_load_field_word(
                field0,
                field1,
                block_base,
                i,
                params.size,
                total_padded_len,
                bit_len
            );
        }

        sha256_extend_schedule(w);
        sha256_compress(state, w);
    }

    sha256_write_digest(output + gid * 32u, state);
}

[[kernel]]
void sha256_many(
    device const uchar *input [[buffer(0)]],
    device uchar *output [[buffer(1)]],
    constant HashManyParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    uint offset = gid * params.size;
    uint total_blocks = (params.size + 9u + 63u) / 64u;
    uint total_padded_len = total_blocks * 64u;
    uint bit_len = params.size * 8u;
    uint state[8];
    sha256_init(state);

    for (uint block = 0; block < total_blocks; ++block) {
        uint block_base = block * 64u;
        uint w[64];

#pragma clang loop unroll(enable)
        for (uint i = 0; i < 16; ++i) {
            w[i] = sha256_load_byte_word(
                input,
                offset,
                block_base,
                i,
                params.size,
                total_padded_len,
                bit_len
            );
        }

        sha256_extend_schedule(w);
        sha256_compress(state, w);
    }

    sha256_write_digest(output + gid * 32u, state);
}
