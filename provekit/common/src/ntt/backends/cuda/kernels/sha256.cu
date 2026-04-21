// CUDA equivalent of metal/kernels/sha256.metal.
//
// Two kernels, exactly like the Metal port:
//   - encode_field_rows_le: writes canonical little-endian bytes for each field,
//     bit-reversing the row index so the byte matrix is in natural codeword order.
//   - sha256_many: hashes equal-sized byte messages.

struct FieldBytesParams {
    uint rows;
    uint cols;
};

__device__ __forceinline__ uint rotr32(uint x, uint n) {
    return (x >> n) | (x << (32u - n));
}

__device__ __forceinline__ uint ch(uint x, uint y, uint z) {
    return (x & y) ^ ((~x) & z);
}

__device__ __forceinline__ uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint big_sigma0(uint x) {
    return rotr32(x, 2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u);
}

__device__ __forceinline__ uint big_sigma1(uint x) {
    return rotr32(x, 6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u);
}

__device__ __forceinline__ uint small_sigma0(uint x) {
    return rotr32(x, 7u) ^ rotr32(x, 18u) ^ (x >> 3u);
}

__device__ __forceinline__ uint small_sigma1(uint x) {
    return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u);
}

__device__ __forceinline__ void sha256_init(uint state[8]) {
    state[0] = 0x6a09e667u;
    state[1] = 0xbb67ae85u;
    state[2] = 0x3c6ef372u;
    state[3] = 0xa54ff53au;
    state[4] = 0x510e527fu;
    state[5] = 0x9b05688cu;
    state[6] = 0x1f83d9abu;
    state[7] = 0x5be0cd19u;
}

__device__ __forceinline__ uchar sha256_padding_byte(
    uint idx, uint size, uint total_padded_len, uint bit_len
) {
    if (idx == size) {
        return 0x80u;
    }
    if (idx >= total_padded_len - 8u) {
        uint shift = (total_padded_len - 1u - idx) * 8u;
        return shift >= 32u ? 0u : (uchar)((bit_len >> shift) & 0xffu);
    }
    return 0u;
}

__device__ __forceinline__ uint sha256_load_byte_word(
    const uchar *input,
    uint offset,
    uint block_base,
    uint word_index,
    uint size,
    uint total_padded_len,
    uint bit_len
) {
    uint word = 0u;
#pragma unroll
    for (uint j = 0; j < 4u; ++j) {
        uint idx = block_base + word_index * 4u + j;
        uchar byte = idx < size
            ? input[offset + idx]
            : sha256_padding_byte(idx, size, total_padded_len, bit_len);
        word = (word << 8) | (uint)byte;
    }
    return word;
}

__device__ __forceinline__ void sha256_extend_schedule(uint w[64]) {
    for (uint i = 16u; i < 64u; ++i) {
        w[i] = small_sigma1(w[i - 2u]) + w[i - 7u] + small_sigma0(w[i - 15u]) + w[i - 16u];
    }
}

__device__ __forceinline__ void sha256_compress(uint state[8], const uint w[64]) {
    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    for (uint i = 0u; i < 64u; ++i) {
        uint t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
        uint t2 = big_sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ __forceinline__ void sha256_write_digest(uchar *out, const uint state[8]) {
#pragma unroll
    for (uint i = 0u; i < 8u; ++i) {
        out[i * 4u + 0u] = (uchar)((state[i] >> 24) & 0xffu);
        out[i * 4u + 1u] = (uchar)((state[i] >> 16) & 0xffu);
        out[i * 4u + 2u] = (uchar)((state[i] >> 8)  & 0xffu);
        out[i * 4u + 3u] = (uchar)( state[i]        & 0xffu);
    }
}

// Convert each `Fe` from Montgomery form to canonical little-endian bytes.
//
// Reads `params.rows × params.cols` fields from `input` and writes
// `params.rows × params.cols × 32` bytes to `output`. The output rows are
// emitted in natural codeword order: the matrix in `input` is laid out in
// bit-reversed row order, so we apply `reverse_bits_width(row, log2(rows))`
// when reading from `input`.
extern "C" __global__ void encode_field_rows_le(
    const Fe *input,
    uchar *output,
    FieldBytesParams params
) {
    uint total_elements = params.rows * params.cols;
    uint gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint row_bits = 31u - __clz(params.rows);
    uint src_row = (row_bits == 0u) ? row : (__brev(row) >> (32u - row_bits));
    Fe canonical = from_mont(input[src_row * params.cols + col]);
    uint byte_offset = gid * 32u;
#pragma unroll
    for (uint limb = 0u; limb < 4u; ++limb) {
        ulong value = canonical.limbs[limb];
#pragma unroll
        for (uint byte = 0u; byte < 8u; ++byte) {
            output[byte_offset + limb * 8u + byte] =
                (uchar)((value >> (byte * 8u)) & 0xffull);
        }
    }
}

// Hash `params.count` equal-size messages of `params.size` bytes each.
extern "C" __global__ void sha256_many(
    const uchar *input,
    uchar *output,
    HashManyParams params
) {
    uint gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= params.count) {
        return;
    }

    uint offset = gid * params.size;
    uint total_blocks = (params.size + 9u + 63u) / 64u;
    uint total_padded_len = total_blocks * 64u;
    uint bit_len = params.size * 8u;
    uint state[8];
    sha256_init(state);

    for (uint block = 0u; block < total_blocks; ++block) {
        uint block_base = block * 64u;
        uint w[64];
#pragma unroll
        for (uint i = 0u; i < 16u; ++i) {
            w[i] = sha256_load_byte_word(
                input, offset, block_base, i,
                params.size, total_padded_len, bit_len
            );
        }
        sha256_extend_schedule(w);
        sha256_compress(state, w);
    }

    sha256_write_digest(output + gid * 32u, state);
}
