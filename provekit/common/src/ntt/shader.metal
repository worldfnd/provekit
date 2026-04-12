#include <metal_stdlib>

using namespace metal;

struct Bn254Element {
    ulong limbs[4];
};

typedef Bn254Element Fe;

struct StageConfig {
    uint row_len;
    uint stride;
    uint twiddle_offset;
    uint _pad0;
};

struct TransposeParams {
    uint rows;
    uint cols;
    uint total_elements;
};

struct FieldBytesParams {
    uint rows;
    uint cols;
};

struct HashManyParams {
    uint size;
    uint count;
};

struct FieldMulParams {
    uint count;
};

struct ReplicateCosetsParams {
    uint row_len;
    uint coset_size;
    uint trailing_elements;
};

constant ulong BN254_MODULUS[4] = {
    0x43e1f593f0000001ul,
    0x2833e84879b97091ul,
    0xb85045b68181585dul,
    0x30644e72e131a029ul,
};

constant ulong BN254_N0PRIME = 0xc2e1f593effffffful;
constant Fe FE_ONE = {{1ul, 0ul, 0ul, 0ul}};

constant uint SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline Fe make_element(ulong a0, ulong a1, ulong a2, ulong a3) {
    Fe value;
    value.limbs[0] = a0;
    value.limbs[1] = a1;
    value.limbs[2] = a2;
    value.limbs[3] = a3;
    return value;
}

inline bool ge_modulus(Fe value) {
    if (value.limbs[3] != BN254_MODULUS[3]) {
        return value.limbs[3] > BN254_MODULUS[3];
    }
    if (value.limbs[2] != BN254_MODULUS[2]) {
        return value.limbs[2] > BN254_MODULUS[2];
    }
    if (value.limbs[1] != BN254_MODULUS[1]) {
        return value.limbs[1] > BN254_MODULUS[1];
    }
    return value.limbs[0] >= BN254_MODULUS[0];
}

inline ulong add_with_carry(ulong a, ulong b, thread ulong &carry) {
    ulong sum = a + b;
    ulong c1 = sum < a ? 1ul : 0ul;
    ulong sum_with_carry = sum + carry;
    ulong c2 = sum_with_carry < sum ? 1ul : 0ul;
    carry = c1 + c2;
    return sum_with_carry;
}

inline ulong sub_with_borrow(ulong a, ulong b, thread ulong &borrow) {
    ulong diff = a - b;
    ulong b1 = diff > a ? 1ul : 0ul;
    ulong diff_with_borrow = diff - borrow;
    ulong b2 = diff_with_borrow > diff ? 1ul : 0ul;
    borrow = b1 | b2;
    return diff_with_borrow;
}

inline Fe sub_modulus(Fe value) {
    ulong borrow = 0;
    value.limbs[0] = sub_with_borrow(value.limbs[0], BN254_MODULUS[0], borrow);
    value.limbs[1] = sub_with_borrow(value.limbs[1], BN254_MODULUS[1], borrow);
    value.limbs[2] = sub_with_borrow(value.limbs[2], BN254_MODULUS[2], borrow);
    value.limbs[3] = sub_with_borrow(value.limbs[3], BN254_MODULUS[3], borrow);
    return value;
}

inline Fe add_modulus(Fe value) {
    ulong carry = 0;
    value.limbs[0] = add_with_carry(value.limbs[0], BN254_MODULUS[0], carry);
    value.limbs[1] = add_with_carry(value.limbs[1], BN254_MODULUS[1], carry);
    value.limbs[2] = add_with_carry(value.limbs[2], BN254_MODULUS[2], carry);
    value.limbs[3] = add_with_carry(value.limbs[3], BN254_MODULUS[3], carry);
    return value;
}

inline Fe add_mod(Fe lhs, Fe rhs) {
    ulong carry = 0;
    Fe result;
    result.limbs[0] = add_with_carry(lhs.limbs[0], rhs.limbs[0], carry);
    result.limbs[1] = add_with_carry(lhs.limbs[1], rhs.limbs[1], carry);
    result.limbs[2] = add_with_carry(lhs.limbs[2], rhs.limbs[2], carry);
    result.limbs[3] = add_with_carry(lhs.limbs[3], rhs.limbs[3], carry);

    if (carry != 0 || ge_modulus(result)) {
        result = sub_modulus(result);
    }

    return result;
}

inline Fe sub_mod(Fe lhs, Fe rhs) {
    ulong borrow = 0;
    Fe result;
    result.limbs[0] = sub_with_borrow(lhs.limbs[0], rhs.limbs[0], borrow);
    result.limbs[1] = sub_with_borrow(lhs.limbs[1], rhs.limbs[1], borrow);
    result.limbs[2] = sub_with_borrow(lhs.limbs[2], rhs.limbs[2], borrow);
    result.limbs[3] = sub_with_borrow(lhs.limbs[3], rhs.limbs[3], borrow);

    if (borrow != 0) {
        result = add_modulus(result);
    }

    return result;
}

inline void add_scaled_step(thread ulong &dst, ulong s, ulong a, thread ulong &carry) {
    ulong product_lo = s * a;
    ulong product_hi = mulhi(s, a);

    ulong sum = dst + product_lo;
    ulong carry0 = sum < dst ? 1ul : 0ul;
    ulong sum_with_carry = sum + carry;
    ulong carry1 = sum_with_carry < sum ? 1ul : 0ul;

    dst = sum_with_carry;
    carry = product_hi + carry0 + carry1;
}

inline void add_scaled(thread ulong *dst, ulong s, ulong a0, ulong a1, ulong a2, ulong a3) {
    ulong carry = 0;
    add_scaled_step(dst[0], s, a0, carry);
    add_scaled_step(dst[1], s, a1, carry);
    add_scaled_step(dst[2], s, a2, carry);
    add_scaled_step(dst[3], s, a3, carry);
    dst[4] += carry;
}

inline Fe mont_mul(Fe lhs, Fe rhs) {
    ulong buf[9] = {0};
    uint off = 0;

    for (uint i = 0; i < 4; i++) {
        add_scaled(
            &buf[off],
            lhs.limbs[i],
            rhs.limbs[0],
            rhs.limbs[1],
            rhs.limbs[2],
            rhs.limbs[3]
        );

        ulong m = buf[off] * BN254_N0PRIME;
        add_scaled(
            &buf[off],
            m,
            BN254_MODULUS[0],
            BN254_MODULUS[1],
            BN254_MODULUS[2],
            BN254_MODULUS[3]
        );

        off += 1;
        buf[off + 4] = 0;
    }

    Fe result = make_element(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
    if (ge_modulus(result)) {
        result = sub_modulus(result);
    }
    return result;
}

inline Fe canonicalize(Fe value) {
    if (ge_modulus(value)) {
        return sub_modulus(value);
    }
    return value;
}

inline Fe from_mont(Fe value) {
    return canonicalize(mont_mul(value, FE_ONE));
}

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

inline uint reverse_bits_width(uint value, uint width) {
    return reverse_bits(value) >> (32u - width);
}

[[kernel]]
void stockham_ntt_stage(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    device const Fe *twiddles [[buffer(2)]],
    constant StageConfig &config [[buffer(3)]],
    uint index [[thread_position_in_grid]]
) {
    uint butterflies_per_row = config.row_len >> 1u;
    uint row = index / butterflies_per_row;
    uint local = index - row * butterflies_per_row;
    uint stride = config.stride;
    uint j = local % stride;
    uint k = local / stride;

    uint row_base = row * config.row_len;
    uint base = row_base + k * (stride << 1u) + j;
    uint mate = base + stride;

    Fe even = input[base];
    Fe odd = input[mate];
    Fe twiddle = twiddles[config.twiddle_offset + k];
    Fe t = mont_mul(twiddle, odd);
    uint out_base = row_base + k * stride + j;

    output[out_base] = add_mod(even, t);
    output[out_base + butterflies_per_row] = sub_mod(even, t);
}

[[kernel]]
void mul_field_elements(
    device const Fe *lhs [[buffer(0)]],
    device const Fe *rhs [[buffer(1)]],
    device Fe *output [[buffer(2)]],
    constant FieldMulParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.count) {
        return;
    }

    output[gid] = mont_mul(lhs[gid], rhs[gid]);
}

[[kernel]]
void transpose_matrix(
    device const Fe *input [[buffer(0)]],
    device Fe *output [[buffer(1)]],
    constant TransposeParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint dst = col * params.rows + row;
    output[dst] = input[gid];
}

[[kernel]]
void replicate_first_coset(
    device Fe *buffer [[buffer(0)]],
    constant ReplicateCosetsParams &params [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.trailing_elements) {
        return;
    }

    uint repeats_per_row = params.row_len - params.coset_size;
    uint row = gid / repeats_per_row;
    uint within = gid - row * repeats_per_row;
    uint dst = row * params.row_len + params.coset_size + within;
    uint src = row * params.row_len + (within % params.coset_size);
    buffer[dst] = buffer[src];
}

[[kernel]]
void encode_field_rows_le(
    device const Fe *input [[buffer(0)]],
    device uchar *output [[buffer(1)]],
    constant FieldBytesParams &params [[buffer(2)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total_elements = params.rows * params.cols;
    if (gid >= total_elements) {
        return;
    }

    uint row = gid / params.cols;
    uint col = gid - row * params.cols;
    uint row_bits = 31u - clz(params.rows);
    uint src_row = reverse_bits_width(row, row_bits);
    Fe canonical = from_mont(input[src_row * params.cols + col]);
    uint byte_offset = gid * 32u;
    for (uint limb = 0; limb < 4; ++limb) {
        ulong value = canonical.limbs[limb];
        for (uint byte = 0; byte < 8; ++byte) {
            output[byte_offset + limb * 8u + byte] = uchar((value >> (byte * 8u)) & 0xfful);
        }
    }
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

    uint h0 = 0x6a09e667u;
    uint h1 = 0xbb67ae85u;
    uint h2 = 0x3c6ef372u;
    uint h3 = 0xa54ff53au;
    uint h4 = 0x510e527fu;
    uint h5 = 0x9b05688cu;
    uint h6 = 0x1f83d9abu;
    uint h7 = 0x5be0cd19u;

    for (uint block = 0; block < total_blocks; ++block) {
        uint w[64];

        for (uint i = 0; i < 16; ++i) {
            uint word = 0u;
            for (uint j = 0; j < 4; ++j) {
                uint idx = block * 64u + i * 4u + j;
                uchar byte = 0u;
                if (idx < params.size) {
                    byte = input[offset + idx];
                } else if (idx == params.size) {
                    byte = 0x80u;
                } else if (idx >= total_padded_len - 8u) {
                    uint shift = (total_padded_len - 1u - idx) * 8u;
                    byte = shift >= 32u ? 0u : uchar((bit_len >> shift) & 0xffu);
                }
                word = (word << 8) | uint(byte);
            }
            w[i] = word;
        }

        for (uint i = 16; i < 64; ++i) {
            w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
        }

        uint a = h0;
        uint b = h1;
        uint c = h2;
        uint d = h3;
        uint e = h4;
        uint f = h5;
        uint g = h6;
        uint h = h7;

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

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    device uchar *out = output + gid * 32u;
    uint digest[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (uint i = 0; i < 8; ++i) {
        out[i * 4 + 0] = uchar((digest[i] >> 24) & 0xffu);
        out[i * 4 + 1] = uchar((digest[i] >> 16) & 0xffu);
        out[i * 4 + 2] = uchar((digest[i] >> 8) & 0xffu);
        out[i * 4 + 3] = uchar(digest[i] & 0xffu);
    }
}
