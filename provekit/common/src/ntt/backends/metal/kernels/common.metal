#include <metal_stdlib>

using namespace metal;

struct Bn254Element {
    ulong limbs[4];
};

typedef Bn254Element Fe;

constant Fe FE_ZERO = {{0ul, 0ul, 0ul, 0ul}};

struct StageConfig {
    uint row_len;
    uint half_m;
    uint twiddle_offset;
    uint _pad0;
};

struct BitReverseParams {
    uint row_len;
    uint log_n;
    uint total_elements;
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

struct GatherRowsParams {
    uint rows;
    uint cols;
    uint count;
    uint _pad0;
};

struct GatherHashesParams {
    uint num_nodes;
    uint count;
    uint _pad0;
    uint _pad1;
};

struct VectorLenParams {
    uint len;
    uint _pad0;
    uint _pad1;
    uint _pad2;
};

struct FoldParams {
    uint len;
    uint half_width;
    uint _pad0;
    uint _pad1;
};

struct SumcheckParams {
    uint len;
    uint half_width;
    uint pair_count;
    uint pairs_per_partial;
};

struct ReduceParams {
    uint len;
    uint values_per_chunk;
    uint _pad0;
    uint _pad1;
};

struct UnivariateAccumParams {
    uint len;
    uint count;
    uint _pad0;
    uint _pad1;
};

struct UnivariateEvalParams {
    uint len;
    uint point_count;
    uint values_per_chunk;
    uint partial_count;
};

struct EqInitParams {
    uint gamma_count;
    uint stride;
    uint _pad0;
    uint _pad1;
};

struct EqExpandParams {
    uint gamma_count;
    uint stride;
    uint stage_width;
    uint stage;
    uint power_stride;
    uint _pad0;
    uint _pad1;
    uint _pad2;
};

struct BeqAccumParams {
    uint half_size;
    uint gamma_count;
    uint _pad0;
    uint _pad1;
};

struct GammaEvalParams {
    uint half_size;
    uint weight_size;
    uint vector_count;
    uint vectors_per_polynomial;
    uint gamma_count;
    uint partial_count;
    uint values_per_partial;
    uint _pad0;
};

struct GammaReduceParams {
    uint row_count;
    uint partial_count;
    uint _pad0;
    uint _pad1;
};

struct PackDeviceVectorParams {
    uint row_count;
    uint codeword_length;
    uint message_length;
    uint mask_length;
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
constant Fe FE_MONT_ONE = {{
    0xac96341c4ffffffbul,
    0x36fc76959f60cd29ul,
    0x666ea36f7879462eul,
    0x0e0a77c19a07df2ful,
}};

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
