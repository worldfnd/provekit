from math import log2

p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

U52_i1 = [
    0x82E644EE4C3D2,
    0xF93893C98B1DE,
    0xD46FE04D0A4C7,
    0x8F0AAD55E2A1F,
    0x005ED0447DE83,
]

U52_i2 = [
    0x74ECCCE9A797A,
    0x16DDCC30BD8A4,
    0x49ECD3539499E,
    0xB23A6FCC592B8,
    0x00E3BD49F6EE5,
]

U52_i3 = [
    0x0E8C656567D77,
    0x430D05713AE61,
    0xEA3BA6B167128,
    0xA7DAE55C5A296,
    0x01B4AFD513572,
]

U52_i4 = [
    0x22E2400E2F27D,
    0x323B46EA19686,
    0xE6C43F0DF672D,
    0x7824014C39E8B,
    0x00C6B48AFE1B8,
]

U64_I1 = [
    0x2D3E8053E396EE4D,
    0xCA478DBEAB3C92CD,
    0xB2D8F06F77F52A93,
    0x24D6BA07F7AA8F04,
]

U64_I2 = [
    0x18EE753C76F9DC6F,
    0x54AD7E14A329E70F,
    0x2B16366F4F7684DF,
    0x133100D71FDF3579,
]

U64_I3 = [
    0x9BACB016127CBE4E,
    0x0B2051FA31944124,
    0xB064EEA46091C76C,
    0x2B062AAA49F80C7D,
]


U51_i1 = pow(
    2**51,
    -1,
    p,
)
U51_i2 = pow(
    2**51,
    -2,
    p,
)
U51_i3 = pow(
    2**51,
    -3,
    p,
)
U51_i4 = pow(
    2**51,
    -4,
    p,
)


def int_to_limbs(size, i):
    mask = 2**size - 1
    limbs = []
    while i != 0:
        limbs.append(i & mask)
        i = i >> size

    return limbs


def format_limbs(limbs):
    return map(lambda x: hex(x), limbs)


def limbs_to_int(size, xs):
    total = 0
    for i, x in enumerate(xs):
        total += x << (size * i)

    return total


u64_i1 = limbs_to_int(64, U64_I1)
u64_i2 = limbs_to_int(64, U64_I2)
u64_i3 = limbs_to_int(64, U64_I3)

u52_i1 = limbs_to_int(52, U52_i1)
u52_i2 = limbs_to_int(52, U52_i2)
u52_i3 = limbs_to_int(52, U52_i3)
u52_i4 = limbs_to_int(52, U52_i4)


def log_jump(single_input_bound):
    product_bound = single_input_bound**2

    first_round = (product_bound >> 2 * 64) + u64_i2 * (2**128 - 1)
    second_round = (first_round >> 64) + u64_i1 * (2**64 - 1)
    mont_round = second_round + p * (2**64 - 1)
    final = mont_round >> 64
    return final


def single_step(single_input_bound):
    product_bound = single_input_bound**2

    first_round = (product_bound >> 3 * 64) + (u64_i3 + u64_i2 + u64_i1) * (2**64 - 1)
    mont_round = first_round + p * (2**64 - 1)
    final = mont_round >> 64
    # print(log2(final))

    return final


def single_step_simd(single_input_bound):
    product_bound = (single_input_bound << 2) ** 2

    first_round = (product_bound >> 4 * 52) + (u52_i4 + u52_i3 + u52_i2 + u52_i1) * (
        2**52 - 1
    )
    mont_round = first_round + p * (2**52 - 1)
    final = mont_round >> 52
    # print(log2(final))
    return final


def single_step_simd_wasm(single_input_bound):
    product_bound = (single_input_bound) ** 2

    first_round = (product_bound >> 4 * 51) + (U51_i1 + U51_i2 + U51_i3 + U51_i4) * (
        2**51 - 1
    )
    mont_round = first_round + p * (2**51 - 1)
    final = mont_round >> 51
    # print(log2(final))
    # print(log2(final + p))

    reduced = (final + p) >> 1 if final & 1 else final >> 1
    # print(log2(reduced))
    return reduced


if __name__ == "__main__":
    print(hex(pow(-p, -1, 2**51)))
    # Test bounds for different input sizes
    test_bounds = [
        ("p", p),
        ("2p", 2 * p),
        ("2ˆ255", 2**255),
        ("3p", 3 * p),
        ("2ˆ256-2p", 2**256 - 2 * p),
    ]
    print("Input Size | single_step | single_step_simd | log_jump| single_step_wasm ")
    print("-----------|-------------|------------------|---------|-----------------|")
    for name, bound in test_bounds:
        single = single_step(bound) / p
        simd = single_step_simd(bound) / p
        simd_wasm = single_step_simd_wasm(bound) / p
        log = log_jump(bound) / p
        single_space = (2**256 - 1 - single_step(bound)) / p
        simd_space = (2**256 - 1 - single_step_simd(bound)) / p
        simd_wasm_space = (2**256 - 1 - single_step_simd_wasm(bound)) / p
        log_space = (2**256 - 1 - log_jump(bound)) / p
        print(
            f"{name:10} | {single:4.2f} [{single_space:4.2f}] | {simd:7.2f} [{simd_space:.4f}] | {log:4.2f} [{log_space:.2f}] | {simd_wasm:4.2f} [{simd_wasm_space:.2f}]"
        )
