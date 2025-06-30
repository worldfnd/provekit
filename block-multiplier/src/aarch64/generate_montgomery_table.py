p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

U52_i1 = [
    0x82e644ee4c3d2,
    0xf93893c98b1de,
    0xd46fe04d0a4c7,
    0x8f0aad55e2a1f,
    0x005ed0447de83,
]

U52_i2 = [
    0x74eccce9a797a,
    0x16ddcc30bd8a4,
    0x49ecd3539499e,
    0xb23a6fcc592b8,
    0x00e3bd49f6ee5,
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
    0x2d3e8053e396ee4d,
    0xca478dbeab3c92cd,
    0xb2d8f06f77f52a93,
    0x24d6ba07f7aa8f04,
]

U64_I2 = [
    0x18ee753c76f9dc6f,
    0x54ad7e14a329e70f,
    0x2b16366f4f7684df,
    0x133100d71fdf3579,
]

U64_I3 = [
    0x9BACB016127CBE4E,
    0x0B2051FA31944124,
    0xB064EEA46091C76C,
    0x2B062AAA49F80C7D,
]

def limbs_to_int(size, xs):
    total = 0
    for (i, x) in enumerate(xs):
        total += x << (size*i)

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

    first_round = (product_bound>>2*64) + u64_i2 * (2**128-1)
    second_round = (first_round >> 64) + u64_i1 * (2**64-1)
    mont_round = second_round + p*(2**64-1)
    final = mont_round >> 64
    return final

def single_step(single_input_bound): 
    product_bound = single_input_bound**2

    first_round = (product_bound>>3*64) + (u64_i3 + u64_i2 + u64_i1) * (2**64-1)
    mont_round = first_round + p*(2**64-1)
    final = mont_round >> 64
    return final

def single_step_simd(single_input_bound): 
    product_bound = (single_input_bound<<2)**2

    first_round = (product_bound>>4*52) + (u52_i4 + u52_i3 + u52_i2 + u52_i1) * (2**52-1)
    mont_round = first_round + p*(2**52-1)
    final = mont_round >> 52
    return final

if __name__ == "__main__":
    # Test bounds for different input sizes
    test_bounds = [("p", p),("2p", 2*p), ("3p", 3*p),  ("2ˆ256-2p",2**256-2*p)]
    print("Input Size | single_step | single_step_simd | log_jump")
    print("-----------|-------------|------------------|---------")
    for name, bound in test_bounds:
        single = single_step(bound)/p
        simd = single_step_simd(bound)/p
        log = log_jump(bound)/p
        single_space = (2**256-1-single_step(bound))/p
        simd_space = (2**256-1-single_step_simd(bound))/p
        log_space = (2**256-1-log_jump(bound))/p
        print(f"{name:10} | {single:4.2f} [{single_space:4.2f}] | {simd:7.2f} [{simd_space:.4f}] | {log:4.2f} [{log_space:.2f}]")

