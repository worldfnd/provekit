"""Generate Rust const lookup tables for multiples of the BN254 scalar field prime."""

p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001


def int_to_limbs(size, n, count):
    mask = 2**size - 1
    limbs = []
    for _ in range(count):
        limbs.append(n & mask)
        n >>= size
    return limbs


def main():
    multiples_64 = [int_to_limbs(64, k * p, 4) for k in range(0, 6)]
    multiples_51 = [int_to_limbs(51, k * p, 5) for k in range(0, 6)]

    # Print 64-bit table (for constants.rs)
    print("pub const U64_P_MULTIPLES: [[u64; 4]; 6] = [")
    for k, limbs in enumerate(multiples_64):
        fmt = ", ".join(f"0x{l:016x}" for l in limbs)
        print(f"    [{fmt}], // {k}P")
    print("];")

    # Print 51-bit table (for rne/constants.rs)
    print("\npub const U51_P_MULTIPLES: [[u64; 5]; 6] = [")
    for k, limbs in enumerate(multiples_51):
        fmt = ", ".join(f"0x{l:013x}" for l in limbs)
        print(f"    [{fmt}], // {k}P")
    print("];")


if __name__ == "__main__":
    main()
