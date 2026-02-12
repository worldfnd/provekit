"""Sub-reduction strategies for bn254 modular arithmetic."""

p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001


def shift_sum():
    """
    Generate truth table for top 3 bit reduction strategy.

    The formula ((i >> 2) & i) + (i >> 1) computes this
    approximation using only shifts and adds — no multiplication needed.
    """
    # Keep track of potential erroneous conditions
    neq = 0
    neg_max = 0
    neg_min = 0

    power = 3

    max_pval = 0
    truth_table = list()

    for i in range(0, 2**power):
        val_min = i << (256 - power)
        subp = val_min // p
        shift_subp = ((i >> 2) & i) + (i >> 1)

        val_max = val_min + (1 << (256 - power)) - 1
        rem_max = val_max - (shift_subp) * p

        rem_min = val_min - (shift_subp) * p

        # Validation: track the maximum remainder relative to p
        max_pval = max(max_pval, rem_max)

        truth_table.append((bin(i)[2:].zfill(power), shift_subp))

        # Check for erroneous situations
        if subp != shift_subp:
            print(hex(val_min), subp, shift_subp)
            neq += 1

        if rem_max < 0:
            neg_max += 1

        if rem_min < 0:
            neg_min += 1

    print(f"{'bits':>5} {'subtractions':>12}")
    for e, r in truth_table:
        print(f"{e:>5} {r:>12}")

    print(
        f"\nmax_remainder/p={max_pval / p:.4f}  mismatches={neq}  neg_max={neg_max}  neg_min={neg_min}"
    )


def warren_magic():
    """
    Generate magic numbers for division by bn254's prime for a range of top-bit widths.

    Based on Warren's "Hacker's Delight" (integer
    division by constants) to find a magic multiplier for each bit-width.

    Returns a list of tuples (w, m_bits, sub, shift, m) where:
    - w: number of bits of the dividend (top bits of the value)
    - m_bits: number of bits in the magic multiplier
    - sub: whether the "subtract and shift" variant is used (m exceeded 2^w,
      so we store m - 2^w and compensate at runtime)
    - shift: the number of bits to right-shift the product (called 's' in Warren)
    - m: the magic multiplier
    """
    res = list()
    for w in range(0, 65):
        d = (p >> (256 - w)) + 1  # d = divisor = ceil(p / 2^(256-w))
        nc = 2**w - 1 - (2**w % d)  # nc = largest value s.t. nc mod d != d-1
        for s in range(0, 128):  # s = shift exponent
            if 2**s > nc * (d - 1 - (2**s - 1) % d):
                if s < w:
                    print(w, s, d.bit_length())
                m = (2**s + d - 1 - (2**s - 1) % d) // d  # m = magic multiplier
                sub = False

                # "Subtract and shift" variant: when m >= 2^w it won't fit in w bits,
                # so subtract 2^w and compensate at runtime.
                # Comment out if the register can hold more bits than w.
                if m >= 2**w:
                    sub = True
                    m = m - 2**w
                res.append(
                    (
                        w,
                        m.bit_length(),
                        sub,
                        s,
                        m,
                    )
                )
                break
    return res


if __name__ == "__main__":
    print("shift sum")
    shift_sum()

    print("\n warren")
    print(f"{'w':>3} {'m_bits':>6} {'sub':>5} {'shift':>5} {'m':>20}")
    for w, m_bits, sub, shift, m in warren_magic():
        print(f"{w:>3} {m_bits:>6} {str(sub):>5} {shift:>5} {m:>20}")
