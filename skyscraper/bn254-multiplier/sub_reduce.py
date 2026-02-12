p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

 def shift_mul():
    print("shift_mul")
    neq = 0
    nlp = 0
    neg_max = 0
    neg_min = 0

    power = 5
    for i in range(0, 2**power):
        val_min = i << (256 - power)
        subp = val_min // p
        shift_subp = (val_min >> (256 - power)) // ((p >> (256 - power)) + 1)

        val_max = val_min + (1 << (256 - power)) - 1
        rem_max = val_max - (shift_subp) * p

        rem_min = val_min - (shift_subp) * p

        if subp != shift_subp:
            neq += 1

        if rem_max >= 1.7 * p:
            print(hex(rem_max))
            nlp += 1

        if rem_max < 0:
            neg_max += 1

        if rem_min < 0:
            neg_min += 1

    print(neq, nlp, neg_max, neg_min)


def shift_count():
    print("shift count")
    neq = 0
    nlp = 0
    neg_max = 0
    neg_min = 0

    power = 2

    for i in range(0, 2**power):
        val_min = i << (256 - power)
        subp = val_min // p
        shift_subp = i
        # shift_subp = ((i >> 2) & i) + (i >> 1)

        val_max = val_min + (1 << (256 - power)) - 1
        rem_max = val_max - (shift_subp) * p

        rem_min = val_min - (shift_subp) * p

        if subp != shift_subp:
            print(hex(val_min), subp, shift_subp)
            neq += 1

        if rem_max >= p + 1.5 * p:
            print(hex(rem_max))
            nlp += 1

        if rem_max < 0:
            neg_max += 1

        if rem_min < 0:
            neg_min += 1

    print(neq, nlp, neg_max, neg_min)


def shift_sum():
    print("shift sum")
    neq = 0
    nlp = 0
    neg_max = 0
    neg_min = 0

    power = 3

    for i in range(0, 2**power):
        val_min = i << (256 - power)
        subp = val_min // p
        shift_subp = ((i >> 2) & i) + (i >> 1)
        print(bin(i)[2:].zfill(power), shift_subp)

        val_max = val_min + (1 << (256 - power)) - 1
        rem_max = val_max - (shift_subp) * p

        rem_min = val_min - (shift_subp) * p

        if subp != shift_subp:
            print(hex(val_min), subp, shift_subp)
            neq += 1

        if rem_max >= p + 0.75 * p:
            print(hex(rem_max))
            nlp += 1

        if rem_max < 0:
            neg_max += 1

        if rem_min < 0:
            neg_min += 1

    print(neq, nlp, neg_max, neg_min)


def m_calculation():
    res = list()
    for w in range(0, 65):
        # increase by +1 otherwise the shift results in a smaller divider than the original problem. For us it's important to not overshoot
        # ceil
        d = (p >> (256 - w)) + 1
        nc = 2**w - 1 - (2**w % d)
        for i in range(0, 128):
            if 2**i > nc * (d - 1 - (2**i - 1) % d):
                if i < w:
                    print(w, i, d.bit_length())
                m = (2**i + d - 1 - (2**i - 1) % d) // d
                neg = False
                # comment out if the bits fit in the register.
                if m >= 2**w:
                    neg = True
                    m = m - 2**w
                res.append(
                    (
                        w,
                        m.bit_length(),
                        neg,
                        i,
                        m,
                    )
                )
                break
    return res


if __name__ == "__main__":
    shift_mul()
    shift_count()
    shift_sum()

    for b in m_calculation():
        print(b)
