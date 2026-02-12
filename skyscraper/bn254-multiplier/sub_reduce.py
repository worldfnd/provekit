import math
from math import ceil

p = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

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


def rho(sign, k):
    sign = 1 if sign else -1

    return pow(sign * 2**51, -1 * k, p)


def rho_combinations(input):
    for i in range(0, 64):
        bitstring = bin(i)[2:].zfill(6)
        # 1 is positive, 0 is negative
        sel1 = int(bitstring[1 - 1])
        sel2 = int(bitstring[2 - 1])
        sel3 = int(bitstring[3 - 1])
        sel4 = int(bitstring[4 - 1])
        sel5 = int(bitstring[5 - 1])
        sel6 = int(bitstring[6 - 1])

        # max_val = input**2 >> 4 * 51
        max_val = input * (p - 1) >> 4 * 51
        # maximum value with these inclusion. Only add the once that are supposed to be added
        # values that are meant to be subtracted are ignored
        max_val += (
            sel1 * rho(sel1, 1)
            + sel1 * rho(sel1, 2)
            + sel3 * rho(sel3, 3)
            + sel4 * rho(sel4, 4)
            + sel5 * p
        ) * (2**51 - 1)

        max_val >>= 51
        max_val += sel6 * p
        max_val >>= 1

        # minimum value with these inclusion. Only add the once that are supposed to be added
        # values that are supposed to be added are ignored
        min_val = 0
        min_val += (
            -(1 - sel1) * rho(sel1, 1)
            - (1 - sel2) * rho(sel2, 2)
            - (1 - sel3) * rho(sel3, 3)
            - (1 - sel4) * rho(sel4, 4)
            - (1 - sel5) * p
        ) * (2**51 - 1)

        min_val = min_val >> 51
        # could be that it doesn't need any compensation for final reduction
        min_val -= (1 - sel6) * p
        min_val >>= 1
        diff = max_val.bit_length() - min_val.bit_length()

        subp = max_val / p

        print(
            bitstring,
            f"{max_val.bit_length():03} {int(math.copysign(1, min_val)):2} {min_val.bit_length():03} {diff:3}\t  {(input + max_val).bit_length()} {(input + ceil(subp) * p).bit_length()} {(input + ceil(subp) * p) / p} {subp}",
        )


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
