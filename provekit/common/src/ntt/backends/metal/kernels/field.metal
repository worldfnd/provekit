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

#pragma clang loop unroll(enable)
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

inline uint reverse_bits_width(uint value, uint width) {
    return reverse_bits(value) >> (32u - width);
}
