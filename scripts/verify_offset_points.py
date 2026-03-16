#!/usr/bin/env python3
"""
Verify MSM offset points are on-curve and reproducible via SHA256
try-and-increment (NUMS construction).

Each offset point is generated as:
  1. x = SHA256(seed) interpreted as big-endian integer mod p
  2. Increment x until y² = x³ + ax + b (mod p) has a square root
  3. Pick the canonical (smaller) y

Usage: python3 scripts/verify_offset_points.py
"""

from __future__ import annotations

import hashlib


def to_int(limbs):
    """Convert [u64; 4] little-endian limbs to a Python int."""
    result = 0
    for i, limb in enumerate(limbs):
        result |= limb << (64 * i)
    return result


def mod_sqrt(a, p):
    """Tonelli-Shanks modular square root. Returns sqrt or None."""
    if a % p == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None

    # p = 3 (mod 4) shortcut
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Factor out powers of 2: p - 1 = Q * 2^S
    Q, S = p - 1, 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # Find a quadratic non-residue
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(a, Q, p)
    R = pow(a, (Q + 1) // 2, p)

    while True:
        if t == 1:
            return R
        i = 1
        tmp = (t * t) % p
        while tmp != 1:
            tmp = (tmp * tmp) % p
            i += 1
        b = pow(c, 1 << (M - i - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p


def try_and_increment(seed, p, a, b, max_attempts=1000):
    """
    NUMS point generation via try-and-increment.
    SHA256(seed) -> x candidate, increment until y^2 = x^3 + ax + b is a QR.
    """
    h = hashlib.sha256(seed.encode()).digest()
    x = int.from_bytes(h, "big") % p

    for attempt in range(max_attempts):
        rhs = (pow(x, 3, p) + a * x + b) % p
        y = mod_sqrt(rhs, p)
        if y is not None:
            # Pick the smaller y (canonical)
            if y > p - y:
                y = p - y
            return x, y, attempt
        x = (x + 1) % p

    return None, None, max_attempts


# =========================================================================
# Curve definitions (must match Rust constants in curve/grumpkin.rs and
# curve/secp256r1.rs)
# =========================================================================

CURVES = {
    "grumpkin": {
        "p": to_int(
            [
                0x43E1F593F0000001,
                0x2833E84879B97091,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]
        ),
        "a": 0,
        "b": to_int(
            [
                0x43E1F593EFFFFFF0,
                0x2833E84879B97091,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]
        ),
        "offset_x": to_int(
            [
                0x0C7F59B08D3ED494,
                0xC9C7CC25211E2D7A,
                0x39C65342A2E5E9F2,
                0x121B63F644122C3D,
            ]
        ),
        "offset_y": to_int(
            [
                0xDBECDEB7A68F782D,
                0x10F1F9045C0BC912,
                0x1CD40A11A67012E1,
                0x00767FCC149FC6B3,
            ]
        ),
        "seed": "provekit-grumpkin-offset",
    },
    "secp256r1": {
        "p": to_int([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x0, 0xFFFFFFFF00000001]),
        "a": to_int(
            [
                0xFFFFFFFFFFFFFFFC,
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0xFFFFFFFF00000001,
            ]
        ),
        "b": to_int(
            [
                0x3BCE3C3E27D2604B,
                0x651D06B0CC53B0F6,
                0xB3EBBD55769886BC,
                0x5AC635D8AA3A93E7,
            ]
        ),
        "offset_x": to_int(
            [
                0x3B8D6E63154AC0B8,
                0x9D50C8F4C290FEB5,
                0x27080C391CED0AC0,
                0x24D812942F1C942A,
            ]
        ),
        "offset_y": to_int(
            [
                0x1D028E001BC65CB8,
                0xC4CB905DF8BD1F90,
                0x9F519D447E4A2D9D,
                0x7C9E0B6CE248A7A0,
            ]
        ),
        "seed": "provekit-secp256r1-offset",
    },
}


def verify_on_curve(name, curve):
    p, a, b = curve["p"], curve["a"], curve["b"]
    x, y = curve["offset_x"], curve["offset_y"]
    lhs = pow(y, 2, p)
    rhs = (pow(x, 3, p) + a * x % p + b) % p
    ok = lhs == rhs
    print("  on-curve: %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        print("    y^2 mod p = %d" % lhs)
        print("    x^3+ax+b mod p = %d" % rhs)
    return ok


def verify_reproduction(name, curve):
    p, a, b = curve["p"], curve["a"], curve["b"]
    seed = curve["seed"]
    expected_x = curve["offset_x"]
    expected_y = curve["offset_y"]

    x, y, attempts = try_and_increment(seed, p, a, b)
    if x is None:
        print("  reproduce: FAIL (no point found in 1000 attempts)")
        return False

    # Check both y and p-y (either sign is valid)
    match_x = x == expected_x
    match_y = y == expected_y or (p - y) == expected_y

    if match_x and match_y:
        print('  reproduce: PASS (SHA256("%s") + %d increments)' % (seed, attempts))
        return True
    else:
        print("  reproduce: MISMATCH")
        print("    expected x: 0x%064x" % expected_x)
        print("    got      x: 0x%064x" % x)
        print("    expected y: 0x%064x" % expected_y)
        print("    got      y: 0x%064x" % y)
        print('    (after %d increments from SHA256("%s"))' % (attempts, seed))
        return False


def main():
    all_ok = True
    for name, curve in CURVES.items():
        print("\n%s:" % name)
        on_curve = verify_on_curve(name, curve)
        reproduced = verify_reproduction(name, curve)
        if not on_curve or not reproduced:
            all_ok = False

    print()
    if all_ok:
        print("All offset points verified: on-curve and reproducible from seed.")
    else:
        print("SOME CHECKS FAILED.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
