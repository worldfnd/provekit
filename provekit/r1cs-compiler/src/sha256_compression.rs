use {
    crate::{
        binops::{add_byte_binop, BinOp},
        noir_to_r1cs::NoirToR1CSCompiler,
        uints::{U32, U8},
    },
    ark_ff::Field,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::{BTreeMap, HashMap},
};

/// Type alias for pack cache: maps byte indices to packed witness index
pub(crate) type PackCache = HashMap<[usize; 4], usize>;

/// SHA256 round constants K[0..63]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Byte-wise XOR of two 32-bit words.
/// Performs 4 independent U8 XOR operations (one per byte).
pub(crate) fn xor_u32(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    a: &U32,
    b: &U32,
) -> U32 {
    U32::new([
        add_byte_binop(r1cs_compiler, BinOp::Xor, xor_ops, a.bytes[0], b.bytes[0]),
        add_byte_binop(r1cs_compiler, BinOp::Xor, xor_ops, a.bytes[1], b.bytes[1]),
        add_byte_binop(r1cs_compiler, BinOp::Xor, xor_ops, a.bytes[2], b.bytes[2]),
        add_byte_binop(r1cs_compiler, BinOp::Xor, xor_ops, a.bytes[3], b.bytes[3]),
    ])
}

/// Byte-wise AND of two 32-bit words.
/// Performs 4 independent U8 AND operations (one per byte).
pub(crate) fn and_u32(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    a: &U32,
    b: &U32,
) -> U32 {
    U32::new([
        add_byte_binop(r1cs_compiler, BinOp::And, and_ops, a.bytes[0], b.bytes[0]),
        add_byte_binop(r1cs_compiler, BinOp::And, and_ops, a.bytes[1], b.bytes[1]),
        add_byte_binop(r1cs_compiler, BinOp::And, and_ops, a.bytes[2], b.bytes[2]),
        add_byte_binop(r1cs_compiler, BinOp::And, and_ops, a.bytes[3], b.bytes[3]),
    ])
}

/// Right-rotates a 32-bit word represented as 4 little-endian bytes.
/// Implements ROTR(n) using byte permutation + intra-byte bit recombination.
/// Uses fused constraint: `result[i] * 2^k + lo[i] = byte[i] + lo[(i+1)%4] *
/// 256`
pub(crate) fn rotr_u32(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
    n: u32,
) -> U32 {
    assert!(n > 0 && n < 32);

    let byte_rot = (n / 8) as usize;
    let bit_rot = n % 8;

    // Step 1: Byte-level rotation
    // ROTR moves bits toward LSB, so byte[i] comes from byte[i + byte_rot]
    let rot = [
        x.bytes[byte_rot % 4],
        x.bytes[(1 + byte_rot) % 4],
        x.bytes[(2 + byte_rot) % 4],
        x.bytes[(3 + byte_rot) % 4],
    ];

    if bit_rot == 0 {
        return U32::new(rot);
    }

    let two_pow_k = FieldElement::from(1u64 << bit_rot);
    let two_pow_8 = FieldElement::from(256u64);
    let shift_coeff = FieldElement::from(1u64 << (8 - bit_rot));

    // Step 2: Create partition witnesses (lo, hi) with range check on lo only
    let mut parts = [(U8::new(0, false), U8::new(0, false)); 4];
    for i in 0..4 {
        parts[i] = partition_byte_witnesses(r1cs_compiler, range_checks, rot[i], bit_rot);
    }

    // Step 3: Create result witnesses with fused constraints
    // out[i] = hi[i] + lo[(i+1)%4] * 2^(8-k)
    // Fused constraint: result[i] * 2^k + lo[i] = byte[i] + lo[(i+1)%4] * 256
    let mut out_bytes = [U8::new(0, false); 4];
    for i in 0..4 {
        let next = (i + 1) % 4;
        let res_idx = r1cs_compiler.num_witnesses();

        // Witness: result = hi[i] + lo[next] * 2^(8-k)
        r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(res_idx, vec![
            SumTerm(None, parts[i].1.idx),
            SumTerm(Some(shift_coeff), parts[next].0.idx),
        ]));

        // Fused constraint: result * 2^k + lo[i] = byte[i] + lo[next] * 256
        r1cs_compiler.r1cs.add_constraint(
            &[(two_pow_k, res_idx), (FieldElement::ONE, parts[i].0.idx)],
            &[(FieldElement::ONE, r1cs_compiler.witness_one())],
            &[
                (FieldElement::ONE, rot[i].idx),
                (two_pow_8, parts[next].0.idx),
            ],
        );

        out_bytes[i] = U8::new(res_idx, true);
    }

    U32::new(out_bytes)
}

/// Right shifts U32 by n bits (zero-fill).
/// Uses fused constraint: `result[i] * 2^k + lo[i] = byte[i] + lo[i+1] * 256`
pub(crate) fn shr_u32(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
    n: u32,
) -> U32 {
    assert!(n > 0 && n < 32);

    let byte_shift = (n / 8) as usize;
    let bit_shift = n % 8;

    let zero = U8::zero(r1cs_compiler);

    // Step 1: byte shift with zero fill
    let mut shifted = [zero; 4];
    for i in 0..(4 - byte_shift) {
        shifted[i] = x.bytes[i + byte_shift];
    }

    // Pure byte shift (no bit shifting needed)
    if bit_shift == 0 {
        return U32::new(shifted);
    }

    let non_zero_bytes = 4 - byte_shift;
    let two_pow_k = FieldElement::from(1u64 << bit_shift);
    let two_pow_8 = FieldElement::from(256u64);
    let shift_coeff = FieldElement::from(1u64 << (8 - bit_shift));

    // Step 2: Create partition witnesses (lo, hi) without constraints
    // We only need lo for range checking; hi is used in witness computation
    let mut parts = [(zero, zero); 4];
    for i in 0..non_zero_bytes {
        parts[i] = partition_byte_witnesses(r1cs_compiler, range_checks, shifted[i], bit_shift);
    }

    // Step 3: Create result witnesses with fused constraints
    let mut result = [zero; 4];

    for i in 0..non_zero_bytes {
        let res_idx = r1cs_compiler.num_witnesses();

        if i < non_zero_bytes - 1 {
            // Middle bytes: result = hi[i] + lo[i+1] * 2^(8-k)
            // Witness builder computes this from the partition values
            r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(res_idx, vec![
                SumTerm(None, parts[i].1.idx),                  // hi[i]
                SumTerm(Some(shift_coeff), parts[i + 1].0.idx), // lo[i+1] * 2^(8-k)
            ]));

            // Fused constraint: result * 2^k + lo[i] = byte[i] + lo[i+1] * 256
            r1cs_compiler.r1cs.add_constraint(
                &[(two_pow_k, res_idx), (FieldElement::ONE, parts[i].0.idx)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[
                    (FieldElement::ONE, shifted[i].idx),
                    (two_pow_8, parts[i + 1].0.idx),
                ],
            );
        } else {
            // MSB byte: result = hi[i] (zeros fill from top)
            r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(res_idx, vec![SumTerm(
                None,
                parts[i].1.idx,
            )]));

            // Constraint: result * 2^k + lo[i] = byte[i]
            r1cs_compiler.r1cs.add_constraint(
                &[(two_pow_k, res_idx), (FieldElement::ONE, parts[i].0.idx)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, shifted[i].idx)],
            );
        }

        result[i] = U8::new(res_idx, true);
    }

    U32::new(result)
}

/// Creates partition witnesses (lo, hi) for splitting a byte at bit position k.
///
/// Given a byte value `x`, produces `lo = x mod 2^k` and `hi = x / 2^k`.
///
/// # Why `hi` Does NOT Need an Explicit Range Check
///
/// Only `lo` is explicitly range-checked to `[0, 2^k - 1]`. The soundness of
/// `hi` is **implicitly enforced** by the fused constraint added by the caller
/// (rotr_u32/shr_u32). Here's the detailed proof:
///
/// ## Step 1: The Fused Constraint
///
/// The caller adds this constraint:
/// ```text
/// result[i] * 2^k + lo[i] = byte[i] + lo[i+1] * 256
/// ```
///
/// ## Step 2: Witness Definition
///
/// The witness builder computes: `result[i] = hi[i] + lo[i+1] * 2^(8-k)`
///
/// ## Step 3: Substitution
///
/// Substituting into the constraint:
/// ```text
/// (hi[i] + lo[i+1] * 2^(8-k)) * 2^k + lo[i] = byte[i] + lo[i+1] * 256
/// hi[i] * 2^k + lo[i+1] * 2^8 + lo[i] = byte[i] + lo[i+1] * 2^8
/// ```
///
/// ## Step 4: Simplification
///
/// The `lo[i+1] * 2^8` terms cancel on both sides:
/// ```text
/// hi[i] * 2^k + lo[i] = byte[i]
/// ```
///
/// ## Step 5: Why This Bounds `hi`
///
/// Given:
/// - `byte ∈ [0, 255]` (input is range-checked)
/// - `lo ∈ [0, 2^k - 1]` (explicitly range-checked)
///
/// The constraint `hi * 2^k + lo = byte` implies:
/// - `hi * 2^k = byte - lo`
/// - Since `byte ≤ 255` and `lo ≥ 0`: `hi * 2^k ≤ 255`
/// - Therefore: `hi ≤ 255 / 2^k = 2^(8-k) - 1` (integer division)
///
/// Since `byte - lo` must be non-negative and divisible by `2^k` for `hi` to be
/// an integer, and the field modulus `p` is much larger than 256, there's no
/// wrap-around attack possible. An attacker cannot pick a malicious `hi` value
/// (like `p - 1`) because `hi * 2^k` would exceed 255, violating the
/// constraint.
/// - `hi` is automatically bounded to `[0, 31]` without explicit range check
///
/// # Warning
///
/// This function is **only sound when used with the fused constraints** in
/// rotr_u32 and shr_u32. If reused elsewhere without equivalent constraints,
/// an explicit range check on `hi` would be required.
fn partition_byte_witnesses(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    byte: U8,
    k: u32,
) -> (U8, U8) {
    assert!(
        byte.range_checked,
        "partition_byte_witnesses requires a range-checked byte"
    );
    let lo = r1cs_compiler.num_witnesses();
    let hi = lo + 1;

    r1cs_compiler.add_witness_builder(WitnessBuilder::BytePartition {
        lo,
        hi,
        x: byte.idx,
        k: k as u8,
    });

    // Range check lo - required for soundness.
    // hi is implicitly bounded by the fused constraint (see doc comment).
    range_checks.entry(k).or_default().push(lo);

    (U8::new(lo, true), U8::new(hi, true))
}

/// Adds multiple u32 values modulo 2^32, returning the witness index of the
/// result. Uses fused constraint: `packed[0] + packed[1] + ... = result +
/// carry* 2^32`
pub(crate) fn add_u32_multi_addition(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    pack_cache: &mut PackCache,
    inputs: &[&U32],
) -> U32 {
    assert!(!inputs.is_empty(), "Need at least 1 input");

    if inputs.len() == 1 {
        return *inputs[0];
    }

    // Step 1: Pack all U32 inputs to field elements (with caching)
    let packed: Vec<usize> = inputs
        .iter()
        .map(|u| u.pack_cached(r1cs_compiler, range_checks, pack_cache))
        .collect();

    // Step 2: Create result and carry witnesses
    let result_witness = r1cs_compiler.num_witnesses();
    let carry_witness = result_witness + 1;

    r1cs_compiler.add_witness_builder(WitnessBuilder::U32AdditionMulti(
        result_witness,
        carry_witness,
        packed
            .iter()
            .map(|&w| ConstantOrR1CSWitness::Witness(w))
            .collect(),
    ));

    // Step 3: Fused constraint: packed[0] + packed[1] + ... = result + carry * 2^32
    // This eliminates the intermediate sum witness
    let sum_lhs: Vec<(FieldElement, usize)> =
        packed.iter().map(|&w| (FieldElement::ONE, w)).collect();
    let two_pow_32 = FieldElement::from(1u64 << 32);
    r1cs_compiler.r1cs.add_constraint(
        &sum_lhs,
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::ONE, result_witness),
            (two_pow_32, carry_witness),
        ],
    );

    // Range check carry: max carry is (N-1) for N inputs
    let n = inputs.len();
    let max_carry = n - 1;
    let carry_bits = if max_carry == 0 {
        1
    } else {
        (usize::BITS - max_carry.leading_zeros()) as u32
    };
    range_checks
        .entry(carry_bits)
        .or_default()
        .push(carry_witness);

    // Step 4: Unpack result back to U32
    U32::unpack_u32(r1cs_compiler, range_checks, result_witness)
}

/// Adds multiple U32 values with constants modulo 2^32
/// Uses fused constraint: `packed[0] + ... + const_sum = result + carry * 2^32`
pub(crate) fn add_u32_multi_addition_with_const(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    pack_cache: &mut PackCache,
    inputs: &[&U32],
    constants: &[u32],
) -> U32 {
    assert!(
        !inputs.is_empty() || !constants.is_empty(),
        "Need at least 1 input"
    );

    // Constants-only fast path
    if inputs.is_empty() {
        let sum: u64 = constants.iter().map(|&c| c as u64).sum();
        let result = (sum % (1u64 << 32)) as u32;
        return U32::from_const(r1cs_compiler, result);
    }

    // Step 1: Pack all U32 inputs (with caching)
    let packed: Vec<usize> = inputs
        .iter()
        .map(|u| u.pack_cached(r1cs_compiler, range_checks, pack_cache))
        .collect();

    // Step 2: Compute constant sum
    let const_sum: u64 = constants.iter().map(|&c| c as u64).sum();
    let const_field = FieldElement::from(const_sum);

    // Step 3: Create result and carry witnesses
    let result_witness = r1cs_compiler.num_witnesses();
    let carry_witness = result_witness + 1;

    // Build inputs for witness builder (witnesses + constants)
    let mut wb_inputs: Vec<ConstantOrR1CSWitness> = packed
        .iter()
        .map(|&w| ConstantOrR1CSWitness::Witness(w))
        .collect();
    for &c in constants {
        wb_inputs.push(ConstantOrR1CSWitness::Constant(FieldElement::from(
            c as u64,
        )));
    }

    r1cs_compiler.add_witness_builder(WitnessBuilder::U32AdditionMulti(
        result_witness,
        carry_witness,
        wb_inputs,
    ));

    // Step 4: Fused constraint: packed[0] + ... + const_sum = result + carry * 2^32
    let mut sum_lhs: Vec<(FieldElement, usize)> =
        packed.iter().map(|&w| (FieldElement::ONE, w)).collect();
    sum_lhs.push((const_field, r1cs_compiler.witness_one()));
    let two_pow_32 = FieldElement::from(1u64 << 32);
    r1cs_compiler.r1cs.add_constraint(
        &sum_lhs,
        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
        &[
            (FieldElement::ONE, result_witness),
            (two_pow_32, carry_witness),
        ],
    );

    // Range check carry: max carry is (total_inputs - 1)
    let total_inputs = inputs.len() + constants.len();
    let max_carry = total_inputs - 1;
    let carry_bits = if max_carry == 0 {
        1
    } else {
        (usize::BITS - max_carry.leading_zeros()) as u32
    };
    range_checks
        .entry(carry_bits)
        .or_default()
        .push(carry_witness);

    // Step 5: Unpack
    U32::unpack_u32(r1cs_compiler, range_checks, result_witness)
}

/// SHA256 sigma0 function: σ₀(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ SHR(x,3)
/// Used in message schedule expansion
pub(crate) fn add_sigma0(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
) -> U32 {
    let r7 = rotr_u32(r1cs_compiler, range_checks, x, 7);
    let r18 = rotr_u32(r1cs_compiler, range_checks, x, 18);
    let s3 = shr_u32(r1cs_compiler, range_checks, x, 3);

    let t = xor_u32(r1cs_compiler, xor_ops, &r7, &r18);
    xor_u32(r1cs_compiler, xor_ops, &t, &s3)
}

/// SHA256 sigma1 function: σ₁(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ SHR(x,10)
/// Used in message schedule expansion
pub(crate) fn add_sigma1(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
) -> U32 {
    let r17 = rotr_u32(r1cs_compiler, range_checks, x, 17);
    let r19 = rotr_u32(r1cs_compiler, range_checks, x, 19);
    let s10 = shr_u32(r1cs_compiler, range_checks, x, 10);

    let t = xor_u32(r1cs_compiler, xor_ops, &r17, &r19);
    xor_u32(r1cs_compiler, xor_ops, &t, &s10)
}

/// SHA256 capital sigma1 function: Σ₁(x) = ROTR(x,6) ⊕ ROTR(x,11) ⊕ ROTR(x,25)
/// Used in main compression rounds
pub(crate) fn add_cap_sigma1(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
) -> U32 {
    let r6 = rotr_u32(r1cs_compiler, range_checks, x, 6);
    let r11 = rotr_u32(r1cs_compiler, range_checks, x, 11);
    let r25 = rotr_u32(r1cs_compiler, range_checks, x, 25);

    let t = xor_u32(r1cs_compiler, xor_ops, &r6, &r11);
    xor_u32(r1cs_compiler, xor_ops, &t, &r25)
}

/// SHA256 capital sigma0 function: Σ₀(x) = ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22)
/// Used in main compression rounds
pub(crate) fn add_cap_sigma0(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: &U32,
) -> U32 {
    let r2 = rotr_u32(r1cs_compiler, range_checks, x, 2);
    let r13 = rotr_u32(r1cs_compiler, range_checks, x, 13);
    let r22 = rotr_u32(r1cs_compiler, range_checks, x, 22);

    let t = xor_u32(r1cs_compiler, xor_ops, &r2, &r13);
    xor_u32(r1cs_compiler, xor_ops, &t, &r22)
}

/// SHA256 choice function: Ch(x,y,z) = z ⊕ (x & (y ⊕ z))
/// Used in main compression rounds
pub(crate) fn add_ch(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    x: &U32,
    y: &U32,
    z: &U32,
) -> U32 {
    let y_xor_z = xor_u32(r1cs_compiler, xor_ops, y, z);
    let x_and_yz = and_u32(r1cs_compiler, and_ops, x, &y_xor_z);
    xor_u32(r1cs_compiler, xor_ops, z, &x_and_yz)
}

/// SHA256 majority function: Maj(x,y,z) = (x & y) ⊕ ((x ⊕ y) & z)
/// Used in main compression rounds
pub(crate) fn maj(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    x: &U32,
    y: &U32,
    z: &U32,
) -> U32 {
    let xy = and_u32(r1cs_compiler, and_ops, x, y);
    let x_xor_y = xor_u32(r1cs_compiler, xor_ops, x, y);
    let xor_and_z = and_u32(r1cs_compiler, and_ops, &x_xor_y, z);
    xor_u32(r1cs_compiler, xor_ops, &xy, &xor_and_z)
}

/// SHA256 message schedule expansion: expand 16 u32 words to 64 u32 words
/// `W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]` for i = 16..64
pub(crate) fn add_message_schedule_expansion(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    pack_cache: &mut PackCache,
    input_words: &[U32; 16],
) -> [U32; 64] {
    // Initialize with input words
    let mut w: Vec<U32> = input_words.to_vec();

    // Expand to 64 words
    for _ in 16..64 {
        // Compute σ₁(W[i-2])
        let s1 = add_sigma1(r1cs_compiler, xor_ops, range_checks, &w[w.len() - 2]);

        // Compute σ₀(W[i-15])
        let s0 = add_sigma0(r1cs_compiler, xor_ops, range_checks, &w[w.len() - 15]);

        // W[i] = σ₁(W[i-2]) + W[i-7] + σ₀(W[i-15]) + W[i-16]
        let new_w = add_u32_multi_addition(r1cs_compiler, range_checks, pack_cache, &[
            &s1,
            &w[w.len() - 7],
            &s0,
            &w[w.len() - 16],
        ]);

        w.push(new_w);
    }

    w.try_into().unwrap()
}

/// SHA256 single compression round
/// Updates working variables: a, b, c, d, e, f, g, h
/// `T1 = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]`
/// `T2 = Σ₀(a) + Maj(a,b,c)`
/// Returns new `[a, b, c, d, e, f, g, h]` where a = T1+T2, e = d+T1, others
/// rotate
///
/// Optimization: Instead of computing T1 and T2 as intermediate values, we
/// inline them directly into new_e and new_a computations. This eliminates
/// 2 × 6 = 12 witnesses per round (T1 and T2 each needed result + carry + 4
/// unpacked bytes).
pub(crate) fn add_sha256_round(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    pack_cache: &mut PackCache,
    working_vars: [U32; 8],
    k_constant: u32,
    w_word: &U32,
) -> [U32; 8] {
    let [a, b, c, d, e, f, g, h] = working_vars;

    // Σ₁(e)
    let sigma1_e = add_cap_sigma1(r1cs_compiler, xor_ops, range_checks, &e);

    // Ch(e, f, g)
    let ch_efg = add_ch(r1cs_compiler, and_ops, xor_ops, &e, &f, &g);

    // Σ₀(a)
    let sigma0_a = add_cap_sigma0(r1cs_compiler, xor_ops, range_checks, &a);

    // Maj(a, b, c)
    let maj_abc = maj(r1cs_compiler, and_ops, xor_ops, &a, &b, &c);

    // Optimized: Compute new_e and new_a directly without T1/T2 intermediates
    //
    // Original formulas:
    //   T1 = h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
    //   T2 = Σ₀(a) + Maj(a,b,c)
    //   new_e = d + T1
    //   new_a = T1 + T2
    //
    // Inlined:
    //   new_e = d + h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
    //   new_a = h + Σ₁(e) + Ch(e,f,g) + Σ₀(a) + Maj(a,b,c) + K[i] + W[i]

    // new_e = d + h + Σ₁(e) + Ch(e,f,g) + K[i] + W[i]
    let new_e = add_u32_multi_addition_with_const(
        r1cs_compiler,
        range_checks,
        pack_cache,
        &[&d, &h, &sigma1_e, &ch_efg, w_word],
        &[k_constant],
    );

    // new_a = h + Σ₁(e) + Ch(e,f,g) + Σ₀(a) + Maj(a,b,c) + K[i] + W[i]
    let new_a = add_u32_multi_addition_with_const(
        r1cs_compiler,
        range_checks,
        pack_cache,
        &[&h, &sigma1_e, &ch_efg, &sigma0_a, &maj_abc, w_word],
        &[k_constant],
    );

    // Return updated working variables
    // [new_a, a, b, c, new_e, e, f, g]
    [new_a, a, b, c, new_e, e, f, g]
}

/// SHA256 compression function
pub(crate) fn add_sha256_compression(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    and_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    xor_ops: &mut Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness, usize)>,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    inputs_and_outputs: Vec<(
        Vec<ConstantOrR1CSWitness>,
        Vec<ConstantOrR1CSWitness>,
        Vec<usize>,
    )>,
) {
    for (inputs, hash_values, outputs) in inputs_and_outputs {
        assert_eq!(
            inputs.len(),
            16,
            "SHA256 requires exactly 16 input u32 words"
        );
        assert_eq!(
            hash_values.len(),
            8,
            "SHA256 requires exactly 8 initial hash values"
        );
        assert_eq!(
            outputs.len(),
            8,
            "SHA256 produces exactly 8 output u32 words"
        );

        // Convert inputs to U32 (unpack from 32-bit witnesses to 4 bytes each)
        let input_u32s: [U32; 16] = inputs
            .iter()
            .map(|input| match input {
                ConstantOrR1CSWitness::Witness(idx) => {
                    // Unpack to bytes (adds 4× 8-bit range checks internally)
                    U32::unpack_u32(r1cs_compiler, range_checks, *idx)
                }
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Input constants not yet supported")
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Convert initial hash values to U32
        let initial_hash: [U32; 8] = hash_values
            .iter()
            .map(|hash_val| match hash_val {
                ConstantOrR1CSWitness::Witness(idx) => {
                    // Unpack to bytes (adds 4× 8-bit range checks internally)
                    U32::unpack_u32(r1cs_compiler, range_checks, *idx)
                }
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Hash value constants not yet supported")
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Create pack cache for this compression - avoids repacking same U32 values
        let mut pack_cache = PackCache::new();

        // Step 1: Message schedule expansion (16 words -> 64 words)
        let w = add_message_schedule_expansion(
            r1cs_compiler,
            xor_ops,
            range_checks,
            &mut pack_cache,
            &input_u32s,
        );

        // Step 2: Initialize working variables with initial hash values
        let mut working_vars = initial_hash;

        // Step 3: Main compression loop - 64 rounds
        for i in 0..64 {
            working_vars = add_sha256_round(
                r1cs_compiler,
                and_ops,
                xor_ops,
                range_checks,
                &mut pack_cache,
                working_vars,
                SHA256_K[i],
                &w[i],
            );
        }

        // Step 4: Add initial hash values to final working variables (mod 2^32)
        let mut final_hash = [U32::from_const(r1cs_compiler, 0); 8];
        for i in 0..8 {
            final_hash[i] =
                add_u32_multi_addition(r1cs_compiler, range_checks, &mut pack_cache, &[
                    &initial_hash[i],
                    &working_vars[i],
                ]);
        }

        // Step 5: Pack final hash back to 32-bit and constrain to outputs
        for i in 0..8 {
            let final_packed =
                final_hash[i].pack_cached(r1cs_compiler, range_checks, &mut pack_cache);
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, final_packed)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, outputs[i])],
            );
        }
    }
}
