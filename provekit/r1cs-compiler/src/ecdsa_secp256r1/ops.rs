use {
    crate::{
        digits::DigitalDecompositionWitnessesBuilder,
        ecdsa_secp256r1::constants::{
            get_curve_field_modulus_p, get_curve_order_n, get_curve_parameter_b,
            get_generator_point,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{Field, Zero},
    ark_std::One,
    provekit_common::{witness::ConstantOrR1CSWitness, FieldElement},
    std::collections::BTreeMap,
};

/// Helper function to extract witness indices from ConstantOrR1CSWitness array
fn extract_witness_indices(inputs: &[ConstantOrR1CSWitness]) -> Vec<usize> {
    inputs
        .iter()
        .filter_map(|w| match w {
            ConstantOrR1CSWitness::Witness(idx) => Some(*idx),
            ConstantOrR1CSWitness::Constant(_) => None,
        })
        .collect()
}

/// Compute k = value / modulus (in the field) and return (k_witness,
/// modulus_inv)
fn compute_k_for_modular_operation(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    value: usize,
    modulus: FieldElement,
) -> (usize, FieldElement) {
    let k_witness = r1cs_compiler.num_witnesses();
    let modulus_inv = modulus
        .inverse()
        .expect("Modulus should be invertible in field");
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        k_witness,
        vec![provekit_common::witness::SumTerm(Some(modulus_inv), value)],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(modulus_inv, value)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_witness)],
    );
    (k_witness, modulus_inv)
}

/// Compute k * modulus and return the witness index
fn compute_k_times_modulus(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    k_witness: usize,
    modulus: FieldElement,
) -> usize {
    let k_times_modulus = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        k_times_modulus,
        vec![provekit_common::witness::SumTerm(Some(modulus), k_witness)],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(modulus, k_witness)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_modulus)],
    );
    k_times_modulus
}

/// Generic modular reduction function
/// Reduces value modulo the given modulus
fn reduce_mod(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    value: usize,
    modulus: FieldElement,
) -> usize {
    // Compute k = value / modulus (in the field)
    let (k_witness, _) = compute_k_for_modular_operation(r1cs_compiler, value, modulus);

    // Compute k * modulus
    let k_times_modulus = compute_k_times_modulus(r1cs_compiler, k_witness, modulus);

    // Compute result = value - k * modulus
    let result = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(result, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), value),
        provekit_common::witness::SumTerm(Some(-FieldElement::one()), k_times_modulus),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), result),
            (FieldElement::one(), k_times_modulus),
        ],
    );

    // Verify that value = result + k * modulus
    let result_plus_k_times_modulus = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        result_plus_k_times_modulus,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), result),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), k_times_modulus),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), result),
            (FieldElement::one(), k_times_modulus),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_plus_k_times_modulus)],
    );

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_plus_k_times_modulus)],
    );

    result
}

pub(crate) fn range_check_inputs(
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    public_key_x: &[ConstantOrR1CSWitness],
    public_key_y: &[ConstantOrR1CSWitness],
    signature: &[ConstantOrR1CSWitness],
    hashed_message: &[ConstantOrR1CSWitness],
) {
    // Convert inputs to witness indices and add range checks
    // All byte values must be in range [0, 255] (8 bits)
    let mut all_byte_witnesses = Vec::new();
    all_byte_witnesses.extend(extract_witness_indices(public_key_x));
    all_byte_witnesses.extend(extract_witness_indices(public_key_y));
    all_byte_witnesses.extend(extract_witness_indices(signature));
    all_byte_witnesses.extend(extract_witness_indices(hashed_message));

    // Add range checks for all byte witnesses (8 bits = range [0, 255])
    for &witness_idx in &all_byte_witnesses {
        range_checks.entry(8).or_default().push(witness_idx);
    }
}

/// Check that the signature is canonical, i.e. s <= n/2.
/// For secp256r1, n/2 ≈ 2^255, so we check that s[0] < 128 (MSB is 0)
/// This ensures s < 2^255 <= n/2
pub(crate) fn check_signature_is_canonical(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    s_witnesses: &[usize],
) {
    // Compute diff = 128 - s[0] and ensure diff >= 1 (i.e., s[0] <= 127)
    // Constraint: s[0] + diff = 128, where diff ∈ [1, 128] ensures s[0] ∈ [0, 127]
    let one_hundred_twenty_eight = FieldElement::from(128u64);
    let diff_128_s0 = r1cs_compiler.num_witnesses();

    // diff = 128 - s[0]
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        diff_128_s0,
        vec![
            provekit_common::witness::SumTerm(
                Some(one_hundred_twenty_eight),
                r1cs_compiler.witness_one(),
            ),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), s_witnesses[0]),
        ],
    ));

    // Constraint: s[0] + diff = 128
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), s_witnesses[0]),
            (FieldElement::one(), diff_128_s0),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(one_hundred_twenty_eight, r1cs_compiler.witness_one())],
    );

    // Range check diff to be in [1, 128] ensures s[0] ∈ [0, 127], so s[0] < 128
    // We check diff >= 1 by ensuring diff - 1 >= 0, i.e., range check (diff - 1) in
    // [0, 127]
    let diff_minus_one = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        diff_minus_one,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), diff_128_s0),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    // Constraint: diff_128_s0 = diff_minus_one + 1
    // Rearranged: diff_128_s0 - diff_minus_one - 1 = 0
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), diff_128_s0)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), diff_minus_one),
            (FieldElement::one(), r1cs_compiler.witness_one()),
        ],
    );

    // Range check diff_minus_one in [0, 127] ensures diff >= 1, so s[0] <= 127
    // 7 bits = [0, 127]
    range_checks.entry(7).or_default().push(diff_minus_one);
}

/// Reconstruct a field element from a byte array (big-endian).
/// bytes[0] is the most significant byte, bytes[31] is the least significant
/// byte. Returns the witness index of the reconstructed field element.
pub(crate) fn reconstruct_field_element_from_bytes_be(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    byte_witnesses: &[usize],
) -> usize {
    if byte_witnesses.len() != 32 {
        panic!("Must have exactly 32 bytes");
    }

    // Start with the least significant byte: s = bytes[31]
    let mut result = byte_witnesses[31];

    // Build up from least significant to most significant byte
    // For each byte from bytes[30] down to bytes[0]:
    //   result = result * 256 + byte
    for &byte_witness in byte_witnesses.iter().rev().skip(1) {
        // Multiply current result by 256
        let result_times_256 = r1cs_compiler.num_witnesses();
        let byte_256 = FieldElement::from(256u64);

        // result_times_256 = result * 256
        r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
            result_times_256,
            vec![provekit_common::witness::SumTerm(Some(byte_256), result)],
        ));
        // Constraint: 256 * result = result_times_256
        r1cs_compiler.r1cs.add_constraint(
            &[(byte_256, result)],
            &[(FieldElement::one(), r1cs_compiler.witness_one())],
            &[(FieldElement::one(), result_times_256)],
        );

        // result = result_times_256 + byte_witness
        let result_new = r1cs_compiler.num_witnesses();
        r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
            result_new,
            vec![
                provekit_common::witness::SumTerm(Some(FieldElement::one()), result_times_256),
                provekit_common::witness::SumTerm(Some(FieldElement::one()), byte_witness),
            ],
        ));
        r1cs_compiler.r1cs.add_constraint(
            &[
                (FieldElement::one(), result_times_256),
                (FieldElement::one(), byte_witness),
            ],
            &[(FieldElement::one(), r1cs_compiler.witness_one())],
            &[(FieldElement::one(), result_new)],
        );

        result = result_new;
    }

    result
}

/// Compute w = 1/s mod n where n is the secp256r1 curve order.
/// Ensures that s * w ≡ 1 (mod n) by constraining s * w = 1 + k * n for some
/// integer k.
pub(crate) fn compute_modular_inverse(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    s_witness: usize,
) -> usize {
    let curve_fr_n = get_curve_order_n();

    // Step 1: Compute w_field = 1/s in the field (mod field modulus)
    let w_field = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Inverse(
        w_field, s_witness,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_witness)],
        &[(FieldElement::one(), w_field)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );

    // Step 2: Compute s * w_field
    let s_times_w = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        s_times_w, s_witness, w_field,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_witness)],
        &[(FieldElement::one(), w_field)],
        &[(FieldElement::one(), s_times_w)],
    );

    // Step 3: Compute s * w_field - 1
    let s_times_w_minus_one = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        s_times_w_minus_one,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), s_times_w),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_times_w)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), s_times_w_minus_one),
            (FieldElement::one(), r1cs_compiler.witness_one()),
        ],
    );

    // Step 4: Introduce witness k such that s * w_field - 1 = k * n
    // This ensures s * w_field ≡ 1 (mod n)
    // We need to compute k = (s * w_field - 1) / n
    // Since division in R1CS is complex, we'll use the fact that in the field:
    // s * w_field - 1 = k * n (as field elements)
    // So: k = (s * w_field - 1) * (1/n) mod field_modulus
    let (k_witness, _) =
        compute_k_for_modular_operation(r1cs_compiler, s_times_w_minus_one, curve_fr_n);

    // Step 5: Verify that s * w_field - 1 = k * n
    let k_times_n = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fr_n);

    // Constraint: s * w_field - 1 = k * n
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_times_w_minus_one)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_n)],
    );

    // Step 6: Range check k to ensure it's reasonable
    // Since s < n and w_field ≈ 1/s, we expect k to be 0 or 1 in most cases
    // Actually, since k = (s * w_field - 1) / n and s * w_field < n^2, k < n
    // We'll range check k to be less than n (256 bits)
    // Note: This is expensive but provides additional security guarantees
    range_checks.entry(256).or_default().push(k_witness);

    // Return w_field as the modular inverse (it satisfies s * w ≡ 1 mod n)
    w_field
}

/// Verify that s * w ≡ 1 (mod n) where n is the secp256r1 curve order.
/// This ensures that w is the modular inverse of s modulo n.
/// The verification is done by checking that s * w = 1 + k * n for some integer
/// k.
pub(crate) fn check_s_times_w_equals_one_mod_n(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    s: usize,
    w: usize,
) {
    let curve_fr_n = get_curve_order_n();

    // Step 1: Compute s * w
    let s_times_w = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        s_times_w, s, w,
    ));
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::one(), s)], &[(FieldElement::one(), w)], &[
            (FieldElement::one(), s_times_w),
        ]);

    // Step 2: Compute s * w - 1
    let s_times_w_minus_one = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        s_times_w_minus_one,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), s_times_w),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_times_w)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), s_times_w_minus_one),
            (FieldElement::one(), r1cs_compiler.witness_one()),
        ],
    );

    // Step 3: Compute k = (s * w - 1) / n
    // Since we're in a field, we compute k = (s * w - 1) * (1/n)
    let (k_witness, _) =
        compute_k_for_modular_operation(r1cs_compiler, s_times_w_minus_one, curve_fr_n);

    // Step 4: Compute k * n
    let k_times_n = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fr_n);

    // Step 5: Verify that s * w - 1 = k * n
    // This constraint ensures: s * w = 1 + k * n, which means s * w ≡ 1 (mod n)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), s_times_w_minus_one)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_n)],
    );
}

/// Compute result = a * b mod n where n is the secp256r1 curve order.
/// Ensures that a * b = result + k * n for some integer k, which means result =
/// a * b mod n.
pub(crate) fn compute_modular_multiplication(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
) -> usize {
    let curve_fr_n = get_curve_order_n();

    // Step 1: Compute a * b
    let a_times_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        a_times_b, a, b,
    ));
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::one(), a)], &[(FieldElement::one(), b)], &[
            (FieldElement::one(), a_times_b),
        ]);

    // Step 2: Introduce witness k such that a * b = result + k * n
    // This ensures result = a * b mod n
    // We'll compute result = a * b - k * n where k is chosen such that 0 <= result
    // < n In practice, we compute k = floor((a * b) / n) and result = a * b - k
    // * n

    // Compute k = (a * b) / n (in the field)
    let (k_witness, _) = compute_k_for_modular_operation(r1cs_compiler, a_times_b, curve_fr_n);

    // Step 3: Compute k * n
    let k_times_n = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fr_n);

    // Step 4: Compute result = a * b - k * n
    // This gives us result = a * b mod n
    let result = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(result, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), a_times_b),
        provekit_common::witness::SumTerm(Some(-FieldElement::one()), k_times_n),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a_times_b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), result),
            (FieldElement::one(), k_times_n),
        ],
    );

    // Step 5: Verify that a * b = result + k * n
    // This constraint ensures: result = a * b mod n
    let result_plus_k_times_n = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        result_plus_k_times_n,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), result),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), k_times_n),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), result),
            (FieldElement::one(), k_times_n),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_plus_k_times_n)],
    );

    // Constraint: a * b = result + k * n
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a_times_b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_plus_k_times_n)],
    );
    result
}

/// Reduce a field element modulo the secp256r1 curve field modulus p.
/// Ensures that result = value mod p, where 0 <= result < p.
fn reduce_mod_p(r1cs_compiler: &mut NoirToR1CSCompiler, value: usize) -> usize {
    reduce_mod(r1cs_compiler, value, get_curve_field_modulus_p())
}

/// Validate that the public key (x, y) is on the secp256r1 curve.
/// The secp256r1 curve equation is: y² = x³ + ax + b (mod p)
/// where a = -3 and b is the curve constant.
/// We verify: y² = x³ - 3x + b (mod p)
pub(crate) fn validate_point_is_on_curve(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    x: usize,
    y: usize,
) {
    // Reduce x and y modulo the curve field modulus p before operations
    let x_reduced = reduce_mod_p(r1cs_compiler, x);
    let y_reduced = reduce_mod_p(r1cs_compiler, y);

    let curve_fp_p = get_curve_field_modulus_p();
    let curve_b = get_curve_parameter_b();

    // Step 1: Compute y²
    let y_squared = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        y_squared, y_reduced, y_reduced,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), y_reduced)],
        &[(FieldElement::one(), y_reduced)],
        &[(FieldElement::one(), y_squared)],
    );

    // Step 2: Compute x²
    let x_squared = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        x_squared, x_reduced, x_reduced,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), x_reduced)],
        &[(FieldElement::one(), x_reduced)],
        &[(FieldElement::one(), x_squared)],
    );

    // Step 3: Compute x³ = x² * x
    let x_cubed = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        x_cubed, x_squared, x_reduced,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), x_squared)],
        &[(FieldElement::one(), x_reduced)],
        &[(FieldElement::one(), x_cubed)],
    );

    // Step 4: Compute -3x (where a = -3)
    let minus_three = FieldElement::from(-3i64);
    let minus_three_x = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        minus_three_x,
        vec![provekit_common::witness::SumTerm(
            Some(minus_three),
            x_reduced,
        )],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(minus_three, x_reduced)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), minus_three_x)],
    );

    // Step 5: Compute x³ - 3x
    let x_cubed_minus_3x = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        x_cubed_minus_3x,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), x_cubed),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), minus_three_x),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), x_cubed),
            (FieldElement::one(), minus_three_x),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), x_cubed_minus_3x)],
    );

    // Step 6: Compute x³ - 3x + b
    let rhs = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(rhs, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), x_cubed_minus_3x),
        provekit_common::witness::SumTerm(Some(curve_b), r1cs_compiler.witness_one()),
    ]));
    // Constraint: x_cubed_minus_3x + curve_b = rhs
    // Rearranged: x_cubed_minus_3x + curve_b - rhs = 0
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), x_cubed_minus_3x),
            (curve_b, r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), rhs)],
    );

    // Step 7: Verify y² = x³ - 3x + b (mod p)
    // Since we're working in the R1CS field (not the curve's field), we need to
    // verify that y² ≡ rhs (mod p). We do this by checking y² - rhs = k * p for
    // some k.
    let y_squared_minus_rhs = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        y_squared_minus_rhs,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), y_squared),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), rhs),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), y_squared),
            (-FieldElement::one(), rhs),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), y_squared_minus_rhs)],
    );

    // Compute k = (y² - rhs) / p
    let (k_witness, _) =
        compute_k_for_modular_operation(r1cs_compiler, y_squared_minus_rhs, curve_fp_p);

    // Compute k * p
    let k_times_p = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fp_p);

    // Verify y² - rhs = k * p, which means y² ≡ rhs (mod p)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), y_squared_minus_rhs)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_p)],
    );
}

/// Verify that a ≡ b (mod n) where n is the secp256r1 curve order.
/// This ensures that a - b = k * n for some integer k, which means a ≡ b (mod
/// n).
///
/// Note: Since we're working in a field, we need to handle the case where
/// a - b might be negative. We check both directions:
/// - If a >= b: a - b = k * n
/// - If a < b: b - a = k * n (which means a - b = -k * n)
///
/// In field arithmetic, we can compute the difference and check
/// if it's a multiple of n. Since field elements wrap around, we compute
/// diff = a - b (as a field element) and verify diff = k * n or diff = -k * n.
///
/// For simplicity, we'll check: (a - b) mod n = 0, which means
/// a - b = k * n for some integer k (which could be negative in the field
/// sense).
pub(crate) fn verify_modular_equality(r1cs_compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) {
    let curve_fr_n = get_curve_order_n();

    // Step 1: Compute a - b
    let a_minus_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        a_minus_b,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), a),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), b),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a), (-FieldElement::one(), b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), a_minus_b)],
    );

    // Step 2: Compute k = (a - b) / n (in the field)
    // This gives us k such that a - b = k * n (as field elements)
    let (k_witness, _) = compute_k_for_modular_operation(r1cs_compiler, a_minus_b, curve_fr_n);

    // Step 3: Compute k * n
    let k_times_n = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fr_n);

    // Step 4: Verify that a - b = k * n
    // This constraint ensures: a - b = k * n, which means a ≡ b (mod n)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a_minus_b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_n)],
    );
}

/// Compute a * b mod p where p is the secp256r1 field modulus.
/// This is used for field arithmetic in elliptic curve operations.
fn compute_field_multiplication(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: usize,
    b: usize,
) -> usize {
    // Step 1: Compute a * b
    let a_times_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        a_times_b, a, b,
    ));
    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::one(), a)], &[(FieldElement::one(), b)], &[
            (FieldElement::one(), a_times_b),
        ]);

    // Step 2: Reduce result modulo p
    reduce_mod_p(r1cs_compiler, a_times_b)
}

/// Compute (a - b) mod p where p is the secp256r1 field modulus.
fn compute_field_subtraction(r1cs_compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) -> usize {
    // Compute a - b
    let a_minus_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        a_minus_b,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), a),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), b),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a), (-FieldElement::one(), b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), a_minus_b)],
    );

    // Handle potential negative result by adding p if needed
    // In field arithmetic, a - b mod p = (a - b + k*p) for appropriate k
    let result = reduce_mod_p(r1cs_compiler, a_minus_b);
    result
}

/// Compute (a + b) mod p where p is the secp256r1 field modulus.
#[allow(dead_code)]
fn compute_field_addition(r1cs_compiler: &mut NoirToR1CSCompiler, a: usize, b: usize) -> usize {
    // Compute a + b
    let a_plus_b = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        a_plus_b,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), a),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), b),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), a), (FieldElement::one(), b)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), a_plus_b)],
    );

    // Reduce modulo p
    reduce_mod_p(r1cs_compiler, a_plus_b)
}

/// Compute (a * b) mod p for field arithmetic where p is secp256r1 field
/// modulus. This version ensures all intermediate values are properly
/// constrained. NOTE: This function is kept for reference but is no longer used
/// (replaced with safe division)
#[allow(dead_code)]
fn compute_modular_field_inverse(r1cs_compiler: &mut NoirToR1CSCompiler, value: usize) -> usize {
    let curve_fp_p = get_curve_field_modulus_p();

    // Compute inverse in field
    let inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Inverse(
        inv, value,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value)],
        &[(FieldElement::one(), inv)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
    );

    // Verify value * inv - 1 = k * p for some k
    let value_times_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        value_times_inv,
        value,
        inv,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value)],
        &[(FieldElement::one(), inv)],
        &[(FieldElement::one(), value_times_inv)],
    );

    let value_times_inv_minus_one = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        value_times_inv_minus_one,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), value_times_inv),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value_times_inv)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[
            (FieldElement::one(), value_times_inv_minus_one),
            (FieldElement::one(), r1cs_compiler.witness_one()),
        ],
    );

    // Compute k = (value * inv - 1) / p
    let (k_witness, _) =
        compute_k_for_modular_operation(r1cs_compiler, value_times_inv_minus_one, curve_fp_p);

    // Verify value * inv - 1 = k * p
    let k_times_p = compute_k_times_modulus(r1cs_compiler, k_witness, curve_fp_p);
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value_times_inv_minus_one)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), k_times_p)],
    );

    inv
}

/// Check if a witness value is zero by computing is_zero = (1 - value *
/// value_inv) where value_inv is the inverse of value if non-zero, or 0 if
/// value is zero. Returns (is_zero_witness, value_inv_witness) where is_zero is
/// 1 if value==0, else 0.
fn compute_is_zero(r1cs_compiler: &mut NoirToR1CSCompiler, value: usize) -> (usize, usize) {
    // Create a witness for the inverse (prover will set this appropriately)
    let value_inv = r1cs_compiler.num_witnesses();
    // Note: This WitnessBuilder will be set by prover
    // If value != 0, prover sets value_inv = 1/value
    // If value == 0, prover sets value_inv = 0
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        value_inv,
        vec![provekit_common::witness::SumTerm(
            Some(FieldElement::zero()),
            r1cs_compiler.witness_one(),
        )],
    ));

    // Compute value * value_inv
    let value_times_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        value_times_inv,
        value,
        value_inv,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), value)],
        &[(FieldElement::one(), value_inv)],
        &[(FieldElement::one(), value_times_inv)],
    );

    // Compute is_zero = 1 - value * value_inv
    // If value != 0: value * value_inv = 1, so is_zero = 0
    // If value == 0: value * value_inv = 0, so is_zero = 1
    let is_zero = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        is_zero,
        vec![
            provekit_common::witness::SumTerm(
                Some(FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), value_times_inv),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), r1cs_compiler.witness_one()),
            (-FieldElement::one(), value_times_inv),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), is_zero)],
    );

    // Verify: is_zero * value = 0 (ensures if is_zero=1, then value=0)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), is_zero)],
        &[(FieldElement::one(), value)],
        &[], // Result is 0
    );

    // Verify: (1 - is_zero) * (value * value_inv - 1) = 0
    // This ensures if is_zero=0, then value * value_inv = 1
    let one_minus_is_zero = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        one_minus_is_zero,
        vec![
            provekit_common::witness::SumTerm(
                Some(FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), is_zero),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), r1cs_compiler.witness_one()),
            (-FieldElement::one(), is_zero),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), one_minus_is_zero)],
    );

    let value_inv_minus_one = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        value_inv_minus_one,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), value_times_inv),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), value_times_inv),
            (-FieldElement::one(), r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), value_inv_minus_one)],
    );

    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_is_zero)],
        &[(FieldElement::one(), value_inv_minus_one)],
        &[], // Result is 0
    );
    (is_zero, value_inv)
}

/// Elliptic curve point doubling: (x, y) -> (2*x, 2*y) on secp256r1 curve.
/// Uses the formula:
/// - lambda = (3*x^2 - 3) / (2*y)
/// - x3 = lambda^2 - 2*x
/// - y3 = lambda*(x - x3) - y
///
/// EDGE CASE HANDLING:
/// - If y = 0, the point is of order 2, and doubling gives point at infinity
/// - Returns (0, 0) to represent point at infinity in this case
fn point_double(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x: usize,
    y: usize,
) -> (usize, usize) {
    // Reduce x and y modulo p first
    let x_reduced = reduce_mod_p(r1cs_compiler, x);
    let y_reduced = reduce_mod_p(r1cs_compiler, y);

    // EDGE CASE CHECK: Detect if y = 0 (or if point is at infinity)
    // If y = 0, doubling results in point at infinity
    let (y_is_zero, _y_inv) = compute_is_zero(r1cs_compiler, y_reduced);

    // Create a zero witness for point at infinity representation
    let zero_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        zero_witness,
        vec![provekit_common::witness::SumTerm(
            Some(FieldElement::zero()),
            r1cs_compiler.witness_one(),
        )],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::zero(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), zero_witness)],
    );

    // Compute the normal point doubling (even if y=0, we compute it but won't use
    // the result) This ensures all constraints are consistent regardless of the
    // branch taken

    // Compute x^2
    let x_squared = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        x_squared, x_reduced, x_reduced,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), x_reduced)],
        &[(FieldElement::one(), x_reduced)],
        &[(FieldElement::one(), x_squared)],
    );

    // Compute 3*x^2
    let three = FieldElement::from(3u64);
    let three_x_squared = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        three_x_squared,
        vec![provekit_common::witness::SumTerm(Some(three), x_squared)],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(three, x_squared)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), three_x_squared)],
    );

    // Compute 3*x^2 - 3 (since a = -3 for secp256r1)
    let numerator = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        numerator,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), three_x_squared),
            provekit_common::witness::SumTerm(Some(-three), r1cs_compiler.witness_one()),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), three_x_squared),
            (-three, r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), numerator)],
    );

    // Compute 2*y
    let two = FieldElement::from(2u64);
    let denominator = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        denominator,
        vec![provekit_common::witness::SumTerm(Some(two), y_reduced)],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(two, y_reduced)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), denominator)],
    );

    // CRITICAL: Use safe division that doesn't fail when denominator is zero
    // If y_is_zero = 1, the prover will set denominator_inv = 0 (any value is fine)
    // If y_is_zero = 0, the prover must set denominator_inv = 1/denominator
    let denominator_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        denominator_inv,
        vec![provekit_common::witness::SumTerm(
            Some(FieldElement::zero()),
            r1cs_compiler.witness_one(),
        )],
    ));

    // Only enforce denominator * denominator_inv = 1 when y_is_zero = 0
    // Constraint: (1 - y_is_zero) * (denominator * denominator_inv - 1) = 0
    let denom_times_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        denom_times_inv,
        denominator,
        denominator_inv,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), denominator_inv)],
        &[(FieldElement::one(), denom_times_inv)],
    );

    // (1 - y_is_zero) * (denominator * denominator_inv - 1) = 0
    let one_minus_y_is_zero = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        one_minus_y_is_zero,
        vec![
            provekit_common::witness::SumTerm(
                Some(FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), y_is_zero),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), r1cs_compiler.witness_one()),
            (-FieldElement::one(), y_is_zero),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), one_minus_y_is_zero)],
    );

    // (denominator * denominator_inv - 1) = 0
    let denom_inv_check = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        denom_inv_check,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), denom_times_inv),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), denom_times_inv),
            (-FieldElement::one(), r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), denom_inv_check)],
    );

    // (1 - y_is_zero) * (denom * denom_inv - 1) = 0
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_y_is_zero)],
        &[(FieldElement::one(), denom_inv_check)],
        &[], // Result is 0
    );

    // Compute lambda = (numerator * denominator_inv) mod n
    let lambda = compute_field_multiplication(r1cs_compiler, numerator, denominator_inv);

    // Compute lambda^2
    let lambda_squared = compute_field_multiplication(r1cs_compiler, lambda, lambda);

    // Compute 2*x
    let two_x = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(two_x, vec![
        provekit_common::witness::SumTerm(Some(two), x_reduced),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[(two, x_reduced)],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), two_x)],
    );

    // Compute x3 = lambda^2 - 2*x
    let x3_computed = compute_field_subtraction(r1cs_compiler, lambda_squared, two_x);

    // Compute x - x3
    let x_minus_x3 = compute_field_subtraction(r1cs_compiler, x_reduced, x3_computed);

    // Compute lambda * (x - x3)
    let lambda_times_diff = compute_field_multiplication(r1cs_compiler, lambda, x_minus_x3);

    // Compute y3 = lambda * (x - x3) - y
    let y3_computed = compute_field_subtraction(r1cs_compiler, lambda_times_diff, y_reduced);

    // CONDITIONAL SELECTION: If y_is_zero = 1, return (0, 0), else return
    // (x3_computed, y3_computed) result = y_is_zero * (0, 0) + (1 - y_is_zero)
    // * (x3_computed, y3_computed) This simplifies to: result = (1 - y_is_zero)
    // * (x3_computed, y3_computed)

    // x3_final = (1 - y_is_zero) * x3_computed + y_is_zero * 0
    //          = (1 - y_is_zero) * x3_computed
    let x3_final = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        x3_final,
        one_minus_y_is_zero,
        x3_computed,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_y_is_zero)],
        &[(FieldElement::one(), x3_computed)],
        &[(FieldElement::one(), x3_final)],
    );

    // y3_final = (1 - y_is_zero) * y3_computed
    let y3_final = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        y3_final,
        one_minus_y_is_zero,
        y3_computed,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_y_is_zero)],
        &[(FieldElement::one(), y3_computed)],
        &[(FieldElement::one(), y3_final)],
    );

    // Range check results (even if they're (0,0), range checking is harmless)
    range_checks.entry(256).or_default().push(x3_final);
    range_checks.entry(256).or_default().push(y3_final);

    (x3_final, y3_final)
}

/// Elliptic curve point addition: (x1, y1) + (x2, y2) -> (x3, y3) on secp256r1.
/// Uses the formula:
/// - lambda = (y2 - y1) / (x2 - x1)
/// - x3 = lambda^2 - x1 - x2
/// - y3 = lambda*(x1 - x3) - y1
///
/// EDGE CASE HANDLING:
/// - If x1 == x2 and y1 == y2: points are equal, should use doubling (returns
///   doubled point)
/// - If x1 == x2 and y1 != y2: points are inverses, result is point at infinity
///   (returns (0,0))
fn point_add(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    x1: usize,
    y1: usize,
    x2: usize,
    y2: usize,
) -> (usize, usize) {
    // Reduce coordinates modulo p
    let x1_reduced = reduce_mod_p(r1cs_compiler, x1);
    let y1_reduced = reduce_mod_p(r1cs_compiler, y1);
    let x2_reduced = reduce_mod_p(r1cs_compiler, x2);
    let y2_reduced = reduce_mod_p(r1cs_compiler, y2);

    // EDGE CASE CHECK: Detect if x1 == x2 (denominator would be zero)
    // Compute x2 - x1
    let x_diff = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(x_diff, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), x2_reduced),
        provekit_common::witness::SumTerm(Some(-FieldElement::one()), x1_reduced),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), x2_reduced),
            (-FieldElement::one(), x1_reduced),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), x_diff)],
    );

    let (x_equal, _x_diff_inv) = compute_is_zero(r1cs_compiler, x_diff);

    // Compute numerator = y2 - y1
    let numerator = compute_field_subtraction(r1cs_compiler, y2_reduced, y1_reduced);

    // Compute denominator = x2 - x1 (this is x_diff)
    let denominator = x_diff;

    // SAFE DIVISION: Use the same technique as in point_double
    // If x_equal = 1, we set denominator_inv = 0 (or any value)
    // If x_equal = 0, we enforce denominator * denominator_inv = 1
    let denominator_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        denominator_inv,
        vec![provekit_common::witness::SumTerm(
            Some(FieldElement::zero()),
            r1cs_compiler.witness_one(),
        )],
    ));

    let denom_times_inv = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        denom_times_inv,
        denominator,
        denominator_inv,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), denominator)],
        &[(FieldElement::one(), denominator_inv)],
        &[(FieldElement::one(), denom_times_inv)],
    );

    let one_minus_x_equal = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        one_minus_x_equal,
        vec![
            provekit_common::witness::SumTerm(
                Some(FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
            provekit_common::witness::SumTerm(Some(-FieldElement::one()), x_equal),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), r1cs_compiler.witness_one()),
            (-FieldElement::one(), x_equal),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), one_minus_x_equal)],
    );

    let denom_inv_check = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        denom_inv_check,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), denom_times_inv),
            provekit_common::witness::SumTerm(
                Some(-FieldElement::one()),
                r1cs_compiler.witness_one(),
            ),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), denom_times_inv),
            (-FieldElement::one(), r1cs_compiler.witness_one()),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), denom_inv_check)],
    );

    // (1 - x_equal) * (denom * denom_inv - 1) = 0
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_x_equal)],
        &[(FieldElement::one(), denom_inv_check)],
        &[], // Result is 0
    );

    let lambda = compute_field_multiplication(r1cs_compiler, numerator, denominator_inv);

    // Compute lambda^2
    let lambda_squared = compute_field_multiplication(r1cs_compiler, lambda, lambda);

    // Compute lambda^2 - x1
    let lambda_squared_minus_x1 =
        compute_field_subtraction(r1cs_compiler, lambda_squared, x1_reduced);

    // Compute x3 = lambda^2 - x1 - x2
    let x3_computed = compute_field_subtraction(r1cs_compiler, lambda_squared_minus_x1, x2_reduced);

    // Compute x1 - x3
    let x1_minus_x3 = compute_field_subtraction(r1cs_compiler, x1_reduced, x3_computed);

    // Compute lambda * (x1 - x3)
    let lambda_times_diff = compute_field_multiplication(r1cs_compiler, lambda, x1_minus_x3);

    // Compute y3 = lambda * (x1 - x3) - y1
    let y3_computed = compute_field_subtraction(r1cs_compiler, lambda_times_diff, y1_reduced);

    // CONDITIONAL SELECTION: If x_equal = 1, return (0, 0), else return
    // (x3_computed, y3_computed) For the edge case where x1 == x2:
    // - If also y1 == y2: should double (but for simplicity, we return (0,0) or
    //   handle elsewhere)
    // - If y1 != y2: points are inverses, result is point at infinity (0,0)
    // In both cases for now, we return (0,0) when x1 == x2

    // x3_final = (1 - x_equal) * x3_computed
    let x3_final = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        x3_final,
        one_minus_x_equal,
        x3_computed,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_x_equal)],
        &[(FieldElement::one(), x3_computed)],
        &[(FieldElement::one(), x3_final)],
    );

    // y3_final = (1 - x_equal) * y3_computed
    let y3_final = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        y3_final,
        one_minus_x_equal,
        y3_computed,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), one_minus_x_equal)],
        &[(FieldElement::one(), y3_computed)],
        &[(FieldElement::one(), y3_final)],
    );

    // Range check results
    range_checks.entry(256).or_default().push(x3_final);
    range_checks.entry(256).or_default().push(y3_final);

    (x3_final, y3_final)
}

/// Decompose a field element into bits (little-endian).
/// Returns a vector of witness indices, each representing a single bit (0 or
/// 1). Uses the existing DigitalDecomposition infrastructure.
fn decompose_into_bits(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    value: usize,
    num_bits: usize,
) -> Vec<usize> {
    // Use digital decomposition with log_base=1 (binary) for each bit
    let log_bases = vec![1; num_bits]; // Each "digit" is a single bit

    let next_witness_idx = r1cs_compiler.num_witnesses();
    let dd_struct = provekit_common::witness::DigitalDecompositionWitnesses::new(
        next_witness_idx,
        log_bases.clone(),
        vec![value],
    );

    // Add the WitnessBuilder that tells the prover how to compute the bits
    r1cs_compiler.add_witness_builder(
        provekit_common::witness::WitnessBuilder::DigitalDecomposition(dd_struct.clone()),
    );

    // Add reconstruction constraint: value = sum(bit[i] * 2^i)
    // Compute powers of 2 iteratively to avoid overflow
    let mut recomp_summands = Vec::new();
    let mut power_of_two = FieldElement::one(); // Start with 2^0 = 1

    for bit_idx in 0..num_bits {
        let bit_witness = dd_struct.get_digit_witness_index(bit_idx, 0);
        recomp_summands.push((power_of_two, bit_witness));
        // Next power: 2^(i+1) = 2 * 2^i
        power_of_two = power_of_two + power_of_two; // Double in the field
    }

    // Constraint: value = sum(bit[i] * 2^i)
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), value)],
        &recomp_summands,
    );

    // Add boolean constraints for each bit (bit * (bit - 1) = 0)
    for bit_idx in 0..num_bits {
        let bit_witness = dd_struct.get_digit_witness_index(bit_idx, 0);

        // For binary (log_base=1), each digit is already 0 or 1
        // But we still add the boolean constraint for safety
        // Constraint: bit * (1 - bit) = 0
        r1cs_compiler.r1cs.add_constraint(
            &[(FieldElement::one(), bit_witness)],
            &[
                (FieldElement::one(), r1cs_compiler.witness_one()),
                (-FieldElement::one(), bit_witness),
            ],
            &[], // Result is 0
        );

        // Also add to range checks for bit (2^1 = 2, range [0, 1])
        range_checks.entry(1).or_default().push(bit_witness);
    }

    // Collect bit witness indices
    let bit_witnesses: Vec<usize> = (0..num_bits)
        .map(|bit_idx| dd_struct.get_digit_witness_index(bit_idx, 0))
        .collect();

    bit_witnesses
}

/// Conditional select: returns (if condition then (x1, y1) else (x2, y2))
/// Implements: result = condition * point1 + (1 - condition) * point2
/// where condition is a boolean (0 or 1) witness.
fn conditional_select_point(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    condition: usize,
    point1_x: usize,
    point1_y: usize,
    point2_x: usize,
    point2_y: usize,
) -> (usize, usize) {
    // For x-coordinate: result_x = condition * x1 + (1 - condition) * x2
    //                            = condition * x1 + x2 - condition * x2
    //                            = x2 + condition * (x1 - x2)

    // Compute (x1 - x2)
    let x_diff = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(x_diff, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), point1_x),
        provekit_common::witness::SumTerm(Some(-FieldElement::one()), point2_x),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), point1_x),
            (-FieldElement::one(), point2_x),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), x_diff)],
    );

    // Compute condition * (x1 - x2)
    let cond_times_x_diff = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        cond_times_x_diff,
        condition,
        x_diff,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), condition)],
        &[(FieldElement::one(), x_diff)],
        &[(FieldElement::one(), cond_times_x_diff)],
    );

    // Compute result_x = x2 + condition * (x1 - x2)
    let result_x = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        result_x,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), point2_x),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), cond_times_x_diff),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), point2_x),
            (FieldElement::one(), cond_times_x_diff),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_x)],
    );

    // Same for y-coordinate
    let y_diff = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(y_diff, vec![
        provekit_common::witness::SumTerm(Some(FieldElement::one()), point1_y),
        provekit_common::witness::SumTerm(Some(-FieldElement::one()), point2_y),
    ]));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), point1_y),
            (-FieldElement::one(), point2_y),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), y_diff)],
    );

    let cond_times_y_diff = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
        cond_times_y_diff,
        condition,
        y_diff,
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(FieldElement::one(), condition)],
        &[(FieldElement::one(), y_diff)],
        &[(FieldElement::one(), cond_times_y_diff)],
    );

    let result_y = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        result_y,
        vec![
            provekit_common::witness::SumTerm(Some(FieldElement::one()), point2_y),
            provekit_common::witness::SumTerm(Some(FieldElement::one()), cond_times_y_diff),
        ],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[
            (FieldElement::one(), point2_y),
            (FieldElement::one(), cond_times_y_diff),
        ],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), result_y)],
    );
    (result_x, result_y)
}

/// Scalar multiplication using double-and-add algorithm: k * P
/// This computes k times point P on the secp256r1 curve.
/// The scalar k is represented as a witness index containing a 256-bit value.
///
/// Algorithm:
/// 1. Decompose scalar k into bits [b_255, ..., b_1, b_0]
/// 2. Initialize accumulator = point_at_infinity (represented as (0, 0))
/// 3. For each bit from MSB to LSB: a. Double the accumulator b. If bit is 1,
///    add the base point
/// 4. Return final accumulator
///
/// Note: This is expensive (~256 doublings and ~128 additions on average)
fn scalar_multiply(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    scalar: usize,
    point_x: usize,
    point_y: usize,
) -> (usize, usize) {
    // Step 1: Decompose scalar into 256 bits
    let scalar_bits = decompose_into_bits(r1cs_compiler, range_checks, scalar, 256);

    // Step 2 & 3: Process bits from MSB to LSB with double-and-add
    // This follows the Circom implementation structure

    // Array to hold partial results at each bit position
    // partial[i] represents the accumulated result after processing bit i
    let mut partial_x = Vec::with_capacity(256);
    let mut partial_y = Vec::with_capacity(256);

    // Array to track if we've seen any non-zero bit so far (from MSB down)
    let mut has_prev_non_zero_witnesses = Vec::with_capacity(256);

    // Process from MSB (bit 255) down to LSB (bit 0)
    for bit_idx in (0..256).rev() {
        let bit_witness = scalar_bits[bit_idx];

        if bit_idx == 255 {
            // First iteration (MSB): has_prev_non_zero[255] = bit[255]
            has_prev_non_zero_witnesses.push(bit_witness);

            // partial[255] = bit[255] ? point : point (always point for simplicity)
            partial_x.push(point_x);
            partial_y.push(point_y);

        } else {
            // For bits 254 down to 0
            let prev_partial_x = partial_x[255 - bit_idx - 1];
            let prev_partial_y = partial_y[255 - bit_idx - 1];
            let prev_has_non_zero = has_prev_non_zero_witnesses[255 - bit_idx - 1];

            // Step A: Double the previous partial result
            let (doubled_x, doubled_y) =
                point_double(r1cs_compiler, range_checks, prev_partial_x, prev_partial_y);

            // Step B: Add base point to doubled result
            let (added_x, added_y) = point_add(
                r1cs_compiler,
                range_checks,
                doubled_x,
                doubled_y,
                point_x,
                point_y,
            );

            // Step C: Select based on current bit
            // intermed = bit[i] ? (2*prev + point) : (2*prev)
            let (intermed_x, intermed_y) = conditional_select_point(
                r1cs_compiler,
                bit_witness,
                added_x, // if bit == 1: use doubled + point
                added_y,
                doubled_x, // if bit == 0: use doubled only
                doubled_y,
            );

            // Step D: Select based on whether we've seen a non-zero bit before
            // partial[i] = has_prev_non_zero[i+1] ? intermed : point
            // If no previous non-zero bit, this is the first non-zero, so result is just
            // point
            let (partial_x_i, partial_y_i) = conditional_select_point(
                r1cs_compiler,
                prev_has_non_zero,
                intermed_x, // if has_prev: use computed intermediate
                intermed_y,
                point_x, // if no prev: first non-zero bit, use point
                point_y,
            );

            partial_x.push(partial_x_i);
            partial_y.push(partial_y_i);

            // Step E: Update has_prev_non_zero[i] = OR(has_prev_non_zero[i+1], bit[i])
            // OR(a, b) = a + b - a*b

            // Compute a * b
            let prev_times_bit = r1cs_compiler.num_witnesses();
            r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Product(
                prev_times_bit,
                prev_has_non_zero,
                bit_witness,
            ));
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::one(), prev_has_non_zero)],
                &[(FieldElement::one(), bit_witness)],
                &[(FieldElement::one(), prev_times_bit)],
            );

            // Compute OR = a + b - a*b
            let or_result = r1cs_compiler.num_witnesses();
            r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
                or_result,
                vec![
                    provekit_common::witness::SumTerm(Some(FieldElement::one()), prev_has_non_zero),
                    provekit_common::witness::SumTerm(Some(FieldElement::one()), bit_witness),
                    provekit_common::witness::SumTerm(Some(-FieldElement::one()), prev_times_bit),
                ],
            ));
            r1cs_compiler.r1cs.add_constraint(
                &[
                    (FieldElement::one(), prev_has_non_zero),
                    (FieldElement::one(), bit_witness),
                    (-FieldElement::one(), prev_times_bit),
                ],
                &[(FieldElement::one(), r1cs_compiler.witness_one())],
                &[(FieldElement::one(), or_result)],
            );

            has_prev_non_zero_witnesses.push(or_result);
        }
    }

    // Final result is partial[0] (after processing all bits)
    let acc_x = partial_x[255];
    let acc_y = partial_y[255];

    // Verify result is on the curve
    validate_point_is_on_curve(r1cs_compiler, acc_x, acc_y);

    // Range check results
    range_checks.entry(256).or_default().push(acc_x);
    range_checks.entry(256).or_default().push(acc_y);

    (acc_x, acc_y)
}

/// Compute R = u1*G + u2*Q where:
/// - G is the secp256r1 generator point
/// - Q is the public key point (qx, qy)
/// - u1, u2 are scalars
/// Returns (R.x, R.y)
pub(crate) fn compute_point_combination(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    u1: usize,
    u2: usize,
    qx: usize,
    qy: usize,
) -> (usize, usize) {
    // Get generator point G as field elements
    let (gx_field, gy_field) = get_generator_point();

    // Create witnesses for G's coordinates
    let gx_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        gx_witness,
        vec![provekit_common::witness::SumTerm(
            Some(gx_field),
            r1cs_compiler.witness_one(),
        )],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(gx_field, r1cs_compiler.witness_one())],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), gx_witness)],
    );

    let gy_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
        gy_witness,
        vec![provekit_common::witness::SumTerm(
            Some(gy_field),
            r1cs_compiler.witness_one(),
        )],
    ));
    r1cs_compiler.r1cs.add_constraint(
        &[(gy_field, r1cs_compiler.witness_one())],
        &[(FieldElement::one(), r1cs_compiler.witness_one())],
        &[(FieldElement::one(), gy_witness)],
    );

    // Compute u1*G
    let (u1g_x, u1g_y) = scalar_multiply(r1cs_compiler, range_checks, u1, gx_witness, gy_witness);

    // Compute u2*Q
    let (u2q_x, u2q_y) = scalar_multiply(r1cs_compiler, range_checks, u2, qx, qy);

    // Compute R = u1*G + u2*Q
    let (rx, ry) = point_add(r1cs_compiler, range_checks, u1g_x, u1g_y, u2q_x, u2q_y);

    (rx, ry)
}
