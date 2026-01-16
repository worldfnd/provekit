use {
    crate::{
        ecdsa_secp256r1::ops::{
            check_s_times_w_equals_one_mod_n, check_signature_is_canonical,
            compute_modular_inverse, compute_modular_multiplication, compute_point_combination,
            range_check_inputs, reconstruct_field_element_from_bytes_be,
            validate_point_is_on_curve, verify_modular_equality,
        },
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_std::One,
    provekit_common::{witness::ConstantOrR1CSWitness, FieldElement},
    std::collections::BTreeMap,
    tracing::info,
};

mod constants;
mod ops;

pub(crate) fn add_ecdsa_secp256r1_verification(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    range_checks: &mut BTreeMap<u32, Vec<usize>>,
    ecdsa_ops: Vec<(
        Vec<ConstantOrR1CSWitness>, // public_key_x (32 bytes)
        Vec<ConstantOrR1CSWitness>, // public_key_y (32 bytes)
        Vec<ConstantOrR1CSWitness>, // signature (64 bytes)
        Vec<ConstantOrR1CSWitness>, // hashed_message (32 bytes)
        usize,                      // output_witness (boolean result)
    )>,
) {
    let num_ops = ecdsa_ops.len();
    info!(
        "Starting ECDSA secp256r1 verification for {} operation(s)",
        num_ops
    );

    for (op_idx, (public_key_x, public_key_y, signature, hashed_message, output_witness)) in
        ecdsa_ops.into_iter().enumerate()
    {
        info!("Processing ECDSA operation {} of {}", op_idx + 1, num_ops);
        if public_key_x.len() != 32 {
            panic!("ECDSA secp256r1: public_key_x must be exactly 32 bytes");
        }
        if public_key_y.len() != 32 {
            panic!("ECDSA secp256r1: public_key_y must be exactly 32 bytes");
        }
        if signature.len() != 64 {
            panic!("ECDSA secp256r1: signature must be exactly 64 bytes");
        }
        if hashed_message.len() != 32 {
            panic!("ECDSA secp256r1: hashed_message must be exactly 32 bytes");
        }
        range_check_inputs(
            range_checks,
            &public_key_x,
            &public_key_y,
            &signature,
            &hashed_message,
        );

        // Parse signature into r and s components as witness indices
        let r_witnesses = signature[0..32]
            .to_vec()
            .into_iter()
            .map(|w| match w {
                ConstantOrR1CSWitness::Witness(idx) => idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Constants are not supported for signature bytes");
                }
            })
            .collect::<Vec<_>>();
        let s_witnesses = signature[32..64]
            .to_vec()
            .into_iter()
            .map(|w| match w {
                ConstantOrR1CSWitness::Witness(idx) => idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Constants are not supported for signature bytes");
                }
            })
            .collect::<Vec<_>>();

        // s <= n/2
        check_signature_is_canonical(r1cs_compiler, range_checks, &s_witnesses);

        // Reconstruct s from its 32 bytes (big-endian)
        let s_reconstructed = reconstruct_field_element_from_bytes_be(r1cs_compiler, &s_witnesses);
        // Range check s < n (256 bits for secp256r1 curve order)
        range_checks.entry(256).or_default().push(s_reconstructed);

        // Compute w = 1/s mod n (where n is the secp256r1 curve order)
        // We need to ensure: s * w ≡ 1 (mod n), i.e., s * w = 1 + k * n for some
        // integer k
        let w = compute_modular_inverse(r1cs_compiler, range_checks, s_reconstructed);

        // Verify that s * w ≡ 1 (mod n)
        check_s_times_w_equals_one_mod_n(r1cs_compiler, s_reconstructed, w);

        // Reconstruct r from its 32 bytes (big-endian)
        let r_reconstructed = reconstruct_field_element_from_bytes_be(r1cs_compiler, &r_witnesses);
        // Range check r < n (256 bits for secp256r1 curve order)
        range_checks.entry(256).or_default().push(r_reconstructed);

        // Reconstruct e (hashed_message) from its bytes
        let e_witnesses = hashed_message
            .iter()
            .map(|w| match w {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Constants are not supported for hashed_message bytes");
                }
            })
            .collect::<Vec<_>>();

        let e_reconstructed = reconstruct_field_element_from_bytes_be(r1cs_compiler, &e_witnesses);
        // Range check e < n (256 bits for secp256r1 curve order)
        range_checks.entry(256).or_default().push(e_reconstructed);

        // Compute u1 = e * w mod n and u2 = r * w mod n
        // These will be used for the elliptic curve point multiplication in ECDSA
        // verification
        let u1 = compute_modular_multiplication(r1cs_compiler, e_reconstructed, w);
        let u2 = compute_modular_multiplication(r1cs_compiler, r_reconstructed, w);

        // Validate public key is on secp256r1 curve
        // Reconstruct x and y from their byte arrays
        let public_key_x_witnesses: Vec<usize> = public_key_x
            .iter()
            .map(|w| match w {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Constants are not supported for public_key_x bytes");
                }
            })
            .collect();
        let public_key_y_witnesses: Vec<usize> = public_key_y
            .iter()
            .map(|w| match w {
                ConstantOrR1CSWitness::Witness(idx) => *idx,
                ConstantOrR1CSWitness::Constant(_) => {
                    panic!("Constants are not supported for public_key_y bytes");
                }
            })
            .collect();

        let x_reconstructed =
            reconstruct_field_element_from_bytes_be(r1cs_compiler, &public_key_x_witnesses);
        let y_reconstructed =
            reconstruct_field_element_from_bytes_be(r1cs_compiler, &public_key_y_witnesses);

        // Range check x and y < p (256 bits for secp256r1 field modulus)
        // Note: These will be reduced mod p in validate_public_key_is_on_curve,
        // but we add range checks here for additional security
        range_checks.entry(256).or_default().push(x_reconstructed);
        range_checks.entry(256).or_default().push(y_reconstructed);

        // Validate public key is on secp256r1 curve
        validate_point_is_on_curve(r1cs_compiler, x_reconstructed, y_reconstructed);

        // 6. Compute the point R = u1*G + u2*Q
        // This requires:
        //   - Scalar multiplication: u1*G (where G is the generator)
        //   - Scalar multiplication: u2*Q (where Q is the public key)
        //   - Point addition: add the two resulting points
        let (r_x, _) = compute_point_combination(
            r1cs_compiler,
            range_checks,
            u1,
            u2,
            x_reconstructed,
            y_reconstructed,
        );

        // 7. Verify that r (from signature) equals R.x mod n
        // This completes the ECDSA verification
        // This means: r_reconstructed - r_x = k * n for some integer k
        verify_modular_equality(r1cs_compiler, r_reconstructed, r_x);

        // Constrain output witness to be boolean (0 or 1)
        let output_minus_one = r1cs_compiler.num_witnesses();
        r1cs_compiler.add_witness_builder(provekit_common::witness::WitnessBuilder::Sum(
            output_minus_one,
            vec![
                provekit_common::witness::SumTerm(Some(FieldElement::one()), output_witness),
                provekit_common::witness::SumTerm(
                    Some(-FieldElement::one()),
                    r1cs_compiler.witness_one(),
                ),
            ],
        ));
        // Constraint: output * (output - 1) = 0
        r1cs_compiler.r1cs.add_constraint(
            &[(FieldElement::one(), output_witness)],
            &[(FieldElement::one(), output_minus_one)],
            &[], // Result is 0
        );
    }
}
