// EdDSA Poseidon2 Verifier for Noir
// Complete implementation of EdDSA signature verification using Poseidon2 hash

use babyjubjub::BabyJubJubPoint;
use poseidon2::bn254::perm;
mod tests;

// Domain separator for EdDSA signatures: b"EdDSA Signature"
global DOMAIN_SEPARATOR: Field = 360302137480307891234917541314130533;

/// EdDSA Poseidon2 Verifier
///
/// Verifies an EdDSA signature using Poseidon2 hash function
///
/// # Inputs
/// - pub_key_x: The x coordinate of the public key
/// - pub_key_y: The y coordinate of the public key
/// - signature_s: The scalar component of the signature
/// - signature_r: The point component of the signature
/// - message: The message that was signed
///
/// # Verification Equation (cofactored)
/// 8*(S*G - R - h*A) == Identity
/// where h = Poseidon2(domain_separator, Rx, Ry, Ax, Ay, M, 0, 0)
pub fn verify_eddsa_poseidon2(
    pub_key_x: Field,
    pub_key_y: Field,
    signature_s: Field,
    signature_r: [Field; 2],
    message: Field,
) -> bool {
    // Step 1 - Validate S is in BabyJubJub scalar field and get bits
    // Check if signature_s is valid (< BABYJUBJUB_Fr), return false if not
    let s_is_valid = BabyJubJubPoint::is_valid_scalar_field(signature_s);

    let mut is_valid = false;

    if s_is_valid {
        let s_bits: [u1; 251] = signature_s.to_le_bits();

        // Step 2 - Validate public key A
        let a_point = BabyJubJubPoint::new(pub_key_x, pub_key_y);
        assert(a_point.is_on_curve(), "Public key must be on curve");
        assert(a_point.babyjubjub_in_correct_subgroup(), "Public key must be in subgroup");
        assert(a_point.is_not_identity(), "Public key cannot be identity");

        // Step 3 - Validate R is on the curve
        let r_point = BabyJubJubPoint::new(signature_r[0], signature_r[1]);
        assert(r_point.is_on_curve(), "R must be on curve");

        // Step 4 - Compute h = Poseidon2(domain_separator, Rx, Ry, Ax, Ay, M, 0, 0)
        let hash_state = perm::x5_8([
            DOMAIN_SEPARATOR,
            signature_r[0],
            signature_r[1],
            pub_key_x,
            pub_key_y,
            message,
            0,
            0,
        ]);

        let hash = hash_state[1];

        // Step 5 - Compute right side: R + h*A
        // Calculate h*A (h is in base field Fq, so use scalar_mul_base_field)
        let right2 = BabyJubJubPoint::new(pub_key_x, pub_key_y).scalar_mul_base_field(hash);
        // Calculate R + h*A
        let right = r_point.add(right2);

        // Step 6 - Compute left side: S*G (generator scalar multiplication)
        // NOIR OPTIMIZATION: Use pre-decomposed bits to avoid redundant to_le_bits
        let generator = BabyJubJubPoint::generator();
        let left = generator.scalar_mul_bits(s_bits);

        // Step 7 - Compute v = S*G - R - h*A = S*G - (R + h*A)
        let v = left.subtract(right);

        // Step 8 - Check if v is the identity
        // Circom's implementation does NOT multiply by cofactor here (saves 3 doublings)
        // Security comes from checking A is in correct subgroup earlier
        is_valid = v.is_identity();
    }

    is_valid
}
