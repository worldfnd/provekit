use super::constants::DS_DLOG;
use babyjubjub::BabyJubJubPoint;
use poseidon2::bn254::perm;

// Verify a Chaim-Pedersen dlog equality proof that shows that A=x*G and C=x*B share the same discrete log x, given A,B,C and proof e,s.
// Point A is a public input in our use case (the OPRF public key and therefore we expect it to be checked to be in the prime order subgroup outside of this circuit)
pub fn verify_dlog_equality(
    e: Field,
    s: Field,
    a_point: BabyJubJubPoint,
    b_point: BabyJubJubPoint,
    c_point: BabyJubJubPoint,
) {
    BabyJubJubPoint::validate_babyjubjub_field(s);

    assert(
        a_point.is_on_curve()
            & b_point.is_on_curve()
            & c_point.is_on_curve()
            & a_point.is_not_identity()
            & b_point.is_not_identity()
            & c_point.is_not_identity(),
        "All points must be on curve and not identity",
    );
    assert(b_point.check_sub_group(), "Point b must be in subgroup");
    assert(c_point.check_sub_group(), "Point c must be in subgroup");

    // Compute r1 = G*s - a*e and r2 = b*s - c*e
    let generator = BabyJubJubPoint::generator();
    let gs = BabyJubJubPoint::generator_scalar_mul(s);
    let ae = a_point.scalar_mul_base_field(e);
    let r1 = gs.subtract(ae);

    let bs = b_point.scalar_mul(s);
    let ce = c_point.scalar_mul_base_field(e);
    let r2 = bs.subtract(ce);

    // Batch check that r1 and r2 are not identity
    assert(r1.is_not_identity() & r2.is_not_identity(), "Computed points cannot be identity");

    // Recompute the challenge hash
    // Hash input: [DS_DLOG, a.x, a.y, b.x, b.y, c.x, c.y, G.x, G.y, r1.x, r1.y, r2.x, r2.y, 0, 0, 0]
    let hash_input = [
        DS_DLOG,
        a_point.x,
        a_point.y,
        b_point.x,
        b_point.y,
        c_point.x,
        c_point.y,
        generator.x,
        generator.y,
        r1.x,
        r1.y,
        r2.x,
        r2.y,
        0,
        0,
        0,
    ];

    let hash_state = perm::x5_16(hash_input);
    let challenge = hash_state[1];

    // Verify that the recomputed challenge matches e
    assert(challenge == e, "Challenge verification failed");
}
