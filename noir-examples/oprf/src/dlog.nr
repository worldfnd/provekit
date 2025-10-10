use super::{constants::DS_DLOG, types::PublicKey};
use babyjubjub::BabyJubJubPoint;
use poseidon2::bn254::perm;

pub fn verify_dlog_equality(e: Field, s: Field, a: PublicKey, b: PublicKey, c: PublicKey) {
    // Validate that s is in the scalar field Fr (do this first as it's cheaper)
    BabyJubJubPoint::validate_babyjubjub_field(s);

    // Create points and validate them
    let a_point = BabyJubJubPoint::new(a.x, a.y);
    let b_point = BabyJubJubPoint::new(b.x, b.y);
    let c_point = BabyJubJubPoint::new(c.x, c.y);

    // Batch validation - check all curve memberships
    assert(a_point.is_on_curve(), "Point a must be on curve");
    assert(b_point.is_on_curve(), "Point b must be on curve");
    assert(c_point.is_on_curve(), "Point c must be on curve");

    // Check that points are not identity (combined assertion message)
    assert(
        a_point.is_not_identity() & b_point.is_not_identity() & c_point.is_not_identity(),
        "Points cannot be identity",
    );

    // Compute r1 = G*s - a*e and r2 = b*s - c*e
    let generator = BabyJubJubPoint::generator();
    let gs = generator.scalar_mul(s);
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
        a.x,
        a.y,
        b.x,
        b.y,
        c.x,
        c.y,
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
