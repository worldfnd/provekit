use crate::bigcurve::BigCurve;
use crate::curve_jac::types::CurveJ;

use bignum::BigNum;

pub(crate) unconstrained fn compute_offset_generators<Fq, let NScalarSlices: u32, Curve>(
    cofactor: Field,
) -> ([Fq; 2], [Fq; 2])
where
    Fq: BigNum,
    Curve: BigCurve<Fq>,
{
    let seed: [u8; 25] = "bigcurve offset generator".as_bytes();

    // we only need well-defined parameters for a and b, for hash_to_curve to work
    // (no offset generators needed)
    let g: Curve = Curve::hash_to_curve(seed);

    let g_init = CurveJ::<Fq, Curve>::from(g);
    let mut gen = g_init;

    let cofactor_bits: [u1; 128] = cofactor.to_be_bits();
    let mut it: u32 = 0;
    for i in 0..128 {
        if (cofactor_bits[i] == 1) {
            it = i + 1;
            break;
        }
    }

    for i in it..128 {
        gen = gen.dbl().0;
        if (cofactor_bits[i] == 1) {
            gen = gen.incomplete_add(g_init).0;
        }
    }

    let mut offset_generator_initial: [Fq; 2] = [Fq::new(); 2];
    let mut offset_generator_final: [Fq; 2] = [Fq::new(); 2];

    {
        let mut genz = gen.z;
        genz = genz.__invmod();
        let zz = genz.__mul(genz);
        let zzz = zz.__mul(genz);

        offset_generator_initial[0] = gen.x.__mul(zz);
        offset_generator_initial[1] = gen.y.__mul(zzz);
    }

    let end = (NScalarSlices - 1) * 4;
    for _ in 0..end {
        gen = gen.dbl().0;
    }
    {
        let mut genz = gen.z;
        genz = genz.__invmod();
        let zz = genz.__mul(genz);
        let zzz = zz.__mul(genz);

        offset_generator_final[0] = gen.x.__mul(zz);
        offset_generator_final[1] = gen.y.__mul(zzz);
    }

    (offset_generator_initial, offset_generator_final)
}

pub(crate) unconstrained fn verify_offset_generators<Fq, let NScalarSlices: u32, Curve>(
    cofactor: Field,
)
where
    Fq: BigNum,
    Curve: BigCurve<Fq>,
{
    let (offset_generator_initial, offset_generator_final) =
        compute_offset_generators::<Fq, NScalarSlices, Curve>(cofactor);

    let expected_initial = Curve::offset_generator();
    assert_eq(
        offset_generator_initial[0],
        expected_initial.x(),
        "Initial offset generator x mismatch",
    );
    assert_eq(
        offset_generator_initial[1],
        expected_initial.y(),
        "Initial offset generator y mismatch",
    );

    let expected_final = Curve::offset_generator_final();
    assert_eq(offset_generator_final[0], expected_final.x(), "Final offset generator x mismatch");
    assert_eq(offset_generator_final[1], expected_final.y(), "Final offset generator y mismatch");
}
