// test the lib
use crate::BabyJubJubPoint;

#[test]
fn test_point_add() {
    let point_1 = BabyJubJubPoint::new(0, 1);
    let point_2 = BabyJubJubPoint::new(0, 1);
    let result = point_1.add(point_2);

    assert_eq(result.x, 0);
    assert_eq(result.y, 1);
}

#[test]
fn test_add_same_point() {
    let point = BabyJubJubPoint::new(
        17777552123799933955779906779655732241715742912184938656739573121738514868268,
        2626589144620713026669568689430873010625803728049924121243784502389097019475,
    );
    let result = point.add(point);
    assert_eq(
        result.x,
        6890855772600357754907169075114257697580319025794532037257385534741338397365,
    );
    assert_eq(
        result.y,
        4338620300185947561074059802482547481416142213883829469920100239455078257889,
    );
}

#[test]
fn test_add_diff_point() {
    let point1 = BabyJubJubPoint::new(
        17777552123799933955779906779655732241715742912184938656739573121738514868268,
        2626589144620713026669568689430873010625803728049924121243784502389097019475,
    );

    let point2 = BabyJubJubPoint::new(
        16540640123574156134436876038791482806971768689494387082833631921987005038935,
        20819045374670962167435360035096875258406992893633759881276124905556507972311,
    );
    let result = point1.add(point2);
    assert_eq(
        result.x,
        7916061937171219682591368294088513039687205273691143098332585753343424131937,
    );
    assert_eq(
        result.y,
        14035240266687799601661095864649209771790948434046947201833777492504781204499,
    );
}

// (0,1) is a valid point
#[test]
fn test_valid_point() {
    let point = BabyJubJubPoint::new(0, 1);
    assert(point.is_on_curve());
}

// (1,0) is an invalid point
#[test]
fn test_invalid_point() {
    let point = BabyJubJubPoint::new(1, 0);
    assert(!point.is_on_curve());
}

#[test]
fn test_scalar_mul_simple() {
    // Test with generator and small scalar first
    let generator = BabyJubJubPoint::generator();

    // 2 * G
    let result_2 = generator.scalar_mul(2);
    let expected_2 = generator.double();

    assert_eq(result_2.x, expected_2.x);
    assert_eq(result_2.y, expected_2.y);
}

#[test]
fn test_double_preserves_curve() {
    // Test that doubling preserves curve membership
    // First test with a point we know works
    let working_point = BabyJubJubPoint::new(
        17777552123799933955779906779655732241715742912184938656739573121738514868268,
        2626589144620713026669568689430873010625803728049924121243784502389097019475,
    );
    assert(working_point.is_on_curve());
    let doubled_working = working_point.double();
    assert(doubled_working.is_on_curve(), "Working point doubled must be on curve");

    // Now test with generator
    let generator = BabyJubJubPoint::generator();

    assert(generator.is_on_curve(), "Generator must be on curve");

    let doubled_gen = generator.double();

    assert(doubled_gen.is_on_curve(), "Doubled generator must be on curve");
}

#[test]
fn test_add_preserves_curve() {
    // Test that addition preserves curve membership
    let p1 = BabyJubJubPoint::generator();
    let p2 = p1.double();

    assert(p1.is_on_curve());
    assert(p2.is_on_curve());

    let sum = p1.add(p2);
    assert(sum.is_on_curve(), "Sum must be on curve");
}

#[test]
fn test_scalar_mul_preserves_curve() {
    // Test that each step of scalar mul preserves curve
    let point = BabyJubJubPoint::generator();

    for scalar in 1..10 {
        let result = point.scalar_mul(scalar as Field);
        assert(result.is_on_curve());
    }
}

#[test]
fn test_identity_operations() {
    let identity = BabyJubJubPoint::identity();
    let point = BabyJubJubPoint::generator();

    // identity + identity = identity
    let id_add_id = identity.add(identity);
    assert(id_add_id.is_identity());

    // identity + point = point
    let id_add_p = identity.add(point);
    assert_eq(id_add_p.x, point.x);
    assert_eq(id_add_p.y, point.y);

    // point + identity = point
    let p_add_id = point.add(identity);
    assert_eq(p_add_id.x, point.x);
    assert_eq(p_add_id.y, point.y);
}

#[test]
fn test_babyjubjub_large_scalar() {
    let point = BabyJubJubPoint::new(
        15861662102942198476185518224532077347254150735350796263259682790715259346390,
        17622332940847650587004774926435083207962382856110852169511204932927794212320,
    );

    let e = 11492769268207265628561501057351602107011197918712374331772632123505784512375;
    let result = point.scalar_mul_base_field(e);

    let expected_x = 3523602879199010149495623080297900308179859578249410293934816830581400276355;
    let expected_y = 17393853688260930176969934211213897678775780885864751648676555439935658367631;

    assert(result.is_on_curve(), "Result must be on curve");
    assert(result.x.eq(expected_x));
    assert(result.y.eq(expected_y));
}
