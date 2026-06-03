use crate::bigcurve::BigCurve;
use crate::curve_jac::types::AffineTranscript;
use dep::bignum::BigNum;
use dep::bignum::bignum::evaluate_quadratic_expression;

/// Doubles a point using an `AffineTranscript` that contains inverses and output witnesses.
///
/// This method is optimized to minimize the number of calls to `evaluate_quadratic_expression`,
/// which is not necessarily the same as minimizing the number of multiplications.
pub(crate) fn double_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    transcript: AffineTranscript<B>,
) -> P {
    let x1 = point.x();
    let y1 = point.y();
    let lambda = transcript.lambda;
    let x3 = transcript.x3;
    let y3 = transcript.y3;

    // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed B objects!
    x3.validate_in_range();
    y3.validate_in_range();
    lambda.validate_in_range();

    // -lambda * 2y + 3*x*x + a = 0
    // validate the provided value of `lambda` is correct
    // n.b. if CurveParams::a() == 0, its inclusion shouldn't cost extra constraints...I thnk
    evaluate_quadratic_expression(
        [[x1, x1, x1], [y1, y1, B::zero()]],
        [[false, false, false], [false, false, false]],
        [[x1], [lambda]],
        [[false], [true]],
        [P::a()],
        [false],
    );

    // validate the provided value of `x3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x1, x1],
        [true, true, true],
    );

    // validate the provided value of `y3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    P::from_coordinates(x3, y3, false)
}

/// Adds two points together using an `AffineTranscript` that contains inverses and output witnesses.
///
/// Only incomplete formulae are used. With the use of offset generators, an honest prover should never
/// need to handle edge cases. Therefore, completeness is sacrificed for cheap soundness: instead of
/// handling edge cases, the function asserts that they do not exist by validating `x2 != x1`.
///
/// This method minimizes the number of calls to `evaluate_quadratic_expression`, which is not the same
/// as minimizing the number of multiplications. The expensive operation in `BigNum` is the modular
/// reduction. For example, `(a * b + c * d = e mod p)` is not much more expensive than `(a * b = c mod p)`.
pub(crate) fn incomplete_add_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    transcript: AffineTranscript<B>,
) -> P {
    let x1: B = point.x();
    let y1: B = point.y();
    let x2: B = other.x();
    let y2: B = other.y();
    let lambda: B = transcript.lambda;
    let x3: B = transcript.x3;
    let y3: B = transcript.y3;

    // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed B objects!
    x3.validate_in_range();
    y3.validate_in_range();
    lambda.validate_in_range();

    // no incomplete Weierstrass shenanigans here
    x1.assert_is_not_equal(x2);

    // validate the provided value of `lambda` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x2, x1]],
        [[false, true]],
        [y2, y1],
        [true, false],
    );

    // validate the provided value of `x3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x2, x1],
        [true, true, true],
    );

    // validate the provided value of `y3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    P::from_coordinates(x3, y3, false)
}

pub(crate) fn conditional_incomplete_add_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    predicate: bool,
    transcript: AffineTranscript<B>,
) -> P {
    let operand_output = incomplete_add_with_hint::<B, P>(point, other, transcript);
    if predicate {
        operand_output
    } else {
        point
    }
}

pub(crate) fn conditional_incomplete_subtract_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    predicate: bool,
    transcript: AffineTranscript<B>,
) -> P {
    let operand_output = incomplete_subtract_with_hint::<B, P>(point, other, transcript);
    if predicate {
        operand_output
    } else {
        point
    }
}

fn incomplete_subtract_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    transcript: AffineTranscript<B>,
) -> P {
    let x1: B = point.x();
    let y1: B = point.y();
    let x2: B = other.x();
    let y2: B = other.y();
    let lambda: B = transcript.lambda;
    let x3: B = transcript.x3;
    let y3: B = transcript.y3;

    // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed BigNum objects!
    x3.validate_in_range();
    y3.validate_in_range();
    lambda.validate_in_range();

    // no incomplete Weierstrass shenanigans here
    x1.assert_is_not_equal(x2);

    // validate the provided value of `lambda` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x2, x1]],
        [[false, true]],
        [y2, y1],
        [false, false],
    );

    // validate the provided value of `x3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x2, x1],
        [true, true, true],
    );

    // validate the provided value of `y3` is correct
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    P::from_coordinates(x3, y3, false)
}

pub fn add_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    transcript: AffineTranscript<B>,
) -> P {
    let x1: B = point.x();
    let y1: B = point.y();
    let x2: B = other.x();
    let y2: B = other.y();
    let lambda: B = transcript.lambda;
    let x3: B = transcript.x3;
    let y3: B = transcript.y3;

    // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed B objects!
    x3.validate_in_range();
    y3.validate_in_range();
    lambda.validate_in_range();

    // TODO: we can probably optimize this boolean flag jenga mess
    let x_equal_predicate = x2.eq(x1);
    let y_equal_predicate = y2.eq(y1);
    let double_predicate = x_equal_predicate | (point.is_infinity() | other.is_infinity()); // if x1 == x2, evaluate double operation. If y1 = -y2 then we set all input/output parameters to be 0
    let infinity_predicate =
        (x_equal_predicate & !y_equal_predicate) | (point.is_infinity() & other.is_infinity());
    let evaluate_group_operation_predicate: bool =
        !infinity_predicate & !point.is_infinity() & !other.is_infinity();

    // If we are skipping the evaluation of a group operation (x2 == x1, y2 == -y1 OR any input points are at infinity),
    // set input operands to 0!
    let (x1, y1, x2, y2, x3, y3) = if evaluate_group_operation_predicate {
        (x1, y1, x2, y2, x3, y3)
    } else {
        (B::zero(), B::zero(), B::zero(), B::zero(), B::zero(), B::zero())
    };

    // lambda * 2y - 3x * x = 0
    // or
    // lambda * (x2 - x1) - (y2 - y1) = 0
    let product_1_rhs_t0 = if double_predicate { y1 } else { x2 };
    let product_1_rhs_t1 = if double_predicate { y1 } else { x1.neg() };
    let product_2_lhs_t0 = if double_predicate { x1 } else { B::one() };
    let product_2_rhs_t0 = if double_predicate { x1 } else { y2 };
    let product_2_rhs_t1 = if double_predicate { x1 } else { y1.neg() };
    let product_2_rhs_t2 = if double_predicate { x1 } else { B::zero() };

    // validate the provided value of `lambda` is correct
    // if double: lambda * (y1 + y1) + x1 * (-x1 -x1 -x1) - a = 0 => lambda * 2y - 3x*x = 0
    // if add:    lambda * (x2 - x1) + 1 * (-y2 + y1) = 0 => lambda * (x2 - x1) - (y2 - y1) = 0
    let mut a_term = if x_equal_predicate
        & y_equal_predicate
        & !point.is_infinity()
        & !other.is_infinity() {
        P::a()
    } else {
        B::zero()
    };

    evaluate_quadratic_expression(
        [[lambda], [product_2_lhs_t0]],
        [[false], [false]],
        [
            [product_1_rhs_t0, product_1_rhs_t1, B::zero()],
            [product_2_rhs_t0, product_2_rhs_t1, product_2_rhs_t2],
        ],
        [[false, false, false], [true, true, true]],
        [a_term],
        [true],
    );

    // x3 = lambda * lambda - x2 - x1
    // if double, then x2 = x1 so we good
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x2, x1],
        [true, true, true],
    );

    // y3 = lambda * (x1 - x3) - y1
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    let output_is_lhs = other.is_infinity() & !point.is_infinity();
    let output_is_rhs = point.is_infinity() & !other.is_infinity();
    let mut x_out = if evaluate_group_operation_predicate {
        x3
    } else {
        x1
    };
    x_out = if output_is_lhs { point.x() } else { x_out };
    x_out = if output_is_rhs { other.x() } else { x_out };
    x_out = if infinity_predicate { B::zero() } else { x_out };
    let mut y_out = if evaluate_group_operation_predicate {
        y3
    } else {
        y1
    };
    y_out = if output_is_lhs { point.y() } else { y_out };
    y_out = if output_is_rhs { other.y() } else { y_out };
    y_out = if infinity_predicate { B::zero() } else { y_out };

    let mut infinity_out = !evaluate_group_operation_predicate;
    infinity_out = if infinity_predicate {
        true
    } else {
        infinity_out
    };
    infinity_out = if output_is_lhs {
        point.is_infinity()
    } else {
        infinity_out
    };
    infinity_out = if output_is_rhs {
        other.is_infinity()
    } else {
        infinity_out
    };

    let result: P = P::from_coordinates(x_out, y_out, infinity_out);
    result
}

pub fn sub_with_hint<B: BigNum, P: BigCurve<B>>(
    point: P,
    other: P,
    transcript: AffineTranscript<B>,
) -> P {
    let x1: B = point.x();
    let y1: B = point.y();
    let x2: B = other.x();
    let y2: B = other.y();
    let lambda: B = transcript.lambda;
    let x3: B = transcript.x3;
    let y3: B = transcript.y3;

    // we pulled x3, y3, lambda out of the ether - we need to make sure they are well-formed B objects!
    x3.validate_in_range();
    y3.validate_in_range();
    lambda.validate_in_range();

    let x_equal_predicate = x2.eq(x1);
    let y_equal_predicate = y2.eq(y1) == false;
    let double_predicate = x_equal_predicate | (point.is_infinity() | other.is_infinity()); // if x1 == x2, evaluate double operation. If y1 = -y2 then we set all input/output parameters to be 0
    let infinity_predicate: bool =
        (x_equal_predicate & !y_equal_predicate) | (point.is_infinity() & other.is_infinity());
    let evaluate_group_operation_predicate: bool =
        !infinity_predicate & !point.is_infinity() & !other.is_infinity();

    // If we are skipping the evaluation of a group operation (x2 == x1, y2 == -y1 OR any input points are at infinity),
    // set input operands to 0!
    let (x1, y1, x2, y2, x3, y3) = if evaluate_group_operation_predicate {
        (x1, y1, x2, y2, x3, y3)
    } else {
        (B::zero(), B::zero(), B::zero(), B::zero(), B::zero(), B::zero())
    };

    // lambda * 2y - 3x*x = 0
    // 3 x * x - lambda * 2y
    // lambda * (x2 - x1) - (y2 - y1) = 0
    // y1 - (y2.neg()) - lambda * (x1 - x2) = 0
    // y1 + y2 - lambda * (x1 - x2) = 0
    // 3 * x * x - lambda * 2 * y
    let product_1_rhs_t0 = if double_predicate { y1 } else { x2.neg() };
    let product_1_rhs_t1 = if double_predicate { y1 } else { x1 };
    let product_2_lhs_t0 = if double_predicate { x1 } else { B::one() };
    let product_2_rhs_t0 = if double_predicate { x1 } else { y2 };
    let product_2_rhs_t1 = if double_predicate { x1 } else { y1 };
    let product_2_rhs_t2 = if double_predicate { x1 } else { B::zero() };

    // validate the provided value of `lambda` is correct
    // if double: -lambda * (y1 + y1) + x1 * (x1 x1 x1) + a= 0 => lambda * 2y - 3x*x = 0
    // if add:    -lambda * (x1 - x2) + 1 * (y2 + y1) = 0 => lambda * (x2 - x1) - (-y2 - y1) = 0
    let a_term = if x_equal_predicate
        & y_equal_predicate
        & !point.is_infinity()
        & !other.is_infinity() {
        P::a()
    } else {
        B::zero()
    };

    evaluate_quadratic_expression(
        [[lambda], [product_2_lhs_t0]],
        [[true], [false]],
        [
            [product_1_rhs_t0, product_1_rhs_t1, B::zero()],
            [product_2_rhs_t0, product_2_rhs_t1, product_2_rhs_t2],
        ],
        [[false, false, false], [false, false, false]],
        [a_term],
        [false],
    );

    // x3 = lambda * lambda - x2 - x1
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[lambda]],
        [[false]],
        [x3, x2, x1],
        [true, true, true],
    );

    // y3 = lambda * (x1 - x3) - y1
    evaluate_quadratic_expression(
        [[lambda]],
        [[false]],
        [[x3, x1]],
        [[false, true]],
        [y3, y1],
        [false, false],
    );

    let output_is_lhs = other.is_infinity() & !point.is_infinity();
    let output_is_rhs = point.is_infinity() & !other.is_infinity();
    let mut x_out = if evaluate_group_operation_predicate {
        x3
    } else {
        x1
    };
    x_out = if output_is_lhs { point.x() } else { x_out };
    x_out = if output_is_rhs { other.x() } else { x_out };
    x_out = if infinity_predicate { B::zero() } else { x_out };
    let mut y_out = if evaluate_group_operation_predicate {
        y3
    } else {
        y1
    };
    y_out = if output_is_lhs { point.y() } else { y_out };
    y_out = if output_is_rhs {
        other.y().neg()
    } else {
        y_out
    };
    y_out = if infinity_predicate { B::zero() } else { y_out };

    let mut infinity_out = !evaluate_group_operation_predicate;
    infinity_out = if infinity_predicate {
        true
    } else {
        infinity_out
    };
    infinity_out = if output_is_lhs {
        point.is_infinity()
    } else {
        infinity_out
    };
    infinity_out = if output_is_rhs {
        other.is_infinity()
    } else {
        infinity_out
    };

    let result: P = P::from_coordinates(x_out, y_out, infinity_out);
    result
}
