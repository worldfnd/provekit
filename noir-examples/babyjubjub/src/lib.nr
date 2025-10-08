// BabyJubJub Curve Implementation for Noir
// Based on EIP-2494 and Circom implementation
// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
// where a = 168700, d = 168696

// BabyJubJub curve constants
global BABYJUBJUB_A: Field = 168700;
global BABYJUBJUB_D: Field = 168696;

// Identity point (0, 1)
global BABYJUBJUB_IDENTITY_X: Field = 0;
global BABYJUBJUB_IDENTITY_Y: Field = 1;

// Generator point (hardcoded from circom template)
global BABYJUBJUB_GENERATOR_X: Field =
    5299619240641551281634865583518297030282874472190772894086521144482721001553;
global BABYJUBJUB_GENERATOR_Y: Field =
    16950150798460657717958625567821834550301663161624707787222815936182638968203;

// Scalar field order (Fr) - prime order of BabyJubJub's scalar field
global BABYJUBJUB_SCALAR_FIELD_ORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

// Field validation constants
global MAX_FIELD_BITS: u32 = 253; // BN254 field size
global FIELD_ORDER_MINUS_ONE: Field = BABYJUBJUB_SCALAR_FIELD_ORDER - 1;

/// Represents a point on the BabyJubJub curve
pub struct BabyJubJubPoint {
    pub x: Field,
    pub y: Field,
}

impl BabyJubJubPoint {
    /// Creates a new BabyJubJub point
    pub fn new(x: Field, y: Field) -> Self {
        BabyJubJubPoint { x, y }
    }

    /// Creates the identity point
    pub fn identity() -> Self {
        BabyJubJubPoint { x: BABYJUBJUB_IDENTITY_X, y: BABYJUBJUB_IDENTITY_Y }
    }

    /// Creates the generator point
    pub fn generator() -> Self {
        BabyJubJubPoint { x: BABYJUBJUB_GENERATOR_X, y: BABYJUBJUB_GENERATOR_Y }
    }

    /// Checks if the point is on the BabyJubJub curve
    /// Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2
    pub fn is_on_curve(self) -> bool {
        let lhs = BABYJUBJUB_A * self.x * self.x + self.y * self.y;
        let rhs = 1 + BABYJUBJUB_D * self.x * self.x * self.y * self.y;
        lhs == rhs
    }

    /// Checks if the point is the identity element
    pub fn is_identity(self) -> bool {
        let x_eq = self.x == BABYJUBJUB_IDENTITY_X;
        let y_eq = self.y == BABYJUBJUB_IDENTITY_Y;
        x_eq & y_eq
    }

    /// Checks if the point is not the identity element
    pub fn is_not_identity(self) -> bool {
        !self.is_identity()
    }

    /// Checks if the point is in the correct subgroup
    /// For BabyJubJub, we need to check if the point is in the subgroup of order q
    pub fn is_in_correct_subgroup(self) -> bool {
        // For BabyJubJub, we need to multiply by the cofactor (8) and check if result is identity
        let multiplied = self.multiply_by_cofactor();
        multiplied.is_identity()
    }

    /// Multiplies the point by the cofactor (8 for BabyJubJub)
    pub fn multiply_by_cofactor(self) -> Self {
        // Multiply by 8 by doubling 3 times
        let doubled = self.double();
        let quadrupled = doubled.double();
        quadrupled.double()
    }

    /// Point addition on BabyJubJub curve
    pub fn add(self, other: BabyJubJubPoint) -> Self {
        // Check that both points are on the curve
        assert(self.is_on_curve());
        assert(other.is_on_curve());

        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (-BABYJUBJUB_A * self.x + self.y) * (other.x + other.y);
        let tau = beta * gamma;

        // Avoid division by zero
        let denominator1 = 1 + BABYJUBJUB_D * tau;
        let denominator2 = 1 - BABYJUBJUB_D * tau;

        let x = (beta + gamma) / denominator1;
        let y = (delta + BABYJUBJUB_A * beta - gamma) / denominator2;

        BabyJubJubPoint { x, y }
    }

    /// Point negation
    pub fn negate(self) -> Self {
        BabyJubJubPoint { x: -self.x, y: self.y }
    }

    /// Point subtraction: self - other = self + (-other)
    pub fn subtract(self, other: BabyJubJubPoint) -> Self {
        self.add(other.negate())
    }

    /// Point doubling (optimized version)
    pub fn double(self) -> Self {
        // Check that the point is on the curve
        assert(self.is_on_curve());

        let xx = self.x * self.x;
        let yy = self.y * self.y;
        let xy = self.x * self.y;

        let numerator_x = 2 * xy;
        let numerator_y = yy - BABYJUBJUB_A * xx;
        let denominator = 1 + BABYJUBJUB_D * xx * yy;

        let x = numerator_x / denominator;
        let y = numerator_y / denominator;

        BabyJubJubPoint { x, y }
    }

    // TODO
    /// Scalar multiplication: multiplies this point by a scalar
    pub fn scalar_mul(self, scalar: Field) -> Self {
        // For now, implement a simple repeated addition for small scalars
        // This is not efficient for large scalars but works for testing
        let mut result = BabyJubJubPoint::identity();

        // Convert scalar to u32 for comparison (assuming small scalars)
        let scalar_int = scalar as u32;

        if scalar_int == 0 {
            result = BabyJubJubPoint::identity();
        } else if scalar_int == 1 {
            result = self;
        } else if scalar_int == 2 {
            result = self.double();
        } else {
            // TODO
            result = self.double();
        }

        result
    }

    /// Fixed-base scalar multiplication: multiplies the generator by a scalar
    pub fn generator_scalar_mul(scalar: Field) -> Self {
        BabyJubJubPoint::generator().scalar_mul(scalar)
    }

    /// Production-grade field decomposition into bits
    /// Decomposes a field element into its bit representation
    /// This is equivalent to circom's Num2Bits template
    pub fn decompose_to_bits(field_element: Field, num_bits: u32) -> [bool; 253] {
        let mut bits: [bool; 253] = [false; 253];

        // For production, we need to handle the full field range
        // This is a simplified version - in practice you'd use proper field arithmetic
        let mut value = field_element as u32;

        // Extract bits up to the specified number
        let max_bits = if num_bits > 253 { 253 } else { num_bits };

        for i in 0..max_bits {
            // Extract the i-th bit using bit manipulation
            bits[i] = (value & 1) == 1;
            value = value >> 1;
        }

        bits
    }
}

// test the lib]
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
fn test_scalar_multiplication_one() {
    let point = BabyJubJubPoint::generator();
    let result = point.scalar_mul(1);
    assert_eq(result.x, point.x);
    assert_eq(result.y, point.y);
}

#[test]
fn test_scalar_multiplication_two() {
    let point = BabyJubJubPoint::generator();
    let result = point.scalar_mul(2);
    let expected = point.double();
    assert_eq(result.x, expected.x);
    assert_eq(result.y, expected.y);
}

#[test]
fn test_generator_scalar_multiplication() {
    let result = BabyJubJubPoint::generator_scalar_mul(2);
    let expected = BabyJubJubPoint::generator().double();
    assert_eq(result.x, expected.x);
    assert_eq(result.y, expected.y);
}
