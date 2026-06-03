use dep::bignum::BigNum;

/// CurveJ represents a Short Weierstrass elliptic curve using Jacobian coordinates.
///
/// # Representation
/// - **Jacobian form:** (X, Y, Z)
/// - **Affine form:** (x, y)
/// - **Relation:** x = X / Z^2, y = Y / Z^3
///
/// # Purpose
/// This class is designed to speed up witness generation when optimally constraining elliptic curve operations.
///
/// # Motivation
/// - Constraints are best constructed in affine coordinates due to fewer field multiplications (3 vs ~14 for Jacobian).
/// - However, affine coordinates require one modular inverse per group operation, which is expensive over a non-native field (~2D multiplications, where D is the field bit-width).
///
/// # Solution
/// - Perform all computations in unconstrained functions using Jacobian coordinates (no inverses required).
/// - Record each ECC operation in a `JTranscript` object.
/// - Use a Montgomery Batch Inverse to compute all required inverses at once when evaluating with affine arithmetic.
/// - This reduces the number of modular inverses from ~256 or 320 (depending on the curve) to just one.
///
/// # Note
/// This approach is complex but necessary due to the high cost of generating modular inverses for witness generation.
pub struct CurveJ<B, BigCurve> {
    pub(crate) x: B,
    pub(crate) y: B,
    pub(crate) z: B,
    pub is_infinity: bool,
}

/// A transcript of a group operation in Jacobian coordinates.
///
/// # Fields
/// - `x3`, `y3`, `z3`: The output coordinates of the group operation in Jacobian form.
/// - `lambda_numerator`: The numerator of the `lambda` term used in the group operation.
///   (The denominator is assumed to be `z3`.)
pub struct JTranscript<B> {
    pub(crate) lambda_numerator: B,
    pub(crate) x3: B,
    pub(crate) y3: B,
    pub(crate) z3: B,
}

impl<B> JTranscript<B>
where
    B: BigNum,
{
    pub unconstrained fn new() -> Self {
        JTranscript { lambda_numerator: B::zero(), x3: B::zero(), y3: B::zero(), z3: B::zero() }
    }
}

/// A transcript of a group operation in Affine coordinates.
///
/// # Fields
/// - `x3`, `y3`: The output coordinates of the group operation.
/// - `lambda`: The gradient of the line that passes through the input points of the group operation.
///
/// # Details
/// - For addition: `lambda = (y2 - y1) / (x2 - x1)`
/// - For doubling: `lambda = (3 * x1 * x1) / (2 * y1)`
///
/// # Optimization
/// If you have an array of `JTranscript` objects, you can convert them into `AffineTranscript` objects using only one modular inverse.
pub struct AffineTranscript<B> {
    pub lambda: B,
    pub x3: B,
    pub y3: B,
}

impl<B> AffineTranscript<B>
where
    B: BigNum,
{
    pub(crate) fn new() -> Self {
        AffineTranscript { lambda: B::zero(), x3: B::zero(), y3: B::zero() }
    }

    pub unconstrained fn from_j(j_tx: JTranscript<B>) -> Self {
        AffineTranscript::from_jacobian_transcript([j_tx])[0]
    }

    pub unconstrained fn from_j_with_hint(j_tx: JTranscript<B>, inverse: B) -> AffineTranscript<B> {
        let z_inv = inverse;
        let zz = z_inv.__mul(z_inv);
        let zzz = zz.__mul(z_inv);
        let lambda = j_tx.lambda_numerator.__mul(z_inv);
        let x3 = j_tx.x3.__mul(zz);
        let y3 = j_tx.y3.__mul(zzz);
        AffineTranscript { x3, y3, lambda }
    }

    pub(crate) unconstrained fn from_jacobian_transcript<let NumEntries: u32>(
        j_tx: [JTranscript<B>; NumEntries],
    ) -> [AffineTranscript<B>; NumEntries] {
        let mut result: [AffineTranscript<B>; NumEntries] = [AffineTranscript::new(); NumEntries];

        let mut inverses: [B; NumEntries] = [B::zero(); NumEntries];
        for i in 0..j_tx.len() {
            inverses[i] = j_tx[i].z3;
        }

        // tadaa
        let inverses: [B; NumEntries] = bignum::bignum::batch_invert(inverses);

        for i in 0..j_tx.len() {
            let z_inv = inverses[i];
            let zz = z_inv.__mul(z_inv);
            let zzz = zz.__mul(z_inv);
            let lambda = j_tx[i].lambda_numerator.__mul(z_inv);
            let x3 = j_tx[i].x3.__mul(zz);
            let y3 = j_tx[i].y3.__mul(zzz);
            result[i] = AffineTranscript { lambda, x3, y3 };
        }
        result
    }
}
