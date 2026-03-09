use {
    crate::{
        sparse_matrix::SparseMatrix,
        utils::{unzip_double_array, workload_size},
        FieldElement, R1CS,
    },
    ark_std::{One, Zero},
    rayon::iter::{IndexedParallelIterator as _, IntoParallelRefIterator, ParallelIterator as _},
    std::array,
    tracing::instrument,
};

/// Compute the sum of a vector valued function over the boolean hypercube in
/// the leading variable.
pub fn sumcheck_fold_map_reduce<const N: usize, const M: usize>(
    mles: [&mut [FieldElement]; N],
    fold: Option<FieldElement>,
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0].len();
    assert!(size.is_power_of_two());
    assert!(size >= 2);
    assert!(mles.iter().all(|mle| mle.len() == size));

    if let Some(fold) = fold {
        assert!(size >= 4);
        let slices = mles.map(|mle| {
            let (p0, tail) = mle.split_at_mut(size / 4);
            let (p1, tail) = tail.split_at_mut(size / 4);
            let (p2, p3) = tail.split_at_mut(size / 4);
            [p0, p1, p2, p3]
        });
        sumcheck_fold_map_reduce_inner::<N, M>(slices, fold, map)
    } else {
        let slices = mles.map(|mle| mle.split_at(size / 2));
        sumcheck_map_reduce_inner::<N, M>(slices, map)
    }
}

fn sumcheck_map_reduce_inner<const N: usize, const M: usize>(
    mles: [(&[FieldElement], &[FieldElement]); N],
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0].0.len();
    if size * N * 2 > workload_size::<FieldElement>() {
        // Split slices
        let pairs = mles.map(|(p0, p1)| (p0.split_at(size / 2), p1.split_at(size / 2)));
        let left = pairs.map(|((l0, _), (l1, _))| (l0, l1));
        let right = pairs.map(|((_, r0), (_, r1))| (r0, r1));

        // Parallel recurse
        let (l, r) = rayon::join(
            || sumcheck_map_reduce_inner(left, map),
            || sumcheck_map_reduce_inner(right, map),
        );

        // Combine results
        array::from_fn(|i| l[i] + r[i])
    } else {
        let mut result = [FieldElement::zero(); M];
        for i in 0..size {
            let e = mles.map(|(p0, p1)| (p0[i], p1[i]));
            let local = map(e);
            result.iter_mut().zip(local).for_each(|(r, l)| *r += l);
        }
        result
    }
}

fn sumcheck_fold_map_reduce_inner<const N: usize, const M: usize>(
    mut mles: [[&mut [FieldElement]; 4]; N],
    fold: FieldElement,
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0][0].len();
    if size * N * 4 > workload_size::<FieldElement>() {
        // Split slices
        let pairs = mles.map(|mles| mles.map(|p| p.split_at_mut(size / 2)));
        let (left, right) = unzip_double_array(pairs);

        // Parallel recurse
        let (l, r) = rayon::join(
            || sumcheck_fold_map_reduce_inner(left, fold, map),
            || sumcheck_fold_map_reduce_inner(right, fold, map),
        );

        // Combine results
        array::from_fn(|i| l[i] + r[i])
    } else {
        let mut result = [FieldElement::zero(); M];
        for i in 0..size {
            let e = array::from_fn(|j| {
                let mle = &mut mles[j];
                mle[0][i] += fold * (mle[2][i] - mle[0][i]);
                mle[1][i] += fold * (mle[3][i] - mle[1][i]);
                (mle[0][i], mle[1][i])
            });
            let local = map(e);
            result.iter_mut().zip(local).for_each(|(r, l)| *r += l);
        }
        result
    }
}

/// List of evaluations for eq(r, x) over the boolean hypercube, truncated to
/// `num_entries` elements. When `num_entries < 2^r.len()`, avoids allocating
/// the full hypercube.
#[instrument(skip_all)]
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &[FieldElement],
    num_entries: usize,
) -> Vec<FieldElement> {
    if num_entries == 0 {
        return vec![];
    }
    let full_size = 1usize << r.len();
    debug_assert!(num_entries <= full_size);
    let mut result = vec![FieldElement::zero(); num_entries];
    eval_eq(r, &mut result, FieldElement::one(), full_size);
    result
}

/// Evaluates the equality polynomial recursively. `subtree_size` tracks the
/// logical size of this recursion level so that truncated output buffers are
/// split correctly.
fn eval_eq(
    eval: &[FieldElement],
    out: &mut [FieldElement],
    scalar: FieldElement,
    subtree_size: usize,
) {
    debug_assert!(out.len() <= subtree_size);
    if let Some((&x, tail)) = eval.split_first() {
        let half = subtree_size / 2;
        let left_len = out.len().min(half);
        let right_len = out.len().saturating_sub(half);
        let (o0, o1) = out.split_at_mut(left_len);
        let s1 = scalar * x;
        let s0 = scalar - s1;
        if right_len == 0 {
            eval_eq(tail, o0, s0, half);
        } else if subtree_size > workload_size::<FieldElement>() {
            rayon::join(
                || eval_eq(tail, o0, s0, half),
                || eval_eq(tail, o1, s1, half),
            );
        } else {
            eval_eq(tail, o0, s0, half);
            eval_eq(tail, o1, s1, half);
        }
    } else {
        out[0] += scalar;
    }
}

/// Evaluates a cubic polynomial on a value
pub fn eval_cubic_poly(poly: [FieldElement; 4], point: FieldElement) -> FieldElement {
    poly[0] + point * (poly[1] + point * (poly[2] + point * poly[3]))
}

/// Given a path to JSON file with sparce matrices and a witness, calculates
/// matrix-vector multiplication and returns them
#[instrument(skip_all)]
pub fn calculate_witness_bounds(
    r1cs: &R1CS,
    witness: &[FieldElement],
) -> (Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>) {
    let (a, b) = rayon::join(|| r1cs.a() * witness, || r1cs.b() * witness);

    let target_len = a.len().next_power_of_two();
    let mut c = Vec::with_capacity(target_len);
    c.extend(a.iter().zip(b.iter()).map(|(a, b)| *a * *b));
    c.resize(target_len, FieldElement::zero());

    let mut a = a;
    let mut b = b;
    a.resize(target_len, FieldElement::zero());
    b.resize(target_len, FieldElement::zero());
    (a, b, c)
}

/// Calculates eq(r, alpha)
pub fn calculate_eq(r: &[FieldElement], alpha: &[FieldElement]) -> FieldElement {
    r.iter()
        .zip(alpha.iter())
        .fold(FieldElement::from(1), |acc, (&r, &alpha)| {
            acc * (r * alpha + (FieldElement::from(1) - r) * (FieldElement::from(1) - alpha))
        })
}

/// Transpose all three R1CS matrices in parallel.
///
/// This depends only on the R1CS structure (from the verifier key), not on any
/// proof-specific data, so it can run concurrently with sumcheck verification.
#[instrument(skip_all)]
pub fn transpose_r1cs_matrices(r1cs: &R1CS) -> (SparseMatrix, SparseMatrix, SparseMatrix) {
    let ((at, bt), ct) = rayon::join(
        || rayon::join(|| r1cs.a.transpose(), || r1cs.b.transpose()),
        || r1cs.c.transpose(),
    );
    (at, bt, ct)
}

/// Multiply pre-transposed R1CS matrices by eq(alpha, ·) to compute the
/// external row.
#[instrument(skip_all)]
pub fn multiply_transposed_by_eq_alpha(
    at: &SparseMatrix,
    bt: &SparseMatrix,
    ct: &SparseMatrix,
    alpha: &[FieldElement],
    r1cs: &R1CS,
) -> [Vec<FieldElement>; 3] {
    let eq_alpha =
        calculate_evaluations_over_boolean_hypercube_for_eq(alpha, r1cs.num_constraints());
    let interner = &r1cs.interner;
    let ((a, b), c) = rayon::join(
        || {
            rayon::join(
                || at.hydrate(interner) * eq_alpha.as_slice(),
                || bt.hydrate(interner) * eq_alpha.as_slice(),
            )
        },
        || ct.hydrate(interner) * eq_alpha.as_slice(),
    );
    [a, b, c]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(v: i64) -> FieldElement {
        if v >= 0 {
            FieldElement::from(v as u64)
        } else {
            FieldElement::from(0u64) - FieldElement::from((-v) as u64)
        }
    }

    /// Build a small 3×4 R1CS for matrix tests.
    ///
    /// A = [[1, 2, 0, 0],   B = [[0, 1, 0, 0],   C = [[0, 0, 1, 0],
    ///      [0, 0, 3, 0],        [2, 0, 0, 1],        [0, 1, 0, 3],
    ///      [1, 0, 0, 1]]        [0, 0, 4, 0]]        [2, 0, 0, 0]]
    fn make_test_r1cs() -> crate::R1CS {
        let mut r1cs = crate::R1CS::new();
        r1cs.add_witnesses(4);
        r1cs.add_constraint(&[(fe(1), 0), (fe(2), 1)], &[(fe(1), 1)], &[(fe(1), 2)]);
        r1cs.add_constraint(&[(fe(3), 2)], &[(fe(2), 0), (fe(1), 3)], &[
            (fe(1), 1),
            (fe(3), 3),
        ]);
        r1cs.add_constraint(&[(fe(1), 0), (fe(1), 3)], &[(fe(4), 2)], &[(fe(2), 0)]);
        r1cs
    }

    /// calculate_eq

    #[test]
    fn test_calculate_eq_non_boolean() {
        // r = [2,3,4,5], alpha = [6,7,8,9]
        // eq = 17 × 33 × 53 × 77 = 2,289,441
        let r = [fe(2), fe(3), fe(4), fe(5)];
        let alpha = [fe(6), fe(7), fe(8), fe(9)];
        assert_eq!(calculate_eq(&r, &alpha), fe(2_289_441));
    }

    #[test]
    fn test_calculate_eq_boolean_identity() {
        let r = [fe(0), fe(1), fe(1), fe(0)];
        assert_eq!(calculate_eq(&r, &[fe(0), fe(1), fe(1), fe(0)]), fe(1));
        assert_eq!(calculate_eq(&r, &[fe(1), fe(0), fe(0), fe(1)]), fe(0));
    }

    #[test]
    fn test_calculate_eq_empty() {
        assert_eq!(calculate_eq(&[], &[]), fe(1));
    }

    /// calculate_evaluations_over_boolean_hypercube_for_eq

    #[test]
    fn test_eq_hypercube_len4() {
        // r of dimension 4 → 16-entry hypercube.
        // Cross-validate every entry against calculate_eq.
        let r = [fe(2), fe(3), fe(4), fe(5)];
        let result = calculate_evaluations_over_boolean_hypercube_for_eq(&r, 16);
        assert_eq!(result.len(), 16);
        let n = r.len();
        for (i, val) in result.iter().enumerate() {
            let point: Vec<FieldElement> = (0..n)
                .map(|j| fe(((i >> (n - 1 - j)) & 1) as i64))
                .collect();
            let expected = calculate_eq(&r, &point);
            assert_eq!(*val, expected, "mismatch at index {i}");
        }
    }
    #[test]
    fn test_eq_hypercube_truncated() {
        let r = [fe(2), fe(3), fe(4), fe(5)];
        let full = calculate_evaluations_over_boolean_hypercube_for_eq(&r, 16);
        let truncated = calculate_evaluations_over_boolean_hypercube_for_eq(&r, 10);
        assert_eq!(truncated.len(), 10);
        assert_eq!(&full[..10], truncated.as_slice());
    }

    #[test]
    fn test_eq_hypercube_empty_r() {
        let result = calculate_evaluations_over_boolean_hypercube_for_eq(&[], 1);
        assert_eq!(result, vec![fe(1)]);
    }

    #[test]
    fn test_eq_hypercube_zero_entries() {
        let result = calculate_evaluations_over_boolean_hypercube_for_eq(&[fe(2), fe(3), fe(5)], 0);
        assert!(result.is_empty(), "non-empty r, zero entries");

        let result = calculate_evaluations_over_boolean_hypercube_for_eq(&[], 0);
        assert!(result.is_empty(), "empty r, zero entries");
    }

    /// eval_eq

    #[test]
    fn test_eval_eq_base_case() {
        // Base case: eval is empty, so out[0] += scalar.
        let mut out = [fe(7)];
        eval_eq(&[], &mut out, fe(3), 1);
        assert_eq!(out[0], fe(10));
    }

    #[test]
    fn test_eval_eq_truncated_left_only() {
        // eval = [2,3,5], out has 1 slot (right_len = 0 each time), subtree_size = 8.
        // Expected: eq([2,3,5], [0,0,0]) = (1-2)(1-3)(1-5) = (-1)(-2)(-4) = -8
        let mut out = [FieldElement::zero()];
        eval_eq(&[fe(2), fe(3), fe(5)], &mut out, FieldElement::one(), 8);
        assert_eq!(out[0], fe(-8));
    }

    /// transpose_r1cs_matrices

    #[test]
    fn test_transpose_r1cs_matrices() {
        let r1cs = make_test_r1cs();
        let (at, bt, ct) = transpose_r1cs_matrices(&r1cs);

        // Dimensions swapped: 3×4 → 4×3.
        assert_eq!((at.num_rows, at.num_cols), (4, 3));
        assert_eq!((bt.num_rows, bt.num_cols), (4, 3));
        assert_eq!((ct.num_rows, ct.num_cols), (4, 3));

        // Standard basis vectors e_i pick out row i of M and column i of M^T.
        // Looping over all 3 gives 3×4 = 12 equations, one per entry of each
        // 3×4 matrix — fully determined coverage.
        let expected_a_rows = [
            vec![fe(1), fe(2), fe(0), fe(0)],
            vec![fe(0), fe(0), fe(3), fe(0)],
            vec![fe(1), fe(0), fe(0), fe(1)],
        ];
        let expected_b_rows = [
            vec![fe(0), fe(1), fe(0), fe(0)],
            vec![fe(2), fe(0), fe(0), fe(1)],
            vec![fe(0), fe(0), fe(4), fe(0)],
        ];
        let expected_c_rows = [
            vec![fe(0), fe(0), fe(1), fe(0)],
            vec![fe(0), fe(1), fe(0), fe(3)],
            vec![fe(2), fe(0), fe(0), fe(0)],
        ];

        // A^T · e_i extracts column i of A^T, which must equal row i of A.
        // Three basis vectors cover all 12 entries of each 3×4 matrix.
        for i in 0..r1cs.num_constraints() {
            let mut e = vec![FieldElement::zero(); r1cs.num_constraints()];
            e[i] = FieldElement::one();

            assert_eq!(
                at.hydrate(&r1cs.interner) * e.as_slice(),
                expected_a_rows[i],
                "AT col {i}"
            );
            assert_eq!(
                bt.hydrate(&r1cs.interner) * e.as_slice(),
                expected_b_rows[i],
                "BT col {i}"
            );
            assert_eq!(
                ct.hydrate(&r1cs.interner) * e.as_slice(),
                expected_c_rows[i],
                "CT col {i}"
            );
        }
    }

    /// multiply_transposed_by_eq_alpha

    #[test]
    fn test_multiply_transposed_by_eq_alpha() {
        let r1cs = make_test_r1cs();
        let (at, bt, ct) = transpose_r1cs_matrices(&r1cs);
        // alpha length 2 → full EQ size 4, truncated to 3 constraints.
        let alpha = [fe(2), fe(3)];

        let expected_a = vec![fe(-2), fe(4), fe(-9), fe(-4)];
        let expected_b = vec![fe(-6), fe(2), fe(-16), fe(-3)];
        let expected_c = vec![fe(-8), fe(-3), fe(2), fe(-9)];

        let [actual_a, actual_b, actual_c] =
            multiply_transposed_by_eq_alpha(&at, &bt, &ct, &alpha, &r1cs);

        assert_eq!(actual_a.len(), r1cs.num_witnesses());
        assert_eq!(actual_a, expected_a, "A result mismatch");
        assert_eq!(actual_b, expected_b, "B result mismatch");
        assert_eq!(actual_c, expected_c, "C result mismatch");
    }
}
