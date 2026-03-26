use {
    crate::FieldElement,
    ark_std::{One, Zero},
    whir::algebra::{dot, linear_form::LinearForm, multilinear_extend},
};

/// A covector that stores only a power-of-two prefix, with the rest
/// implicitly zero-padded to `domain_size`. Saves memory when the
/// covector is known to be zero beyond the prefix (e.g. R1CS alpha
/// weights that are zero-padded from witness_size to 2^m).
///
/// Implements whir's [`LinearForm`] so it can be passed directly to
/// `prove()` / `verify()` in place of a full-length `Covector`.
///
/// [`LinearForm`]: https://github.com/WizardOfMenlo/whir/blob/main/src/algebra/linear_form/mod.rs
pub struct PrefixCovector {
    /// The non-zero prefix. Length must be a power of two.
    vector:      Vec<FieldElement>,
    /// The full logical domain size (also a power of two, >= vector.len()).
    domain_size: usize,
}

impl PrefixCovector {
    /// Create a new `PrefixCovector` from a prefix vector and domain size.
    ///
    /// # Panics
    ///
    /// Debug-asserts that both `vector.len()` and `domain_size` are powers of
    /// two, and that `domain_size >= vector.len()`.
    #[must_use]
    pub fn new(vector: Vec<FieldElement>, domain_size: usize) -> Self {
        debug_assert!(vector.len().is_power_of_two());
        debug_assert!(domain_size.is_power_of_two());
        assert!(
            domain_size >= vector.len(),
            "PrefixCovector: domain_size ({domain_size}) must be >= vector.len() ({})",
            vector.len()
        );
        Self {
            vector,
            domain_size,
        }
    }

    /// Access the underlying prefix vector.
    #[must_use]
    pub fn vector(&self) -> &[FieldElement] {
        &self.vector
    }

    /// Length of the non-zero prefix.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vector.len()
    }

    /// Returns `true` if the prefix vector is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vector.is_empty()
    }
}

impl LinearForm<FieldElement> for PrefixCovector {
    fn size(&self) -> usize {
        self.domain_size
    }

    fn mle_evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let k = self.vector.len().trailing_zeros() as usize;
        let r = point.len() - k;
        let head_factor: FieldElement =
            point[..r].iter().map(|p| FieldElement::one() - p).product();
        let prefix_mle = multilinear_extend(&self.vector, &point[r..]);
        head_factor * prefix_mle
    }

    fn accumulate(&self, accumulator: &mut [FieldElement], scalar: FieldElement) {
        for (acc, val) in accumulator[..self.vector.len()]
            .iter_mut()
            .zip(&self.vector)
        {
            *acc += scalar * *val;
        }
    }
}

/// A covector that is zero everywhere except at positions
/// `[offset .. offset + weights.len())` within a `domain_size`-length domain.
pub struct OffsetCovector {
    weights:     Vec<FieldElement>,
    offset:      usize,
    domain_size: usize,
}

impl OffsetCovector {
    #[must_use]
    pub fn new(weights: Vec<FieldElement>, offset: usize, domain_size: usize) -> Self {
        debug_assert!(domain_size.is_power_of_two());
        assert!(
            offset + weights.len() <= domain_size,
            "OffsetCovector: offset ({offset}) + weights.len() ({}) exceeds domain_size \
             ({domain_size})",
            weights.len()
        );
        Self {
            weights,
            offset,
            domain_size,
        }
    }
}

impl LinearForm<FieldElement> for OffsetCovector {
    fn size(&self) -> usize {
        self.domain_size
    }

    fn mle_evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let n = point.len();
        let mut result = FieldElement::zero();
        for (i, &w) in self.weights.iter().enumerate() {
            if w.is_zero() {
                continue;
            }
            let idx = self.offset + i;
            // point[0] = MSB, matching whir's multilinear_extend convention
            let mut basis = FieldElement::one();
            for (k, pk) in point.iter().enumerate() {
                if (idx >> (n - 1 - k)) & 1 == 1 {
                    basis *= pk;
                } else {
                    basis *= FieldElement::one() - pk;
                }
            }
            result += w * basis;
        }
        result
    }

    fn accumulate(&self, accumulator: &mut [FieldElement], scalar: FieldElement) {
        for (acc, &w) in accumulator[self.offset..self.offset + self.weights.len()]
            .iter_mut()
            .zip(&self.weights)
        {
            *acc += scalar * w;
        }
    }
}

/// Expand each field element into `[1, x, x², …, x^{D-1}]`.
///
/// Used to build weight vectors for the spartan blinding polynomial
/// evaluation in both prover and verifier.
#[must_use]
pub fn expand_powers<const D: usize>(values: &[FieldElement]) -> Vec<FieldElement> {
    let mut result = Vec::with_capacity(values.len() * D);
    for &value in values {
        let mut power = FieldElement::one();
        for _ in 0..D {
            result.push(power);
            power *= value;
        }
    }
    result
}

/// Create a public weight [`PrefixCovector`] from Fiat-Shamir randomness `x`.
///
/// Builds the vector `[1, x, x², …, x^{n-1}]` padded to a power of two,
/// where `n = public_inputs_len`.
#[must_use]
pub fn make_public_weight(x: FieldElement, public_inputs_len: usize, m: usize) -> PrefixCovector {
    let domain_size = 1 << m;
    let prefix_len = public_inputs_len.next_power_of_two().max(2);
    let mut public_weights = vec![FieldElement::zero(); prefix_len];

    let mut current_pow = FieldElement::one();
    for slot in public_weights.iter_mut().take(public_inputs_len) {
        *slot = current_pow;
        current_pow *= x;
    }

    PrefixCovector::new(public_weights, domain_size)
}

/// Build [`PrefixCovector`] weights from alpha vectors, consuming the alphas.
///
/// Each alpha vector is padded to a power-of-two length (min 2) and wrapped
/// in a `PrefixCovector` with the given domain size `2^m`.
#[must_use]
pub fn build_prefix_covectors<const N: usize>(
    m: usize,
    alphas: [Vec<FieldElement>; N],
) -> Vec<PrefixCovector> {
    let domain_size = 1usize << m;
    alphas
        .into_iter()
        .map(|mut w| {
            let base_len = w.len().next_power_of_two().max(2);
            w.resize(base_len, FieldElement::zero());
            PrefixCovector::new(w, domain_size)
        })
        .collect()
}

/// Compute dot products of alpha vectors against a polynomial without
/// allocating [`PrefixCovector`] weights. Used to write transcript hints
/// before deferring weight construction (saves memory in dual-commit).
#[must_use]
pub fn compute_alpha_evals<const N: usize>(
    polynomial: &[FieldElement],
    alphas: &[Vec<FieldElement>; N],
) -> Vec<FieldElement> {
    alphas
        .iter()
        .map(|w| dot(w, &polynomial[..w.len()]))
        .collect()
}

/// Compute the public weight evaluation `⟨[1, x, x², …], poly⟩` without
/// allocating a [`PrefixCovector`].
#[must_use]
pub fn compute_public_eval(
    x: FieldElement,
    public_inputs_len: usize,
    polynomial: &[FieldElement],
) -> FieldElement {
    let mut eval = FieldElement::zero();
    let mut x_pow = FieldElement::one();
    for &p in polynomial.iter().take(public_inputs_len) {
        eval += x_pow * p;
        x_pow *= x;
    }
    eval
}

/// Covector with non-zero weights at arbitrary (possibly non-contiguous)
/// positions.  Used for challenge binding where Fiat-Shamir challenge
/// witnesses may be scattered throughout the w2 polynomial.
pub struct SparseCovector {
    entries:     Vec<(usize, FieldElement)>,
    domain_size: usize,
}

impl SparseCovector {
    /// Create a new `SparseCovector` from `(position, weight)` pairs and a
    /// domain size.
    pub fn new(entries: Vec<(usize, FieldElement)>, domain_size: usize) -> Self {
        assert!(domain_size.is_power_of_two());
        assert!(
            entries.iter().all(|&(pos, _)| pos < domain_size),
            "SparseCovector: all entry positions must be < domain_size ({domain_size})"
        );
        Self {
            entries,
            domain_size,
        }
    }
}

impl LinearForm<FieldElement> for SparseCovector {
    fn size(&self) -> usize {
        self.domain_size
    }

    fn mle_evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let n = point.len();
        let mut result = FieldElement::zero();
        for &(idx, w) in &self.entries {
            if w.is_zero() {
                continue;
            }
            let mut basis = FieldElement::one();
            for (k, pk) in point.iter().enumerate() {
                if (idx >> (n - 1 - k)) & 1 == 1 {
                    basis *= pk;
                } else {
                    basis *= FieldElement::one() - pk;
                }
            }
            result += w * basis;
        }
        result
    }

    fn accumulate(&self, accumulator: &mut [FieldElement], scalar: FieldElement) {
        for &(pos, w) in &self.entries {
            accumulator[pos] += scalar * w;
        }
    }
}

/// Build a [`SparseCovector`] that extracts the challenge positions from a w2
/// polynomial, weighted by successive powers of `x`.
#[must_use]
pub fn make_challenge_weight(
    x: FieldElement,
    challenge_offsets: &[usize],
    m: usize,
) -> SparseCovector {
    let domain_size = 1usize << m;
    let mut x_pow = FieldElement::one();
    let entries: Vec<(usize, FieldElement)> = challenge_offsets
        .iter()
        .map(|&pos| {
            let entry = (pos, x_pow);
            x_pow *= x;
            entry
        })
        .collect();
    SparseCovector::new(entries, domain_size)
}

/// Evaluate `Σ xⁱ · polynomial[challenge_offsets[i]]` — the challenge binding
/// value that the prover sends as a transcript-bound message.
#[must_use]
pub fn compute_challenge_eval(
    x: FieldElement,
    challenge_offsets: &[usize],
    polynomial: &[FieldElement],
) -> FieldElement {
    let mut result = FieldElement::zero();
    let mut x_pow = FieldElement::one();
    for &pos in challenge_offsets {
        result += x_pow * polynomial[pos];
        x_pow *= x;
    }
    result
}

#[cfg(test)]
mod tests {
    use {super::*, whir::algebra::multilinear_extend};

    /// Build a full domain-size vector that is zero everywhere except at
    /// `[offset .. offset + weights.len())`.
    fn full_vector(
        weights: &[FieldElement],
        offset: usize,
        domain_size: usize,
    ) -> Vec<FieldElement> {
        let mut v = vec![FieldElement::zero(); domain_size];
        for (i, &w) in weights.iter().enumerate() {
            v[offset + i] = w;
        }
        v
    }

    /// Deterministic field elements for reproducible tests.
    fn fe(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    #[test]
    fn mle_evaluate_matches_full_vector() {
        let domain_size = 16; // 2^4
        let offset = 5;
        let weights = vec![fe(7), fe(3), fe(11)];
        let point = vec![fe(2), fe(5), fe(13), fe(17)];

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
        let full = full_vector(&weights, offset, domain_size);

        let expected = multilinear_extend(&full, &point);
        let actual = covector.mle_evaluate(&point);

        assert_eq!(actual, expected);
    }

    #[test]
    fn mle_evaluate_offset_zero_matches_prefix() {
        // With offset=0, OffsetCovector should give the same result as
        // evaluating a full vector with a non-zero prefix.
        let domain_size = 8; // 2^3
        let weights = vec![fe(1), fe(2), fe(3), fe(4)];
        let point = vec![fe(7), fe(11), fe(13)];

        let covector = OffsetCovector::new(weights.clone(), 0, domain_size);
        let full = full_vector(&weights, 0, domain_size);

        let expected = multilinear_extend(&full, &point);
        let actual = covector.mle_evaluate(&point);

        assert_eq!(actual, expected);
    }

    #[test]
    fn mle_evaluate_at_end_of_domain() {
        // Weights placed at the very end of the domain.
        let domain_size = 8;
        let weights = vec![fe(42), fe(99)];
        let offset = 6; // positions 6, 7 in an 8-element domain
        let point = vec![fe(3), fe(5), fe(7)];

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
        let full = full_vector(&weights, offset, domain_size);

        let expected = multilinear_extend(&full, &point);
        let actual = covector.mle_evaluate(&point);

        assert_eq!(actual, expected);
    }

    #[test]
    fn mle_evaluate_single_weight() {
        // Single non-zero weight — Lagrange basis for one index.
        let domain_size = 4; // 2^2
        let weights = vec![fe(1)];
        let point = vec![fe(3), fe(7)];

        for offset in 0..4 {
            let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
            let full = full_vector(&weights, offset, domain_size);

            let expected = multilinear_extend(&full, &point);
            let actual = covector.mle_evaluate(&point);

            assert_eq!(actual, expected, "failed for offset={offset}");
        }
    }

    #[test]
    fn mle_evaluate_skips_zero_weights() {
        // Zero weights should not contribute to the result.
        let domain_size = 8;
        let weights = vec![fe(0), fe(5), fe(0)];
        let offset = 2;
        let point = vec![fe(3), fe(7), fe(11)];

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
        let full = full_vector(&weights, offset, domain_size);

        let expected = multilinear_extend(&full, &point);
        let actual = covector.mle_evaluate(&point);

        assert_eq!(actual, expected);
    }

    #[test]
    fn accumulate_writes_correct_positions() {
        let domain_size = 16;
        let offset = 5;
        let weights = vec![fe(7), fe(3), fe(11)];
        let scalar = fe(4);

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
        let mut accumulator = vec![FieldElement::zero(); domain_size];
        covector.accumulate(&mut accumulator, scalar);

        for i in 0..domain_size {
            if i >= offset && i < offset + weights.len() {
                assert_eq!(
                    accumulator[i],
                    scalar * weights[i - offset],
                    "mismatch at position {i}"
                );
            } else {
                assert_eq!(
                    accumulator[i],
                    FieldElement::zero(),
                    "expected zero at position {i}"
                );
            }
        }
    }

    #[test]
    fn accumulate_adds_to_existing_values() {
        let domain_size = 8;
        let offset = 2;
        let weights = vec![fe(3), fe(5)];
        let scalar = fe(2);

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);
        let mut accumulator = vec![fe(100); domain_size];
        covector.accumulate(&mut accumulator, scalar);

        assert_eq!(accumulator[0], fe(100));
        assert_eq!(accumulator[1], fe(100));
        assert_eq!(accumulator[2], fe(100) + scalar * fe(3));
        assert_eq!(accumulator[3], fe(100) + scalar * fe(5));
        assert_eq!(accumulator[4], fe(100));
    }

    #[test]
    fn mle_and_accumulate_are_consistent() {
        // For a given covector v and polynomial p (as full vector),
        // dot(v_full, p) should equal mle_evaluate(point) when p = basis,
        // but more practically: accumulate followed by dot should give
        // the same linear combination as the mle on random-ish points.
        let domain_size = 8;
        let offset = 3;
        let weights = vec![fe(2), fe(7), fe(13)];

        let covector = OffsetCovector::new(weights.clone(), offset, domain_size);

        // Build the full weight vector via accumulate
        let mut full_weights = vec![FieldElement::zero(); domain_size];
        covector.accumulate(&mut full_weights, FieldElement::one());

        // Verify it matches the expected sparse layout
        let expected_full = full_vector(&weights, offset, domain_size);
        assert_eq!(full_weights, expected_full);

        // Now verify MLE evaluation consistency: the MLE of the accumulated
        // vector should equal what mle_evaluate returns.
        let point = vec![fe(5), fe(11), fe(17)];
        let mle_from_full = multilinear_extend(&full_weights, &point);
        let mle_from_covector = covector.mle_evaluate(&point);

        assert_eq!(mle_from_full, mle_from_covector);
    }

    #[test]
    fn size_returns_domain_size() {
        let covector = OffsetCovector::new(vec![fe(1)], 3, 16);
        assert_eq!(covector.size(), 16);
    }

    #[test]
    #[should_panic(expected = "exceeds domain_size")]
    fn new_panics_on_out_of_bounds() {
        // offset + weights.len() = 7 + 2 = 9 > 8
        let _ = OffsetCovector::new(vec![fe(1), fe(2)], 7, 8);
    }

    #[test]
    fn sparse_covector_mle_matches_dense() {
        let entries = vec![(0, fe(3)), (3, fe(7))];
        let sc = SparseCovector::new(entries, 4);
        let mut dense = vec![FieldElement::zero(); 4];
        dense[0] = fe(3);
        dense[3] = fe(7);
        let pc = PrefixCovector::new(dense, 4);
        let point = vec![fe(2), fe(5)];
        assert_eq!(sc.mle_evaluate(&point), pc.mle_evaluate(&point));
    }

    #[test]
    fn sparse_covector_accumulate() {
        let entries = vec![(1, fe(4)), (3, fe(2))];
        let sc = SparseCovector::new(entries, 4);
        let mut acc = vec![FieldElement::zero(); 4];
        sc.accumulate(&mut acc, fe(3));
        assert_eq!(acc[0], FieldElement::zero());
        assert_eq!(acc[1], fe(12));
        assert_eq!(acc[2], FieldElement::zero());
        assert_eq!(acc[3], fe(6));
    }

    #[test]
    fn make_challenge_weight_consistency() {
        let x = fe(11);
        let offsets = vec![2, 5, 9];
        let cw = make_challenge_weight(x, &offsets, 4);
        assert_eq!(cw.size(), 16);
        let mut poly = vec![FieldElement::zero(); 16];
        poly[2] = fe(100);
        poly[5] = fe(200);
        poly[9] = fe(300);
        let eval = compute_challenge_eval(x, &offsets, &poly);
        let mut acc = vec![FieldElement::zero(); 16];
        cw.accumulate(&mut acc, FieldElement::one());
        let dot: FieldElement = acc.iter().zip(poly.iter()).map(|(a, b)| *a * *b).sum();
        assert_eq!(eval, dot);
    }

    #[test]
    fn compute_challenge_eval_basic() {
        let x = fe(3);
        let offsets = vec![0, 2];
        let poly = vec![fe(10), fe(20), fe(30)];
        let eval = compute_challenge_eval(x, &offsets, &poly);
        assert_eq!(eval, fe(10) + fe(3) * fe(30));
    }

    #[test]
    fn sparse_covector_empty_entries() {
        let sc = SparseCovector::new(vec![], 8);
        let point = vec![fe(1), fe(2), fe(3)];
        assert_eq!(sc.mle_evaluate(&point), FieldElement::zero());
    }

    #[test]
    fn sparse_covector_single_entry_matches_prefix() {
        let sc = SparseCovector::new(vec![(0, fe(5))], 4);
        let pc = PrefixCovector::new(vec![fe(5), FieldElement::zero()], 4);
        let point = vec![fe(7), fe(11)];
        assert_eq!(sc.mle_evaluate(&point), pc.mle_evaluate(&point));
    }
}
