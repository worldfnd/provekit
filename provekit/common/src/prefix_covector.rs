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

    fn deferred(&self) -> bool {
        false
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

    fn deferred(&self) -> bool {
        false
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
