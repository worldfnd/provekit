use {
    crate::{
        utils::{pad_to_power_of_two, unzip_double_array, workload_size},
        FieldElement, R1CS,
    },
    ark_std::{One, Zero},
    rayon::iter::{IndexedParallelIterator as _, IntoParallelRefIterator, ParallelIterator as _},
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    std::array,
    tracing::instrument,
};

/// Compute the sum of a vector valued function over the boolean hypercube in
/// the leading variable.
// TODO: Figure out a way to also half the mles on folding
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

/// Trait which is used to add sumcheck functionality fo `IOPattern`
pub trait SumcheckIOPattern {
    /// Prover sends coefficients of the qubic sumcheck polynomial and the
    /// verifier sends randomness for the next sumcheck round
    fn add_sumcheck_polynomials(self, num_vars: usize) -> Self;

    fn add_sumcheck_quadratic_polynomials(self, num_vars: usize) -> Self;

    /// Verifier sends the randomness on which the supposed 0-polynomial is
    /// evaluated
    fn add_rand(self, num_rand: usize) -> Self;
}

impl<IOPattern> SumcheckIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_sumcheck_polynomials(mut self, num_vars: usize) -> Self {
        for _ in 0..num_vars {
            self = self.add_scalars(4, "Sumcheck Polynomials");
            self = self.challenge_scalars(1, "Sumcheck Random");
        }
        self
    }

    //TODO: Potentially merge this with add_sumcheck_polynomials
    fn add_sumcheck_quadratic_polynomials(mut self, num_vars: usize) -> Self {
        for _ in 0..num_vars {
            self = self.add_scalars(2, "Sumcheck Polynomials");
            self = self.challenge_scalars(1, "Sumcheck Random");
        }
        self
    }

    fn add_rand(self, num_rand: usize) -> Self {
        self.challenge_scalars(num_rand, "rand")
    }
}

/// List of evaluations for eq(r, x) over the boolean hypercube
#[instrument(skip_all)]
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &[FieldElement],
) -> Vec<FieldElement> {
    let mut result = vec![FieldElement::zero(); 1 << r.len()];
    eval_eq(r, &mut result, FieldElement::one());
    result
}

/// Evaluates the equality polynomial recursively.
fn eval_eq(eval: &[FieldElement], out: &mut [FieldElement], scalar: FieldElement) {
    debug_assert_eq!(out.len(), 1 << eval.len());
    let size = out.len();
    if let Some((&x, tail)) = eval.split_first() {
        let (o0, o1) = out.split_at_mut(out.len() / 2);
        let s1 = scalar * x;
        let s0 = scalar - s1;
        if size > workload_size::<FieldElement>() {
            rayon::join(|| eval_eq(tail, o0, s0), || eval_eq(tail, o1, s1));
        } else {
            eval_eq(tail, o0, s0);
            eval_eq(tail, o1, s1);
        }
    } else {
        out[0] += scalar;
    }
}

/// Evaluates a qubic polynomial on a value
pub fn eval_qubic_poly(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

/// Given a path to JSON file with sparce matrices and a witness, calculates
/// matrix-vector multiplication and returns them
#[instrument(skip_all)]
pub fn calculate_witness_bounds(
    r1cs: &R1CS,
    witness: &[FieldElement],
) -> (Vec<FieldElement>, Vec<FieldElement>, Vec<FieldElement>) {
    let (a, b) = rayon::join(|| r1cs.a() * witness, || r1cs.b() * witness);
    // Derive C from R1CS relation (faster than matrix multiplication)
    let c = a.par_iter().zip(b.par_iter()).map(|(a, b)| a * b).collect();
    (
        pad_to_power_of_two(a),
        pad_to_power_of_two(b),
        pad_to_power_of_two(c),
    )
}

/// Calculates eq(r, alpha)
pub fn calculate_eq(r: &[FieldElement], alpha: &[FieldElement]) -> FieldElement {
    r.iter()
        .zip(alpha.iter())
        .fold(FieldElement::from(1), |acc, (&r, &alpha)| {
            acc * (r * alpha + (FieldElement::from(1) - r) * (FieldElement::from(1) - alpha))
        })
}

/// Calculates a random row of R1CS matrix extension. Made possible due to
/// sparseness.
#[instrument(skip_all)]
pub fn calculate_external_row_of_r1cs_matrices(
    alpha: &[FieldElement],
    r1cs: &R1CS,
) -> [Vec<FieldElement>; 3] {
    let eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(alpha);
    let eq_alpha = &eq_alpha[..r1cs.num_constraints()];
    let ((a, b), c) = rayon::join(
        || rayon::join(|| eq_alpha * r1cs.a(), || eq_alpha * r1cs.b()),
        || eq_alpha * r1cs.c(),
    );
    [a, b, c]
}
