use {
    crate::FieldElement,
    ark_ff::{Field, UniformRand},
    rayon::prelude::*,
    whir::poly_utils::evals::EvaluationsList,
};

pub fn create_masked_polynomial(
    original: EvaluationsList<FieldElement>,
    mask: &[FieldElement],
) -> EvaluationsList<FieldElement> {
    let mut combined = Vec::with_capacity(original.num_evals() * 2);
    combined.extend_from_slice(original.evals());
    combined.extend_from_slice(mask);
    EvaluationsList::new(combined)
}

pub fn generate_random_multilinear_polynomial(num_vars: usize) -> Vec<FieldElement> {
    let num_elements = 1 << num_vars;
    let mut elements = Vec::with_capacity(num_elements);

    // TODO(px): find the optimal chunk size
    const CHUNK_SIZE: usize = 32;

    // Get access to the uninitialized memory
    let spare = elements.spare_capacity_mut();

    // Fill the uninitialized memory in parallel using chunked approach
    spare.par_chunks_mut(CHUNK_SIZE).for_each(|chunk| {
        let mut rng = ark_std::rand::thread_rng();
        for element in chunk {
            element.write(FieldElement::rand(&mut rng));
        }
    });

    unsafe {
        elements.set_len(num_elements);
    }

    elements
}

/// Evaluates the mle of a polynomial from evaluations in a geometric
/// progression.
///
/// The evaluation list is of the form [1,a,a^2,a^3,...,a^{n-1},0,...,0]
/// a is the base of the geometric progression.
/// n is the number of non-zero terms in the progression.
pub fn geometric_till<F: Field>(mut a: F, n: usize, x: &[F]) -> F {
    let k = x.len();
    assert!(n > 0 && n < (1 << k));
    let mut borrow_0 = F::one();
    let mut borrow_1 = F::zero();
    for (i, &xi) in x.iter().rev().enumerate() {
        let bn = ((n - 1) >> i) & 1;
        let b0 = F::one() - xi;
        let b1 = a * xi;
        (borrow_0, borrow_1) = if bn == 0 {
            (b0 * borrow_0, (b0 + b1) * borrow_1 + b1 * borrow_0)
        } else {
            ((b0 + b1) * borrow_0 + b0 * borrow_1, b1 * borrow_1)
        };
        a = a.square();
    }
    borrow_0
}
