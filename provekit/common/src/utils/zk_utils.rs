use {
    crate::FieldElement,
    whir::algebra::{
        dot, linear_form::Covector, ntt::wavelet_transform, polynomials::CoefficientList,
    },
};

/// Transform coefficients to evaluation form. Avoids the per-call
/// clone+transform inside `Covector::evaluate`.
pub fn coeffs_to_evals(poly: &CoefficientList<FieldElement>) -> Vec<FieldElement> {
    let mut evals = poly.coeffs().to_vec();
    wavelet_transform(&mut evals);
    evals
}

/// Dot product of a covector's weight vector against pre-transformed
/// evaluations.
pub fn covector_dot(w: &Covector<FieldElement>, evals: &[FieldElement]) -> FieldElement {
    dot(&w.vector, evals)
}
