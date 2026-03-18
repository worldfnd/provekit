use {
    ark_bn254::Fr as FieldElement, ark_ff::AdditiveGroup, ntt::ntt_nr, std::marker::PhantomData,
    whir::algebra::ntt::ReedSolomon,
};

#[derive(Debug, Default)]
pub struct InPlaceNTT<T>(PhantomData<T>);

impl ReedSolomon<FieldElement> for InPlaceNTT<FieldElement> {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[FieldElement]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<FieldElement> {
        debug_assert!(codeword_length > 0);
        interleaved_rs_encode(interleaved_coeffs, codeword_length, interleaving_depth)
    }

    fn evaluation_order(&self) -> whir::algebra::ntt::EvaluationOrder {
        whir::algebra::ntt::EvaluationOrder::InPlace
    }
}

fn interleaved_rs_encode(
    coeffs: &[&[FieldElement]],
    codeword_length: usize,
    interleaving_depth: usize,
) -> Vec<FieldElement> {
    assert!(codeword_length > 0);
    if coeffs.is_empty() {
        return Vec::new();
    }

    let poly_size = coeffs[0].len();
    for poly in coeffs {
        assert_eq!(poly.len(), poly_size);
    }
    assert!(poly_size.is_multiple_of(interleaving_depth));
    let message_length = poly_size / interleaving_depth;

    let per_poly_size = codeword_length * interleaving_depth; // codeword_length * interleaving_depth = message_length * expanstion *
                                                              // interleaving depth = poly_size / interleaving_depth * expansion *
                                                              // interleaving depth = poly_size * expansion.;

    let total_size = coeffs.len() * per_poly_size;

    let mut result = vec![FieldElement::ZERO; total_size];

    let k = interleaving_depth * coeffs.len();
    for i in 0..message_length {
        let row = &mut result[i * k..(i + 1) * k];
        for (poly_index, poly) in coeffs.iter().enumerate() {
            for d in 0..interleaving_depth {
                row[poly_index * interleaving_depth + d] = poly[d * message_length + i];
            }
        }
    }

    let mut ntt = ntt::NTT::new(result, k)
        .expect("poly_size * expansion / interleaving_depth needs to be a power of two.");

    ntt_nr(&mut ntt);

    ntt.into_inner()
}
