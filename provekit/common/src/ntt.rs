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
        expansion: usize,
        interleaving_depth: usize,
    ) -> Vec<FieldElement> {
        debug_assert!(expansion > 0);
        interleaved_rs_encode(interleaved_coeffs, expansion, interleaving_depth)
    }

    fn evaluation_order(&self) -> whir::algebra::ntt::EvaluationOrder {
        whir::algebra::ntt::EvaluationOrder::InPlace
    }
}

fn interleaved_rs_encode(
    coeffs: &[&[FieldElement]],
    expansion: usize,
    interleaving_depth: usize,
) -> Vec<FieldElement> {
    assert!(expansion > 0);
    if coeffs.is_empty() {
        return Vec::new();
    }

    let poly_size = coeffs[0].len();
    assert!(poly_size.is_multiple_of(interleaving_depth));
    for poly in coeffs {
        assert_eq!(poly.len(), poly_size);
    }

    let expanded_size = coeffs.len() * expansion * poly_size;

    let mut result = vec![FieldElement::ZERO; expanded_size];

    let k = interleaving_depth * coeffs.len();
    let block_size = poly_size / interleaving_depth;
    for i in 0..block_size {
        let row = &mut result[i * k..(i + 1) * k];
        for (poly_index, poly) in coeffs.iter().enumerate() {
            for d in 0..interleaving_depth {
                row[poly_index * interleaving_depth + d] = poly[d * block_size + i];
            }
        }
    }

    let mut ntt = ntt::NTT::new(result, k)
        .expect("poly_size * expansion / interleaving_depth needs to be a power of two.");

    ntt_nr(&mut ntt);

    ntt.into_inner()
}

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
pub fn register_ntt() {
    use std::sync::{Arc, Once};
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
        //     Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default());
        // whir::algebra::ntt::NTT.insert(ntt);
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> =
            Arc::new(InPlaceNTT::<FieldElement>::default());
        whir::algebra::ntt::NTT.insert(ntt);

        let skyscraper: Arc<dyn whir::hash::HashEngine> =
            Arc::new(crate::skyscraper::SkyscraperHashEngine);
        whir::hash::ENGINES.register(skyscraper);
    });
}
