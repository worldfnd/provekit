use {
    crate::FieldElement, ark_ff::AdditiveGroup, provekit_ntt::ntt_nr, rayon::prelude::*,
    whir::algebra::ntt::ReedSolomon,
};

#[derive(Debug)]
pub struct RSFr;

impl ReedSolomon<FieldElement> for RSFr {
    fn interleaved_encode(
        &self,
        coeffs: &[&[FieldElement]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<FieldElement> {
        if coeffs.is_empty() {
            return Vec::new();
        }

        let poly_size = coeffs[0].len();
        for poly in coeffs {
            assert_eq!(poly_size, poly.len());
        }
        assert!(poly_size.is_multiple_of(interleaving_depth));
        assert!(codeword_length.is_power_of_two());

        let message_length = poly_size / interleaving_depth;
        assert!(codeword_length.is_multiple_of(message_length));

        interleaved_rs_encode(coeffs, codeword_length, message_length, interleaving_depth)
    }
}

fn interleaved_rs_encode(
    coeffs: &[&[FieldElement]],
    codeword_length: usize,
    message_length: usize,
    interleaving_depth: usize,
) -> Vec<FieldElement> {
    let column_count = coeffs.len() * interleaving_depth;
    let mut result = vec![FieldElement::ZERO; codeword_length * column_count];

    write_interleaved_coefficients(
        &mut result[..message_length * column_count],
        coeffs,
        message_length,
        interleaving_depth,
    );

    ntt_nr(&mut result, codeword_length, 1);
    bit_reverse_rows(&mut result, codeword_length, column_count);
    result
}

fn write_interleaved_coefficients(
    interleaved_coeffs: &mut [FieldElement],
    coeffs: &[&[FieldElement]],
    message_length: usize,
    interleaving_depth: usize,
) {
    let column_count = coeffs.len() * interleaving_depth;
    debug_assert_eq!(interleaved_coeffs.len(), message_length * column_count);

    for (column_index, column_coeffs) in coeffs
        .iter()
        .flat_map(|poly| poly.chunks_exact(message_length))
        .enumerate()
    {
        for (row, &coeff) in interleaved_coeffs
            .chunks_exact_mut(column_count)
            .zip(column_coeffs)
        {
            row[column_index] = coeff;
        }
    }
}

fn bit_reverse_rows(matrix: &mut [FieldElement], rows: usize, cols: usize) {
    debug_assert_eq!(matrix.len(), rows * cols);
    debug_assert!(rows.is_power_of_two());

    let bits = rows.trailing_zeros();
    let ptr = matrix.as_mut_ptr() as usize;

    let swap_bit_reversed_pair = |row: usize| {
        let rev = row.reverse_bits() >> (usize::BITS - bits);
        if row < rev {
            // Bit reversal is an involution; keeping only row < rev gives each
            // worker a disjoint row pair.
            unsafe {
                std::ptr::swap_nonoverlapping(
                    (ptr as *mut FieldElement).add(row * cols),
                    (ptr as *mut FieldElement).add(rev * cols),
                    cols,
                );
            }
        }
    };

    if rows >= 1 << 14 {
        (0..rows).into_par_iter().for_each(swap_bit_reversed_pair);
    } else {
        (0..rows).for_each(swap_bit_reversed_pair);
    }
}

#[cfg(test)]
mod tests {
    use {super::*, whir::algebra::ntt::ArkNtt};

    #[test]
    fn matches_ark_ntt_for_interleaved_encode() {
        let poly_a: Vec<_> = (0..16).map(FieldElement::from).collect();
        let poly_b: Vec<_> = (20..36).map(FieldElement::from).collect();
        let coeffs = vec![poly_a.as_slice(), poly_b.as_slice()];

        let fast = RSFr.interleaved_encode(&coeffs, 32, 4);
        let reference = ArkNtt::<FieldElement>::default().interleaved_encode(&coeffs, 32, 4);

        assert_eq!(fast, reference);
    }
}
