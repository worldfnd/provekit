//! Linear claims for the virtual two-stage witness `[w1, w2]`.
//!
//! Each block has size `2^m`. Matrix columns split at `w1_size` before padding.
//! Claim order is A, B, C, public inputs, then challenges.

use {
    crate::{
        prefix_covector::{build_prefix_covectors, make_challenge_weight, make_public_weight},
        JointLinearForm,
    },
    anyhow::{ensure, Result},
    ark_ff::Field,
};

/// Build combined matrix forms and optional binding forms.
///
/// Public inputs belong to the first block. Challenge offsets refer to the
/// second block. The R1CS constant at index zero accompanies each public-input
/// form.
pub fn build_joint_forms<F: Field + 'static>(
    m: usize,
    w1_size: usize,
    alphas: [Vec<F>; 3],
    binding_challenge: F,
    num_public_inputs: usize,
    challenge_offsets: &[usize],
) -> Result<Vec<JointLinearForm<F>>> {
    ensure!(
        m > 0 && m < usize::BITS as usize - 1,
        "Invalid joint block dimension"
    );
    let block_size = 1usize << m;
    let total_size = alphas[0].len();
    ensure!(
        alphas.iter().all(|alpha| alpha.len() == total_size),
        "Joint matrix covectors must have equal lengths"
    );
    ensure!(
        w1_size <= total_size,
        "Witness split exceeds matrix columns"
    );
    ensure!(
        w1_size <= block_size && total_size - w1_size <= block_size,
        "Witness block exceeds the joint block size"
    );
    if num_public_inputs > 0 {
        ensure!(
            num_public_inputs < w1_size,
            "Public inputs exceed the first witness block"
        );
    }
    ensure!(
        challenge_offsets
            .iter()
            .all(|&offset| offset < total_size - w1_size),
        "Challenge offset exceeds the second witness block"
    );

    let mut forms = Vec::with_capacity(5);
    for mut alpha in alphas {
        let right = alpha.split_off(w1_size);
        let mut blocks = build_prefix_covectors(m, [alpha, right]).into_iter();
        let left = blocks.next().expect("first matrix block");
        let right = blocks.next().expect("second matrix block");
        forms.push(JointLinearForm::new(left, right));
    }
    if num_public_inputs > 0 {
        forms.push(JointLinearForm::left_only(make_public_weight(
            binding_challenge,
            num_public_inputs,
            m,
        )));
    }
    if !challenge_offsets.is_empty() {
        forms.push(JointLinearForm::right_only(make_challenge_weight(
            binding_challenge,
            challenge_offsets,
            m,
        )));
    }
    Ok(forms)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        whir::algebra::{fields::Field64 as F, linear_form::LinearForm, multilinear_extend},
    };

    fn fields(values: &[u64]) -> Vec<F> {
        values.iter().copied().map(F::from).collect()
    }

    fn dense(form: &JointLinearForm<F>) -> Vec<F> {
        let mut weights = vec![F::from(0); form.size()];
        form.accumulate(&mut weights, F::from(1));
        weights
    }

    fn dot(weights: &[F], witness: &[F]) -> F {
        weights.iter().zip(witness).map(|(a, b)| *a * b).sum()
    }

    #[test]
    fn joint_claims_prove_three_times_four_equals_twelve() {
        // Original columns: w1 = [1, 3, 12], w2 = [4, 9].
        // A selects 3. B selects 4. C selects 12.
        let forms = build_joint_forms(
            2,
            3,
            [
                fields(&[0, 1, 0, 0, 0]),
                fields(&[0, 0, 0, 1, 0]),
                fields(&[0, 0, 1, 0, 0]),
            ],
            F::from(2),
            0,
            &[],
        )
        .unwrap();
        let witness = fields(&[1, 3, 12, 0, 4, 9, 0, 0]);
        let values: Vec<F> = forms
            .iter()
            .map(|form| dot(&dense(form), &witness))
            .collect();
        assert_eq!(values, fields(&[3, 4, 12]));
        assert_eq!(values[0] * values[1], values[2]);

        // Changing either selected witness breaks the same constraint.
        for changed_index in [1, 4] {
            let mut changed = witness.clone();
            changed[changed_index] += F::from(1);
            let values: Vec<F> = forms
                .iter()
                .map(|form| dot(&dense(form), &changed))
                .collect();
            assert_ne!(values[0] * values[1], values[2]);
        }
    }

    #[test]
    fn joint_claims_add_stage_contributions_without_selector_weights() {
        let forms = build_joint_forms(
            2,
            3,
            [
                fields(&[2, 3, 4, 11, 13]),
                fields(&[0, 1, 0, 0, 1]),
                fields(&[0, 0, 1, 1, 0]),
            ],
            F::from(2),
            0,
            &[],
        )
        .unwrap();
        let witness = fields(&[1, 2, 3, 0, 5, 7, 0, 0]);
        // A = (2 + 6 + 12) + (55 + 91) = 166.
        let values: Vec<F> = forms
            .iter()
            .map(|form| dot(&dense(form), &witness))
            .collect();
        assert_eq!(values, fields(&[166, 9, 8]));
    }

    #[test]
    fn joint_claims_keep_public_inputs_left_and_scattered_challenges_right() {
        let forms = build_joint_forms(
            2,
            3,
            [fields(&[0; 6]), fields(&[0; 6]), fields(&[0; 6])],
            F::from(2),
            1,
            &[2, 0],
        )
        .unwrap();
        assert_eq!(forms.len(), 5);
        assert_eq!(dense(&forms[3]), fields(&[1, 2, 0, 0, 0, 0, 0, 0]));
        assert_eq!(dense(&forms[4]), fields(&[0, 0, 0, 0, 2, 0, 1, 0]));

        let witness = fields(&[1, 3, 12, 0, 4, 9, 5, 0]);
        assert_eq!(dot(&dense(&forms[3]), &witness), F::from(7)); // 1 + 2*3
        assert_eq!(dot(&dense(&forms[4]), &witness), F::from(13)); // 5 + 2*4
    }

    #[test]
    fn joint_claims_final_matrix_evaluations_match_the_combined_dense_matrix() {
        let forms = build_joint_forms(
            2,
            3,
            [
                fields(&[2, 3, 4, 11, 13]),
                fields(&[0, 1, 0, 0, 1]),
                fields(&[0, 0, 1, 1, 0]),
            ],
            F::from(2),
            0,
            &[],
        )
        .unwrap();
        let point = fields(&[2, 3, 5]);
        for form in &forms {
            assert_eq!(
                form.mle_evaluate(&point),
                multilinear_extend(&dense(form), &point)
            );
        }
    }

    #[test]
    fn joint_claims_support_a_larger_second_stage_and_empty_stage() {
        for split in [0, 1, 3, 4] {
            let forms = build_joint_forms(
                2,
                split,
                std::array::from_fn(|_| fields(&[1, 2, 3, 4])),
                F::from(2),
                0,
                &[],
            )
            .unwrap();
            let mut expected = vec![F::from(0); 8];
            expected[..split].copy_from_slice(&fields(&[1, 2, 3, 4])[..split]);
            expected[4..4 + 4 - split].copy_from_slice(&fields(&[1, 2, 3, 4])[split..]);
            assert_eq!(dense(&forms[0]), expected);
        }
    }

    #[test]
    fn joint_claims_reject_invalid_layouts_and_binding_positions() {
        let alphas = || std::array::from_fn(|_| fields(&[1, 2, 3, 4, 5]));
        assert!(build_joint_forms(2, 6, alphas(), F::from(2), 0, &[]).is_err());
        assert!(build_joint_forms(2, 0, alphas(), F::from(2), 0, &[]).is_err());
        assert!(build_joint_forms(2, 3, alphas(), F::from(2), 3, &[]).is_err());
        assert!(build_joint_forms(2, 3, alphas(), F::from(2), 0, &[2]).is_err());
        assert!(build_joint_forms(
            2,
            3,
            [fields(&[1; 5]), fields(&[1; 4]), fields(&[1; 5])],
            F::from(2),
            0,
            &[]
        )
        .is_err());
    }
}
