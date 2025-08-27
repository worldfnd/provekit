use noir_r1cs::{utils::{sumcheck::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_qubic_poly, sumcheck_fold_map_reduce}, HALF}, FieldElement, SkyscraperSponge};
use spongefish::{codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField}, ProverState};
use whir::poly_utils::evals::EvaluationsList;

// TODO: Fix gpa and add line integration

pub fn run_gpa (
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    left: &Vec<FieldElement>, 
    right: &Vec<FieldElement>,
) {
    let mut h = left.clone();
    h.extend(right.iter().cloned());
    let layers = calculate_binary_multiplication_tree(h);
    
    let mut saved_val_for_sumcheck_equality_assertion;
    let mut r;
    let mut line_evaluations;
    let mut alpha = Vec::<FieldElement>::new();

    (r, saved_val_for_sumcheck_equality_assertion) = add_line_to_merlin(merlin, layers[1].clone());

    for i in 2..layers.len() {
        (line_evaluations, alpha) = run_gpa_sumcheck(merlin, &r, layers[i].clone(), saved_val_for_sumcheck_equality_assertion, alpha);
        (r, saved_val_for_sumcheck_equality_assertion) = add_line_to_merlin(merlin, line_evaluations.to_vec());
    }

    alpha.push(r[0]);
}

fn calculate_binary_multiplication_tree(array_to_prove: Vec<FieldElement>) -> Vec<Vec<FieldElement>> {
    let mut layers = vec![];
    let mut current_layer = array_to_prove;

    while current_layer.len() > 1 {
        let mut next_layer = vec![];

        for i in (0..current_layer.len()).step_by(2) {
            let product = current_layer[i] * current_layer[i + 1];
            next_layer.push(product);
        }

        layers.push(current_layer);
        current_layer = next_layer;
    }

    layers.push(current_layer);
    layers.reverse();
    layers
}

fn add_line_to_merlin( merlin: &mut ProverState<SkyscraperSponge, FieldElement>, arr: Vec<FieldElement>) -> ([FieldElement; 1], FieldElement) {
    let l_evaluations = EvaluationsList::new(arr);
    let l_temp = l_evaluations.to_coeffs();
    let l: &[FieldElement] = l_temp.coeffs();
    merlin
        .add_scalars(&l)
        .expect("Failed to add l");

    let mut r = [FieldElement::from(0); 1];
    merlin.fill_challenge_scalars(&mut r)
        .expect("Failed to add a challenge scalar");

    let saved_val_for_sumcheck_equality_assertion = l[0] + l[1] * r[0];

    (r, saved_val_for_sumcheck_equality_assertion)
}

fn run_gpa_sumcheck(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    r: &[FieldElement; 1],
    layer: Vec<FieldElement>,
    mut saved_val_for_sumcheck_equality_assertion: FieldElement,
    mut alpha: Vec<FieldElement>,
) -> ([FieldElement; 2], Vec<FieldElement>) {
    let (mut v0, mut v1) = split_by_index(layer);
    alpha.push(r[0]);
    let mut eq_r = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let mut alpha_i_wrapped_in_vector = [FieldElement::from(0)];
    let mut alpha = Vec::<FieldElement>::new();
    let mut fold = None;

    loop {
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut eq_r, &mut v0, &mut v1], fold, |[eq_r, v0, v1]| {
                [
                    // Evaluation at 0
                    eq_r.0 * v0.0 * v1.0,
                    // Evaluation at -1
                    (eq_r.0 + eq_r.0 - eq_r.1) * (v0.0 + v0.0 - v0.1) * (v1.0 + v1.0 - v1.1),
                    // Evaluation at infinity
                    (eq_r.1 - eq_r.0) * (v0.1 - v0.0) * (v1.1 - v1.0),
                ]
            });

        if fold.is_some() {
            eq_r.truncate(eq_r.len() / 2);
            v0.truncate(v0.len() / 2);
            v1.truncate(v1.len() / 2);
        }

        let mut hhat_i_coeffs = [FieldElement::from(0); 4];
        
        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] = HALF
            * (saved_val_for_sumcheck_equality_assertion + hhat_i_at_em1
                - hhat_i_at_0
                - hhat_i_at_0
                - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = saved_val_for_sumcheck_equality_assertion
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        assert_eq!(
            saved_val_for_sumcheck_equality_assertion,
            hhat_i_coeffs[0]
                + hhat_i_coeffs[0]
                + hhat_i_coeffs[1]
                + hhat_i_coeffs[2]
                + hhat_i_coeffs[3]
        );
        
        let _ = merlin.add_scalars(&hhat_i_coeffs[..]);
        let _ = merlin.fill_challenge_scalars(&mut alpha_i_wrapped_in_vector);
        fold = Some(alpha_i_wrapped_in_vector[0]);
        saved_val_for_sumcheck_equality_assertion = eval_qubic_poly(&hhat_i_coeffs, &alpha_i_wrapped_in_vector[0]);
        alpha.push(alpha_i_wrapped_in_vector[0]);
        if eq_r.len() <= 2 {
            break;
        }
    }

    let folded_v0 = v0[0] + (v0[1] - v0[0]) * alpha_i_wrapped_in_vector[0];
    let folded_v1 = v1[0] + (v1[1] - v1[0]) * alpha_i_wrapped_in_vector[0];

    ([folded_v0, folded_v1], alpha) 
}

fn split_by_index(input: Vec<FieldElement>) -> (Vec<FieldElement>, Vec<FieldElement>) {
    let mut even_indexed = Vec::new();
    let mut odd_indexed = Vec::new();

    for (i, item) in input.into_iter().enumerate() {
        if i % 2 == 0 {
            even_indexed.push(item);
        } else {
            odd_indexed.push(item);
        }
    }

    (even_indexed, odd_indexed)
}