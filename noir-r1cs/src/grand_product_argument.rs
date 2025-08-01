use spongefish::{codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField}, ProverState, VerifierState};
use whir::{poly_utils::{evals::EvaluationsList}};

use crate::{skyscraper::SkyscraperSponge, utils::{sumcheck::{calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_qubic_poly, sumcheck_fold_map_reduce}, HALF}, FieldElement};
use anyhow::{ensure, Context, Result};
use ark_std::Zero;

pub struct GrandProductArgument {
    pub randomness: Vec<FieldElement>,
}

impl GrandProductArgument {
    pub fn new(
        addr: Vec<FieldElement>,
        value: Vec<FieldElement>,
        time_stamp: Vec<FieldElement>,
        tau: FieldElement,
        gamma: FieldElement,
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    ) -> Self {
        let h: Vec<FieldElement> = addr
            .iter()
            .zip(value.iter())
            .zip(time_stamp.iter())
            .map(|((a, v), t)| Self::h(&gamma, a, v, t)-tau)
            .collect();
        let layers = Self::calculate_binary_multiplication_tree(h);
        
        let _ = merlin.add_scalars(&layers[0]);

        let mut saved_val_for_sumcheck_equality_assertion;
        let mut r;
        let mut line_evaluations;
        let mut alpha = Vec::<FieldElement>::new();

        (r, saved_val_for_sumcheck_equality_assertion) = Self::add_line_to_merlin(merlin, layers[1].clone());

        for i in 2..layers.len() {
            (line_evaluations, alpha) = Self::run_sumcheck(merlin, &r, layers[i].clone(), saved_val_for_sumcheck_equality_assertion, alpha);
            (r, saved_val_for_sumcheck_equality_assertion) = Self::add_line_to_merlin(merlin, line_evaluations.to_vec());
        }
        alpha.push(r[0]);
        
        GrandProductArgument {
            randomness: alpha,
        }
    }
    
    fn h(gamma : &FieldElement, a: &FieldElement, v: &FieldElement, t: &FieldElement) -> FieldElement {
        a * gamma * gamma + v * gamma + t
    }

    fn calculate_binary_multiplication_tree(array_to_prove: Vec<FieldElement>) -> Vec<Vec<FieldElement>> {
        // TODO assert if size is pow of 2
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
    
        let saved_val_for_sumcheck_equality_assertion = Self::eval_linear_poly(&l, &r[0]);
    
        (r, saved_val_for_sumcheck_equality_assertion)
    }

    pub fn eval_linear_poly(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
        poly[0] + *point * poly[1]
    }

    fn run_sumcheck(
        merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
        r: &[FieldElement; 1],
        layer: Vec<FieldElement>,
        mut saved_val_for_sumcheck_equality_assertion: FieldElement,
        mut alpha: Vec<FieldElement>,
    ) -> ([FieldElement; 2], Vec<FieldElement>) {
        let (mut v0, mut v1) = Self::split_by_index(layer);
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
    
}

pub fn run_gpa_init_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    tau: &FieldElement,
    gamma: &FieldElement,
    layer_count: usize,
    randomness:  Vec<FieldElement>,
) -> Result<FieldElement> {
    let gpa_result = gpa_sumcheck_verifier(arthur, layer_count)
        .context("while verifying GPA sumcheck")?;

    let adr = calculate_adr(&gpa_result.randomness);
    let mem = calculate_eq(&randomness, &gpa_result.randomness);
    let cntr = FieldElement::from(0);

    ensure!(
        gpa_result.last_sumcheck_value == adr * gamma * gamma + mem * gamma + cntr - tau,
        "spark last failed"
    );

    Ok(gpa_result.claimed_product)
}

pub fn calculate_adr(alpha: &Vec<FieldElement>) -> FieldElement {
    let mut ans = FieldElement::from(0);
    let mut mult = FieldElement::from(1);
    for a in alpha.iter().rev() {
        ans = ans + *a * mult;
        mult = mult * FieldElement::from(2);
    }
    ans
}

pub fn gpa_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    height_of_binary_tree: usize,
) -> Result<GPASumcheckResult> {
    let mut prev_rand = Vec::<FieldElement>::new();
    let mut rand = Vec::<FieldElement>::new();
    let mut l = [FieldElement::from(0); 2];
    let mut r = [FieldElement::from(0); 1];
    let mut h = [FieldElement::from(0); 4];
    let mut alpha = [FieldElement::from(0); 1];
    let mut gpa_claimed_product = [FieldElement::from(0); 1];
    arthur
        .fill_next_scalars(&mut gpa_claimed_product)
        .expect("Failed to fill next scalars");
    let mut last_sumcheck_value = gpa_claimed_product[0];
    for i in 0..height_of_binary_tree - 1 {
        for _ in 0..i {
            arthur
                .fill_next_scalars(&mut h)
                .expect("Failed to fill next scalars");
            arthur
                .fill_challenge_scalars(&mut alpha)
                .expect("Failed to fill next scalars");
            assert_eq!(
                eval_qubic_poly(&h, &FieldElement::from(0))
                    + eval_qubic_poly(&h, &FieldElement::from(1)),
                last_sumcheck_value
            );
            rand.push(alpha[0]);
            last_sumcheck_value = eval_qubic_poly(&h, &alpha[0]);
        }
        arthur
            .fill_next_scalars(&mut l)
            .expect("Failed to fill next scalars");
        arthur
            .fill_challenge_scalars(&mut r)
            .expect("Failed to fill next scalars");
        let claimed_last_sch = calculate_eq(&prev_rand, &rand)
            * eval_linear_poly(&l, &FieldElement::from(0))
            * eval_linear_poly(&l, &FieldElement::from(1));
        assert_eq!(claimed_last_sch, last_sumcheck_value);
        rand.push(r[0]);
        prev_rand = rand;
        rand = Vec::<FieldElement>::new();
        last_sumcheck_value = eval_linear_poly(&l, &r[0]);
    }

    Ok(GPASumcheckResult {
        claimed_product: gpa_claimed_product[0],
        last_sumcheck_value,
        randomness: prev_rand,
    })
}

pub struct GPASumcheckResult {
    pub claimed_product: FieldElement,
    pub last_sumcheck_value: FieldElement,
    pub randomness: Vec<FieldElement>,
}

pub fn eval_linear_poly(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * poly[1]
}

pub fn run_gpa_init_prover (
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    tau: FieldElement,
    gamma: FieldElement,
    eq: Vec<FieldElement>,
) {
    let memory_size = eq.len();
    GrandProductArgument::new(
        (0..memory_size as u64)
            .map(FieldElement::from)
            .collect(),
        eq,
        vec![FieldElement::zero(); memory_size],
        tau,
        gamma,
        merlin,
    );
}