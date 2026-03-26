use {
    anyhow::{ensure, Context},
    provekit_common::{
        utils::{
            next_power_of_two,
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_cubic_poly,
                sumcheck_fold_map_reduce,
            },
            HALF,
        },
        FieldElement, TranscriptSponge,
    },
    tracing::instrument,
    whir::transcript::{ProverState, VerifierMessage, VerifierState},
};

#[instrument(skip_all)]
pub fn run_gpa2(
    merlin: &mut ProverState<TranscriptSponge>,
    left: &[FieldElement],
    right: &[FieldElement],
) -> anyhow::Result<Vec<FieldElement>> {
    let mut concatenated = left.to_vec();
    concatenated.extend_from_slice(right);
    let mut layers = calculate_binary_multiplication_tree(concatenated)?;

    let mut drain = layers.drain(1..);

    let first_layer = drain.next().context("GPA tree has fewer than 2 layers")?;
    let (accumulated_randomness, mut sumcheck_claim) = add_line_to_transcript(merlin, first_layer);
    let mut accumulated_randomness = accumulated_randomness.to_vec();

    for layer in drain {
        (sumcheck_claim, accumulated_randomness) =
            run_gpa_sumcheck(merlin, layer, sumcheck_claim, accumulated_randomness)?;
    }

    Ok(accumulated_randomness)
}

#[instrument(skip_all)]
pub fn run_gpa4(
    merlin: &mut ProverState<TranscriptSponge>,
    leaves: Vec<FieldElement>,
) -> anyhow::Result<Vec<FieldElement>> {
    let mut layers = calculate_binary_multiplication_tree(leaves)?;

    let mut drain = layers.drain(2..);

    let coeffs = drain.next().context("GPA tree has fewer than 3 layers")?;
    let coeffs = [
        coeffs[0],
        coeffs[1] - coeffs[0],
        coeffs[2] - coeffs[0],
        coeffs[3] - coeffs[2] - coeffs[1] + coeffs[0],
    ];

    for c in &coeffs {
        merlin.prover_message(c);
    }

    let r0: FieldElement = merlin.verifier_message();
    let r1: FieldElement = merlin.verifier_message();
    let mut accumulated_randomness = vec![r0, r1];

    let mut sumcheck_claim = coeffs[0] + coeffs[1] * r1 + coeffs[2] * r0 + coeffs[3] * r0 * r1;

    for layer in drain {
        (sumcheck_claim, accumulated_randomness) =
            run_gpa_sumcheck(merlin, layer, sumcheck_claim, accumulated_randomness)?;
    }

    Ok(accumulated_randomness)
}

fn calculate_binary_multiplication_tree(
    array_to_prove: Vec<FieldElement>,
) -> anyhow::Result<Vec<Vec<FieldElement>>> {
    use rayon::prelude::*;

    ensure!(
        array_to_prove.len() == (1 << next_power_of_two(array_to_prove.len())),
        "Input length must be power of two"
    );

    let mut layers = vec![];
    let mut current_layer = array_to_prove;

    while current_layer.len() > 1 {
        let next_layer: Vec<FieldElement> = current_layer
            .par_chunks_exact(2)
            .map(|pair| pair[0] * pair[1])
            .collect();

        layers.push(current_layer);
        current_layer = next_layer;
    }

    layers.push(current_layer);
    layers.reverse();
    Ok(layers)
}

fn add_line_to_transcript(
    merlin: &mut ProverState<TranscriptSponge>,
    arr: Vec<FieldElement>,
) -> ([FieldElement; 1], FieldElement) {
    let line_poly = [arr[0], arr[1] - arr[0]];

    for c in line_poly.iter() {
        merlin.prover_message(c);
    }

    let challenge: FieldElement = merlin.verifier_message();

    let next_claim = line_poly[0] + line_poly[1] * challenge;

    ([challenge], next_claim)
}

fn run_gpa_sumcheck(
    merlin: &mut ProverState<TranscriptSponge>,
    layer: Vec<FieldElement>,
    mut sumcheck_claim: FieldElement,
    accumulated_randomness: Vec<FieldElement>,
) -> anyhow::Result<(FieldElement, Vec<FieldElement>)> {
    let (mut even_layer, mut odd_layer) = split_even_odd(layer);

    let mut eq_evaluations = calculate_evaluations_over_boolean_hypercube_for_eq(
        &accumulated_randomness,
        1 << accumulated_randomness.len(),
    );
    let mut challenge;
    let mut round_randomness = Vec::<FieldElement>::new();
    let mut fold = None;

    loop {
        let [eval_at_0, eval_at_neg1, eval_at_inf_over_x3] = sumcheck_fold_map_reduce(
            [&mut eq_evaluations, &mut even_layer, &mut odd_layer],
            fold,
            |[eq, v0, v1]| {
                [
                    eq.0 * v0.0 * v1.0,
                    (eq.0 + eq.0 - eq.1) * (v0.0 + v0.0 - v0.1) * (v1.0 + v1.0 - v1.1),
                    (eq.1 - eq.0) * (v0.1 - v0.0) * (v1.1 - v1.0),
                ]
            },
        );

        if fold.is_some() {
            eq_evaluations.truncate(eq_evaluations.len() / 2);
            even_layer.truncate(even_layer.len() / 2);
            odd_layer.truncate(odd_layer.len() / 2);
        }

        let poly_coeffs = reconstruct_cubic_from_evaluations(
            sumcheck_claim,
            eval_at_0,
            eval_at_neg1,
            eval_at_inf_over_x3,
        );

        ensure!(
            sumcheck_claim
                == poly_coeffs[0]
                    + poly_coeffs[0]
                    + poly_coeffs[1]
                    + poly_coeffs[2]
                    + poly_coeffs[3],
            "Sumcheck binding check failed"
        );

        for coeff in &poly_coeffs {
            merlin.prover_message(coeff);
        }
        challenge = merlin.verifier_message();

        fold = Some(challenge);
        sumcheck_claim = eval_cubic_poly(poly_coeffs, challenge);
        round_randomness.push(challenge);

        if eq_evaluations.len() <= 2 {
            break;
        }
    }

    let final_v0 = even_layer[0] + (even_layer[1] - even_layer[0]) * challenge;
    let final_v1 = odd_layer[0] + (odd_layer[1] - odd_layer[0]) * challenge;
    let final_v2 = eq_evaluations[0] + (eq_evaluations[1] - eq_evaluations[0]) * challenge;

    ensure!(
        sumcheck_claim == final_v0 * final_v1 * final_v2,
        "GPA sumcheck claim mismatch"
    );

    let line_coeffs = [final_v0, final_v1 - final_v0];

    for c in &line_coeffs {
        merlin.prover_message(c);
    }

    let line_challenge: FieldElement = merlin.verifier_message();
    let next_claim = line_coeffs[0] + line_coeffs[1] * line_challenge;
    round_randomness.push(line_challenge);

    Ok((next_claim, round_randomness))
}

fn reconstruct_cubic_from_evaluations(
    binding_value: FieldElement,
    at_0: FieldElement,
    at_neg1: FieldElement,
    at_inf_over_x3: FieldElement,
) -> [FieldElement; 4] {
    let mut coeffs = [FieldElement::from(0u64); 4];

    coeffs[0] = at_0;
    coeffs[2] = HALF * (binding_value + at_neg1 - at_0 - at_0 - at_0);
    coeffs[3] = at_inf_over_x3;
    coeffs[1] = binding_value - coeffs[0] - coeffs[0] - coeffs[3] - coeffs[2];

    coeffs
}

fn split_even_odd(input: Vec<FieldElement>) -> (Vec<FieldElement>, Vec<FieldElement>) {
    input
        .chunks_exact(2)
        .map(|chunk| (chunk[0], chunk[1]))
        .unzip()
}

pub struct GPASumcheckResult {
    pub claimed_values:      Vec<FieldElement>,
    pub last_sumcheck_value: FieldElement,
    pub randomness:          Vec<FieldElement>,
}

#[instrument(skip_all)]
pub fn gpa_sumcheck_verifier2(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    height_of_binary_tree: usize,
) -> anyhow::Result<GPASumcheckResult> {
    let mut prev_randomness;
    let mut current_randomness = Vec::<FieldElement>::new();

    let claimed_0: FieldElement = arthur
        .prover_message()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let claimed_1: FieldElement = arthur
        .prover_message()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let claimed_values = [claimed_0, claimed_1];

    let line_challenge: FieldElement = arthur.verifier_message();

    let mut sumcheck_value = eval_line(&claimed_values, &line_challenge);
    current_randomness.push(line_challenge);
    prev_randomness = current_randomness;
    current_randomness = Vec::new();

    for layer_idx in 1..height_of_binary_tree - 1 {
        for _ in 0..layer_idx {
            let cubic_coeffs: [FieldElement; 4] = [
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            ];
            let sumcheck_challenge: FieldElement = arthur.verifier_message();

            ensure!(
                eval_cubic_poly(cubic_coeffs, FieldElement::from(0u64))
                    + eval_cubic_poly(cubic_coeffs, FieldElement::from(1u64))
                    == sumcheck_value,
                "Sumcheck verification failed at layer {layer_idx}"
            );

            current_randomness.push(sumcheck_challenge);
            sumcheck_value = eval_cubic_poly(cubic_coeffs, sumcheck_challenge);
        }

        let line_coeffs: [FieldElement; 2] = [
            arthur
                .prover_message()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            arthur
                .prover_message()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ];
        let line_challenge: FieldElement = arthur.verifier_message();

        let expected_line_value = calculate_eq(&prev_randomness, &current_randomness)
            * eval_line(&line_coeffs, &FieldElement::from(0u64))
            * eval_line(&line_coeffs, &FieldElement::from(1u64));
        ensure!(
            expected_line_value == sumcheck_value,
            "Line evaluation mismatch"
        );

        current_randomness.push(line_challenge);
        prev_randomness = current_randomness;
        current_randomness = Vec::new();
        sumcheck_value = eval_line(&line_coeffs, &line_challenge);
    }

    let claimed_values = [claimed_values[0], claimed_values[0] + claimed_values[1]].to_vec();

    Ok(GPASumcheckResult {
        claimed_values,
        last_sumcheck_value: sumcheck_value,
        randomness: prev_randomness,
    })
}

#[instrument(skip_all)]
pub fn gpa_sumcheck_verifier4(
    arthur: &mut VerifierState<'_, TranscriptSponge>,
    height_of_binary_tree: usize,
) -> anyhow::Result<GPASumcheckResult> {
    let claimed_values: [FieldElement; 4] = [
        arthur
            .prover_message()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        arthur
            .prover_message()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        arthur
            .prover_message()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        arthur
            .prover_message()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    ];
    let r0: FieldElement = arthur.verifier_message();
    let r1: FieldElement = arthur.verifier_message();
    let mut prev_randomness = vec![r0, r1];
    let mut current_randomness = Vec::<FieldElement>::new();

    let mut sumcheck_value = claimed_values[0]
        + claimed_values[1] * prev_randomness[1]
        + claimed_values[2] * prev_randomness[0]
        + claimed_values[3] * prev_randomness[0] * prev_randomness[1];

    for layer_idx in 2..height_of_binary_tree - 1 {
        for _ in 0..layer_idx {
            let cubic_coeffs: [FieldElement; 4] = [
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                arthur
                    .prover_message()
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            ];
            let sumcheck_challenge: FieldElement = arthur.verifier_message();

            ensure!(
                eval_cubic_poly(cubic_coeffs, FieldElement::from(0u64))
                    + eval_cubic_poly(cubic_coeffs, FieldElement::from(1u64))
                    == sumcheck_value,
                "Sumcheck verification failed at layer {layer_idx}"
            );

            current_randomness.push(sumcheck_challenge);
            sumcheck_value = eval_cubic_poly(cubic_coeffs, sumcheck_challenge);
        }

        let line_coeffs: [FieldElement; 2] = [
            arthur
                .prover_message()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            arthur
                .prover_message()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ];
        let line_challenge: FieldElement = arthur.verifier_message();

        let expected_line_value = calculate_eq(&prev_randomness, &current_randomness)
            * eval_line(&line_coeffs, &FieldElement::from(0u64))
            * eval_line(&line_coeffs, &FieldElement::from(1u64));
        ensure!(
            expected_line_value == sumcheck_value,
            "Line evaluation mismatch"
        );

        current_randomness.push(line_challenge);
        prev_randomness = current_randomness;
        current_randomness = Vec::new();
        sumcheck_value = eval_line(&line_coeffs, &line_challenge);
    }

    let claimed_values = [
        claimed_values[0],
        claimed_values[0] + claimed_values[1],
        claimed_values[0] + claimed_values[2],
        claimed_values[0] + claimed_values[1] + claimed_values[2] + claimed_values[3],
    ]
    .to_vec();

    Ok(GPASumcheckResult {
        claimed_values,
        last_sumcheck_value: sumcheck_value,
        randomness: prev_randomness,
    })
}

pub fn eval_line(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * poly[1]
}

pub fn calculate_adr(randomness: &[FieldElement]) -> FieldElement {
    randomness
        .iter()
        .rev()
        .enumerate()
        .fold(FieldElement::from(0u64), |acc, (i, &r)| {
            acc + r * FieldElement::from(1u64 << i)
        })
}
