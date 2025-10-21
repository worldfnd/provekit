use {
    provekit_common::{
        skyscraper::SkyscraperSponge,
        utils::{
            next_power_of_two,
            sumcheck::{
                calculate_eq, calculate_evaluations_over_boolean_hypercube_for_eq, eval_cubic_poly,
                sumcheck_fold_map_reduce,
            },
            HALF,
        },
        FieldElement,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
        ProverState, VerifierState,
    },
    whir::poly_utils::evals::EvaluationsList,
};

/// Runs the Grand Product Argument (GPA) protocol to prove product equality.
///
/// GPA constructs a binary multiplication tree from `left` and `right` vectors,
/// then uses sumcheck-based proofs to verify that `∏left[i] = ∏right[i]`
/// without revealing the individual values.
///
/// This is the core primitive for memory checking in SPARK, enabling efficient
/// verification that read and write sets are consistent.
///
/// # Arguments
///
/// * `merlin` - The prover's Fiat-Shamir transcript
/// * `left` - Initial state vector (must be power-of-2 length)
/// * `right` - Final state vector (must match `left` length)
///
/// # Returns
///
/// Vector of challenge randomness accumulated across all sumcheck rounds
///
/// # Panics
///
/// Panics if input vectors are not power-of-2 length
pub fn run_gpa(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    left: &[FieldElement],
    right: &[FieldElement],
) -> Vec<FieldElement> {
    let mut concatenated = left.to_vec();
    concatenated.extend_from_slice(right);
    let layers = calculate_binary_multiplication_tree(concatenated);

    let mut sumcheck_claim;
    let mut line_randomness;
    let mut line_evaluations;
    let mut accumulated_randomness = Vec::<FieldElement>::new();

    (line_randomness, sumcheck_claim) = add_line_to_transcript(merlin, layers[1].clone());

    for i in 2..layers.len() {
        (line_evaluations, accumulated_randomness) = run_gpa_sumcheck(
            merlin,
            &line_randomness,
            layers[i].clone(),
            sumcheck_claim,
            accumulated_randomness,
        );
        (line_randomness, sumcheck_claim) =
            add_line_to_transcript(merlin, line_evaluations.to_vec());
    }

    accumulated_randomness.push(line_randomness[0]);
    accumulated_randomness
}

/// Constructs a binary multiplication tree from the input vector.
///
/// Each parent node is the product of its two children, forming a complete
/// binary tree where the root is the product of all elements.
///
/// # Returns
///
/// Vector of layers, where:
/// - `layers[0]` is the root (single element)
/// - `layers[layers.len()-1]` is the leaf layer (input)
///
/// # Panics
///
/// Panics if input length is not a power of two
fn calculate_binary_multiplication_tree(
    array_to_prove: Vec<FieldElement>,
) -> Vec<Vec<FieldElement>> {
    assert!(
        array_to_prove.len() == (1 << next_power_of_two(array_to_prove.len())),
        "Input length must be power of two"
    );

    let mut layers = vec![];
    let mut current_layer = array_to_prove;

    while current_layer.len() > 1 {
        let next_layer = current_layer
            .chunks_exact(2)
            .map(|pair| pair[0] * pair[1])
            .collect();

        layers.push(current_layer);
        current_layer = next_layer;
    }

    layers.push(current_layer);
    layers.reverse();
    layers
}

/// Adds a line polynomial to the transcript and samples verifier challenge.
///
/// Converts evaluations to coefficients, commits them to the transcript,
/// then receives a random challenge to bind the prover to this layer.
///
/// # Returns
///
/// Tuple of `(challenge, next_sumcheck_claim)` for the following GPA round
fn add_line_to_transcript(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    arr: Vec<FieldElement>,
) -> ([FieldElement; 1], FieldElement) {
    let evaluations = EvaluationsList::new(arr);
    let coeffs = evaluations.to_coeffs();
    let line_poly: &[FieldElement] = coeffs.coeffs();

    merlin
        .add_scalars(line_poly)
        .expect("Failed to add line polynomial to transcript");

    let mut challenge = [FieldElement::from(0); 1];
    merlin
        .fill_challenge_scalars(&mut challenge)
        .expect("Failed to sample challenge");

    let next_claim = line_poly[0] + line_poly[1] * challenge[0];

    (challenge, next_claim)
}

/// Executes a single sumcheck round within the GPA protocol.
///
/// This proves the relation: `eq(r, x) · v₀(x) · v₁(x)` sums correctly
/// over the boolean hypercube, where `v₀` and `v₁` are child layers
/// in the multiplication tree.
///
/// # Returns
///
/// Tuple of `(final_evaluations, accumulated_randomness)` for next round
fn run_gpa_sumcheck(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    r: &[FieldElement; 1],
    layer: Vec<FieldElement>,
    mut sumcheck_claim: FieldElement,
    mut accumulated_randomness: Vec<FieldElement>,
) -> ([FieldElement; 2], Vec<FieldElement>) {
    let (mut even_layer, mut odd_layer) = split_even_odd(layer);
    accumulated_randomness.push(r[0]);

    let mut eq_evaluations =
        calculate_evaluations_over_boolean_hypercube_for_eq(accumulated_randomness);
    let mut challenge = [FieldElement::from(0)];
    let mut round_randomness = Vec::<FieldElement>::new();
    let mut fold = None;

    loop {
        // Evaluate sumcheck polynomial at special points: 0, -1, ∞
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

        // Reconstruct cubic polynomial from evaluation points
        let poly_coeffs = reconstruct_cubic_from_evaluations(
            sumcheck_claim,
            eval_at_0,
            eval_at_neg1,
            eval_at_inf_over_x3,
        );

        // Verify sumcheck binding: h(0) + h(1) = claimed_sum
        assert_eq!(
            sumcheck_claim,
            poly_coeffs[0] + poly_coeffs[0] + poly_coeffs[1] + poly_coeffs[2] + poly_coeffs[3],
            "Sumcheck binding check failed"
        );

        merlin
            .add_scalars(&poly_coeffs)
            .expect("Failed to add polynomial");
        merlin
            .fill_challenge_scalars(&mut challenge)
            .expect("Failed to sample challenge");

        fold = Some(challenge[0]);
        sumcheck_claim = eval_cubic_poly(poly_coeffs, challenge[0]);
        round_randomness.push(challenge[0]);

        if eq_evaluations.len() <= 2 {
            break;
        }
    }

    let final_v0 = even_layer[0] + (even_layer[1] - even_layer[0]) * challenge[0];
    let final_v1 = odd_layer[0] + (odd_layer[1] - odd_layer[0]) * challenge[0];

    ([final_v0, final_v1], round_randomness)
}

/// Reconstructs cubic polynomial coefficients from special point evaluations.
///
/// Given evaluations at 0, -1, and ∞/x³, computes the unique cubic polynomial
/// that passes through these points and satisfies the sumcheck binding.
fn reconstruct_cubic_from_evaluations(
    binding_value: FieldElement,
    at_0: FieldElement,
    at_neg1: FieldElement,
    at_inf_over_x3: FieldElement,
) -> [FieldElement; 4] {
    let mut coeffs = [FieldElement::from(0); 4];

    coeffs[0] = at_0;
    coeffs[2] = HALF * (binding_value + at_neg1 - at_0 - at_0 - at_0);
    coeffs[3] = at_inf_over_x3;
    coeffs[1] = binding_value - coeffs[0] - coeffs[0] - coeffs[3] - coeffs[2];

    coeffs
}

/// Splits vector into even-indexed and odd-indexed elements.
///
/// Used to separate left/right children in the binary multiplication tree.
fn split_even_odd(input: Vec<FieldElement>) -> (Vec<FieldElement>, Vec<FieldElement>) {
    let mut even = Vec::new();
    let mut odd = Vec::new();

    for (i, item) in input.into_iter().enumerate() {
        if i % 2 == 0 {
            even.push(item);
        } else {
            odd.push(item);
        }
    }

    (even, odd)
}

/// Result of GPA sumcheck verification containing final randomness and claims.
pub struct GPASumcheckResult {
    /// The two claimed values at the leaves (left and right products)
    pub claimed_values:        Vec<FieldElement>,
    /// Final sumcheck evaluation after all rounds
    pub a_last_sumcheck_value: FieldElement,
    /// Accumulated verifier randomness from all rounds
    pub randomness:            Vec<FieldElement>,
}

/// Verifies a Grand Product Argument proof from the transcript.
///
/// This is the verifier's counterpart to [`run_gpa`], checking that the
/// prover's sumcheck proofs are valid without recomputing the multiplication
/// tree.
///
/// # Arguments
///
/// * `arthur` - The verifier's transcript state (Fiat-Shamir)
/// * `height_of_binary_tree` - Number of layers in the multiplication tree
///
/// # Returns
///
/// [`GPASumcheckResult`] containing verified claims and randomness
pub fn gpa_sumcheck_verifier(
    arthur: &mut VerifierState<SkyscraperSponge, FieldElement>,
    height_of_binary_tree: usize,
) -> anyhow::Result<GPASumcheckResult> {
    let mut prev_randomness;
    let mut current_randomness = Vec::<FieldElement>::new();
    let mut claimed_values = [FieldElement::from(0); 2];
    let mut line_coeffs = [FieldElement::from(0); 2];
    let mut line_challenge = [FieldElement::from(0); 1];
    let mut cubic_coeffs = [FieldElement::from(0); 4];
    let mut sumcheck_challenge = [FieldElement::from(0); 1];

    arthur.fill_next_scalars(&mut claimed_values)?;
    arthur.fill_challenge_scalars(&mut line_challenge)?;

    let mut sumcheck_value = eval_line(&claimed_values, &line_challenge[0]);
    current_randomness.push(line_challenge[0]);
    prev_randomness = current_randomness;
    current_randomness = Vec::new();

    for layer_idx in 1..height_of_binary_tree - 1 {
        for _ in 0..layer_idx {
            arthur.fill_next_scalars(&mut cubic_coeffs)?;
            arthur.fill_challenge_scalars(&mut sumcheck_challenge)?;

            // Verify sumcheck binding
            assert_eq!(
                eval_cubic_poly(cubic_coeffs, FieldElement::from(0))
                    + eval_cubic_poly(cubic_coeffs, FieldElement::from(1)),
                sumcheck_value,
                "Sumcheck verification failed at layer {layer_idx}"
            );

            current_randomness.push(sumcheck_challenge[0]);
            sumcheck_value = eval_cubic_poly(cubic_coeffs, sumcheck_challenge[0]);
        }

        arthur.fill_next_scalars(&mut line_coeffs)?;
        arthur.fill_challenge_scalars(&mut line_challenge)?;

        // Verify line polynomial evaluation
        let expected_line_value = calculate_eq(&prev_randomness, &current_randomness)
            * eval_line(&line_coeffs, &FieldElement::from(0))
            * eval_line(&line_coeffs, &FieldElement::from(1));
        assert_eq!(
            expected_line_value, sumcheck_value,
            "Line evaluation mismatch"
        );

        current_randomness.push(line_challenge[0]);
        prev_randomness = current_randomness;
        current_randomness = Vec::new();
        sumcheck_value = eval_line(&line_coeffs, &line_challenge[0]);
    }

    Ok(GPASumcheckResult {
        claimed_values:        claimed_values.to_vec(),
        a_last_sumcheck_value: sumcheck_value,
        randomness:            prev_randomness,
    })
}

/// Evaluates a linear polynomial at a given point.
///
/// Computes `poly[0] + point * poly[1]` for a degree-1 polynomial.
pub fn eval_line(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * poly[1]
}

/// Calculates address from binary representation of evaluation point.
///
/// Interprets the randomness vector as a binary number in reverse order,
/// converting it to the corresponding memory address in the hypercube.
///
/// # Example
///
/// `[r₀, r₁, r₂]` → `r₂·2² + r₁·2¹ + r₀·2⁰`
pub fn calculate_adr(randomness: &[FieldElement]) -> FieldElement {
    randomness
        .iter()
        .rev()
        .enumerate()
        .fold(FieldElement::from(0), |acc, (i, &r)| {
            acc + r * FieldElement::from(1 << i)
        })
}
