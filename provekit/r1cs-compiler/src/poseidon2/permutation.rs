/// Implementation inspired by the Circom Poseidon2 templates: [https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom](https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom)
use {
    super::constants::{
        amount_partial_rounds, load_diag, load_rc_full1, load_rc_full2, load_rc_partial,
    },
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::Field,
    ark_std::Zero,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
};

// Multiply two values: linearize const*w, use product gate for w*w.
fn add_mul(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    x: ConstantOrR1CSWitness,
    y: ConstantOrR1CSWitness,
) -> ConstantOrR1CSWitness {
    match (x, y) {
        (ConstantOrR1CSWitness::Constant(a), ConstantOrR1CSWitness::Constant(b)) => {
            ConstantOrR1CSWitness::Constant(a * b)
        }
        (ConstantOrR1CSWitness::Constant(a), ConstantOrR1CSWitness::Witness(w))
        | (ConstantOrR1CSWitness::Witness(w), ConstantOrR1CSWitness::Constant(a)) => {
            if a.is_zero() {
                return ConstantOrR1CSWitness::Constant(FieldElement::from(0u64));
            }
            let z = r1cs_compiler.num_witnesses();

            r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(z, vec![SumTerm(Some(a), w)]));
            r1cs_compiler.r1cs.add_constraint(
                &[(a, w)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, z)],
            );
            ConstantOrR1CSWitness::Witness(z)
        }
        (ConstantOrR1CSWitness::Witness(wx), ConstantOrR1CSWitness::Witness(wy)) => {
            let z = r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
                r1cs_compiler.num_witnesses(),
                wx,
                wy,
            ));
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, wx)],
                &[(FieldElement::ONE, wy)],
                &[(FieldElement::ONE, z)],
            );
            ConstantOrR1CSWitness::Witness(z)
        }
    }
}

// Represents a linear form: sum_i (coeffs[i] * witnesses[i]) + constant
struct LinearForm {
    terms:    Vec<(FieldElement, usize)>,
    constant: FieldElement,
}

impl LinearForm {
    fn clone(&self) -> Self {
        LinearForm {
            terms:    self.terms.clone(),
            constant: self.constant,
        }
    }
    fn from_witness(witness: ConstantOrR1CSWitness) -> Self {
        match witness {
            ConstantOrR1CSWitness::Constant(k) => LinearForm {
                terms:    vec![],
                constant: k,
            },
            ConstantOrR1CSWitness::Witness(w) => LinearForm {
                terms:    vec![(FieldElement::ONE, w)],
                constant: FieldElement::from(0u64),
            },
        }
    }
    fn zero() -> Self {
        LinearForm {
            terms:    Vec::new(),
            constant: FieldElement::from(0u64),
        }
    }
}

// Compute linear combination without creating witness
fn compute_linear_form(coeffs: &[FieldElement], vs: &[ConstantOrR1CSWitness]) -> LinearForm {
    let mut terms = Vec::new();
    let mut constant = FieldElement::from(0u64);

    for (c, v) in coeffs.iter().zip(vs.iter()) {
        match v {
            ConstantOrR1CSWitness::Witness(w) => {
                terms.push((*c, *w));
            }
            ConstantOrR1CSWitness::Constant(k) => {
                constant += *c * k;
            }
        }
    }
    LinearForm { terms, constant }
}

// Apply pow5 to a linear form directly
fn linear_form_pow5(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    form: LinearForm,
) -> ConstantOrR1CSWitness {
    // If it's just a constant, compute directly
    if form.terms.is_empty() {
        let val = form.constant;
        return ConstantOrR1CSWitness::Constant(val * val * val * val * val);
    }

    // Create a witness for the linear form (for witness builders only)
    let form_witness = r1cs_compiler.num_witnesses();
    let mut sum_terms: Vec<SumTerm> = form
        .terms
        .iter()
        .map(|(c, w)| SumTerm(Some(*c), *w))
        .collect();
    if !form.constant.is_zero() {
        sum_terms.push(SumTerm(Some(form.constant), r1cs_compiler.witness_one()));
    }
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(form_witness, sum_terms.clone()));

    // y2 = (linear_form)²
    let y2 = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(y2, form_witness, form_witness));

    // Build constraint terms for the linear form
    let mut constraint_terms = form.terms.clone();
    if !form.constant.is_zero() {
        constraint_terms.push((form.constant, r1cs_compiler.witness_one()));
    }

    r1cs_compiler
        .r1cs
        .add_constraint(&constraint_terms, &constraint_terms, &[(
            FieldElement::ONE,
            y2,
        )]);

    // Compute y4 = y2^2 using add_mul
    let y4 = add_mul(
        r1cs_compiler,
        ConstantOrR1CSWitness::Witness(y2),
        ConstantOrR1CSWitness::Witness(y2),
    );

    // Compute y5 = y4 * (linear_form)
    let y5 = match y4 {
        ConstantOrR1CSWitness::Witness(y4_witness) => {
            let y5_witness = r1cs_compiler.num_witnesses();
            r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
                y5_witness,
                y4_witness,
                form_witness,
            ));

            // Constraint: y4 * (linear_form) = y5
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, y4_witness)],
                &constraint_terms,
                &[(FieldElement::ONE, y5_witness)],
            );
            ConstantOrR1CSWitness::Witness(y5_witness)
        }
        _ => unreachable!("y4 should always be a witness"),
    };

    y5
}

// Applies RC and the 3-constraint pow5 S-Box to a vector of linear forms.
fn apply_sbox_to_linear_forms(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    mds_forms: Vec<LinearForm>,
    rc: &[FieldElement],
) -> Vec<ConstantOrR1CSWitness> {
    let t = mds_forms.len();
    assert_eq!(
        t,
        rc.len(),
        "Forms and round constants must have the same length"
    );

    let mut results = Vec::with_capacity(t);
    for (i, mut form) in mds_forms.into_iter().enumerate() {
        form.constant += rc[i];

        results.push(linear_form_pow5(r1cs_compiler, form));
    }
    results
}

// Helper: add two linear forms
fn add_forms(mut a: LinearForm, b: &LinearForm) -> LinearForm {
    a.terms.extend_from_slice(&b.terms);
    a.constant = a.constant + b.constant;
    a
}

// Helper: sum a slice of linear forms
fn sum_forms(forms: &[LinearForm]) -> LinearForm {
    let mut acc = LinearForm {
        terms:    Vec::new(),
        constant: FieldElement::from(0u64),
    };
    for f in forms {
        acc = add_forms(acc, f);
    }
    acc
}

// Helper: Multiplies all terms and the constant in a LinearForm by a scalar.
fn scale_form(form: &LinearForm, scalar: FieldElement) -> LinearForm {
    if scalar.is_zero() {
        return LinearForm::zero();
    }

    let new_terms = form.terms.iter().map(|(c, w)| (*c * scalar, *w)).collect();

    LinearForm {
        terms:    new_terms,
        constant: form.constant * scalar,
    }
}

// external MDS2 as linear forms
fn mds2_block_forms(s: &[ConstantOrR1CSWitness]) -> Vec<LinearForm> {
    let f1 = FieldElement::ONE;
    let f2 = FieldElement::from(2u64);

    let o0 = compute_linear_form(&[f2, f1], s);
    let o1 = compute_linear_form(&[f1, f2], s);
    vec![o0, o1]
}

// external MDS3 as linear forms
fn mds3_block_forms(s: &[ConstantOrR1CSWitness]) -> Vec<LinearForm> {
    let f1 = FieldElement::ONE;
    let f2 = FieldElement::from(2u64);

    let o0 = compute_linear_form(&[f2, f1, f1], s);
    let o1 = compute_linear_form(&[f1, f2, f1], s);
    let o2 = compute_linear_form(&[f1, f1, f2], s);
    vec![o0, o1, o2]
}

// external MDS4 as linear forms on a 4-lane block, matching
fn mds4_block_forms(s: &[ConstantOrR1CSWitness]) -> Vec<LinearForm> {
    let f1 = FieldElement::from(1u64);
    let f3 = FieldElement::from(3u64);
    let f4 = FieldElement::from(4u64);
    let f5 = FieldElement::from(5u64);
    let f6 = FieldElement::from(6u64);
    let f7 = FieldElement::from(7u64);

    let o0 = compute_linear_form(&[f5, f7, f1, f3], s);
    let o1 = compute_linear_form(&[f4, f6, f1, f1], s);
    let o2 = compute_linear_form(&[f1, f3, f5, f7], s);
    let o3 = compute_linear_form(&[f1, f1, f4, f6], s);
    vec![o0, o1, o2, o3]
}

// External MDS for general t in {2, 3, 4, 8, 12, 16}.
fn mds_t_block_forms(s: &[ConstantOrR1CSWitness]) -> Vec<LinearForm> {
    let t = s.len();
    match t {
        2 => mds2_block_forms(s),
        3 => mds3_block_forms(s),
        4 => mds4_block_forms(s),
        t if [8, 12, 16].contains(&t) => {
            let blocks = t / 4;

            // Apply MDS4 per 4-lane block
            let mut block_out: Vec<Vec<LinearForm>> = Vec::with_capacity(blocks);
            for i in 0..blocks {
                let block_s = &s[4 * i..4 * i + 4];
                let forms4 = mds4_block_forms(block_s); // This is a Vec<LinearForm>
                block_out.push(forms4);
            }

            // Sum columns across blocks: sum of block_out[i][j]
            let mut col_acc: Vec<LinearForm> = Vec::with_capacity(4);
            for j in 0..4 {
                let col_forms: Vec<LinearForm> =
                    (0..blocks).map(|i| block_out[i][j].clone()).collect();
                col_acc.push(sum_forms(&col_forms));
            }

            // Add column sums back to each lane
            let mut out = Vec::with_capacity(t);
            for i in 0..blocks {
                for j in 0..4 {
                    let final_form = add_forms(block_out[i][j].clone(), &col_acc[j]);
                    out.push(final_form);
                }
            }
            out
        }
        _ => panic!("unsupported t for external MDS forms"),
    }
}

// Internal MDS for general t in {2, 3, 4, 8, 12, 16}.
fn internal_mds_forms_t_from_forms<FDiag: Fn(u32) -> Vec<FieldElement>>(
    t: u32,
    x_forms: &[LinearForm],
    load_diag: &FDiag,
) -> Vec<LinearForm> {
    match t {
        2 => {
            let sum = add_forms(x_forms[0].clone(), &x_forms[1]);

            let o0 = add_forms(x_forms[0].clone(), &sum);

            let two_x1 = scale_form(&x_forms[1], FieldElement::from(2u64));
            let o1 = add_forms(two_x1, &sum);
            vec![o0, o1]
        }
        3 => {
            let sum = sum_forms(x_forms);

            let o0 = add_forms(x_forms[0].clone(), &sum);
            let o1 = add_forms(x_forms[1].clone(), &sum);
            let two_x2 = scale_form(&x_forms[2], FieldElement::from(2u64));
            let o2 = add_forms(two_x2, &sum);
            vec![o0, o1, o2]
        }
        t if [4, 8, 12, 16].contains(&t) => {
            let coeffs = load_diag(t);
            let sum_all = sum_forms(x_forms);
            (0..(t as usize))
                .map(|i| {
                    let scaled = scale_form(&x_forms[i], coeffs[i]);
                    add_forms(scaled, &sum_all)
                })
                .collect()
        }
        _ => panic!("unsupported t for internal MDS"),
    }
}

// Poseidon2 permutation: applies ext MDS -> 4 full -> pr partial -> 4 full;
// outputs constrained to final state.
pub(crate) fn add_poseidon2_permutation(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    ops: Vec<(u32, Vec<ConstantOrR1CSWitness>, Vec<usize>)>,
) {
    for (t, inputs, outputs) in ops {
        let t_usize = t as usize;
        assert!(matches!(t, 2 | 3 | 4 | 8 | 12 | 16));
        assert_eq!(inputs.len(), t_usize);
        assert_eq!(outputs.len(), t_usize);

        let pr = amount_partial_rounds(t);
        let rc_full1 = load_rc_full1(t);
        let rc_part = load_rc_partial(t);
        let rc_full2 = load_rc_full2(t);
        let load_diag_fn = |tt: u32| load_diag(tt);

        let mut state_witnesses: Vec<ConstantOrR1CSWitness> = inputs.clone();

        let mut state_forms = mds_t_block_forms(&state_witnesses);

        // Poseidon2 round schedule: 4 full rounds -> pr partial rounds -> 4 full
        // rounds. Matches the 4 + Rp + 4 design from the Poseidon2 spec and reference templates ("https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom").
        for r in 0..4 {
            state_witnesses = apply_sbox_to_linear_forms(r1cs_compiler, state_forms, &rc_full1[r]);

            state_forms = mds_t_block_forms(&state_witnesses);
        }

        for r in 0..pr as usize {
            let mut forms_for_next_round: Vec<LinearForm> = Vec::with_capacity(t_usize);

            let mut form_0 = state_forms[0].clone();
            form_0.constant += rc_part[r];
            let sboxed_witness_0 = linear_form_pow5(r1cs_compiler, form_0);

            forms_for_next_round.push(LinearForm::from_witness(sboxed_witness_0));

            for i in 1..t_usize {
                forms_for_next_round.push(state_forms[i].clone());
            }

            state_forms = internal_mds_forms_t_from_forms(t, &forms_for_next_round, &load_diag_fn);
        }
        for r in 0..4 {
            state_witnesses = apply_sbox_to_linear_forms(r1cs_compiler, state_forms, &rc_full2[r]);

            state_forms = mds_t_block_forms(&state_witnesses);
        }

        for i in 0..t_usize {
            let form = &state_forms[i];
            let output_witness = outputs[i];

            // Handle the case where the form is just a constant
            if form.terms.is_empty() {
                let k = form.constant;
                r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(output_witness, vec![
                    SumTerm(Some(k), r1cs_compiler.witness_one()),
                ]));

                r1cs_compiler.r1cs.add_constraint(
                    &[(FieldElement::ONE, output_witness)],
                    &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                    &[(k, r1cs_compiler.witness_one())],
                );
            } else {
                // Handle the case where the form is a linear combination.
                let mut a_recipe = form.terms.clone();
                if !form.constant.is_zero() {
                    a_recipe.push((form.constant, r1cs_compiler.witness_one()));
                }

                let mut sum_terms: Vec<SumTerm> = form
                    .terms
                    .iter()
                    .map(|(c, w)| SumTerm(Some(*c), *w))
                    .collect();
                if !form.constant.is_zero() {
                    sum_terms.push(SumTerm(Some(form.constant), r1cs_compiler.witness_one()));
                }
                r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(output_witness, sum_terms));

                r1cs_compiler.r1cs.add_constraint(
                    &a_recipe,
                    &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                    &[(FieldElement::ONE, output_witness)],
                );
            }
        }
    }
}

fn materialize_linear_form(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    form: &LinearForm,
) -> ConstantOrR1CSWitness {
    if form.terms.is_empty() {
        return ConstantOrR1CSWitness::Constant(form.constant);
    }

    let y = r1cs_compiler.num_witnesses();

    let mut sum_terms: Vec<SumTerm> = form
        .terms
        .iter()
        .map(|(c, w)| SumTerm(Some(*c), *w))
        .collect();
    if !form.constant.is_zero() {
        sum_terms.push(SumTerm(Some(form.constant), r1cs_compiler.witness_one()));
    }
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(y, sum_terms));

    let mut a_recipe = form.terms.clone();
    if !form.constant.is_zero() {
        a_recipe.push((form.constant, r1cs_compiler.witness_one()));
    }

    ConstantOrR1CSWitness::Witness(y)
}

fn internal_mds_forms_t<FDiag: Fn(u32) -> Vec<FieldElement>>(
    t: u32,
    s: &[ConstantOrR1CSWitness],
    load_diag: &FDiag,
) -> Vec<LinearForm> {
    match t {
        2 => {
            let f1 = FieldElement::ONE;
            let f2 = FieldElement::from(2u64);
            let f3 = FieldElement::from(3u64);

            let o0 = compute_linear_form(&[f2, f1], s);
            let o1 = compute_linear_form(&[f1, f3], s);
            vec![o0, o1]
        }
        3 => {
            let f1 = FieldElement::ONE;
            let f2 = FieldElement::from(2u64);
            let f3 = FieldElement::from(3u64);

            let o0 = compute_linear_form(&[f2, f1, f1], s);
            let o1 = compute_linear_form(&[f1, f2, f1], s);
            let o2 = compute_linear_form(&[f1, f1, f3], s);
            vec![o0, o1, o2]
        }
        t if [4, 8, 12, 16].contains(&t) => {
            let t_usize = t as usize;
            let diag_coeffs = load_diag(t);
            let one = FieldElement::ONE;

            (0..t_usize)
                .map(|i| {
                    // Manually build the fused coefficient vector for out[i]
                    let mut fused_coeffs = vec![one; t_usize];
                    fused_coeffs[i] = diag_coeffs[i] + one;

                    // Create the LinearForm recipe
                    compute_linear_form(&fused_coeffs, s)
                })
                .collect()
        }
        _ => panic!("unsupported t for internal MDS forms"),
    }
}
