/// Implementation inspired by the Circom Poseidon2 templates: [https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom](https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom)
use {
    super::constants::{
        amount_partial_rounds, load_diag, load_rc_full1, load_rc_full2, load_rc_partial,
    },
    crate::noir_to_r1cs::NoirToR1CSCompiler,
    ark_ff::Field,
    ark_std::One,
    ark_std::Zero,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::rc::Rc,
};

/// Threshold for switching from quadratic to sort+merge term canonicalization.
const CANONICALIZE_THRESHOLD: usize = 16;

/// Multiply two values: linearize const*w, use product gate for w*w.
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

            // z = a * w
            r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(z, vec![SumTerm(Some(a), w)]));
            r1cs_compiler.r1cs.add_constraint(
                &[(a, w)],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, z)],
            );
            ConstantOrR1CSWitness::Witness(z)
        }

        (ConstantOrR1CSWitness::Witness(wx), ConstantOrR1CSWitness::Witness(wy)) => {
            // z = wx * wy
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

/// Sparse linear form: sum_i (coeff_i * witness_i) + constant.
#[derive(Clone, Debug)]
struct LinearForm {
    terms:    Rc<Vec<(FieldElement, usize)>>,
    constant: FieldElement,
}

impl LinearForm {
    /// Linear form equal to 0.
    fn zero() -> Self {
        LinearForm {
            terms:    Rc::new(Vec::new()),
            constant: FieldElement::from(0u64),
        }
    }

    /// Construct a linear form from a single constant or witness.
    fn from_witness(witness: ConstantOrR1CSWitness) -> Self {
        match witness {
            ConstantOrR1CSWitness::Constant(k) => LinearForm {
                terms:    Rc::new(vec![]),
                constant: k,
            },
            ConstantOrR1CSWitness::Witness(w) => LinearForm {
                terms:    Rc::new(vec![(FieldElement::ONE, w)]),
                constant: FieldElement::from(0u64),
            },
        }
    }

    /// Add another linear form into `self`.
    fn add_mut(&mut self, other: &Self) {
        let self_len = self.terms.len();
        let other_len = other.terms.len();

        // Only constants to merge.
        if other_len == 0 {
            self.constant += other.constant;
            return;
        }

        // `self` has no terms: adopt `other`'s term buffer.
        if self_len == 0 {
            if !Rc::ptr_eq(&self.terms, &other.terms) {
                self.terms = other.terms.clone();
            }
            self.constant += other.constant;
            return;
        }

        let desired = self_len + other_len;

        // Unique owner: extend in-place.
        if let Some(vec_mut) = Rc::get_mut(&mut self.terms) {
            vec_mut.reserve(other_len);
            vec_mut.extend_from_slice(other.terms.as_slice());
            self.constant += other.constant;
            return;
        }

        // Shared: allocate once and copy both slices.
        let mut new_vec: Vec<(FieldElement, usize)> = Vec::with_capacity(desired);
        new_vec.extend_from_slice(self.terms.as_slice());
        new_vec.extend_from_slice(other.terms.as_slice());
        self.terms = Rc::new(new_vec);

        self.constant += other.constant;
    }

    /// Scale this linear form in-place.
    fn scale_mut(&mut self, scalar: FieldElement) {
        if scalar.is_one() {
            return;
        }

        if scalar.is_zero() {
            // Clear all terms and constant.
            if let Some(vec_mut) = Rc::get_mut(&mut self.terms) {
                vec_mut.clear();
            } else {
                self.terms = Rc::new(Vec::new());
            }
            self.constant = FieldElement::from(0u64);
            return;
        }

        // Unique-owner: mutate elements in-place
        if let Some(vec_mut) = Rc::get_mut(&mut self.terms) {
            for (c, _w) in vec_mut.iter_mut() {
                *c = *c * scalar;
            }
            self.constant = self.constant * scalar;
            return;
        }

        // Shared owner: allocate a new scaled buffer.
        let len = self.terms.len();
        let mut new_vec: Vec<(FieldElement, usize)> = Vec::with_capacity(len);
        new_vec.extend(self.terms.iter().map(|(c, w)| (*c * scalar, *w)));
        self.terms = Rc::new(new_vec);
        self.constant = self.constant * scalar;
    }

    /// Add a constant term in-place.
    fn add_constant_mut(&mut self, c: FieldElement) {
        self.constant += c;
    }

    /// Append a single (coeff, witness) term, skipping zero coefficients.
    fn add_term_mut(&mut self, coeff: FieldElement, witness: usize) {
        if coeff.is_zero() {
            return;
        }
        let vec_mut = Rc::make_mut(&mut self.terms);
        vec_mut.push((coeff, witness));
    }

    /// Return the constant term.
    fn get_constant(&self) -> FieldElement {
        self.constant
    }

    /// Canonicalize terms by merging duplicates and dropping zeros.
    /// Uses quadratic or sort+merge strategy based on `threshold`.
    fn canonicalize_terms(&mut self, threshold: usize) {
        if self.terms.len() <= 1 {
            return;
        }

        // Unique owner: canonicalize in-place.
        if let Some(vec_mut) = Rc::get_mut(&mut self.terms) {
            collapse_terms_inplace(vec_mut, threshold);
            return;
        }

        // Shared owner: clone, canonicalize, then re-wrap.
        let mut owned: Vec<(FieldElement, usize)> = self.terms.to_vec();
        collapse_terms_inplace(&mut owned, threshold);
        self.terms = Rc::new(owned);
    }
}

/// Add two linear forms
fn add_forms(mut a: LinearForm, b: &LinearForm) -> LinearForm {
    // Only constants in `b`.
    if b.terms.is_empty() {
        a.constant += b.constant;
        return a;
    }

    // `a` has no terms: adopt `b`'s term buffer.
    if a.terms.is_empty() {
        if !Rc::ptr_eq(&a.terms, &b.terms) {
            a.terms = b.terms.clone();
        }
        a.constant += b.constant;
        return a;
    }

    a.add_mut(b);
    a
}

/// Sum a slice of linear forms into a single accumulator.
fn sum_forms(forms: &[LinearForm]) -> LinearForm {
    if forms.is_empty() {
        return LinearForm::zero();
    }
    if forms.len() == 1 {
        return forms[0].clone();
    }

    let mut acc = forms[0].clone();

    for f in &forms[1..] {
        acc.add_mut(f);
    }

    acc
}

/// Return a scaled copy of a linear form.
fn scale_form(form: &LinearForm, scalar: FieldElement) -> LinearForm {
    if scalar.is_one() {
        return form.clone();
    }

    let mut out = form.clone();
    out.scale_mut(scalar);
    out
}

/// Merge duplicate witnesses in-place using a quadratic scan.
fn collapse_terms_quadratic_inplace(v: &mut Vec<(FieldElement, usize)>) {
    let mut i = 0;
    while i < v.len() {
        let mut coeff_i = v[i].0;
        let witness_i = v[i].1;

        // Drop explicit zero terms early.
        if coeff_i.is_zero() {
            v.swap_remove(i);
            continue;
        }

        let mut j = i + 1;
        while j < v.len() {
            let coeff_j = v[j].0;
            let witness_j = v[j].1;
            if witness_j == witness_i {
                coeff_i += coeff_j;
                v.swap_remove(j);
            } else {
                j += 1;
            }
        }

        if coeff_i.is_zero() {
            // Entire term cancels out.
            v.swap_remove(i);
        } else {
            v[i].0 = coeff_i;
            i += 1;
        }
    }
}

/// Merge duplicate witnesses in-place using sort + linear scan.
fn collapse_terms_sort_merge_inplace(v: &mut Vec<(FieldElement, usize)>) {
    if v.is_empty() {
        return;
    }

    // Sort by witness index
    v.sort_unstable_by_key(|&(_c, w)| w);

    let mut write = 0usize;

    let mut acc_coeff = v[0].0;
    let mut acc_witness = v[0].1;

    for read in 1..v.len() {
        let (coeff_r, witness_r) = v[read];

        if witness_r == acc_witness {
            acc_coeff += coeff_r;
        } else {
            if !acc_coeff.is_zero() {
                v[write] = (acc_coeff, acc_witness);
                write += 1;
            }
            acc_coeff = coeff_r;
            acc_witness = witness_r;
        }
    }

    // Flush final accumulator.
    if !acc_coeff.is_zero() {
        v[write] = (acc_coeff, acc_witness);
        write += 1;
    }

    v.truncate(write);
}

/// Canonicalize a term vector by collapsing duplicates and removing zeros.
/// Uses a quadratic or sort+merge strategy based on `threshold`.
fn collapse_terms_inplace(v: &mut Vec<(FieldElement, usize)>, threshold: usize) {
    if v.len() <= threshold {
        collapse_terms_quadratic_inplace(v);
    } else {
        collapse_terms_sort_merge_inplace(v);
    }
}

/// Build a `LinearForm` from parallel slices of coefficients and inputs.
fn compute_linear_form(coeffs: &[FieldElement], vs: &[ConstantOrR1CSWitness]) -> LinearForm {
    let mut acc = LinearForm::zero();

    for (c, v) in coeffs.iter().zip(vs.iter()) {
        if c.is_zero() {
            continue;
        }

        match v {
            ConstantOrR1CSWitness::Constant(k) => {
                acc.add_constant_mut(*c * *k);
            }
            ConstantOrR1CSWitness::Witness(w) => {
                acc.add_term_mut(*c, *w);
            }
        }
    }

    acc
}

/// Constrain `y = form^5` and return the witness for `y`.
fn linear_form_pow5(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    form: &LinearForm,
    sum_terms: &mut Vec<SumTerm>,
    constraint_terms: &mut Vec<(FieldElement, usize)>,
) -> ConstantOrR1CSWitness {
    // Constant-only form: compute in the field, no constraints.
    if form.terms.is_empty() {
        let val = form.get_constant();
        return ConstantOrR1CSWitness::Constant(val * val * val * val * val);
    }

    let terms_slice: &[(FieldElement, usize)] = form.terms.as_slice();
    let const_val: FieldElement = form.constant;
    let has_constant = !const_val.is_zero();
    let capacity = terms_slice.len() + if has_constant { 1 } else { 0 };

    // form_witness = Σ coeff_i * w_i + const
    sum_terms.clear();
    sum_terms.reserve(capacity);
    sum_terms.extend(terms_slice.iter().map(|(c, w)| SumTerm(Some(*c), *w)));
    if has_constant {
        sum_terms.push(SumTerm(Some(const_val), r1cs_compiler.witness_one()));
    }

    let form_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(form_witness, std::mem::take(sum_terms)));

    // y2 = form_witness^2
    let y2 = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(y2, form_witness, form_witness));

    constraint_terms.clear();
    constraint_terms.reserve(capacity);
    constraint_terms.extend(terms_slice.iter().copied());
    if has_constant {
        constraint_terms.push((const_val, r1cs_compiler.witness_one()));
    }

    r1cs_compiler
        .r1cs
        .add_constraint(&constraint_terms, &constraint_terms, &[(
            FieldElement::ONE,
            y2,
        )]);

    // y4 = y2^2
    let y4 = add_mul(
        r1cs_compiler,
        ConstantOrR1CSWitness::Witness(y2),
        ConstantOrR1CSWitness::Witness(y2),
    );

    let ConstantOrR1CSWitness::Witness(y4_witness) = y4 else {
        unreachable!("y4 should always be a witness")
    };

    // y5 = y4 * form_witness
    let y5_witness = r1cs_compiler.num_witnesses();
    r1cs_compiler.add_witness_builder(WitnessBuilder::Product(
        y5_witness,
        y4_witness,
        form_witness,
    ));

    r1cs_compiler
        .r1cs
        .add_constraint(&[(FieldElement::ONE, y4_witness)], &constraint_terms, &[(
            FieldElement::ONE,
            y5_witness,
        )]);

    ConstantOrR1CSWitness::Witness(y5_witness)
}

/// Applies the Poseidon2 S-box to each linear form: (form + rc)^5.
fn apply_sbox_to_linear_forms_out(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    forms: &mut [LinearForm],
    rc: &[FieldElement],
    out: &mut Vec<ConstantOrR1CSWitness>,
    sum_terms: &mut Vec<SumTerm>,
    constraint_terms: &mut Vec<(FieldElement, usize)>,
) {
    let t = forms.len();
    assert_eq!(t, rc.len());

    out.clear();
    out.reserve(t);

    for (i, form) in forms.iter_mut().enumerate() {
        form.add_constant_mut(rc[i]);
        out.push(linear_form_pow5(
            r1cs_compiler,
            &form,
            sum_terms,
            constraint_terms,
        ));
    }
}

/// external MDS2 as linear forms
fn mds2_block_forms(s: &[ConstantOrR1CSWitness]) -> [LinearForm; 2] {
    let f1 = FieldElement::ONE;
    let f2 = FieldElement::from(2u64);

    let o0 = compute_linear_form(&[f2, f1], s);
    let o1 = compute_linear_form(&[f1, f2], s);
    [o0, o1]
}

/// external MDS3 as linear forms
fn mds3_block_forms(s: &[ConstantOrR1CSWitness]) -> [LinearForm; 3] {
    let f1 = FieldElement::ONE;
    let f2 = FieldElement::from(2u64);

    let o0 = compute_linear_form(&[f2, f1, f1], s);
    let o1 = compute_linear_form(&[f1, f2, f1], s);
    let o2 = compute_linear_form(&[f1, f1, f2], s);
    [o0, o1, o2]
}

/// external MDS4 as linear forms on a 4-lane block, matching
fn mds4_block_forms(s: &[ConstantOrR1CSWitness]) -> [LinearForm; 4] {
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
    [o0, o1, o2, o3]
}

/// External MDS for general t in {2, 3, 4, 8, 12, 16}.
fn mds_t_block_forms(s: &[ConstantOrR1CSWitness]) -> Vec<LinearForm> {
    let t = s.len();
    match t {
        2 => mds2_block_forms(s).to_vec(),
        3 => mds3_block_forms(s).to_vec(),
        4 => mds4_block_forms(s).to_vec(),
        t if [8, 12, 16].contains(&t) => {
            let blocks = t / 4;

            // Per-block outputs, each block is 4 lanes.
            let mut block_outs: Vec<[LinearForm; 4]> = Vec::with_capacity(blocks);

            // Column accumulators across all 4-lane blocks.
            let mut col_acc: Vec<LinearForm> = vec![LinearForm::zero(); 4];

            //  Compute MDS_4 for each 4-lane block and accumulate column sums.
            for i in 0..blocks {
                let block_s = &s[4 * i..4 * i + 4];

                let forms4 = mds4_block_forms(block_s);
                debug_assert_eq!(forms4.len(), 4);

                // Convert Vec<LinearForm> -> [LinearForm; 4].
                let arr: [LinearForm; 4] = [
                    forms4[0].clone(),
                    forms4[1].clone(),
                    forms4[2].clone(),
                    forms4[3].clone(),
                ];

                // accumulate per-column sums in-place
                for j in 0..4 {
                    col_acc[j].add_mut(&arr[j]);
                }

                block_outs.push(arr);
            }

            // Add the column sums back into each block lane to get the full MDS output.
            let mut out: Vec<LinearForm> = Vec::with_capacity(t);
            for i in 0..blocks {
                let arr = &block_outs[i];
                for j in 0..4 {
                    let mut cell = arr[j].clone();
                    cell.add_mut(&col_acc[j]);
                    out.push(cell);
                }
            }

            out
        }

        _ => panic!("unsupported t for external MDS forms"),
    }
}

/// Internal MDS for general t in {2, 3, 4, 8, 12, 16}.
fn internal_mds_forms_t_from_forms<FDiag: Fn(u32) -> Vec<FieldElement>>(
    t: u32,
    x_forms: &[LinearForm],
    load_diag: &FDiag,
) -> Vec<LinearForm> {
    match t {
        2 => {
            let sum = add_forms(x_forms[0].clone(), &x_forms[1]);

            let mut o0 = add_forms(x_forms[0].clone(), &sum);
            let two_x1 = scale_form(&x_forms[1], FieldElement::from(2u64));
            let mut o1 = add_forms(two_x1, &sum);

            // canonicalize outputs
            o0.canonicalize_terms(CANONICALIZE_THRESHOLD);
            o1.canonicalize_terms(CANONICALIZE_THRESHOLD);

            vec![o0, o1]
        }
        3 => {
            let sum = sum_forms(x_forms);

            let mut o0 = add_forms(x_forms[0].clone(), &sum);
            let mut o1 = add_forms(x_forms[1].clone(), &sum);
            let two_x2 = scale_form(&x_forms[2], FieldElement::from(2u64));
            let mut o2 = add_forms(two_x2, &sum);

            o0.canonicalize_terms(CANONICALIZE_THRESHOLD);
            o1.canonicalize_terms(CANONICALIZE_THRESHOLD);
            o2.canonicalize_terms(CANONICALIZE_THRESHOLD);

            vec![o0, o1, o2]
        }
        t if [4, 8, 12, 16].contains(&t) => {
            let coeffs = load_diag(t);
            let sum_all = sum_forms(x_forms);
            let t_usize = t as usize;

            let mut out: Vec<LinearForm> = Vec::with_capacity(t_usize);

            for i in 0..t_usize {
                // out[i] = diag[i] * x[i] + sum_j x[j]
                let scaled = scale_form(&x_forms[i], coeffs[i]);
                let mut li = add_forms(scaled, &sum_all);

                li.canonicalize_terms(CANONICALIZE_THRESHOLD);

                out.push(li);
            }

            out
        }
        _ => panic!("unsupported t for internal MDS"),
    }
}

/// Poseidon2 permutation: applies ext MDS -> 4 full -> pr partial -> 4 full;
/// outputs constrained to final state.
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

        // Current state as concrete witnesses and as symbolic linear forms.
        let mut state_witnesses: Vec<ConstantOrR1CSWitness> = inputs.clone();
        let mut state_forms = mds_t_block_forms(&state_witnesses);

        // Re-usable buffers to reduce allocations across rounds.
        let mut temp_sbox_out: Vec<ConstantOrR1CSWitness> = Vec::with_capacity(t_usize);
        let mut scratch_sum_terms: Vec<SumTerm> = Vec::with_capacity(t_usize);
        let mut scratch_constraint_terms: Vec<(FieldElement, usize)> = Vec::with_capacity(t_usize);

        // Poseidon2 round schedule: 4 full rounds -> pr partial rounds -> 4 full
        // rounds. Matches the 4 + Rp + 4 design from the Poseidon2 spec and reference templates ("https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom").

        // First 4 full rounds.
        for r in 0..4 {
            apply_sbox_to_linear_forms_out(
                r1cs_compiler,
                state_forms.as_mut_slice(),
                &rc_full1[r],
                &mut temp_sbox_out,
                &mut scratch_sum_terms,
                &mut scratch_constraint_terms,
            );

            // Update state witnesses and recompute linear forms via external MDS.
            std::mem::swap(&mut state_witnesses, &mut temp_sbox_out);
            state_forms = mds_t_block_forms(&state_witnesses);
        }

        let mut forms_for_next_round: Vec<LinearForm> = Vec::with_capacity(t_usize);

        // Partial rounds: non-linear on lane 0, linear on the rest.
        for r in 0..pr as usize {
            forms_for_next_round.clear();

            // Apply RC + S-box only to the first limb.
            let mut form_0 = state_forms[0].clone();
            form_0.add_constant_mut(rc_part[r]);

            let sboxed_witness_0 = linear_form_pow5(
                r1cs_compiler,
                &form_0,
                &mut scratch_sum_terms,
                &mut scratch_constraint_terms,
            );

            forms_for_next_round.push(LinearForm::from_witness(sboxed_witness_0));

            // Remaining limbs pass through unchanged for this step.
            for i in 1..t_usize {
                forms_for_next_round.push(state_forms[i].clone());
            }

            // Apply internal MDS to mix all limbs.
            state_forms = internal_mds_forms_t_from_forms(t, &forms_for_next_round, &load_diag_fn);
        }

        // Final 4 full rounds.
        for r in 0..4 {
            apply_sbox_to_linear_forms_out(
                r1cs_compiler,
                state_forms.as_mut_slice(),
                &rc_full2[r],
                &mut temp_sbox_out,
                &mut scratch_sum_terms,
                &mut scratch_constraint_terms,
            );
            std::mem::swap(&mut state_witnesses, &mut temp_sbox_out);
            state_forms = mds_t_block_forms(&state_witnesses);
        }

        // Constrain final linear forms to equal the requested output witnesses.
        // Output witnesses already have WitnessBuilder::Acir entries (from
        // fetch_r1cs_witness_index), so their values come from the ACIR witness
        // map (populated by the blackbox solver). We only need to add
        // constraints here, not additional witness builders.
        let mut a_recipe: Vec<(FieldElement, usize)> = Vec::new();

        for i in 0..t_usize {
            let form = &state_forms[i];
            let output_witness = outputs[i];

            // Constant-only form: constrain output_witness to equal the constant.
            if form.terms.is_empty() {
                let const_k = form.get_constant();
                r1cs_compiler.r1cs.add_constraint(
                    &[(FieldElement::ONE, output_witness)],
                    &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                    &[(const_k, r1cs_compiler.witness_one())],
                );
                continue;
            }

            let terms_slice = form.terms.as_slice();
            let const_val = form.get_constant();
            let need_const = !const_val.is_zero();

            // Build a_recipe for the constraint
            a_recipe.clear();
            a_recipe.reserve(terms_slice.len() + if need_const { 1 } else { 0 });
            a_recipe.extend_from_slice(terms_slice);
            if need_const {
                a_recipe.push((const_val, r1cs_compiler.witness_one()));
            }

            // Enforce: output_witness = Σ coeff_i * witness_i (+ const).
            r1cs_compiler.r1cs.add_constraint(
                &a_recipe,
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, output_witness)],
            );
        }
    }
}
