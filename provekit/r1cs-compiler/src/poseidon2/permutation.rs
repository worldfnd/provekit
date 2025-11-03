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

// y = a + c  (c is a field constant)
fn add_const(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    a: ConstantOrR1CSWitness,
    c: FieldElement,
) -> ConstantOrR1CSWitness {
    match a {
        // Fold constant + constant
        ConstantOrR1CSWitness::Constant(k) => ConstantOrR1CSWitness::Constant(k + c),

        // Witness path: y = a + c*1
        ConstantOrR1CSWitness::Witness(w) => {
            let y = r1cs_compiler.num_witnesses();

            // Builder: y = w + c*1
            r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(y, vec![
                SumTerm(None, w),
                SumTerm(Some(c), r1cs_compiler.witness_one()),
            ]));

            // Constraint: (1*w + c*1) * 1 = (1*y)
            r1cs_compiler.r1cs.add_constraint(
                &[(FieldElement::ONE, w), (c, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                &[(FieldElement::ONE, y)],
            );

            ConstantOrR1CSWitness::Witness(y)
        }
    }
}

// Linear combo: y = sum_i (c_i * v_i); returns a witness.
fn add_linear_combo(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    coeffs: &[FieldElement],
    vs: &[ConstantOrR1CSWitness],
) -> ConstantOrR1CSWitness {
    assert_eq!(coeffs.len(), vs.len());

    // Split into witness terms and a folded constant offset
    let mut lc: Vec<(FieldElement, usize)> = Vec::new();
    let mut c0 = FieldElement::from(0u64);
    for (c, v) in coeffs.iter().copied().zip(vs.iter()) {
        match *v {
            ConstantOrR1CSWitness::Witness(w) => lc.push((c, w)),
            ConstantOrR1CSWitness::Constant(k) => c0 += c * k,
        }
    }

    let y = r1cs_compiler.num_witnesses();

    // Builder: y = sum_i (c_i * w_i) + c0*1 (if c0 != 0)
    let mut sum_terms: Vec<SumTerm> = lc.iter().map(|(c, w)| SumTerm(Some(*c), *w)).collect();
    if !c0.is_zero() {
        sum_terms.push(SumTerm(Some(c0), r1cs_compiler.witness_one()));
    }
    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(y, sum_terms));

    // Constraint: (sum_i c_i*w_i + c0*1) * 1 = (1*y)
    let mut A = lc;
    if !c0.is_zero() {
        A.push((c0, r1cs_compiler.witness_one()));
    }
    r1cs_compiler
        .r1cs
        .add_constraint(&A, &[(FieldElement::ONE, r1cs_compiler.witness_one())], &[
            (FieldElement::ONE, y),
        ]);

    ConstantOrR1CSWitness::Witness(y)
}

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

// Compute x^5: fold for constants; else three muls (x^2, x^4, x^5).
fn add_pow5(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    x: ConstantOrR1CSWitness,
) -> ConstantOrR1CSWitness {
    match x {
        ConstantOrR1CSWitness::Constant(k) => ConstantOrR1CSWitness::Constant(k * k * k * k * k),
        ConstantOrR1CSWitness::Witness(w) => {
            let x2 = add_mul(
                r1cs_compiler,
                ConstantOrR1CSWitness::Witness(w),
                ConstantOrR1CSWitness::Witness(w),
            );
            let x4 = add_mul(r1cs_compiler, x2.clone(), x2);
            add_mul(r1cs_compiler, x4, ConstantOrR1CSWitness::Witness(w))
        }
    }
}

/// External MDS (t=2): linear realization using `out[i] = s[i] + sum_i s[i]`
fn external_mds2(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    s: &[ConstantOrR1CSWitness],
) -> Vec<ConstantOrR1CSWitness> {
    debug_assert_eq!(s.len(), 2);
    let one = FieldElement::ONE;

    // sum = s0 + s1
    let sum = add_linear_combo(r1cs_compiler, &[one, one], &[s[0].clone(), s[1].clone()]);

    // out0 = s0 + sum
    let out0 = add_linear_combo(r1cs_compiler, &[one, one], &[s[0].clone(), sum.clone()]);

    // out1 = s1 + sum
    let out1 = add_linear_combo(r1cs_compiler, &[one, one], &[s[1].clone(), sum]);
    vec![out0, out1]
}

/// External MDS (t=3): linear realization using `out[i] = s[i] + sum_i s[i]`
fn external_mds3(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    s: &[ConstantOrR1CSWitness],
) -> Vec<ConstantOrR1CSWitness> {
    let one = FieldElement::ONE;
    let sum = add_linear_combo(r1cs_compiler, &[one, one, one], s); // y = s0 + s1 + s2

    vec![
        add_linear_combo(r1cs_compiler, &[one, one], &[s[0].clone(), sum.clone()]),
        add_linear_combo(r1cs_compiler, &[one, one], &[s[1].clone(), sum.clone()]),
        add_linear_combo(r1cs_compiler, &[one, one], &[s[2].clone(), sum]),
    ]
}

/// External MDS (t=4): optimized linear schedule.
fn external_mds4(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    s: &[ConstantOrR1CSWitness],
) -> Vec<ConstantOrR1CSWitness> {
    let double = |c: FieldElement| c + c;
    let four = |c: FieldElement| double(double(c));
    let f1 = FieldElement::from(1u64);

    let double_in1 = add_linear_combo(r1cs_compiler, &[double(f1)], &[s[1].clone()]);
    let double_in3 = add_linear_combo(r1cs_compiler, &[double(f1)], &[s[3].clone()]);

    let t0 = add_linear_combo(r1cs_compiler, &[f1, f1], &[s[0].clone(), s[1].clone()]);
    let t1 = add_linear_combo(r1cs_compiler, &[f1, f1], &[s[2].clone(), s[3].clone()]);

    let quad_t0 = add_linear_combo(r1cs_compiler, &[four(f1)], &[t0.clone()]);
    let quad_t1 = add_linear_combo(r1cs_compiler, &[four(f1)], &[t1.clone()]);

    let t2 = add_linear_combo(r1cs_compiler, &[f1, f1], &[double_in1, t1]);
    let t3 = add_linear_combo(r1cs_compiler, &[f1, f1], &[double_in3, t0]);
    let t4 = add_linear_combo(r1cs_compiler, &[f1, f1], &[quad_t1, t3.clone()]);
    let t5 = add_linear_combo(r1cs_compiler, &[f1, f1], &[quad_t0, t2.clone()]);

    vec![
        add_linear_combo(r1cs_compiler, &[f1, f1], &[t3, t5.clone()]),
        t5,
        add_linear_combo(r1cs_compiler, &[f1, f1], &[t2, t4.clone()]),
        t4,
    ]
}

// External MDS for general t in {2, 3, 4, 8, 12, 16}.

fn external_mds_t(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    s: &[ConstantOrR1CSWitness],
) -> Vec<ConstantOrR1CSWitness> {
    match s.len() {
        2 => external_mds2(r1cs_compiler, s),
        3 => external_mds3(r1cs_compiler, s),
        4 => external_mds4(r1cs_compiler, s),
        t if [8, 12, 16].contains(&t) => {
            let blocks = t / 4;

            // Apply MDS4 per 4-lane block
            let mut block_out: Vec<[ConstantOrR1CSWitness; 4]> = Vec::with_capacity(blocks);
            for i in 0..blocks {
                let o = external_mds4(r1cs_compiler, &s[4 * i..4 * i + 4]);
                block_out.push([o[0], o[1], o[2], o[3]]);
            }

            // Sum columns across blocks: sum of block_out[i][j]
            let mut col_acc: Vec<ConstantOrR1CSWitness> = Vec::with_capacity(4);
            for j in 0..4 {
                let coeffs = vec![FieldElement::ONE; blocks];
                let ws: Vec<ConstantOrR1CSWitness> =
                    (0..blocks).map(|i| block_out[i][j].clone()).collect();
                let acc = add_linear_combo(r1cs_compiler, &coeffs, &ws);
                col_acc.push(acc);
            }

            // Add column sums back to each lane
            let mut out = Vec::with_capacity(t);
            for i in 0..blocks {
                for j in 0..4 {
                    let tmp = add_linear_combo(
                        r1cs_compiler,
                        &[FieldElement::ONE, FieldElement::ONE],
                        &[block_out[i][j], col_acc[j]],
                    );
                    out.push(tmp);
                }
            }
            out
        }
        _ => panic!("unsupported t for external MDS"),
    }
}

// Internal MDS (partial rounds).
fn internal_mds_t(
    r1cs_compiler: &mut NoirToR1CSCompiler,
    t: u32,
    x: &[ConstantOrR1CSWitness],
    load_diag: &dyn Fn(u32) -> Vec<FieldElement>,
) -> Vec<ConstantOrR1CSWitness> {
    match t {
        2 => {
            let one = FieldElement::ONE;
            let sum = add_linear_combo(r1cs_compiler, &[one, one], &[x[0].clone(), x[1].clone()]);
            let o0 = add_linear_combo(r1cs_compiler, &[one, one], &[x[0].clone(), sum.clone()]);
            let o1 = add_linear_combo(r1cs_compiler, &[FieldElement::from(2u64), one], &[
                x[1].clone(),
                sum,
            ]);

            vec![o0, o1]
        }
        3 => {
            let one = FieldElement::ONE;
            let sum = add_linear_combo(r1cs_compiler, &[one, one, one], &[
                x[0].clone(),
                x[1].clone(),
                x[2].clone(),
            ]);
            let o0 = add_linear_combo(r1cs_compiler, &[one, one], &[x[0].clone(), sum.clone()]);
            let o1 = add_linear_combo(r1cs_compiler, &[one, one], &[x[1].clone(), sum.clone()]);
            let o2 = add_linear_combo(r1cs_compiler, &[FieldElement::from(2u64), one], &[
                x[2].clone(),
                sum,
            ]);
            vec![o0, o1, o2]
        }
        t if [4, 8, 12, 16].contains(&t) => {
            let coeffs = load_diag(t);
            let ones = vec![FieldElement::ONE; t as usize];
            let sum_all = add_linear_combo(r1cs_compiler, &ones, x);

            (0..t as usize)
                .map(|i| {
                    add_linear_combo(r1cs_compiler, &[coeffs[i], FieldElement::ONE], &[
                        x[i].clone(),
                        sum_all.clone(),
                    ])
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

        let mut state: Vec<ConstantOrR1CSWitness> = inputs.clone();

        state = external_mds_t(r1cs_compiler, &state);

        // Poseidon2 round schedule: 4 full rounds -> pr partial rounds -> 4 full
        // rounds. Matches the 4 + Rp + 4 design from the Poseidon2 spec and reference templates ("https://github.com/TaceoLabs/nullifier-oracle-service/tree/main/circom/poseidon2/poseidon2_constants.circom").
        for r in 0..4 {
            let mut after = Vec::with_capacity(t_usize);
            for i in 0..t_usize {
                let with_rc = add_const(r1cs_compiler, state[i].clone(), rc_full1[r][i]);
                after.push(add_pow5(r1cs_compiler, with_rc));
            }
            state = external_mds_t(r1cs_compiler, &after);
        }

        for r in 0..pr as usize {
            let mut tmp = state.clone();
            let x_plus_rc = add_const(r1cs_compiler, tmp[0].clone(), rc_part[r]);
            tmp[0] = add_pow5(r1cs_compiler, x_plus_rc);

            state = internal_mds_t(r1cs_compiler, t, &tmp, &|tt| load_diag_fn(tt));
        }

        for r in 0..4 {
            let mut after = Vec::with_capacity(t_usize);
            for i in 0..t_usize {
                let with_rc = add_const(r1cs_compiler, state[i].clone(), rc_full2[r][i]);
                after.push(add_pow5(r1cs_compiler, with_rc));
            }
            state = external_mds_t(r1cs_compiler, &after);
        }

        for i in 0..t_usize {
            match state[i] {
                ConstantOrR1CSWitness::Witness(w) => {
                    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(outputs[i], vec![
                        SumTerm(None, w),
                    ]));
                    r1cs_compiler.r1cs.add_constraint(
                        &[(FieldElement::ONE, w)],
                        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                        &[(FieldElement::ONE, outputs[i])],
                    );
                }
                ConstantOrR1CSWitness::Constant(k) => {
                    r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(outputs[i], vec![
                        SumTerm(Some(k), r1cs_compiler.witness_one()),
                    ]));
                    r1cs_compiler.r1cs.add_constraint(
                        &[(FieldElement::ONE, outputs[i])],
                        &[(FieldElement::ONE, r1cs_compiler.witness_one())],
                        &[(k, r1cs_compiler.witness_one())],
                    );
                }
            }
        }
    }
}
