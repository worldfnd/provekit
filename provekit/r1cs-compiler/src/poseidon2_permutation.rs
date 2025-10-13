use {
    crate::{noir_to_r1cs::NoirToR1CSCompiler, poseidon2_constants},
    ark_ff::Field,
    ark_std::One,
    provekit_common::{
        witness::{ConstantOrR1CSWitness, SumTerm, WitnessBuilder},
        FieldElement,
    },
};

// y = a + c  (c is a field constant)
fn add_add_const(cs: &mut NoirToR1CSCompiler, a: usize, c: FieldElement) -> usize {
    let y = cs.num_witnesses();
    cs.r1cs.add_witnesses(1);
    cs.add_witness_builder(WitnessBuilder::Sum(y, vec![
        SumTerm(None, a),
        SumTerm(Some(c), cs.witness_one()),
    ]));
    cs.r1cs.add_constraint(
        &[(FieldElement::ONE, y)],
        &[(FieldElement::ONE, cs.witness_one())],
        &[(FieldElement::ONE, a), (c, cs.witness_one())],
    );
    y
}

// z = x * y
fn add_mul(cs: &mut NoirToR1CSCompiler, x: usize, y: usize) -> usize {
    let z = cs.add_witness_builder(WitnessBuilder::Product(cs.num_witnesses(), x, y));

    // Enforce (1*x) * (1*y) = (1*z)
    cs.r1cs.add_constraint(
        &[(FieldElement::one(), x)], // left linear comb A
        &[(FieldElement::one(), y)], // right linear comb B
        &[(FieldElement::one(), z)], // output linear comb C
    );

    z
}

// y = sum_i (coeff_i * w_i). coeffs.len() == ws.len()
fn add_linear_combo(cs: &mut NoirToR1CSCompiler, coeffs: &[FieldElement], ws: &[usize]) -> usize {
    assert_eq!(coeffs.len(), ws.len());
    let y = cs.num_witnesses();
    cs.r1cs.add_witnesses(1);

    cs.add_witness_builder(WitnessBuilder::Sum(
        y,
        ws.iter()
            .zip(coeffs.iter())
            .map(|(&w, c)| SumTerm(Some(*c), w))
            .collect(),
    ));

    cs.r1cs.add_constraint(
        &ws.iter()
            .zip(coeffs.iter())
            .map(|(&w, c)| (*c, w))
            .collect::<Vec<_>>(),
        &[(FieldElement::ONE, cs.witness_one())],
        &[(FieldElement::ONE, y)],
    );
    y
}

// y = x^5 = (((x^2)^2) * x). Returns y
fn add_pow5(cs: &mut NoirToR1CSCompiler, x: usize) -> usize {
    let x2 = add_mul(cs, x, x);
    let x4 = add_mul(cs, x2, x2);
    let x5 = add_mul(cs, x4, x);
    x5
}
// External MDS for t=2
fn external_mds2(cs: &mut NoirToR1CSCompiler, s: &[usize]) -> Vec<usize> {
    // sum = s0 + s1
    let sum = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[0], s[1]]);
    // out0 = s0 + sum ; out1 = s1 + sum
    let out0 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[0], sum]);
    let out1 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[1], sum]);
    vec![out0, out1]
}

fn external_mds3(cs: &mut NoirToR1CSCompiler, s: &[usize]) -> Vec<usize> {
    let sum = add_linear_combo(
        cs,
        &[FieldElement::ONE, FieldElement::ONE, FieldElement::ONE],
        &[s[0], s[1], s[2]],
    );
    let o0 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[0], sum]);
    let o1 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[1], sum]);
    let o2 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[s[2], sum]);
    vec![o0, o1, o2]
}

fn external_mds4(cs: &mut NoirToR1CSCompiler, s: &[usize]) -> Vec<usize> {
    let double = |c: FieldElement| c + c;
    let four = |c: FieldElement| double(double(c));

    let f1 = FieldElement::from(1u64);

    let double_in1 = add_linear_combo(cs, &[double(f1)], &[s[1]]);
    let double_in3 = add_linear_combo(cs, &[double(f1)], &[s[3]]);

    let t0 = add_linear_combo(cs, &[f1, f1], &[s[0], s[1]]);
    let t1 = add_linear_combo(cs, &[f1, f1], &[s[2], s[3]]);

    let quad_t0 = add_linear_combo(cs, &[four(f1)], &[t0]);
    let quad_t1 = add_linear_combo(cs, &[four(f1)], &[t1]);

    let t2 = add_linear_combo(cs, &[f1, f1], &[double_in1, t1]);
    let t3 = add_linear_combo(cs, &[f1, f1], &[double_in3, t0]);
    let t4 = add_linear_combo(cs, &[f1, f1], &[quad_t1, t3]);
    let t5 = add_linear_combo(cs, &[f1, f1], &[quad_t0, t2]);

    let o0 = add_linear_combo(cs, &[f1, f1], &[t3, t5]);
    let o1 = t5;
    let o2 = add_linear_combo(cs, &[f1, f1], &[t2, t4]);
    let o3 = t4;
    vec![o0, o1, o2, o3]
}

// add per-column accumulators with linear combos.
fn external_mds_t(cs: &mut NoirToR1CSCompiler, s: &[usize]) -> Vec<usize> {
    match s.len() {
        2 => external_mds2(cs, s),
        3 => external_mds3(cs, s),
        4 => external_mds4(cs, s),
        t if [8, 12, 16].contains(&t) => {
            // apply external_mds4 on each chunk
            let blocks = t / 4;
            let mut block_out: Vec<[usize; 4]> = Vec::with_capacity(blocks);
            for i in 0..blocks {
                let o = external_mds4(cs, &s[4 * i..4 * i + 4]);
                block_out.push([o[0], o[1], o[2], o[3]]);
            }
            // column sums across blocks
            let mut col_acc = vec![0usize; 4];
            for j in 0..4 {
                let coeffs = vec![FieldElement::ONE; blocks];
                let ws = (0..blocks).map(|i| block_out[i][j]).collect::<Vec<_>>();
                col_acc[j] = add_linear_combo(cs, &coeffs, &ws);
            }
            // out[i*4+j] = block_out[i][j] + col_acc[j]
            let mut out = vec![0usize; t];
            for i in 0..blocks {
                for j in 0..4 {
                    out[4 * i + j] =
                        add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[
                            block_out[i][j],
                            col_acc[j],
                        ]);
                }
            }
            out
        }
        _ => panic!("unsupported t for external MDS"),
    }
}

// Internal MDS (partial rounds)
fn internal_mds_t(
    cs: &mut NoirToR1CSCompiler,
    t: u32,
    x: &[usize],
    load_diag: &dyn Fn(u32) -> Vec<FieldElement>,
) -> Vec<usize> {
    match t {
        2 => {
            // [ x0 + sum, 2*x1 + sum ]
            let sum = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[x[0], x[1]]);
            let o0 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[x[0], sum]);
            let o1 = add_linear_combo(cs, &[FieldElement::from(2u64), FieldElement::ONE], &[
                x[1], sum,
            ]);
            vec![o0, o1]
        }
        3 => {
            let sum = add_linear_combo(
                cs,
                &[FieldElement::ONE, FieldElement::ONE, FieldElement::ONE],
                &[x[0], x[1], x[2]],
            );
            let o0 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[x[0], sum]);
            let o1 = add_linear_combo(cs, &[FieldElement::ONE, FieldElement::ONE], &[x[1], sum]);
            let o2 = add_linear_combo(cs, &[FieldElement::from(2u64), FieldElement::ONE], &[
                x[2], sum,
            ]);
            vec![o0, o1, o2]
        }
        t if [4, 8, 12, 16].contains(&t) => {
            // diag[i]*x[i] + sum_all
            let coeffs = load_diag(t);
            let sum_all = add_linear_combo(cs, &vec![FieldElement::ONE; t as usize], x);
            (0..t as usize)
                .map(|i| add_linear_combo(cs, &[coeffs[i], FieldElement::ONE], &[x[i], sum_all]))
                .collect()
        }
        _ => panic!("unsupported t for internal MDS"),
    }
}

pub(crate) fn add_poseidon2_permutation(
    cs: &mut NoirToR1CSCompiler,
    ops: Vec<(u32, Vec<ConstantOrR1CSWitness>, Vec<usize>)>, // (t, inputs, outputs)
) {
    for (t, inputs, outputs) in ops {
        let t_usize = t as usize;
        assert!(matches!(t, 2 | 3 | 4 | 8 | 12 | 16));
        assert_eq!(inputs.len(), t_usize);
        assert_eq!(outputs.len(), t_usize);

        // Load constants
        let pr = poseidon2_constants::amount_partial_rounds(t);
        let rc_full1 = poseidon2_constants::load_rc_full1(t); // -> Vec<[FieldElement; t]>
        let rc_part = poseidon2_constants::load_rc_partial(t); // -> Vec<FieldElement>, len pr
        let rc_full2 = poseidon2_constants::load_rc_full2(t); // -> Vec<[FieldElement; t]>
        let load_diag_fn = |tt: u32| poseidon2_constants::load_diag(tt); // -> Vec<FieldElement; t>

        // Materialize initial state witnesses from inputs (allow constants)
        let mut state: Vec<usize> = inputs
            .iter()
            .map(|ino| {
                match ino {
                    ConstantOrR1CSWitness::Witness(w) => *w,
                    ConstantOrR1CSWitness::Constant(c) => {
                        // allocate a witness equal to that constant
                        let y = cs.num_witnesses();
                        cs.r1cs.add_witnesses(1);
                        cs.add_witness_builder(WitnessBuilder::Sum(y, vec![SumTerm(
                            Some(*c),
                            cs.witness_one(),
                        )]));
                        // constrain y = c
                        cs.r1cs.add_constraint(
                            &[(FieldElement::ONE, cs.witness_one())],
                            &[(FieldElement::ONE, cs.witness_one())],
                            &[(FieldElement::ONE, y), (*c, cs.witness_one())],
                        );
                        y
                    }
                }
            })
            .collect();

        // state = ExternalMDS(state)
        state = external_mds_t(cs, &state);

        // --- full rounds (4) ---
        for r in 0..4 {
            // add round constants + sbox(x^5) on all lanes
            let mut after_sbox = Vec::with_capacity(t_usize);
            for i in 0..t_usize {
                let with_rc = add_add_const(cs, state[i], rc_full1[r][i]);
                let sboxed = add_pow5(cs, with_rc);
                after_sbox.push(sboxed);
            }
            // external MDS
            state = external_mds_t(cs, &after_sbox);
        }

        // --- partial rounds (pr) ---
        for r in 0..pr as usize {
            // first lane: add rc + sbox; other lanes pass through
            let mut tmp = state.clone();
            let x_plus_rc = add_add_const(cs, state[0], rc_part[r]);

            // apply the x^5 S-box to that
            let x_pow5 = add_pow5(cs, x_plus_rc);

            tmp[0] = x_pow5; // internal MDS
            state = internal_mds_t(cs, t, &tmp, &|tt| load_diag_fn(tt));
        }

        // --- full rounds (4) ---
        for r in 0..4 {
            let mut after_sbox = Vec::with_capacity(t_usize);
            for i in 0..t_usize {
                let with_rc = add_add_const(cs, state[i], rc_full2[r][i]);
                let sboxed = add_pow5(cs, with_rc);
                after_sbox.push(sboxed);
            }
            state = external_mds_t(cs, &after_sbox);
        }

        // Constrain outputs == state
        for i in 0..t_usize {
            cs.r1cs.add_constraint(
                &[(FieldElement::ONE, state[i])],
                &[(FieldElement::ONE, cs.witness_one())],
                &[(FieldElement::ONE, outputs[i])],
            );
        }
    }
}
