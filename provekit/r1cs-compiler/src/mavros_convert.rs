use {mavros_artifacts::R1CS as MavrosR1CS, provekit_common::R1CS};

/// Convert a Mavros-emitted R1CS into the ProveKit [`R1CS`] representation.
///
/// Lives in the r1cs-compiler (the only consumer) so that `provekit-common`
/// stays free of the `mavros-artifacts` dependency.
pub(crate) fn convert_mavros_r1cs_to_provekit(mavros_r1cs: &MavrosR1CS) -> R1CS {
    let num_witnesses = mavros_r1cs.witness_layout.size();
    let num_constraints = mavros_r1cs.constraints.len();

    let total_entries: usize = mavros_r1cs
        .constraints
        .iter()
        .map(|c| c.a.len() + c.b.len() + c.c.len())
        .sum();

    let mut r1cs = R1CS::new();
    r1cs.add_witnesses(num_witnesses);
    r1cs.reserve_constraints(num_constraints, total_entries);

    // Element type (`InternedFieldElement`) is inferred from `r1cs.intern`, so
    // it need not be a public type of provekit-common.
    let mut a_buf = Vec::with_capacity(64);
    let mut b_buf = Vec::with_capacity(64);
    let mut c_buf = Vec::with_capacity(64);

    for constraint in &mavros_r1cs.constraints {
        a_buf.clear();
        a_buf.extend(
            constraint
                .a
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        b_buf.clear();
        b_buf.extend(
            constraint
                .b
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        c_buf.clear();
        c_buf.extend(
            constraint
                .c
                .iter()
                .map(|(idx, coeff)| (*idx as u32, r1cs.intern(*coeff))),
        );

        r1cs.push_constraint(
            a_buf.iter().copied(),
            b_buf.iter().copied(),
            c_buf.iter().copied(),
        );
    }

    r1cs
}
