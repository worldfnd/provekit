//! Twist prover: fills Twist polynomial witnesses and runs the Twist sumcheck
//! within the Fiat-Shamir transcript.

use {
    ark_ff::PrimeField,
    provekit_common::{
        twist::{
            sumcheck::{
                eval_round_poly, fold_twist_polys, twist_sumcheck_round, TwistPolynomials,
            },
            MemoryOp, TwistMemoryOpInfo, TwistSchemeInfo, TwistTrace,
        },
        utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq,
        FieldElement, TranscriptSponge,
    },
    tracing::instrument,
    whir::transcript::{ProverState, VerifierMessage},
};

/// Data returned from the Twist sumcheck prover.
pub struct TwistSumcheckResult {
    /// Evaluation point (sequence of challenges from each sumcheck round).
    pub tau: Vec<FieldElement>,
    /// Evaluations of the 6 Twist polynomials at tau:
    /// `[inc, is_write, val, val_prev, addr, addr_prev]`.
    pub evals: [FieldElement; 6],
}

/// Fill all Twist-related witness slots: old values for Store operations and
/// the 6 Twist polynomials (inc, is_write, val, val_prev, addr, addr_prev).
///
/// Must be called after solving w1 but before extracting/committing.
#[instrument(skip_all)]
pub fn fill_twist_witnesses(
    witness: &mut [Option<FieldElement>],
    twist_info: &TwistSchemeInfo,
) {
    let mut all_initial_values = Vec::new();
    let mut all_ops = Vec::new();
    let mut addr_offset = 0usize;
    let mut timestamp = 1usize;

    for block in &twist_info.ram_blocks {
        let memory_size = block.initial_value_witnesses.len();

        // Simulate memory state for this block to determine old values
        let mut memory: Vec<FieldElement> = block
            .initial_value_witnesses
            .iter()
            .map(|&w| witness[w].expect("initial value witness must be solved before Twist"))
            .collect();

        all_initial_values.extend_from_slice(&memory);

        for op in &block.operations {
            match op {
                TwistMemoryOpInfo::Load(addr_w, val_w) => {
                    let addr_fe = witness[*addr_w].expect("address witness must be solved");
                    let addr: u64 = addr_fe.into_bigint().0[0];
                    all_ops.push(MemoryOp {
                        address: addr as usize + addr_offset,
                        value: witness[*val_w].expect("value witness must be solved"),
                        is_write: false,
                        timestamp,
                    });
                    timestamp += 1;
                }
                TwistMemoryOpInfo::Store(addr_w, old_val_w, new_val_w) => {
                    let addr_fe = witness[*addr_w].expect("address witness must be solved");
                    let addr: u64 = addr_fe.into_bigint().0[0];
                    let addr_usize = addr as usize;

                    // Fill old_value witness from simulated memory state
                    witness[*old_val_w] = Some(memory[addr_usize]);

                    let new_value = witness[*new_val_w].expect("new value witness must be solved");
                    memory[addr_usize] = new_value;

                    all_ops.push(MemoryOp {
                        address: addr_usize + addr_offset,
                        value: new_value,
                        is_write: true,
                        timestamp,
                    });
                    timestamp += 1;
                }
            }
        }

        addr_offset += memory_size;
    }

    let trace = TwistTrace::from_operations(&all_initial_values, &all_ops);
    debug_assert!(
        trace.check_consistency(),
        "Twist trace is inconsistent — memory violation"
    );

    let polys = TwistPolynomials::from_trace(&trace);
    debug_assert!(
        polys.check_zero_everywhere(),
        "Twist constraint violated — invalid memory trace"
    );

    // Write the 6 polynomials into witness slots
    let poly_vecs: [&[FieldElement]; 6] = [
        &polys.inc,
        &polys.is_write,
        &polys.val,
        &polys.val_prev,
        &polys.addr,
        &polys.addr_prev,
    ];
    for (idx, vals) in poly_vecs.iter().enumerate() {
        let start = twist_info.poly_start(idx);
        for (i, &v) in vals.iter().enumerate() {
            witness[start + i] = Some(v);
        }
    }
}

/// Run the Twist sumcheck within the Fiat-Shamir transcript.
///
/// Reads the Twist polynomial values from the committed w1 polynomial at the
/// offsets described by `twist_info`. After sumcheck, sends the 6 polynomial
/// evaluations as hints (independently verified by WHIR).
#[instrument(skip_all)]
pub fn run_twist_sumcheck_prover(
    merlin: &mut ProverState<TranscriptSponge>,
    w1_polynomial: &[FieldElement],
    twist_info: &TwistSchemeInfo,
) -> TwistSumcheckResult {
    let num_vars = twist_info.num_vars;
    let tsp = twist_info.trace_size_padded;

    // Extract the 6 polynomials from the committed w1
    let extract = |idx: usize| -> Vec<FieldElement> {
        let start = twist_info.poly_start(idx);
        w1_polynomial[start..start + tsp].to_vec()
    };

    let mut polys = TwistPolynomials {
        inc: extract(0),
        is_write: extract(1),
        val: extract(2),
        val_prev: extract(3),
        addr: extract(4),
        addr_prev: extract(5),
    };

    // Get randomness from transcript
    let r: Vec<FieldElement> = merlin.verifier_message_vec(num_vars);
    let beta: [FieldElement; 2] = [merlin.verifier_message(), merlin.verifier_message()];

    let mut eq_evals = calculate_evaluations_over_boolean_hypercube_for_eq(&r, tsp);

    // Initial claimed sum is 0 (valid trace ⇒ constraint sums to zero)
    let mut claimed_sum = FieldElement::from(0u64);

    let mut tau = Vec::with_capacity(num_vars);

    for _round in 0..num_vars {
        let round_poly = twist_sumcheck_round(&eq_evals, &polys, &beta);

        debug_assert_eq!(
            round_poly[0] + round_poly[1],
            claimed_sum,
            "Twist sumcheck round consistency failed"
        );

        // Send the 5 evaluation points to transcript
        for coeff in &round_poly {
            merlin.prover_message(coeff);
        }

        // Receive challenge
        let alpha_i: FieldElement = merlin.verifier_message();
        tau.push(alpha_i);

        // Update claimed sum and fold
        claimed_sum = eval_round_poly(&round_poly, alpha_i);
        fold_twist_polys(&mut polys, &mut eq_evals, alpha_i);
    }

    // After all rounds, polys have length 1 — these are evaluations at tau
    debug_assert_eq!(polys.len(), 1);
    let evals = [
        polys.inc[0],
        polys.is_write[0],
        polys.val[0],
        polys.val_prev[0],
        polys.addr[0],
        polys.addr_prev[0],
    ];

    // Send evaluations as hints (independently verified by WHIR)
    merlin.prover_hint_ark(&evals);

    TwistSumcheckResult { tau, evals }
}
