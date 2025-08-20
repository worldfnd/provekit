use {
    crate::{
        memory::{EValuesForMatrix, Memory},
        utilities::matrix::SparkMatrix,
    },
    anyhow::Result,
    noir_r1cs::{
        utils::{
            sumcheck::{eval_qubic_poly, sumcheck_fold_map_reduce},
            HALF,
        },
        FieldElement, SkyscraperSponge,
    },
    spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        ProverState,
    },
};

pub fn prove_spark_for_single_matrix(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    matrix: SparkMatrix,
    memory: Memory,
    e_values: EValuesForMatrix,
    claimed_value: FieldElement,
) -> Result<()> {
    let mles = [matrix.coo.val.clone(), e_values.e_rx, e_values.e_ry];
    run_spark_sumcheck(merlin, mles, claimed_value)?;
    Ok(())
}

pub fn run_spark_sumcheck(
    merlin: &mut ProverState<SkyscraperSponge, FieldElement>,
    mles: [Vec<FieldElement>; 3],
    mut claimed_value: FieldElement,
) -> Result<([FieldElement; 3], Vec<FieldElement>)> {
    let mut sumcheck_randomness = [FieldElement::from(0)];
    let mut sumcheck_randomness_accumulator = Vec::<FieldElement>::new();
    let mut fold = None;

    let mut m0 = mles[0].clone();
    let mut m1 = mles[1].clone();
    let mut m2 = mles[2].clone();

    loop {
        let [hhat_i_at_0, hhat_i_at_em1, hhat_i_at_inf_over_x_cube] =
            sumcheck_fold_map_reduce([&mut m0, &mut m1, &mut m2], fold, |[m0, m1, m2]| {
                [
                    // Evaluation at 0
                    m0.0 * m1.0 * m2.0,
                    // Evaluation at -1
                    (m0.0 + m0.0 - m0.1) * (m1.0 + m1.0 - m1.1) * (m2.0 + m2.0 - m2.1),
                    // Evaluation at infinity
                    (m0.1 - m0.0) * (m1.1 - m1.0) * (m2.1 - m2.0),
                ]
            });

        if fold.is_some() {
            m0.truncate(m0.len() / 2);
            m1.truncate(m1.len() / 2);
            m2.truncate(m2.len() / 2);
        }

        let mut hhat_i_coeffs = [FieldElement::from(0); 4];

        hhat_i_coeffs[0] = hhat_i_at_0;
        hhat_i_coeffs[2] =
            HALF * (claimed_value + hhat_i_at_em1 - hhat_i_at_0 - hhat_i_at_0 - hhat_i_at_0);
        hhat_i_coeffs[3] = hhat_i_at_inf_over_x_cube;
        hhat_i_coeffs[1] = claimed_value
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[0]
            - hhat_i_coeffs[3]
            - hhat_i_coeffs[2];

        assert_eq!(
            claimed_value,
            hhat_i_coeffs[0]
                + hhat_i_coeffs[0]
                + hhat_i_coeffs[1]
                + hhat_i_coeffs[2]
                + hhat_i_coeffs[3]
        );

        merlin.add_scalars(&hhat_i_coeffs[..])?;
        merlin.fill_challenge_scalars(&mut sumcheck_randomness)?;
        fold = Some(sumcheck_randomness[0]);
        claimed_value = eval_qubic_poly(&hhat_i_coeffs, &sumcheck_randomness[0]);
        sumcheck_randomness_accumulator.push(sumcheck_randomness[0]);
        if m0.len() <= 2 {
            break;
        }
    }

    let folded_v0 = m0[0] + (m0[1] - m0[0]) * sumcheck_randomness[0];
    let folded_v1 = m1[0] + (m1[1] - m1[0]) * sumcheck_randomness[0];
    let folded_v2 = m2[0] + (m2[1] - m2[0]) * sumcheck_randomness[0];

    Ok((
        [folded_v0, folded_v1, folded_v2],
        sumcheck_randomness_accumulator,
    ))
}
