use {
    anyhow::Result,
    provekit_common::FieldElement,
    rand::{rng, Rng},
    tracing::{info, instrument},
};

mod digits;
mod ram;
pub(crate) mod witness_builder;
pub(crate) mod witness_io_pattern;

/// Complete a partial witness with random values.
#[instrument(skip_all, fields(size = witness.len()))]
pub(crate) fn fill_witness(witness: Vec<Option<FieldElement>>) -> Result<Vec<FieldElement>> {
    // TODO: Use better entropy source and proper sampling.
    let mut rng = rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                FieldElement::from(rng.random::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}
