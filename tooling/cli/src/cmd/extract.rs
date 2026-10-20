use {ark_ff::Field, provekit_common::R1CS, std::collections::HashMap, tracing::info};

/// Group matrix positions by coefficient triple, omitting the all-zero triple.
pub(super) fn extract<F: Field>(r1cs: &R1CS<F>) {
    let entries = collect_entries(r1cs);

    let total_nonzero = entries.values().map(|v| v.len()).sum::<usize>();
    info!(
        "Collected {} unique triplets among {}.",
        entries.len(),
        total_nonzero
    );
}

fn collect_entries<F: Field>(r1cs: &R1CS<F>) -> HashMap<(F, F, F), Vec<(usize, usize)>> {
    let matrices = [r1cs.a(), r1cs.b(), r1cs.c()];
    let mut entries = matrices.each_ref().map(|matrix| matrix.iter().peekable());
    let mut triples = HashMap::<_, Vec<_>>::new();

    // Merge the three sorted streams, visiting each occupied position once.
    loop {
        let Some(index) = entries
            .iter_mut()
            .filter_map(|entries| entries.peek().map(|&(index, _)| index))
            .min()
        else {
            break;
        };

        let [a, b, c] = entries.each_mut().map(|entries| {
            entries
                .next_if(|&(entry_index, _)| entry_index == index)
                .map_or(F::ZERO, |(_, value)| value)
        });

        if !a.is_zero() || !b.is_zero() || !c.is_zero() {
            triples.entry((a, b, c)).or_default().push(index);
        }
    }

    triples
}
