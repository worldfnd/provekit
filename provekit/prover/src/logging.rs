use {
    ::tracing::{debug, enabled, Level},
    ark_std::Zero,
    provekit_common::FieldElement,
};

pub(crate) fn log_commit_input(label: &str, values: &[FieldElement], scheme_domain_len: usize) {
    if !enabled!(Level::DEBUG) {
        return;
    }

    let input_len = values.len();
    let input_padded_len = input_len.max(1).next_power_of_two();
    let nonzero_entries = values.iter().filter(|v| !v.is_zero()).count();
    debug!(
        label,
        input_len, input_padded_len, scheme_domain_len, nonzero_entries, "WHIR commit input"
    );
}
