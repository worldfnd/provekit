use {
    ::tracing::{debug, enabled, Level},
    ark_ff::Field,
};

/// Log nonzero-density statistics for a WHIR commit input (debug level only).
pub fn log_commit_input<F: Field>(label: &str, values: &[F], scheme_domain_len: usize) {
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
