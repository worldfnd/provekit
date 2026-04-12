use std::env;

pub(super) fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_METAL_NTT_TRACE").is_some() {
        eprintln!("[provekit-metal-ntt] {args}");
    }
}
