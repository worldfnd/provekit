//! bn254 witness-hint computation: digit decomposition, multi-limb I/O, and
//! Spice RAM hints. These are the field-specific witness solvers invoked by the
//! prover's per-builder `solve()` dispatch.

pub mod digits;
pub mod limb_io;
pub mod ram;
