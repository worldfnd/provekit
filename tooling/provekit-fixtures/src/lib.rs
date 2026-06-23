//! Synthetic R1CS fixtures and a field-generic prove→verify harness.
//!
//! [`builders`] constructs custom-size R1CS instances and satisfying witnesses
//! with the `R1CS` API alone — no circuit compiler — generic over the field.
//! [`harness`] runs a full commit→prove→verify roundtrip over any
//! [`FieldHash`](provekit_common::FieldHash) proof field. Together they
//! exercise the field-generic proof-system spine on instances of arbitrary
//! shape, independently of any frontend.

pub mod builders;
pub mod harness;
