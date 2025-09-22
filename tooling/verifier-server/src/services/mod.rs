//! Service layer for the verifier server
//!
//! This module contains the business logic for proof verification,
//! artifact management, and external system interactions.

pub mod artifact;
pub mod verification;

pub use {artifact::ArtifactService, verification::VerificationService};
