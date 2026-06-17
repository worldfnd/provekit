//! `FileFormat` / `MaybeHashAware` implementations for the on-disk frontend
//! types.
//!
//! These live in `provekit-noir` alongside the types themselves so that
//! `provekit-common` stays field- and frontend-agnostic. The generic
//! `read`/`write`/`serialize`/`deserialize` machinery (and the traits) remain
//! in `provekit-common`'s `file` module.

use {
    crate::{NoirProof, NoirProofScheme, Prover, Verifier},
    provekit_common::{
        binary_format,
        file::{Compression, FileFormat, MaybeHashAware},
        HashConfig,
    },
};

/// Impl for Prover (has hash config).
impl MaybeHashAware for Prover {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            Prover::Noir(p) => Some(p.hash_config),
            Prover::Mavros(p) => Some(p.hash_config),
        }
    }
}

/// Impl for Verifier (has hash config).
impl MaybeHashAware for Verifier {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        Some(self.hash_config)
    }
}

/// Impl for NoirProof (no hash config).
impl MaybeHashAware for NoirProof {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        None
    }
}

/// Impl for NoirProofScheme (has hash config).
impl MaybeHashAware for NoirProofScheme {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            NoirProofScheme::Noir(d) => Some(d.hash_config),
            NoirProofScheme::Mavros(d) => Some(d.hash_config),
        }
    }
}

impl FileFormat for NoirProofScheme {
    const FORMAT: [u8; 8] = binary_format::NOIR_PROOF_SCHEME_FORMAT;
    const EXTENSION: &'static str = "nps";
    const VERSION: (u16, u16) = binary_format::NOIR_PROOF_SCHEME_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl FileFormat for Prover {
    const FORMAT: [u8; 8] = binary_format::PROVER_FORMAT;
    const EXTENSION: &'static str = "pkp";
    const VERSION: (u16, u16) = binary_format::PROVER_VERSION;
    const COMPRESSION: Compression = Compression::Xz;
}

impl FileFormat for Verifier {
    const FORMAT: [u8; 8] = binary_format::VERIFIER_FORMAT;
    const EXTENSION: &'static str = "pkv";
    const VERSION: (u16, u16) = binary_format::VERIFIER_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}

impl FileFormat for NoirProof {
    const FORMAT: [u8; 8] = binary_format::NOIR_PROOF_FORMAT;
    const EXTENSION: &'static str = "np";
    const VERSION: (u16, u16) = binary_format::NOIR_PROOF_VERSION;
    const COMPRESSION: Compression = Compression::Zstd;
}
