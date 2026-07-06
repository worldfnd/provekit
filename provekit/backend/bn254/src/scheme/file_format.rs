//! File-format glue for the bn254 scheme types. The generic machinery
//! ([`FileFormat`], `write`/`read`) lives in `provekit_common::file`; these
//! impls bind the concrete scheme types to their on-disk formats.

use {
    crate::{NoirProofScheme, Prover, Verifier},
    provekit_common::{
        binary_format,
        file::{Compression, FileFormat, MaybeHashAware},
        HashConfig,
    },
};

impl MaybeHashAware for Prover {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        match self {
            Prover::Noir(p) => Some(p.hash_config),
            Prover::Mavros(p) => Some(p.hash_config),
        }
    }
}

impl MaybeHashAware for Verifier {
    fn maybe_hash_config(&self) -> Option<HashConfig> {
        Some(self.hash_config)
    }
}

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
