//! Shared binary format constants for ProveKit artifact files.
//!
//! These constants define the wire format for `.pkp`, `.pkv`, `.nps`, and `.np`
//! files. They are the **single source of truth** — both the native file I/O
//! ([`crate::file`]) and the WASM bindings (`provekit-wasm`) must reference
//! these definitions.

/// Magic bytes identifying ProveKit binary artifacts.
pub const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Header size in bytes: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) +
/// HASH_CONFIG(1) = 21.
pub const HEADER_SIZE: usize = 21;

/// Zstd magic number: `28 B5 2F FD`.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// XZ magic number: `FD 37 7A 58 5A 00`.
pub const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

// ---------------------------------------------------------------------------
// Per-format identifiers and versions
// ---------------------------------------------------------------------------

/// Prover artifact format (`.pkp` files).
pub const PROVER_FORMAT: [u8; 8] = *b"PrvKitPr";
/// Prover artifact version.
pub const PROVER_VERSION: (u16, u16) = (1, 2);

/// Verifier artifact format (`.pkv` files).
pub const VERIFIER_FORMAT: [u8; 8] = *b"PrvKitVr";
/// Verifier artifact version.
pub const VERIFIER_VERSION: (u16, u16) = (1, 3);

/// Noir proof scheme format (`.nps` files).
pub const NOIR_PROOF_SCHEME_FORMAT: [u8; 8] = *b"NrProScm";
/// Noir proof scheme version.
pub const NOIR_PROOF_SCHEME_VERSION: (u16, u16) = (1, 2);

/// Noir proof format (`.np` files).
pub const NOIR_PROOF_FORMAT: [u8; 8] = *b"NPSProof";
/// Noir proof version.
pub const NOIR_PROOF_VERSION: (u16, u16) = (1, 1);
