pub const MAGIC_BYTES: &[u8] = b"\xDC\xDFOZkp\x01\x00";

/// Header layout: MAGIC(8) + FORMAT(8) + MAJOR(2) + MINOR(2) + HASH_CONFIG(1) =
/// 21 bytes
pub const HEADER_SIZE: usize = 21;

/// Zstd magic number: `28 B5 2F FD`.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// XZ magic number: `FD 37 7A 58 5A 00`.
pub const XZ_MAGIC: [u8; 6] = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];

// ---------------------------------------------------------------------------
// Per-format identifiers and versions
// ---------------------------------------------------------------------------

pub const PROVER_FORMAT: [u8; 8] = *b"PrvKitPr";
pub const PROVER_VERSION: (u16, u16) = (1, 2);

pub const VERIFIER_FORMAT: [u8; 8] = *b"PrvKitVr";
pub const VERIFIER_VERSION: (u16, u16) = (1, 3);

pub const NOIR_PROOF_SCHEME_FORMAT: [u8; 8] = *b"NrProScm";
pub const NOIR_PROOF_SCHEME_VERSION: (u16, u16) = (1, 2);

pub const NOIR_PROOF_FORMAT: [u8; 8] = *b"NPSProof";
pub const NOIR_PROOF_VERSION: (u16, u16) = (1, 1);
