//! Noir-compatible commitment functions for passport circuit inputs.
//!
//! These functions replicate the commitment computations from the Noir
//! circuits, allowing the Rust input generator to compute actual values instead
//! of placeholders.

use {
    crate::{parser::types::PassportError, poseidon2::poseidon2_hash},
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
};

/// Parse a 0x-prefixed hex string (e.g. "0x2") into a BN254 field element.
pub fn parse_hex_to_field(hex_str: &str) -> Result<Fr, PassportError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    // Padding to 64 hex chars (32 bytes) is specific to BN254 field element size.
    // This assumes the curve is BN254, which has 254-bit field elements.
    let padded = format!("{:0>64}", stripped);
    let bytes = hex::decode(&padded).map_err(|e| PassportError::InvalidHexField {
        field:  hex_str.to_string(),
        source: e,
    })?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

/// Pack big-endian bytes into BN254 field elements, matching Noir's
/// `pack_be_bytes_into_fields<NBytes, N, 31>()`.
///
/// Packing scheme (31 bytes per field, reversed storage order):
/// - N = (len + 30) / 31  field elements
/// - First chunk (may be shorter): `bytes[0..first_chunk_size]` → `result[N-1]`
/// - Remaining chunks (31 bytes each): stored in `result[N-2]`, `result[N-3]`,
///   ..., `result[0]`
///
/// Each chunk is interpreted as a big-endian integer.
pub fn pack_be_bytes_into_fields(bytes: &[u8]) -> Vec<Fr> {
    let n_bytes = bytes.len();
    if n_bytes == 0 {
        return vec![];
    }
    // Packing scheme is designed for BN254 curve (field size = 31 bytes per
    // element).
    let n = (n_bytes + 30) / 31;
    let mut result = vec![Fr::from(0u64); n];

    let mut k = 0usize;

    // First chunk: may be shorter than 31 bytes
    // first_chunk_size = 31 - (N*31 - NBytes) = NBytes - 31*(N-1)
    let first_chunk_size = 31 - (n * 31 - n_bytes);
    let mut limb = Fr::from(0u64);
    for _ in 0..first_chunk_size {
        limb *= Fr::from(256u64);
        limb += Fr::from(bytes[k] as u64);
        k += 1;
    }
    result[n - 1] = limb;

    // Remaining chunks: each exactly 31 bytes
    for i in 1..n {
        let mut limb = Fr::from(0u64);
        for _ in 0..31 {
            limb *= Fr::from(256u64);
            limb += Fr::from(bytes[k] as u64);
            k += 1;
        }
        result[n - i - 1] = limb;
    }

    result
}

/// Compute SOD hash: Poseidon2(pack_be_bytes_into_fields(e_content)).
///
/// Matches Noir's `calculate_sod_hash<ECONTENT_SIZE>(e_content)` from
/// `utils/commitment/common/src/lib.nr:111-117`.
pub fn calculate_sod_hash(e_content: &[u8]) -> Fr {
    let packed = pack_be_bytes_into_fields(e_content);
    poseidon2_hash(&packed)
}

/// Compute Stage 1 commitment: Poseidon2(salt, packed_country, packed_tbs).
///
/// Matches Noir's `hash_salt_country_tbs<TBS_MAX_SIZE>()` from
/// `passport/lib/commitment/common/src/lib.nr`.
///
/// Field layout (variable, depends on TBS size):
///   `[0]`     = salt
///   `[1]`     = packed country (3 bytes → 1 field)
///   `[2..]`   = packed TBS certificate (e.g. 700 bytes → 23 fields)
pub fn hash_salt_country_tbs(
    salt: &str,
    country: &[u8],
    tbs_certificate: &[u8],
) -> Result<Fr, PassportError> {
    let mut fields = Vec::new();
    fields.push(parse_hex_to_field(salt)?);
    fields.extend(pack_be_bytes_into_fields(country));
    fields.extend(pack_be_bytes_into_fields(tbs_certificate));
    Ok(poseidon2_hash(&fields))
}

/// Compute private nullifier: Poseidon2(packed_dg1, packed_e_content,
/// packed_sod_sig).
///
/// Matches Noir's `calculate_private_nullifier<SIG>()` from
/// `passport/lib/commitment/common/src/lib.nr`.
///
/// Field layout (variable, depends on signature size):
///   packed DG1 (95 bytes → 4 fields)
///   packed eContent (700 bytes → 23 fields)
///   packed SOD signature (e.g. 256 bytes → 9 fields)
pub fn calculate_private_nullifier(dg1: &[u8], e_content: &[u8], sod_signature: &[u8]) -> Fr {
    let mut fields = Vec::new();
    fields.extend(pack_be_bytes_into_fields(dg1));
    fields.extend(pack_be_bytes_into_fields(e_content));
    fields.extend(pack_be_bytes_into_fields(sod_signature));
    poseidon2_hash(&fields)
}

/// Compute Stage 2 commitment: Poseidon2(salt, country, signed_attr, sa_size,
/// dg1, e_content, nullifier).
///
/// Matches Noir's
/// `hash_salt_country_signed_attr_dg1_e_content_private_nullifier()` from
/// `passport/lib/commitment/common/src/lib.nr`.
///
/// Field layout (39 fields for SA=220, DG1=95, ECONTENT=700):
///   `[0]`       = salt
///   `[1]`       = packed country (3 bytes → 1 field)
///   `[2..10]`   = packed signed_attributes (220 bytes → 8 fields)
///   `[10]`      = signed_attr_size as field
///   `[11..15]`  = packed DG1 (95 bytes → 4 fields)
///   `[15..38]`  = packed eContent (700 bytes → 23 fields)
///   `[38]`      = private_nullifier
pub fn hash_salt_country_sa_dg1_econtent_nullifier(
    salt: &str,
    country: &[u8],
    signed_attr: &[u8],
    signed_attr_size: u64,
    dg1: &[u8],
    e_content: &[u8],
    private_nullifier: Fr,
) -> Result<Fr, PassportError> {
    let mut fields = Vec::new();
    fields.push(parse_hex_to_field(salt)?);
    fields.extend(pack_be_bytes_into_fields(country));
    fields.extend(pack_be_bytes_into_fields(signed_attr));
    fields.push(Fr::from(signed_attr_size));
    fields.extend(pack_be_bytes_into_fields(dg1));
    fields.extend(pack_be_bytes_into_fields(e_content));
    fields.push(private_nullifier);
    Ok(poseidon2_hash(&fields))
}

/// Compute h_dg1 (blinded_dg1): Poseidon2([r_dg1, packed_dg1]).
///
/// Matches Noir's `calculate_blinded_dg1(r_dg1, dg1)` from
/// `passport/lib/commitment/common/src/lib.nr`.
pub fn calculate_h_dg1(r_dg1: &str, dg1: &[u8]) -> Result<Fr, PassportError> {
    let mut fields = Vec::with_capacity(5);
    fields.push(parse_hex_to_field(r_dg1)?);
    fields.extend(pack_be_bytes_into_fields(dg1));
    Ok(poseidon2_hash(&fields))
}

/// Compute Merkle leaf: Poseidon2([h_dg1, sod_hash]).
///
/// Matches Noir's `calculate_merkle_leaf(r_dg1, dg1, e_content)` from
/// `passport/lib/commitment/common/src/lib.nr`.
pub fn calculate_leaf(h_dg1: Fr, sod_hash: Fr) -> Fr {
    poseidon2_hash(&[h_dg1, sod_hash])
}

/// Compute Merkle root from leaf, index, and sibling path.
///
/// Translates Noir's `compute_merkle_root<N>(leaf, index, hash_path)` from
/// `zkpassport_libs/commitment/common/src/lib.nr:315-328`.
///
/// Binary Merkle tree with Poseidon2 hashing. Bit `i` of `leaf_index` (LE)
/// determines whether `current` is the left or right child at level `i`.
pub fn compute_merkle_root(leaf: Fr, leaf_index: u64, merkle_path: &[Fr]) -> Fr {
    let mut current = leaf;
    for (i, sibling) in merkle_path.iter().enumerate() {
        let bit = (leaf_index >> i) & 1;
        let (left, right) = if bit == 0 {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        current = poseidon2_hash(&[left, right]);
    }
    current
}

/// Convert a BN254 field element to a 0x-prefixed hex string (64 hex chars).
pub fn field_to_hex_string(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_be_bytes_3_bytes() {
        // 3 bytes → 1 field element: N = (3+30)/31 = 1
        // first_chunk_size = 3 - 31*(1-1) = 3
        let bytes = [0x41u8, 0x42, 0x43]; // "ABC"
        let packed = pack_be_bytes_into_fields(&bytes);
        assert_eq!(packed.len(), 1);
        // 0x41*256^2 + 0x42*256 + 0x43 = 65*65536 + 66*256 + 67 = 4276803
        assert_eq!(packed[0], Fr::from(4276803u64));
    }

    #[test]
    fn test_pack_be_bytes_32_bytes() {
        // 32 bytes → 2 field elements: N = (32+30)/31 = 2
        // first_chunk_size = 32 - 31*(2-1) = 1
        let mut bytes = [0u8; 32];
        bytes[0] = 0xff; // First chunk: 1 byte → result[1]
        for i in 1..32 {
            bytes[i] = i as u8; // Second chunk: 31 bytes → result[0]
        }
        let packed = pack_be_bytes_into_fields(&bytes);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[1], Fr::from(0xffu64)); // Short first chunk
    }

    #[test]
    fn test_pack_be_bytes_700_bytes() {
        // 700 bytes → 23 field elements (matching new e_content size)
        let bytes = [0u8; 700];
        let packed = pack_be_bytes_into_fields(&bytes);
        assert_eq!(packed.len(), 23);
    }

    #[test]
    fn test_calculate_sod_hash_deterministic() {
        // Verify sod_hash is deterministic and non-zero (700-byte econtent)
        let mut e_content = [0u8; 700];
        e_content[0..32].copy_from_slice(&[
            54, 197, 174, 86, 62, 194, 237, 211, 184, 91, 92, 169, 195, 149, 233, 156, 60, 80, 224,
            124, 161, 170, 204, 239, 154, 92, 165, 10, 81, 42, 90, 7,
        ]);
        let hash1 = calculate_sod_hash(&e_content);
        let hash2 = calculate_sod_hash(&e_content);
        assert_eq!(hash1, hash2, "sod_hash should be deterministic");
        assert_ne!(
            field_to_hex_string(&hash1),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "sod_hash should be non-zero"
        );
    }

    #[test]
    fn test_parse_hex_to_field_small() {
        // "0x2" should parse to Fr(2)
        assert_eq!(parse_hex_to_field("0x2").unwrap(), Fr::from(2u64));
        assert_eq!(parse_hex_to_field("0x3").unwrap(), Fr::from(3u64));
    }

    #[test]
    fn test_parse_hex_to_field_roundtrip() {
        let hex = "0x0f7f8bb032ad068e1c3b717ec1e7020d3537e20688af7bd7a7ae51df72f368bc";
        let f = parse_hex_to_field(hex).unwrap();
        let back = field_to_hex_string(&f);
        assert_eq!(back, hex);
    }

    #[test]
    fn test_field_count_sanity() {
        // Verify field counts match Noir's expectations for new buffer sizes
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 3]).len(), 1); // country
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 700]).len(), 23); // tbs_certificate 700
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 1000]).len(), 33); // tbs_certificate 1000
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 1200]).len(), 39); // tbs_certificate 1200
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 1600]).len(), 52); // tbs_certificate 1600
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 95]).len(), 4); // dg1
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 220]).len(), 8); // signed_attributes
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 700]).len(), 23); // e_content
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 128]).len(), 5); // RSA-1024 sig
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 256]).len(), 9); // RSA-2048 sig
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 384]).len(), 13); // RSA-3072 sig
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 512]).len(), 17); // RSA-4096 sig
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 768]).len(), 25); // RSA-6144 sig
    }

    #[test]
    fn test_compute_merkle_root_empty_tree() {
        let r_dg1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let dg1 = [0u8; 95];

        let e_content = [0u8; 700];
        let sod_hash = calculate_sod_hash(&e_content);

        let h_dg1 = calculate_h_dg1(r_dg1, &dg1).unwrap();
        let leaf = calculate_leaf(h_dg1, sod_hash);

        // leaf_index=0, all-zero path (24 levels)
        let merkle_path = vec![Fr::from(0u64); 24];
        let root = compute_merkle_root(leaf, 0, &merkle_path);

        // The root should be deterministic and non-zero
        assert_ne!(root, Fr::from(0u64), "merkle root should not be zero");

        // Verify consistency: computing the same root again gives the same value
        let root2 = compute_merkle_root(leaf, 0, &merkle_path);
        assert_eq!(root, root2, "merkle root should be deterministic");
    }
}
