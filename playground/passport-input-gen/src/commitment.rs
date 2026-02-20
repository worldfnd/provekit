//! Noir-compatible commitment functions for passport circuit inputs.
//!
//! These functions replicate the commitment computations from the Noir
//! circuits, allowing the Rust input generator to compute actual values instead
//! of placeholders.

use {
    crate::parser::types::PassportError,
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
    poseidon2::poseidon2_hash,
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

/// Compute circuit 1 commitment: Poseidon2(salt, packed_country, packed_tbs).
///
/// Matches Noir's `hash_salt_country_tbs<TBS_MAX_SIZE>()` from
/// `utils/commitment/common/src/lib.nr:46-65`.
///
/// Field layout (26 fields for TBS_MAX_SIZE=720):
///   `[0]`     = salt
///   `[1]`     = packed country (3 bytes → 1 field)
///   `[2..26]` = packed TBS certificate (720 bytes → 24 fields)
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
/// Matches Noir's `calculate_private_nullifier<DG1_SIZE, ECONTENT_SIZE,
/// SIG_SIZE>()` from `utils/commitment/common/src/lib.nr:81-109`.
///
/// Field layout (20 fields for DG1=95, ECONTENT=200, SIG=256):
///   [0..4]   = packed DG1 (95 bytes → 4 fields)
///   [4..11]  = packed eContent (200 bytes → 7 fields)
///   [11..20] = packed SOD signature (256 bytes → 9 fields)
pub fn calculate_private_nullifier(dg1: &[u8], e_content: &[u8], sod_signature: &[u8]) -> Fr {
    let mut fields = Vec::new();
    fields.extend(pack_be_bytes_into_fields(dg1));
    fields.extend(pack_be_bytes_into_fields(e_content));
    fields.extend(pack_be_bytes_into_fields(sod_signature));
    poseidon2_hash(&fields)
}

/// Compute circuit 2 commitment: Poseidon2(salt, country, signed_attr, sa_size,
/// dg1, e_content, nullifier).
///
/// Matches Noir's
/// `hash_salt_country_signed_attr_dg1_e_content_private_nullifier<...>()` from
/// `utils/commitment/common/src/lib.nr:119-161`.
///
/// Field layout (22 fields for SA=200, DG1=95, ECONTENT=200):
///   `[0]`      = salt
///   `[1]`      = packed country (3 bytes → 1 field)
///   `[2..9]`   = packed signed_attributes (200 bytes → 7 fields)
///   `[9]`      = signed_attr_size as field
///   `[10..14]` = packed DG1 (95 bytes → 4 fields)
///   `[14..21]` = packed eContent (200 bytes → 7 fields)
///   `[21]`     = private_nullifier
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

/// Commit to a data chunk: Poseidon2(salt, packed_data).
///
/// Matches Noir's `commit_to_data_chunk<N>(salt, data)` from
/// `partial_sha256/src/lib.nr`.
///
/// Field layout for CHUNK1_SIZE=640:
///   `[0]`      = salt
///   `[1..22]`  = pack_be_bytes_into_fields(data) (640 bytes → 21 fields)
pub fn commit_to_data_chunk(salt: &str, data: &[u8]) -> Result<Fr, PassportError> {
    let mut fields = Vec::new();
    fields.push(parse_hex_to_field(salt)?);
    fields.extend(pack_be_bytes_into_fields(data));
    Ok(poseidon2_hash(&fields))
}

/// Commit to SHA256 state + data commitment: Poseidon2(salt, state[0..7],
/// processed_bytes, data_commitment).
///
/// Matches Noir's `commit_to_sha256_state_and_data(salt, state,
/// processed_bytes, data_commitment)` from `partial_sha256/src/lib.nr`.
///
/// Field layout (always 11 fields):
///   `[0]`     = salt
///   `[1..9]`  = `state[0]`, `state[1]`, ..., `state[7]`  (each u32 → Field)
///   `[9]`     = processed_bytes as Field
///   `[10]`    = data_commitment
pub fn commit_to_sha256_state_and_data(
    salt: &str,
    state: &[u32; 8],
    processed_bytes: u32,
    data_commitment: Fr,
) -> Result<Fr, PassportError> {
    let mut fields = Vec::with_capacity(11);
    fields.push(parse_hex_to_field(salt)?);
    for &s in state.iter() {
        fields.push(Fr::from(s as u64));
    }
    fields.push(Fr::from(processed_bytes as u64));
    fields.push(data_commitment);
    Ok(poseidon2_hash(&fields))
}

/// Compute h_dg1: Poseidon2([r_dg1, packed_dg1[0..4]]).
///
/// Matches Noir's `Poseidon2::hash([r_dg1].concat(packed_dg1), 5)` from
/// `t_attest/src/main.nr` and `t_add_integrity_commit/src/main.nr`.
pub fn calculate_h_dg1(r_dg1: &str, dg1: &[u8]) -> Result<Fr, PassportError> {
    let mut fields = Vec::with_capacity(5);
    fields.push(parse_hex_to_field(r_dg1)?);
    fields.extend(pack_be_bytes_into_fields(dg1));
    Ok(poseidon2_hash(&fields))
}

/// Compute Merkle leaf: Poseidon2([h_dg1, sod_hash]).
///
/// Matches Noir's `Poseidon2::hash([h_dg1, sod_hash], 2)` from
/// `t_attest/src/main.nr` and `t_add_integrity_commit/src/main.nr`.
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
    fn test_pack_be_bytes_200_bytes() {
        // 200 bytes → 7 field elements (matching e_content size)
        let bytes = [0u8; 200];
        let packed = pack_be_bytes_into_fields(&bytes);
        assert_eq!(packed.len(), 7);
    }

    #[test]
    fn test_calculate_sod_hash_known_good() {
        // e_content from both known-good and test TOML files (identical)
        let e_content: [u8; 200] = [
            54, 197, 174, 86, 62, 194, 237, 211, 184, 91, 92, 169, 195, 149, 233, 156, 60, 80, 224,
            124, 161, 170, 204, 239, 154, 92, 165, 10, 81, 42, 90, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let hash = calculate_sod_hash(&e_content);
        let hash_hex = field_to_hex_string(&hash);
        assert_eq!(
            hash_hex, "0x0f7f8bb032ad068e1c3b717ec1e7020d3537e20688af7bd7a7ae51df72f368bc",
            "sod_hash mismatch with known-good value from t_attest.toml"
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
        // Verify field counts match Noir's expectations
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 3]).len(), 1); // country
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 720]).len(), 24); // tbs_certificate 720
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 1300]).len(), 42); // tbs_certificate 1300
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 640]).len(), 21); // chunk1
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 95]).len(), 4); // dg1
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 200]).len(), 7); // e_content/signed_attr
        assert_eq!(pack_be_bytes_into_fields(&[0u8; 256]).len(), 9); // sod_signature
    }

    #[test]
    fn test_commit_to_sha256_state_and_data_matches_benchmark() {
        // Use benchmark data from tbs_1300 to verify the commitment chain:
        // t_add_dsc_hash_1300.toml provides: salt="0x1", chunk1 (640 bytes)
        // t_add_dsc_verify_1300.toml provides: comm_in, state1
        //
        // The dsc_hash circuit computes:
        //   data_comm1 = commit_to_data_chunk("0x1", chunk1)
        //   comm_out   = commit_to_sha256_state_and_data("0x1", state1, 640,
        // data_comm1) This comm_out must equal the comm_in in
        // t_add_dsc_verify_1300.toml.

        let chunk1: [u8; 640] = [
            48, 130, 1, 10, 2, 130, 1, 1, 0, 175, 129, 169, 48, 75, 201, 148, 9, 44, 101, 74, 102,
            208, 170, 80, 87, 167, 158, 254, 182, 81, 253, 14, 124, 113, 45, 48, 144, 36, 5, 248,
            31, 93, 49, 75, 149, 184, 114, 188, 161, 128, 33, 61, 152, 20, 57, 11, 226, 80, 82, 80,
            10, 209, 152, 144, 112, 231, 229, 31, 130, 146, 213, 195, 46, 163, 187, 24, 68, 79, 56,
            124, 205, 49, 44, 70, 146, 221, 223, 68, 147, 89, 27, 16, 80, 111, 178, 109, 166, 123,
            27, 29, 37, 120, 192, 202, 246, 6, 132, 249, 14, 254, 239, 204, 225, 127, 186, 207,
            215, 178, 142, 60, 232, 125, 83, 126, 240, 68, 243, 79, 119, 91, 83, 101, 115, 122, 64,
            30, 91, 221, 154, 108, 225, 93, 137, 17, 211, 26, 118, 192, 139, 66, 108, 134, 167,
            187, 106, 71, 227, 24, 98, 192, 198, 153, 49, 239, 67, 212, 101, 101, 4, 76, 153, 212,
            177, 159, 190, 78, 10, 224, 173, 157, 91, 210, 237, 178, 115, 123, 245, 116, 202, 34,
            222, 78, 153, 81, 155, 248, 151, 112, 213, 128, 252, 173, 11, 165, 189, 128, 245, 216,
            176, 34, 8, 89, 234, 4, 237, 161, 225, 16, 206, 84, 251, 235, 84, 100, 148, 53, 18,
            159, 134, 159, 65, 197, 221, 254, 23, 118, 144, 109, 54, 163, 163, 137, 13, 21, 182,
            72, 183, 104, 190, 89, 8, 248, 244, 38, 62, 248, 56, 97, 149, 68, 81, 218, 203, 203,
            183, 2, 3, 1, 0, 1, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
            79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
            117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
            134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
            151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167,
            168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
            185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201,
            202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
            219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
            236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252,
            253, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
            68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            126, 127, 128, 129, 130, 131, 132, 133, 134,
        ];
        let state1: [u32; 8] = [
            3828948639, 4073271942, 433182166, 3811311365, 3566743306, 1923568254, 3109579459,
            1110735471,
        ];

        let data_comm1 = commit_to_data_chunk("0x1", &chunk1).unwrap();
        let comm_out = commit_to_sha256_state_and_data("0x1", &state1, 640, data_comm1).unwrap();
        let comm_out_hex = field_to_hex_string(&comm_out);

        assert_eq!(
            comm_out_hex, "0x045433920bc35680c37f22815da747e86bf7974625da04b1f015af21e42446b1",
            "commit_to_sha256_state_and_data output mismatch with benchmark comm_in"
        );
    }

    #[test]
    fn test_compute_merkle_root_empty_tree() {
        // Compute merkle root for leaf_index=0, merkle_path=all zeros (first leaf in
        // empty tree). This exercises the full chain: h_dg1 -> leaf ->
        // merkle_root.
        let r_dg1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let dg1 = [0u8; 95]; // placeholder DG1

        let e_content: [u8; 200] = [0u8; 200]; // placeholder eContent
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
