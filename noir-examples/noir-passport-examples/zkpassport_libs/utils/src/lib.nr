/**
* The standards for passports and any other travel documents, electronic or not,
* are defined in the ICAO (International Civil Aviation Organization) 9303 document available here:
* https://www.icao.int/publications/pages/publication.aspx?docnum=9303
*/

/**
* The structure of the MRZ is well defined and standardized by the ICAO
* so the index will always be the same for every passport
* c.f. ICAO 9303-4, Appendix B
*/

// The following constants define the indices of the information
// we need to generate various proofs of identity from the MRZ
// The structure of the MRZ is slightly different between passports
// and ID cards so we need to define indices for both types

mod tests;

// Index for the country of issuance of the passport
pub global PASSPORT_MRZ_COUNTRY_INDEX: u32 = 2;
// Index for the three letter code of the country of citizenship
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global PASSPORT_MRZ_NATIONALITY_INDEX: u32 = 54;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global PASSPORT_MRZ_GENDER_INDEX: u32 = 64;
// Index for the date of expiry (YYMMDD)
pub global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;
// Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
pub global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;
// Index for the document number in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 44;
// Index for the document type in the MRZ
pub global PASSPORT_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global PASSPORT_MRZ_NAME_INDEX: u32 = 5;
// Length of the MRZ on a passport
pub global PASSPORT_MRZ_LENGTH: u32 = 88;

// Index for the country of issuance of the ID card
pub global ID_CARD_MRZ_COUNTRY_INDEX: u32 = 2;
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits
// where the issuing country differs from the citizenship country
pub global ID_CARD_MRZ_NATIONALITY_INDEX: u32 = 45;
// Index for the gender of the passport holder (M, F or < if unspecified)
pub global ID_CARD_MRZ_GENDER_INDEX: u32 = 37;
// Index for the date of expiry (YYMMDD)
pub global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;
// Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
pub global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;
// Index for the document number in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX: u32 = 5;
// Index for the document type in the MRZ
pub global ID_CARD_MRZ_DOCUMENT_TYPE_INDEX: u32 = 0;
// Index for the name of the passport holder
pub global ID_CARD_MRZ_NAME_INDEX: u32 = 60;
// Length of the MRZ on an ID card
pub global ID_CARD_MRZ_LENGTH: u32 = 90;

// ECDSA curves mapping
pub global ECDSA_CURVE_P256: u32 = 0;
pub global ECDSA_CURVE_P384: u32 = 1;
pub global ECDSA_CURVE_P521: u32 = 2;
pub global ECDSA_CURVE_BRAINPOOL_B256R1: u32 = 3;
pub global ECDSA_CURVE_BRAINPOOL_B256T1: u32 = 4;
pub global ECDSA_CURVE_BRAINPOOL_B384R1: u32 = 5;
pub global ECDSA_CURVE_BRAINPOOL_B384T1: u32 = 6;
pub global ECDSA_CURVE_BRAINPOOL_B512R1: u32 = 7;
pub global ECDSA_CURVE_BRAINPOOL_B512T1: u32 = 8;

// Proof type to identify the circuit used for a given parameter commitment
pub global PROOF_TYPE_DISCLOSE: u8 = 0;
pub global PROOF_TYPE_AGE: u8 = 1;
pub global PROOF_TYPE_BIRTHDATE: u8 = 2;
pub global PROOF_TYPE_EXPIRY_DATE: u8 = 3;
pub global PROOF_TYPE_NATIONALITY_INCLUSION: u8 = 4;
pub global PROOF_TYPE_NATIONALITY_EXCLUSION: u8 = 5;
pub global PROOF_TYPE_ISSUING_COUNTRY_INCLUSION: u8 = 6;
pub global PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION: u8 = 7;
pub global PROOF_TYPE_BIND: u8 = 8;

// D<<
global GERMANY_PASSPORT_CODE: [u8; 3] = [68, 60, 60];
// DEU
global GERMANY_ISO_CODE: [u8; 3] = [68, 69, 85];

pub struct IDData {
    // Regroups the hashes of all the data groups plus some padding
    // at the start and in between each data group hashes
    pub e_content: [u8; 700],
    pub e_content_size: u32,
    // Where we can find e_content in the signed_attributes
    // It varies from document to document according to the length
    // of the padding at the start
    pub dg1_offset_in_e_content: u32,
    // Last 32 bytes: result of the hash of all the hashes of the data groups
    // Rest of the bytes: information about the signature algorithm, date, etc.
    pub signed_attributes: [u8; 200],
    pub signed_attributes_size: u32,
    // The DG1 contains the Machine Readable Zone (MRZ) of the document
    // The two lines at the bottom of the passport data page
    // or the three bottom lines on the rear of an ID card
    // 95 bytes for passports, 93 bytes for ID cards
    // Including 88 bytes of MRZ and 5 bytes of padding for passports
    // and 90 bytes of MRZ and 5 bytes of padding for ID cards
    pub dg1: [u8; 95],
    // The signature over the data groups
    pub sod_signature: [u8; 512],
    pub sod_signature_size: u32,
}

pub struct DSCData {
    // The TBS certificate of the DSC
    // TBS stands for To Be Signed
    pub tbs_certificate: [u8; 1500],
    pub tbs_certificate_size: u32,
    // The public key of the DSC (up to 512 bytes to account for RSA-4096)
    pub pubkey: [u8; 512],
    // The actual size of the public key
    pub pubkey_size: u32,
    // The index of the public key in the TBS certificate
    pub pubkey_index: u32,
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    pub pubkey_redc_param: [u8; 513],
    // The signature over the TBS certificate
    pub signature: [u8; 512],
    pub signature_size: u32,
    // The exponent of the public key
    // Only useful for RSA, can be ignored for ECDSA
    pub exponent: u32,
}

pub struct CSCData {
    // The public key of the CSC (up to 512 bytes to account for RSA-4096)
    pub pubkey: [u8; 512],
    // The actual size of the public key
    pub pubkey_size: u32,
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    pub pubkey_redc_param: [u8; 513],
    // Only useful for RSA, can be ignored for ECDSA
    pub exponent: u32,
}

pub struct DiscloseFlags {
    pub issuing_country: bool,
    pub nationality: bool,
    pub document_type: bool,
    pub document_number: bool,
    pub date_of_expiry: bool,
    pub date_of_birth: bool,
    pub gender: bool,
    pub name: bool,
}

pub struct DisclosedData {
    pub issuing_country: [u8; 3],
    pub nationality: [u8; 3],
    pub document_type: [u8; 2],
    pub document_number: [u8; 9],
    pub date_of_expiry: [u8; 6],
    pub date_of_birth: [u8; 6],
    pub name: [u8; 39],
    pub gender: [u8; 1],
}

pub fn get_array_slice<let N: u32, let M: u32>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        slice[i - start] = arr[i];
    }
    slice
}

pub fn get_array_slice_constant<let N: u32, let M: u32>(arr: [u8; N]) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in 0..M {
        slice[i] = arr[i];
    }
    slice
}

// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

pub fn insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
) -> [u8; N] {
    for i in index..index + M {
        arr[i] = sub_arr[i - index];
    }
    arr
}

pub fn dynamic_insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32,
    max_size: u32,
) -> [u8; N] {
    for i in index..index + max_size {
        if i - index < M {
            arr[i] = sub_arr[i - index];
        }
    }
    arr
}

pub fn is_id_card(dg1: [u8; 95]) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[93] != 0) & (dg1[94] != 0)
}

pub fn pack_be_bytes_into_field<let NBytes: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> Field {
    let mut result: Field = 0;
    for i in 0..MAX_FIELD_SIZE {
        result *= 256;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

pub fn pack_be_bytes_into_u128s<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> [u128; N] {
    let mut result = [0 as u128; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb as u128;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb as u128;
    }

    result
}

pub fn pack_be_bytes_into_fields<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE: u32>(
    x: [u8; NBytes],
) -> [Field; N] {
    let mut result = [0 as Field; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb;
    }

    result
}

pub fn get_mrz_from_dg1(dg1: [u8; 95]) -> [u8; 90] {
    let mut mrz = [0 as u8; 90];
    for i in 0..90 {
        mrz[i] = dg1[i + 5];
    }
    mrz
}

pub fn split_array<let N: u32>(array: [u8; N * 2]) -> ([u8; N], [u8; N]) {
    let mut array_x = [0 as u8; N];
    let mut array_y = [0 as u8; N];
    for i in 0..N {
        array_x[i] = array[i];
        array_y[i] = array[i + N];
    }
    (array_x, array_y)
}

pub fn concat_array<let N: u32>(array_x: [u8; N], array_y: [u8; N]) -> [u8; N * 2] {
    let mut array = [0 as u8; N * 2];
    for i in 0..N {
        array[i] = array_x[i];
        array[i + N] = array_y[i];
    }
    array
}

pub fn check_zero_padding<let N: u32, T>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            assert_eq(padded_array[i], T::default());
        }
    }
}

pub fn get_nationality_from_mrz(dg1: [u8; 95]) -> [u8; 3] {
    let mrz = get_mrz_from_dg1(dg1);

    let mut country_bytes: [u8; 3] = [0; 3];

    if is_id_card(dg1) {
        country_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_NATIONALITY_INDEX,
            ID_CARD_MRZ_NATIONALITY_INDEX + 3,
        );
    } else {
        country_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_NATIONALITY_INDEX,
            PASSPORT_MRZ_NATIONALITY_INDEX + 3,
        );
    }

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}

pub fn get_issuing_country_from_mrz(dg1: [u8; 95]) -> [u8; 3] {
    let mrz = get_mrz_from_dg1(dg1);
    // No need to check if it's an ID card since the issuing country
    // is always at the same index for both passports and ID cards
    let mut country_bytes = get_array_slice(
        mrz,
        PASSPORT_MRZ_COUNTRY_INDEX,
        PASSPORT_MRZ_COUNTRY_INDEX + 3,
    );

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}

/// Returns total TLV length (tag + length field + content) for any
/// ASN.1 element using DER/BER **definite-length** encoding with a
/// single-byte tag (tag number field < 31)
pub unconstrained fn unsafe_get_asn1_element_length<let N: u32>(asn1: [u8; N]) -> u32 {
    let tag: u8 = asn1[0];
    let elem_len: u8 = asn1[1];

    // Need at least tag(1) + length(1)
    assert(N >= 2, "TLV too short");
    // Only support single-byte tag number (no high-tag-number 0x1F)
    assert((tag & 0x1F) < 0x1F, "High-tag-number form not supported");
    // BER indefinite-length (0x80) is not supported here
    assert(elem_len != 0x80, "Indefinite length not supported");

    // Short form: content length is in low 7 bits
    if (elem_len & 0x80) == 0 {
        let content_len: u32 = (elem_len & 0x7F) as u32;
        let total: u32 = 2 + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
    // Long form: low 7 bits = number of following length bytes
    else {
        let nlen: u32 = (elem_len & 0x7F) as u32;
        assert(nlen > 0, "Zero length-of-length");
        assert(nlen <= 4, "Length field too large");
        assert(2 + nlen <= N, "Length bytes exceed buffer");
        // Parse big-endian content length
        let mut content_len: u32 = 0;
        for i in 0..nlen {
            content_len = content_len * 256 + (asn1[2 + i] as u32);
        }
        let total: u32 = 2 + nlen + content_len;
        assert(total <= N, "TLV exceeds buffer");
        total
    }
}

/// Find the index of the first occurrence of the needle in the haystack
/// Returns the index of the first occurrence of the needle in the haystack
/// Returns HAYSTACK_SIZE if the needle is not found
pub fn find_subarray_index<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    // Safety: This is safe because the offset is only used as a starting point
    // to verify the substring exists
    let offsetUnchecked = unsafe { find_subarray_index_unsafe(needle, haystack) };
    let mut offset = offsetUnchecked;
    // Check if offset is valid before attempting verification
    if (offsetUnchecked < HAYSTACK_SIZE) & (offsetUnchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offsetUnchecked] != needle[i] {
                offset = HAYSTACK_SIZE;
            }
        }
    } else {
        // If offset is out of bounds, needle was not found
        offset = HAYSTACK_SIZE;
    }
    offset
}

pub fn is_subarray_in_array<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> bool {
    find_subarray_index(needle, haystack) < HAYSTACK_SIZE
}

/// Safety: This is safe because the offset is only used as a starting point
/// to verify the substring exists
pub unconstrained fn find_subarray_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    let mut result = HAYSTACK_SIZE; // Default to "not found" value
    // Handle edge cases
    if NEEDLE_SIZE == 0 {
        result = 0;
    } else if NEEDLE_SIZE <= HAYSTACK_SIZE {
        // Search for the needle in the haystack
        for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
            let mut found = true;
            for j in 0..NEEDLE_SIZE {
                if haystack[i + j] != needle[j] {
                    found = false;
                    break;
                }
            }
            if found {
                result = i;
                break;
            }
        }
    }
    result
}
