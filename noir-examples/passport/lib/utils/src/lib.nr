/**
* The standards for passports and any other travel documents, electronic or not,
* are defined in the ICAO (International Civil Aviation Organization) 9303 document available here:
* https://www.icao.int/publications/pages/publication.aspx?docnum=9303
*/
pub mod tests;
pub mod types;
pub mod constants;

/**
* The structure of the MRZ is well defined and standardized by the ICAO
* so the index will always be the same for every passport
* c.f. ICAO 9303-4, Appendix B
*/

// The following constants define the indices of the information
// we need to generate various proofs of identity from the MRZ
// The structure of the MRZ is slightly different between passports
// and ID cards so we need to define indices for both types

use types::{
    DG1Data, MRZData, MRZName, MRZDOB, MRZYOB, MRZDocumentNumber, MRZNationality, MRZIssuingCountry,
    MRZExpiryDate,
};

use constants::{
    ASCII_CODE_FOR_LESS_THAN, DG1_TO_MRZ_OFFSET, ID_CARD_MRZ_BIRTHDATE_INDEX,
    ID_CARD_MRZ_BIRTHDATE_LENGTH, ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX,
    ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH, ID_CARD_MRZ_EXPIRY_DATE_INDEX, ID_CARD_MRZ_NAME_INDEX,
    ID_CARD_MRZ_NAME_LENGTH, ID_CARD_MRZ_NATIONALITY_INDEX, ID_CARD_MRZ_NATIONALITY_LENGTH,
    ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH, MAX_MRZ_LENGTH, PASSPORT_MRZ_BIRTHDATE_INDEX,
    PASSPORT_MRZ_BIRTHDATE_LENGTH, PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
    PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH, PASSPORT_MRZ_EXPIRY_DATE_INDEX,
    PASSPORT_MRZ_ISSUING_COUNTRY_INDEX, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH,
    PASSPORT_MRZ_NAME_INDEX, PASSPORT_MRZ_NAME_LENGTH, PASSPORT_MRZ_NATIONALITY_INDEX,
    PASSPORT_MRZ_NATIONALITY_LENGTH, PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH, YYMMDD_DATE_LENGTH,
};

use poseidon::poseidon2::Poseidon2;

// D<<
global GERMANY_PASSPORT_CODE: [u8; 3] = [68, 60, 60];
// DEU
global GERMANY_ISO_CODE: [u8; 3] = [68, 69, 85];

pub fn get_array_slice<let N: u32, let SLICE_LEN: u32>(
    arr: [u8; N],
    start: u32,
) -> [u8; SLICE_LEN] {
    let mut slice = [0 as u8; SLICE_LEN];
    for i in 0..SLICE_LEN {
        slice[i] = arr[start + i];
    }
    slice
}

pub fn is_id_card(dg1: DG1Data) -> bool {
    // For passport, the last two bytes are 0
    // since the real length is 93 for passports
    // while it is 95 for ID cards
    (dg1[93] != 0) & (dg1[94] != 0)
}

pub fn pack_be_bytes_and_truncate_into_field<let NBytes: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> Field {
    std::static_assert(
        MAX_FIELD_SIZE_IN_BYTES <= NBytes,
        "MAX_FIELD_SIZE_IN_BYTES must be less than or equal to NBytes",
    );

    let mut result: Field = 0;
    for i in 0..MAX_FIELD_SIZE_IN_BYTES {
        result *= 256;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

pub fn pack_be_bytes_into_field<let NBytes: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> Field {
    std::static_assert(
        NBytes <= MAX_FIELD_SIZE_IN_BYTES,
        "NBytes must be less than or equal to MAX_FIELD_SIZE_IN_BYTES",
    );

    let mut result: Field = 0;
    for i in 0..(MAX_FIELD_SIZE_IN_BYTES - (MAX_FIELD_SIZE_IN_BYTES - NBytes)) {
        result *= 256;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

pub fn pack_be_bytes_into_u128s<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> [u128; N] {
    let mut result = [0 as u128; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE_IN_BYTES - (N * MAX_FIELD_SIZE_IN_BYTES - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    limb.assert_max_bit_size::<128>();
    result[N - 1] = limb as u128;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE_IN_BYTES {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        limb.assert_max_bit_size::<128>();
        result[N - i - 1] = limb as u128;
    }

    result
}

pub fn pack_be_bits_into_fields<let NBits: u32, let N: u32, let MAX_FIELD_SIZE_IN_BITS: u32>(
    x: [u1; NBits],
) -> [Field; N] {
    let mut result = [0 as Field; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE_IN_BITS - (N * MAX_FIELD_SIZE_IN_BITS - NBits)) {
        limb *= 2;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE_IN_BITS {
            limb *= 2;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb;
    }

    result
}

pub fn pack_be_bit_into_field<let NBits: u32>(x: [u1; NBits]) -> Field {
    std::static_assert(
        NBits < std::field::modulus_num_bits() as u32,
        "NBits must be less than the bits field size",
    );

    let mut result: Field = 0;
    for i in 0..NBits {
        result *= 2;
        result += x[i] as Field;
    }
    std::as_witness(result);
    result
}

pub fn pack_be_bytes_into_fields<let NBytes: u32, let N: u32, let MAX_FIELD_SIZE_IN_BYTES: u32>(
    x: [u8; NBytes],
) -> [Field; N] {
    let mut result = [0 as Field; N];

    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..(MAX_FIELD_SIZE_IN_BYTES - (N * MAX_FIELD_SIZE_IN_BYTES - NBytes)) {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    std::as_witness(limb);

    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..MAX_FIELD_SIZE_IN_BYTES {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        std::as_witness(limb);
        result[N - i - 1] = limb;
    }

    result
}

pub fn get_mrz_from_dg1(dg1: DG1Data) -> MRZData {
    let mut mrz: MRZData = std::mem::zeroed();
    for i in 0..MAX_MRZ_LENGTH {
        mrz[i] = dg1[i + DG1_TO_MRZ_OFFSET];
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

/**
 * Concatenate two arrays (of different sizes) into one array
 */
pub fn array_concat_as_field<let N: u32, let M: u32>(
    array1: [u8; N],
    array2: [u8; M],
) -> [Field; N + M] {
    let mut result = [0 as Field; N + M];
    for i in 0..N {
        result[i] = array1[i] as Field;
    }
    for i in 0..M {
        result[N + i] = array2[i] as Field;
    }
    result
}

pub fn u8_array_to_fields<let N: u32>(array: [u8; N]) -> [Field; N] {
    let mut result = [0 as Field; N];
    for i in 0..N {
        result[i] = array[i] as Field;
    }
    result
}

pub fn check_zero_padding<let N: u32, T>(padded_array: [T; N], len: u32)
where
    T: Eq,
    T: Default,
{
    for i in 0..N {
        if i >= len {
            assert_eq(padded_array[i], std::mem::zeroed(), "Array is not zero-padded");
        }
    }
}

pub fn get_nationality_from_mrz(dg1: DG1Data) -> MRZNationality {
    let mrz = get_mrz_from_dg1(dg1);

    let mut country_bytes: MRZNationality = std::mem::zeroed();

    if is_id_card(dg1) {
        country_bytes = get_array_slice::<_, ID_CARD_MRZ_NATIONALITY_LENGTH>(
            mrz,
            ID_CARD_MRZ_NATIONALITY_INDEX,
        );
    } else {
        country_bytes = get_array_slice::<_, PASSPORT_MRZ_NATIONALITY_LENGTH>(
            mrz,
            PASSPORT_MRZ_NATIONALITY_INDEX,
        );
    }

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}

pub fn get_issuing_country_from_mrz(dg1: DG1Data) -> MRZIssuingCountry {
    let mrz = get_mrz_from_dg1(dg1);
    // No need to check if it's an ID card since the issuing country
    // is always at the same index for both passports and ID cards
    let mut country_bytes = get_array_slice::<_, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH>(
        mrz,
        PASSPORT_MRZ_ISSUING_COUNTRY_INDEX,
    );

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
}

/// Get the name from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_name_from_mrz(dg1: DG1Data) -> MRZName {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_name_id_card(mrz)
    } else {
        get_name_passport(mrz)
    }
}

/// Get the name from the MRZ for a passport
pub fn get_name_passport(mrz: MRZData) -> MRZName {
    get_array_slice::<_, PASSPORT_MRZ_NAME_LENGTH>(mrz, PASSPORT_MRZ_NAME_INDEX)
}

/// Get the name from the MRZ for an ID card
pub fn get_name_id_card(mrz: MRZData) -> MRZName {
    let mut padded_mrz_name: MRZName = std::mem::zeroed();
    let mrz_name = get_array_slice::<_, ID_CARD_MRZ_NAME_LENGTH>(mrz, ID_CARD_MRZ_NAME_INDEX);
    for i in 0..ID_CARD_MRZ_NAME_LENGTH {
        padded_mrz_name[i] = mrz_name[i];
    }
    // Pad the name with spaces to the length of the MRZ name
    for i in 0..(PASSPORT_MRZ_NAME_LENGTH - ID_CARD_MRZ_NAME_LENGTH) {
        padded_mrz_name[ID_CARD_MRZ_NAME_LENGTH + i] = ASCII_CODE_FOR_LESS_THAN;
    }

    padded_mrz_name
}

/// Get the date of birth from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_dob_from_mrz(dg1: DG1Data) -> MRZDOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_date_of_birth_id_card(mrz)
    } else {
        get_date_of_birth_passport(mrz)
    }
}

/// Get the date of birth from the MRZ for a passport
pub fn get_date_of_birth_passport(mrz: MRZData) -> MRZDOB {
    get_array_slice::<_, PASSPORT_MRZ_BIRTHDATE_LENGTH>(mrz, PASSPORT_MRZ_BIRTHDATE_INDEX)
}

/// Get the date of birth from the MRZ for an ID card
pub fn get_date_of_birth_id_card(mrz: MRZData) -> MRZDOB {
    get_array_slice::<_, ID_CARD_MRZ_BIRTHDATE_LENGTH>(mrz, ID_CARD_MRZ_BIRTHDATE_INDEX)
}

/// Get the year of birth from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_yob_from_mrz(dg1: DG1Data) -> MRZYOB {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_yob_from_mrz_id_card(mrz)
    } else {
        get_yob_from_mrz_passport(mrz)
    }
}

/// Get the year of birth from the MRZ for an ID card
pub fn get_yob_from_mrz_passport(mrz: MRZData) -> MRZYOB {
    get_array_slice::<_, PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH>(mrz, PASSPORT_MRZ_BIRTHDATE_INDEX)
}

/// Get the year of birth from the MRZ for an ID card
pub fn get_yob_from_mrz_id_card(mrz: MRZData) -> MRZYOB {
    get_array_slice::<_, ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH>(mrz, ID_CARD_MRZ_BIRTHDATE_INDEX)
}

/// Get the expiry date from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_expiry_date_from_mrz(dg1: DG1Data) -> MRZExpiryDate {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_expiry_date_id_card(mrz)
    } else {
        get_expiry_date_passport(mrz)
    }
}

/// Get the expiry date from the MRZ for a passport
pub fn get_expiry_date_passport(mrz: MRZData) -> MRZExpiryDate {
    get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, PASSPORT_MRZ_EXPIRY_DATE_INDEX)
}

/// Get the expiry date from the MRZ for an ID card
pub fn get_expiry_date_id_card(mrz: MRZData) -> MRZExpiryDate {
    get_array_slice::<_, YYMMDD_DATE_LENGTH>(mrz, ID_CARD_MRZ_EXPIRY_DATE_INDEX)
}

/// Get the document number from the MRZ
///
/// Conditionally calls the correct function based on the type of document
pub fn get_document_number_from_mrz(dg1: DG1Data) -> MRZDocumentNumber {
    let mrz = get_mrz_from_dg1(dg1);
    if is_id_card(dg1) {
        get_document_number_id_card(mrz)
    } else {
        get_document_number_passport(mrz)
    }
}

/// Get the document number from the MRZ for a passport
pub fn get_document_number_passport(mrz: MRZData) -> MRZDocumentNumber {
    get_array_slice::<_, PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH>(
        mrz,
        PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX,
    )
}

/// Get the document number from the MRZ for an ID card
pub fn get_document_number_id_card(mrz: MRZData) -> MRZDocumentNumber {
    get_array_slice::<_, ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH>(mrz, ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX)
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
        assert(nlen <= 4, "Length > 4 not supported");
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
pub fn find_subarray_index_after_index<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
    start_index: u32,
) -> u32 {
    // Safety: This is safe because the offset is only used as a starting point
    // to verify the substring exists
    let offset_unchecked =
        unsafe { find_subarray_index_after_index_unsafe(needle, haystack, start_index) };
    let mut offset = offset_unchecked;
    // Check if offset is valid before attempting verification
    if (offset_unchecked < HAYSTACK_SIZE) & (offset_unchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offset_unchecked] != needle[i] {
                offset = HAYSTACK_SIZE;
            }
        }
    } else {
        // If offset is out of bounds, needle was not found
        offset = HAYSTACK_SIZE;
    }
    offset
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
    let offset_unchecked = unsafe { find_subarray_index_unsafe(needle, haystack) };
    let mut offset = offset_unchecked;
    // Check if offset is valid before attempting verification
    if (offset_unchecked < HAYSTACK_SIZE) & (offset_unchecked + NEEDLE_SIZE <= HAYSTACK_SIZE) {
        for i in 0..NEEDLE_SIZE {
            if haystack[i + offset_unchecked] != needle[i] {
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
pub unconstrained fn find_subarray_index_after_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
    start_index: u32,
) -> u32 {
    let mut result = HAYSTACK_SIZE; // Default to "not found" value
    // Handle edge cases
    if NEEDLE_SIZE == 0 {
        result = 0;
    } else if NEEDLE_SIZE <= HAYSTACK_SIZE {
        // Search for the needle in the haystack
        for i in 0..(HAYSTACK_SIZE - NEEDLE_SIZE + 1) {
            let mut found = i >= start_index;
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

/// Safety: This is safe because the offset is only used as a starting point
/// to verify the substring exists
pub unconstrained fn find_subarray_index_unsafe<let NEEDLE_SIZE: u32, let HAYSTACK_SIZE: u32>(
    needle: [u8; NEEDLE_SIZE],
    haystack: [u8; HAYSTACK_SIZE],
) -> u32 {
    find_subarray_index_after_index_unsafe(needle, haystack, 0)
}

fn pack_le_bytes_into_fields_internal<let BYTES_PER_FIELD: u32, let NUM_BYTES: u32, let NUM_FIELDS: u32>(
    x: [u8; NUM_BYTES],
) -> [Field; NUM_FIELDS] {
    let mut result = [0 as Field; NUM_FIELDS];
    let mut k = 0;
    // Pack all fields in little-endian order
    for field_index in 0..NUM_FIELDS {
        let remaining_bytes = NUM_BYTES - k;
        let chunk_size = if remaining_bytes > BYTES_PER_FIELD {
            BYTES_PER_FIELD
        } else {
            remaining_bytes
        };
        let mut limb: Field = 0;
        // Pack bytes in little-endian order (reverse the chunk)
        for j in 0..chunk_size {
            limb *= 256;
            limb += x[k + chunk_size - 1 - j] as Field;
        }
        k += chunk_size;
        std::as_witness(limb);
        result[field_index] = limb;
    }
    result
}

pub fn pack_le_bytes_into_fields<let BYTES_PER_FIELD: u32, let NUM_BYTES: u32>(
    x: [u8; NUM_BYTES],
) -> [Field; (NUM_BYTES + BYTES_PER_FIELD - 1) / BYTES_PER_FIELD] {
    pack_le_bytes_into_fields_internal::<BYTES_PER_FIELD, NUM_BYTES, (NUM_BYTES + BYTES_PER_FIELD - 1) / BYTES_PER_FIELD>(
        x,
    )
}

pub fn poseidon2_hash_packed<let NUM_BYTES: u32>(padded_input: [u8; NUM_BYTES], len: u32) -> Field {
    let packed: [Field; _] = pack_le_bytes_into_fields::<31, _>(padded_input);
    let num_of_fields: u32 = (len + 31 - 1) / 31;
    Poseidon2::hash_fixed(packed, num_of_fields)
}

pub fn encode_integer_over_bytes<let NUM_BYTES: u32>(x: u32) -> [u8; NUM_BYTES] {
    let field_number = x as Field;
    let bytes: [u8; NUM_BYTES] = field_number.to_be_bytes();
    bytes
}
