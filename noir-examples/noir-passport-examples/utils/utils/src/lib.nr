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

use types::{DG1Data, MRZData, MRZIssuingCountry};

// Index for the country of issuance of the passport
pub global PASSPORT_MRZ_COUNTRY_INDEX: u32 = 2;
// Length of the country code in the MRZ
pub global PASSPORT_MRZ_COUNTRY_LENGTH: u32 = 3;
// Index for the date of expiry (YYMMDD)
pub global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;
// Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
pub global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;

// Index for the date of expiry (YYMMDD)
pub global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;
// Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
pub global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;

// Proof type to identify the circuit used for a given parameter commitment
pub global PROOF_TYPE_AGE: u8 = 1;

// D<<
global GERMANY_PASSPORT_CODE: [u8; 3] = [68, 60, 60];
// DEU
global GERMANY_ISO_CODE: [u8; 3] = [68, 69, 85];

/// Offset of the MRZ in the DG1
pub global DG1_TO_MRZ_OFFSET: u32 = 5;

pub fn get_array_slice<let N: u32, let M: u32>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        slice[i - start] = arr[i];
    }
    slice
}

pub fn is_id_card(dg1: DG1Data) -> bool {
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

pub fn get_mrz_from_dg1(dg1: DG1Data) -> MRZData {
    let mut mrz: MRZData = [0 as u8; 90];
    for i in 0..90 {
        mrz[i] = dg1[i + DG1_TO_MRZ_OFFSET];
    }
    mrz
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

pub fn get_issuing_country_from_mrz(dg1: DG1Data) -> MRZIssuingCountry {
    let mrz = get_mrz_from_dg1(dg1);
    // No need to check if it's an ID card since the issuing country
    // is always at the same index for both passports and ID cards
    let mut country_bytes = get_array_slice(
        mrz,
        PASSPORT_MRZ_COUNTRY_INDEX,
        PASSPORT_MRZ_COUNTRY_INDEX + PASSPORT_MRZ_COUNTRY_LENGTH,
    );

    // Handle the special case of Germany
    if (country_bytes == GERMANY_PASSPORT_CODE) {
        country_bytes = GERMANY_ISO_CODE;
    }

    country_bytes
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
