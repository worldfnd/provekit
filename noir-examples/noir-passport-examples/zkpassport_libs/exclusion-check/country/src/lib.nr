use utils::{get_issuing_country_from_mrz, get_nationality_from_mrz};

unconstrained fn get_closest_index<let N: u32>(sorted_list: [u32; N], value: u32) -> u32 {
    let mut index: u32 = 0;
    for i in 0..N {
        if sorted_list[i] > value {
            index = i;
            break;
        }
    }
    index
}

/// Check if the nationality from the MRZ is not in the country list
/// The list of countries is assumed to be sorted in ascending order
/// So it must come either from a public input that can be independently checked
/// or from a previous in-circuit check that the list is sorted
///
/// # Arguments
///
/// * `dg1` - The DG1 of the passport or ID card
/// * `country_list` - The sorted list of countries to check against, must be formatted as a list of u32
/// which are the Alpha-3 codes of the countries with each letter ASCII code put together using a weighted sum.
/// e.g. for "FRA", the sum is 70 * 2^16 (0x10000) + 82 * 2^8 (0x100) + 65 = 4587520 + 20992 + 65 = 4608577
pub fn check_nationality_exclusion<let N: u32>(dg1: [u8; 95], country_list: [u32; N]) {
    let nationality_bytes = get_nationality_from_mrz(dg1);
    let nationality_sum: u32 = nationality_bytes[0] as u32 * 0x10000
        + nationality_bytes[1] as u32 * 0x100
        + nationality_bytes[2] as u32;

    // Safety: since the list is assumed to be sorted in ascending order, we can get the index to check against
    // from an unconstrained function
    let closest_index = unsafe { get_closest_index(country_list, nationality_sum) };
    // Assert that either the index is the first element of the list or the previous element is less than the nationality sum
    if closest_index == 0 {
        // Assert that the country at the index is greater than the nationality sum
        assert(country_list[closest_index] > nationality_sum);
    }
    // Cannot be done in a single if statement otherwise the second check will fail if closest_index is 0
    else if country_list[closest_index - 1] < nationality_sum {
        // Assert that the country at the index is greater than the nationality sum
        assert(country_list[closest_index] > nationality_sum);
    } else {
        // Otherwise it should fail
        assert(false);
    }
    // If those two checks pass, then the nationality is not in the country list
}

/// Check if the issuing country from the MRZ is not in the country list
/// The list of countries is assumed to be sorted in ascending order
/// So it must come either from a public input that can be independently checked
/// or from a previous in-circuit check that the list is sorted
pub fn check_issuing_country_exclusion<let N: u32>(dg1: [u8; 95], country_list: [u32; N]) {
    let issuing_country_bytes = get_issuing_country_from_mrz(dg1);
    let issuing_country_sum: u32 = issuing_country_bytes[0] as u32 * 0x10000
        + issuing_country_bytes[1] as u32 * 0x100
        + issuing_country_bytes[2] as u32;

    // Safety: since the list is assumed to be sorted in ascending order, we can get the index to check against
    // from an unconstrained function
    let closest_index = unsafe { get_closest_index(country_list, issuing_country_sum) };

    if closest_index == 0 {
        // Assert that the country at the index is greater than the issuing country sum
        assert(country_list[closest_index] > issuing_country_sum);
    } else if country_list[closest_index - 1] < issuing_country_sum {
        // Assert that the country at the index is greater than the issuing country sum
        assert(country_list[closest_index] > issuing_country_sum);
    } else {
        // Otherwise it should fail
        assert(false);
    }
    // If those two checks pass, then the issuing country is not in the country list
}
