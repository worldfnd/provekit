use utils::{get_issuing_country_from_mrz, get_nationality_from_mrz};

unconstrained fn get_index<let N: u32>(list: [str<3>; N], value: [u8; 3]) -> i32 {
    let mut index: i32 = -1;
    for i in 0..N {
        let list_item = list[i].as_bytes();
        if (list_item[0] == value[0]) & (list_item[1] == value[1]) & (list_item[2] == value[2]) {
            index = i as i32;
        }
    }
    index
}

/// Check if the nationality from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_nationality_inclusion<let N: u32>(dg1: [u8; 95], country_list: [str<3>; N]) {
    let nationality_bytes = get_nationality_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { get_index(country_list, nationality_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the nationality is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index].as_bytes();
    assert_eq(nationality_bytes[0], country_code[0], "Nationality does not match the country code");
    assert_eq(nationality_bytes[1], country_code[1], "Nationality does not match the country code");
    assert_eq(nationality_bytes[2], country_code[2], "Nationality does not match the country code");
}

/// Check if the issuing country from the MRZ is in the country list
///
/// # Arguments
///
/// * `dg1`: The MRZ
/// * `country_list`: The list of countries
pub fn check_issuing_country_inclusion<let N: u32>(dg1: [u8; 95], country_list: [str<3>; N]) {
    let issuing_country_bytes = get_issuing_country_from_mrz(dg1);

    // Safety: get the index of the country in the list from an unconstrained function
    let country_index = unsafe { get_index(country_list, issuing_country_bytes) };
    // Assert that the country was found
    assert(country_index != -1, "Country not found in the list");

    // Assert that the issuing country is equal to the country in the list
    // at the index found by the unconstrained function
    let country_code = country_list[country_index].as_bytes();
    assert_eq(
        issuing_country_bytes[0],
        country_code[0],
        "Issuing country does not match the country code",
    );
    assert_eq(
        issuing_country_bytes[1],
        country_code[1],
        "Issuing country does not match the country code",
    );
    assert_eq(
        issuing_country_bytes[2],
        country_code[2],
        "Issuing country does not match the country code",
    );
}
