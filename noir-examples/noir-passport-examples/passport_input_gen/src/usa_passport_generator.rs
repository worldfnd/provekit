use crate::generate_dummy_prover_toml::{
    dg1_bytes_with_birthdate_expiry_date,
    generate_prover_toml_string_from_custom_dg1_date_and_required_age,
};

pub fn generate_usa_passport_sample() -> String {
    // USA passport MRZ example from the test file
    // P<USAJOHNSON<<JANE<MARIE<<<<<<<<<<<<<<<<<<<US1234567<USA9001018F2501011<NEWYORK<<<<<<<

    // Extract birthdate and expiry from the US MRZ format:
    // Birth: 900101 (January 1, 1990) -> YYMMDD format
    // Expiry: 250101 (January 1, 2025) -> YYMMDD format
    let birthdate_bytes = [b'9', b'0', b'0', b'1', b'0', b'1']; // Jan 1, 1990
    let expiry_bytes = [b'2', b'5', b'0', b'1', b'0', b'1']; // Jan 1, 2025
    let current_date = 20250101; // Current date for age verification

    // Generate DG1 with USA passport data
    let usa_dg1_with_birthdate_expiry =
        dg1_bytes_with_birthdate_expiry_date(&birthdate_bytes, &expiry_bytes);

    let usa_prover_toml = generate_prover_toml_string_from_custom_dg1_date_and_required_age(
        &usa_dg1_with_birthdate_expiry,
        18,
        70,
        current_date,
    );

    usa_prover_toml
}

pub fn generate_age_testcases() -> Vec<(String, String)> {
    let mut testcases = Vec::new();
    let current_date = 20250101; // January 1, 2025

    // Test Case 1: Below 18 (17 years old - born January 2, 2007)
    let birthdate_below_18 = [b'0', b'7', b'0', b'1', b'0', b'2']; // January 2, 2007
    let expiry_below_18 = [b'3', b'2', b'0', b'1', b'0', b'2']; // January 2, 2032
    let below_18_dg1 = dg1_bytes_with_birthdate_expiry_date(&birthdate_below_18, &expiry_below_18);
    let below_18_toml = generate_prover_toml_string_from_custom_dg1_date_and_required_age(
        &below_18_dg1,
        1,
        18,
        current_date,
    );
    testcases.push(("below_18".to_string(), below_18_toml));

    // Test Case 2: Exactly 18 (born January 1, 2007)
    let birthdate_exactly_18 = [b'0', b'7', b'0', b'1', b'0', b'1']; // January 1, 2007
    let expiry_exactly_18 = [b'3', b'2', b'0', b'1', b'0', b'1']; // January 1, 2032
    let exactly_18_dg1 =
        dg1_bytes_with_birthdate_expiry_date(&birthdate_exactly_18, &expiry_exactly_18);
    let exactly_18_toml = generate_prover_toml_string_from_custom_dg1_date_and_required_age(
        &exactly_18_dg1,
        18,
        70,
        current_date,
    );
    testcases.push(("exactly_18".to_string(), exactly_18_toml));

    // Test Case 3: Above 18 (19 years old - born December 31, 2005)
    let birthdate_above_18 = [b'0', b'5', b'1', b'2', b'3', b'1']; // December 31, 2005
    let expiry_above_18 = [b'3', b'0', b'1', b'2', b'3', b'1']; // December 31, 2030
    let above_18_dg1 = dg1_bytes_with_birthdate_expiry_date(&birthdate_above_18, &expiry_above_18);
    let above_18_toml = generate_prover_toml_string_from_custom_dg1_date_and_required_age(
        &above_18_dg1,
        18,
        70,
        current_date,
    );
    testcases.push(("above_18".to_string(), above_18_toml));

    testcases
}

pub fn create_usa_dg1_from_mrz(mrz: &str) -> Option<[u8; 95]> {
    // US MRZ format:
    // P<USAJOHNSON<<JANE<MARIE<<<<<<<<<<<<<<<<<<<US1234567<USA9001018F2501011<NEWYORK<<<<<<<
    // Extract birthdate (positions 57-62) and expiry (positions 65-70) from MRZ

    if mrz.len() < 88 {
        return None;
    }

    // Extract birthdate (YYMMDD)
    let birthdate_str = &mrz[57..63];
    let expiry_str = &mrz[65..71];

    let birthdate_bytes: [u8; 6] = birthdate_str.as_bytes().try_into().ok()?;
    let expiry_bytes: [u8; 6] = expiry_str.as_bytes().try_into().ok()?;

    Some(dg1_bytes_with_birthdate_expiry_date(
        &birthdate_bytes,
        &expiry_bytes,
    ))
}
