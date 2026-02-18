use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{constants::PROOF_TYPE_AGE, get_dob_from_mrz, types::DG1Data};

pub mod tests;

fn get_birthdate(dg1: DG1Data, timestamp: u64) -> Date {
    let mut birthdate_bytes = get_dob_from_mrz(dg1);

    let current_date = Date::from_timestamp(timestamp);

    // Create a Date object from the birthdate using the current date as
    // the pivot year to differentiate between 20th and 21st centuries
    // as the format is "YYMMDD"
    Date::from_bytes_short_year(birthdate_bytes, current_date)
}

pub fn compare_age(dg1: DG1Data, min_age: u8, max_age: u8, timestamp: u64) {
    // Restrict the age to be less than 100 as the dg1 birthdate only encodes
    // two digits for the year
    // TODO: Add support for dg11 to support 100+
    assert((max_age < 100) & (min_age < 100), "Age must be less than 100");

    let birthdate: Date = get_birthdate(dg1, timestamp);

    let current_date = Date::from_timestamp(timestamp);

    assert((min_age != 0) | (max_age != 0), "Either min or max age must be non-zero");

    if (min_age != 0) & (max_age == 0) {
        // Check if age is above min age
        // The minimum age is more likely to be inclusive, so we use gte
        assert(
            current_date.gte(birthdate.add_years(min_age as u32)),
            "Age is not above or equal to min age",
        );
    } else if (max_age != 0) & (min_age == 0) {
        // Check if age is below max age
        // Adding 1 and using lt, so that max_age is inclusive up to the very last day before reaching max_age + 1
        assert(
            current_date.lt(birthdate.add_years(max_age as u32 + 1)),
            "Age is not below or equal to max age",
        );
    } else {
        assert(min_age <= max_age, "Min age must be less than or equal to max age");

        assert(
            current_date.gte(birthdate.add_years(min_age as u32)),
            "Age is not above or equal to min age",
        );
        // This way if max_age = min_age, the proof will be valid whenever the age
        // is equal to min_age = max_age
        assert(
            current_date.lt(birthdate.add_years((max_age + 1) as u32)),
            "Age is not below or equal to max age",
        );
    }
}

/// Calculate the commitment of the current date, min age and max age using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `min_age_required`: The minimum age required
/// * `max_age_required`: The maximum age required
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min age and max age
pub fn calculate_param_commitment(min_age_required: u8, max_age_required: u8) -> Field {
    let mut params = [0 as Field; 4];
    params[0] = PROOF_TYPE_AGE as Field;
    params[1] = (params.len() - 2) as Field;
    params[2] = min_age_required as Field;
    params[3] = max_age_required as Field;
    Poseidon2::hash(params, params.len())
}

/// Calculate the commitment of the current date, min age and max age using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `min_age_required`: The minimum age required
/// * `max_age_required`: The maximum age required
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min age and max age
pub fn calculate_param_commitment_sha2(min_age_required: u8, max_age_required: u8) -> Field {
    let mut params = [0 as u8; 5];
    params[0] = PROOF_TYPE_AGE;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    params[3] = min_age_required;
    params[4] = max_age_required;
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
