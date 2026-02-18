use date::Date;
use poseidon::poseidon2::Poseidon2;
use utils::{get_dob_from_mrz, get_expiry_date_from_mrz, is_id_card, types::{DG1Data, YYMMDDDate}};

pub mod tests;

fn get_date(date_bytes: YYMMDDDate, threshold_date: Date) -> Date {
    // Create a Date object from the date using the current date as
    // the pivot year to differentiate between 20th and 21st centuries
    // as the format is "YYMMDD"
    Date::from_bytes_short_year(date_bytes, threshold_date)
}

pub fn get_birthdate(dg1: DG1Data, current_date_timestamp: u64) -> Date {
    let current_date = Date::from_timestamp(current_date_timestamp);
    let mut birthdate = Date::new(1, 1, 1);

    // Get the slice of the MRZ representing the birthdate
    if is_id_card(dg1) {
        birthdate = get_date(get_dob_from_mrz(dg1), current_date);
    } else {
        birthdate = get_date(get_dob_from_mrz(dg1), current_date);
    }

    birthdate
}

pub fn get_expiry_date(dg1: DG1Data, current_date_timestamp: u64) -> Date {
    let current_date = Date::from_timestamp(current_date_timestamp);
    let mut expiry_date = Date::new(1, 1, 1);

    // We base the threshold year for the expiry date on the current date plus 20 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 20 years we should be safe
    let threshold_year = current_date.add_years(20);

    // Get the slice of the MRZ representing the expiry date
    if is_id_card(dg1) {
        expiry_date = get_date(get_expiry_date_from_mrz(dg1), threshold_year);
    } else {
        expiry_date = get_date(get_expiry_date_from_mrz(dg1), threshold_year);
    }

    expiry_date
}

pub fn compare_date(
    date_to_compare: Date,
    min_date_timestamp: u64,
    max_date_timestamp: u64,
    epoch_year: u32,
) {
    assert(
        (min_date_timestamp != 0) | (max_date_timestamp != 0),
        "Either min or max date must be non-zero",
    );

    let min_date = Date::from_timestamp_with_epoch(min_date_timestamp, epoch_year);
    let max_date = Date::from_timestamp_with_epoch(max_date_timestamp, epoch_year);

    if (min_date_timestamp != 0) & (max_date_timestamp == 0) {
        // The minimum date is more likely to be inclusive, so we use gte
        assert(date_to_compare.gte(min_date), "Date is not above or equal to min date");
    } else if (max_date_timestamp != 0) & (min_date_timestamp == 0) {
        // The maximum date is more likely to be inclusive, so we use lte
        assert(date_to_compare.lte(max_date), "Date is not below or equal to max date");
    } else {
        assert(min_date.lte(max_date), "Min date must be less than or equal to max date");

        // Check if birthdate is within the range
        assert(date_to_compare.gte(min_date), "Date is not above or equal to min date");
        assert(date_to_compare.lte(max_date), "Date is not below or equal to max date");
    }
}

/// Calculate the commitment of the current date, min date and max date using Poseidon2
///
/// This is less demanding on the prover but much more demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `min_date`: The minimum date
/// * `max_date`: The maximum date
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min date and max date
pub fn calculate_param_commitment(
    proof_type: u8,
    min_date_timestamp: u64,
    max_date_timestamp: u64,
) -> Field {
    let mut params = [0 as Field; 4];
    params[0] = proof_type as Field;
    params[1] = (params.len() - 2) as Field;
    params[2] = min_date_timestamp as Field;
    params[3] = max_date_timestamp as Field;
    Poseidon2::hash(params, params.len())
}

/// Calculate the commitment of the current date, min date and max date using SHA2-256
///
/// This is more demanding on the prover but less demanding on EVM verifiers
///
/// # Arguments
///
/// * `proof_type`: The proof type
/// * `min_date`: The minimum date
/// * `max_date`: The maximum date
///
/// # Returns
///
/// * `commitment`: The commitment of the current date, min date and max date
pub fn calculate_param_commitment_sha2(
    proof_type: u8,
    min_date_timestamp: u64,
    max_date_timestamp: u64,
) -> Field {
    let mut params = [0 as u8; 19];
    params[0] = proof_type;
    let len_bytes: [u8; 2] = utils::encode_integer_over_bytes(params.len() - 3);
    params[1] = len_bytes[0];
    params[2] = len_bytes[1];
    let min_date_timestamp_bytes: [u8; 8] = (min_date_timestamp as Field).to_be_bytes();
    for i in 3..11 {
        params[i] = min_date_timestamp_bytes[i - 3];
    }
    let max_date_timestamp_bytes: [u8; 8] = (max_date_timestamp as Field).to_be_bytes();
    for i in 11..19 {
        params[i] = max_date_timestamp_bytes[i - 11];
    }
    let hash = sha256::sha256_var(params, params.len() as u64);
    utils::pack_be_bytes_and_truncate_into_field::<32, 31>(hash)
}
