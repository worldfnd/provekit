use date::Date;
use utils::{get_expiry_date_from_mrz, types::{DG1Data, YYMMDDDate}};

pub mod tests;

pub fn check_expiry(dg1: DG1Data, current_date_timestamp: u64) {
    let expiry_date_bytes = get_expiry_date_from_mrz(dg1);
    check_expiry_from_date(expiry_date_bytes, current_date_timestamp);
}

pub fn check_expiry_from_date(expiry_date_bytes: YYMMDDDate, current_date_timestamp: u64) {
    let current_date = Date::from_timestamp(current_date_timestamp);

    // We base the threshold year for the expiry date on the current date plus 30 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 30 years we should be safe
    let threshold_year = current_date.add_years(30);

    let expiry_date = Date::from_bytes_short_year(expiry_date_bytes, threshold_year);

    assert(current_date.lt(expiry_date), "Document is expired");
}
