use super::check_expiry;
use date::Date;
use utils::constants::SAMPLE_DG1;

#[test]
fn test_check_expiry() {
    let current_date = Date::new(2025, 9, 12);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}

#[test]
fn test_check_expiry_edge() {
    // This one day before the expiry date, so it is still valid
    let current_date = Date::new(2029, 12, 31);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}

#[test(should_fail_with = "Document is expired")]
fn test_check_expiry_expired() {
    // The expiry date is 2030-1-1 so here it is expired
    let current_date = Date::new(2030, 1, 1);
    check_expiry(SAMPLE_DG1, current_date.to_timestamp());
}
