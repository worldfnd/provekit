use super::{compare_date, get_birthdate, get_expiry_date};
use date::Date;
use utils::constants::SAMPLE_DG1;

#[test]
fn test_get_birthdate() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2025, 9, 12).to_timestamp());
    assert_eq(birthdate, Date::new(1988, 11, 12));
}

#[test]
fn test_get_birthdate_wrong_century() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2088, 1, 1).to_timestamp());
    // If passed a date after 100 years (ignoring the day and month) after the birthdate, it will get the wrong century
    assert_eq(birthdate, Date::new(2088, 11, 12));
}

#[test]
fn test_get_birthdate_edge_current_date() {
    let birthdate = get_birthdate(SAMPLE_DG1, Date::new(2087, 12, 31).to_timestamp());
    // Just one year away from being 100 years after the birthdate
    // so it will still be the correct century
    assert_eq(birthdate, Date::new(1988, 11, 12));
}

#[test]
fn test_get_expiry_date() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(2025, 9, 12).to_timestamp());
    assert_eq(expiry_date, Date::new(2030, 1, 1));
}

#[test]
fn test_get_expiry_date_wrong_century() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(2009, 1, 1).to_timestamp());
    // If passed a date with a year more than 20 years before the expiry date, it will get the wrong century
    // as get_expiry_date adds 20 years to the current date to get the threshold year
    assert_eq(expiry_date, Date::new(1930, 1, 1));
}

#[test]
fn test_get_expiry_date_edge_current_date() {
    let expiry_date = get_expiry_date(SAMPLE_DG1, Date::new(2010, 1, 1).to_timestamp());
    // Just one year away from being 20 years before the expiry date
    // so it will still be the correct century
    assert_eq(expiry_date, Date::new(2030, 1, 1));
}

#[test]
fn test_compare_date_range() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2020, 1, 1);
    let max_date = Date::new(2040, 1, 1);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not above or equal to min date")]
fn test_compare_date_range_min_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 2);
    let max_date = Date::new(2030, 1, 3);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not below or equal to max date")]
fn test_compare_date_range_max_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2029, 12, 29);
    let max_date = Date::new(2029, 12, 31);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test]
fn test_compare_date_equal() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 1);
    let max_date = Date::new(2030, 1, 1);
    compare_date(date, min_date.to_timestamp(), max_date.to_timestamp(), 1970);
}

#[test]
fn test_compare_date_greater_than_or_equal() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2029, 12, 31);
    compare_date(date, min_date.to_timestamp(), 0, 1970);
}

#[test(should_fail_with = "Date is not above or equal to min date")]
fn test_compare_date_greater_than_or_equal_fail() {
    let date = Date::new(2030, 1, 1);
    let min_date = Date::new(2030, 1, 2);
    compare_date(date, min_date.to_timestamp(), 0, 1970);
}

#[test]
fn test_compare_date_less_than_or_equal() {
    let date = Date::new(2030, 1, 1);
    let max_date = Date::new(2030, 1, 2);
    compare_date(date, 0, max_date.to_timestamp(), 1970);
}

#[test(should_fail_with = "Date is not below or equal to max date")]
fn test_compare_date_less_than_or_equal_fail() {
    let date = Date::new(2030, 1, 1);
    let max_date = Date::new(2029, 12, 31);
    compare_date(date, 0, max_date.to_timestamp(), 1970);
}
