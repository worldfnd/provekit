use super::{compare_age, get_birthdate};
use date::Date;
use utils::constants::SAMPLE_DG1;

#[test]
fn test_get_birthdate() {
    let birthdate = get_birthdate(SAMPLE_DG1, 1757609123);
    let expected_birthdate = Date::new(1988, 11, 12);
    assert_eq(birthdate, expected_birthdate);
}

#[test]
fn test_compare_age_range() {
    let dg1 = SAMPLE_DG1;
    let min_age = 35;
    let max_age = 37;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 36;
    let max_age = 36;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_greater_than_or_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 36;
    let max_age = 0;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should pass because the age just reached 37
#[test]
fn test_compare_age_greater_than_or_equal_edge() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 0;
    let timestamp = Date::new(2025, 11, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should fail because the age is one day away from 37
#[test(should_fail_with = "Age is not above or equal to min age")]
fn test_compare_age_greater_than_or_equal_fail() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 0;
    let timestamp = Date::new(2025, 11, 11).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test]
fn test_compare_age_less_than_or_equal() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should pass because the birthdate is the next day,
// so the age is still 36
#[test]
fn test_compare_age_less_than_or_equal_edge() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    let timestamp = Date::new(2025, 11, 11).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

// Should fail because the age is now 37
#[test(should_fail_with = "Age is not below or equal to max age")]
fn test_compare_age_less_than_or_equal_fail() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 36;
    let timestamp = Date::new(2025, 11, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Min age must be less than or equal to max age")]
fn test_compare_age_min_greater_than_max() {
    let dg1 = SAMPLE_DG1;
    let min_age = 37;
    let max_age = 36;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Either min or max age must be non-zero")]
fn test_compare_age_min_and_max_zero() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 0;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}

#[test(should_fail_with = "Age must be less than 100")]
fn test_compare_age_max_greater_than_100() {
    let dg1 = SAMPLE_DG1;
    let min_age = 0;
    let max_age = 100;
    let timestamp = Date::new(2025, 9, 12).to_timestamp();
    compare_age(dg1, min_age, max_age, timestamp);
}
