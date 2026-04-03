use bench_mobile::passport::{
    passport_complete_age_check_end_to_end_smoke, prepare_complete_age_check_fixture,
};

#[test]
fn embedded_passport_fixture_prepares_non_empty_artifacts() {
    let prepared = prepare_complete_age_check_fixture().expect("prepare fixture");
    let (constraints, witnesses) = prepared.prover.size();

    assert!(constraints > 0, "expected non-empty constraint set");
    assert!(witnesses > 0, "expected non-empty witness set");
}

#[test]
fn embedded_passport_fixture_proves_and_verifies() {
    passport_complete_age_check_end_to_end_smoke().expect("passport smoke benchmark");
}
