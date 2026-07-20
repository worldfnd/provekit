#![cfg(feature = "fixture-tests")]

use bench_mobile::passport::{
    passport_complete_age_check_end_to_end_smoke, passport_fragmented_age_check_end_to_end_smoke,
    prepare_complete_age_check_fixture, prepare_fragmented_age_check_fixture,
};

#[test]
fn embedded_passport_fixture_prepares_non_empty_artifacts() {
    let prepared = prepare_complete_age_check_fixture().expect("prepare fixture");
    let (constraints, witnesses) = prepared.prover_size();

    assert!(constraints > 0, "expected non-empty constraint set");
    assert!(witnesses > 0, "expected non-empty witness set");
}

#[test]
fn embedded_passport_fixture_proves_and_verifies() {
    passport_complete_age_check_end_to_end_smoke().expect("passport smoke benchmark");
}

#[test]
fn embedded_fragmented_passport_fixture_prepares_non_empty_artifacts() {
    let prepared = prepare_fragmented_age_check_fixture().expect("prepare fragmented fixture");

    for (name, fixture) in [
        ("t_add_dsc_720", prepared.add_dsc),
        ("t_add_id_data_720", prepared.add_id_data),
        ("t_add_integrity_commit", prepared.add_integrity_commit),
        ("t_attest", prepared.attest),
    ] {
        let (constraints, witnesses) = fixture.prover_size();

        assert!(constraints > 0, "{name} should have non-empty constraints");
        assert!(witnesses > 0, "{name} should have non-empty witnesses");
    }
}

#[test]
fn embedded_fragmented_passport_fixture_proves_and_verifies() {
    passport_fragmented_age_check_end_to_end_smoke().expect("fragmented passport smoke benchmark");
}
