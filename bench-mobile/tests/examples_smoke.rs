#![cfg(feature = "fixture-tests")]

use bench_mobile::examples::{fixture_end_to_end_smoke, prepare_fixture, MobileBenchFixture};

#[test]
fn embedded_example_fixtures_prepare_non_empty_artifacts() {
    for fixture in [
        MobileBenchFixture::CompleteAgeCheck,
        MobileBenchFixture::Oprf,
        MobileBenchFixture::PassportP1,
        MobileBenchFixture::P256Bigcurve,
        MobileBenchFixture::WebauthnAssertion,
    ] {
        let prepared = prepare_fixture(fixture).expect("prepare fixture");
        let (constraints, witnesses) = prepared.prover_size();

        assert!(constraints > 0, "expected non-empty constraint set");
        assert!(witnesses > 0, "expected non-empty witness set");
    }
}

#[test]
fn embedded_oprf_fixture_proves_and_verifies() {
    fixture_end_to_end_smoke(MobileBenchFixture::Oprf).expect("oprf smoke benchmark");
}

#[test]
fn embedded_passport_p1_fixture_proves_and_verifies() {
    fixture_end_to_end_smoke(MobileBenchFixture::PassportP1).expect("passport_p1 smoke benchmark");
}

#[test]
fn embedded_p256_bigcurve_fixture_proves_and_verifies() {
    fixture_end_to_end_smoke(MobileBenchFixture::P256Bigcurve)
        .expect("p256_bigcurve smoke benchmark");
}

#[test]
fn embedded_webauthn_assertion_fixture_proves_and_verifies() {
    fixture_end_to_end_smoke(MobileBenchFixture::WebauthnAssertion)
        .expect("webauthn_assertion smoke benchmark");
}
