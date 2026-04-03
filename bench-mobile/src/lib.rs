//! Mobile benchmarks for ProveKit's monolithic passport circuit.

use {
    crate::passport::{
        prove_complete_age_check_fixture, verify_complete_age_check_fixture,
        PreparedCompleteAgeCheckFixture, VerifiedCompleteAgeCheckFixture,
    },
    mobench_sdk::{benchmark, profile_phase},
    std::{cell::RefCell, hint::black_box},
};

pub mod passport;

thread_local! {
    static PREPARED_COMPLETE_AGE_CHECK: RefCell<Option<PreparedCompleteAgeCheckFixture>> =
        const { RefCell::new(None) };
    static VERIFIED_COMPLETE_AGE_CHECK: RefCell<Option<VerifiedCompleteAgeCheckFixture>> =
        const { RefCell::new(None) };
}

fn with_prepared_complete_age_check<T>(f: impl FnOnce(&PreparedCompleteAgeCheckFixture) -> T) -> T {
    PREPARED_COMPLETE_AGE_CHECK.with(|cache| {
        if cache.borrow().is_none() {
            *cache.borrow_mut() = Some(
                passport::prepare_complete_age_check_fixture()
                    .expect("prepare complete_age_check fixture"),
            );
        }

        let cache_ref = cache.borrow();
        let prepared = cache_ref
            .as_ref()
            .expect("prepared complete_age_check fixture");
        f(prepared)
    })
}

fn with_verified_complete_age_check<T>(f: impl FnOnce(&VerifiedCompleteAgeCheckFixture) -> T) -> T {
    VERIFIED_COMPLETE_AGE_CHECK.with(|cache| {
        if cache.borrow().is_none() {
            let prepared = passport::prepare_complete_age_check_fixture().expect("prepare fixture");
            let verified = prove_complete_age_check_fixture(prepared).expect("prove fixture");
            *cache.borrow_mut() = Some(verified);
        }

        let cache_ref = cache.borrow();
        let verified = cache_ref
            .as_ref()
            .expect("verified complete_age_check fixture");
        f(verified)
    })
}

#[benchmark]
pub fn bench_passport_complete_age_check_prepare() {
    let prepared = profile_phase("prepare", || {
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
    });

    black_box((
        prepared.prover.size(),
        prepared.verifier.r1cs.num_constraints(),
        prepared.input_map.len(),
    ));
}

#[benchmark]
pub fn bench_passport_complete_age_check_prove() {
    with_prepared_complete_age_check(|prepared| {
        let verified = profile_phase("prove", || {
            prove_complete_age_check_fixture(prepared.clone())
                .expect("prove complete_age_check fixture")
        });

        black_box(verified);
    });
}

#[benchmark]
pub fn bench_passport_complete_age_check_verify() {
    with_verified_complete_age_check(|verified| {
        let verified = profile_phase("verify", || {
            verify_complete_age_check_fixture(verified.clone())
                .expect("verify complete_age_check fixture")
        });

        black_box(verified);
    });
}

#[benchmark]
pub fn bench_passport_complete_age_check_e2e() {
    let prepared = profile_phase("prepare", || {
        passport::prepare_complete_age_check_fixture().expect("prepare complete_age_check fixture")
    });
    let verified = profile_phase("prove", || {
        prove_complete_age_check_fixture(prepared).expect("prove complete_age_check fixture")
    });
    let verified = profile_phase("verify", || {
        verify_complete_age_check_fixture(verified).expect("verify complete_age_check fixture")
    });

    black_box(verified);
}
