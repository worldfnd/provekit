// Extract DOB from MRZ, verify age and expiry, generate nullifier
use commitment::nullify;
use compare_age::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use utils::types::{DG1Data, SaltedValue,MRZExpiryDate};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    min_age_required: u8,
    max_age_required: u8,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    compare_age(
        salted_dg1.value,
        min_age_required,
        max_age_required,
        current_date,
    );
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(current_date, min_age_required, max_age_required);
    (param_commitment, nullifier_type, nullifier)
}
