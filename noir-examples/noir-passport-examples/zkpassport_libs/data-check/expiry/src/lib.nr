use date::Date;
use utils::{
    get_array_slice, get_mrz_from_dg1, ID_CARD_MRZ_EXPIRY_DATE_INDEX, is_id_card,
    PASSPORT_MRZ_EXPIRY_DATE_INDEX,
};

pub fn check_expiry(dg1: [u8; 95], current_date_bytes: [u8; 8]) {
    let mrz = get_mrz_from_dg1(dg1);

    // We base the threshold year for the expiry date on the current date plus 20 years
    // As most documents will have a 10 year validity (and some maybe 15 years?)
    // So with 20 years we should be safe
    let threshold_year = Date::from_bytes_long_year(current_date_bytes).add_years(20);
    let threshold_year_bytes = threshold_year.to_bytes();

    let current_date = Date::from_bytes_long_year(current_date_bytes);

    let mut expiry_date_bytes = [0 as u8; 6];

    if is_id_card(dg1) {
        expiry_date_bytes = get_array_slice(
            mrz,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX,
            ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6,
        );
    } else {
        expiry_date_bytes = get_array_slice(
            mrz,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX,
            PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6,
        );
    }

    let expiry_date = Date::from_bytes_short_year(
        expiry_date_bytes,
        [threshold_year_bytes[2], threshold_year_bytes[3]],
    );

    assert(current_date.lt(expiry_date));
}
