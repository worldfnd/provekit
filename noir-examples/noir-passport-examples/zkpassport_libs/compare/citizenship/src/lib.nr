use utils::get_nationality_from_mrz;

pub fn compare_citizenship(dg1: [u8; 95], country: [u8; 3]) {
    let country_bytes = get_nationality_from_mrz(dg1);

    assert(country_bytes[0] == country[0]);
    assert(country_bytes[1] == country[1]);
    assert(country_bytes[2] == country[2]);
}
