use acir::{AcirField, FieldElement};

pub fn pow_field(base: FieldElement, exponent: u32) -> FieldElement {
    let mut exponent_to_bits: Vec<bool> = (0..32).map(|i| (exponent >> i) & 1 != 0).collect();
    // Truncate to only get the most significant bits.
    while let Some(false) = exponent_to_bits.last() {
        exponent_to_bits.pop();
    }
    let mut field_element_exponentiated = FieldElement::one();
    let mut repeated_squaring_value = base;
    exponent_to_bits.iter().for_each(|bit| {
        if *bit {
            field_element_exponentiated = field_element_exponentiated * repeated_squaring_value;
        }
        repeated_squaring_value = repeated_squaring_value * repeated_squaring_value;
    });
    field_element_exponentiated
}
