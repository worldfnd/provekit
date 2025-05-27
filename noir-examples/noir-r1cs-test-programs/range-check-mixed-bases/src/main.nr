// Test a range check that requires a digital decomposition mixed bases
// The program compiles to the following ACIR:
//   BrilligCall
//   RANGE CHECK of witness 1 to 238 bits
//   RANGE CHECK of witness 2 to 16 bits
//   BrilligCall
//   RANGE CHECK of witness 7 to 17 bits
//   ..
// + The 238 bit range check is done using a digital decomposition using 29
//   base-2^8 digits and one
// base-2^6 digit.
// + The 16 bit range check is done using a digital decomposition using 2
//   base-2^8 digits.
// + The 17 bit range check is done using a digital decomposition using 2
//   base-2^8 digits and one
// base-2^1 digit.
// Note that the range check of the base-2^1 digit will be done using a direct
// ("naive") range check.
fn main(x: Field, y: Field) -> pub u16 {
    (x as u16) + (y as u16)
}
