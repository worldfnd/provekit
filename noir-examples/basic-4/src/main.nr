// Basic arithmetic: addition, subtraction, multiplication.
// Proves knowledge of (a, b) such that (a + b) * (a - b) == result.
// Mathematically: result = a^2 - b^2.
// Honest inputs: a = 5, b = 3 -> result = 16.
fn main(a: Field, b: Field) -> pub Field {
    let sum = a + b;
    let diff = a - b;
    sum * diff
}
