#[allow(missing_docs)]
use whir::crypto::fields::Field256;
use ark_std::str::FromStr;
use serde::Deserialize;
use ark_std::ops::{Add, Sub, Mul};
use ruint_macro::uint;
use crate::skyscraper::uint_to_field;
use ark_std::{Zero, One};


/// Convert vector string to vector field
pub fn stringvec_to_fieldvec(witness: &Vec<String>) -> Vec<Field256> {
    witness.iter().map(|x|{Field256::from_str(x).expect("Failed to create Field256 value from a string")}).collect()
}

pub fn next_power_of_two(n: usize) -> usize {
    let mut power = 1;
    let mut ans = 0;
    while power < n {
        power <<= 1;
        ans += 1;
    }
    ans
}

/// Pads the vector with 0 so that the number of elements in the vector is a power of 2
pub fn pad_to_power_of_two(mut witness: Vec<Field256>) -> Vec<Field256> {
    let target_len = next_power_of_two(witness.len());
    while witness.len() < 1<<target_len {
        witness.push(Field256::zero()); // Pad with zeros
    }
    witness
}

pub fn calculate_witness_bound(matrix_cells: Vec<MatrixCell>, witness: &Vec<Field256>, num_constraints: u32)->Vec<Field256> {
    let mut witness_bound = vec![Field256::zero(); num_constraints as usize];
    for x in matrix_cells {
        let cell = Field256::from_str(&x.value).expect("Failed to create Field256 value from a string");
        let witness_cell = witness[x.signal as usize];
        witness_bound[x.constraint as usize] = witness_bound[x.constraint as usize].add(cell.mul(witness_cell));
    }
    witness_bound
}

pub fn evaluations_over_boolean_hypercube_for_eq(r: Vec<Field256>) -> Vec<Field256> {
    let mut ans = vec![Field256::from(1)];
    for x in r {
        let mut left: Vec<Field256> = ans.clone().into_iter().map(|y| {y.mul(Field256::one().sub(x))}).collect();
        let right: Vec<Field256> = ans.into_iter().map(|y| {y.mul(x)}).collect();
        left.extend(right);
        ans = left;
    }
    ans
}

pub const HALF: Field256 = uint_to_field(uint!(10944121435919637611123202872628637544274182200208017171849102093287904247809_U256));


#[derive(Deserialize)]
pub struct MatrixCell {
    pub constraint: u32,
    pub signal: u32,
    pub value: String,
}

#[derive(Deserialize)]
pub struct R1CSWithWitness {
    pub num_public: u32,
    pub num_variables: u32,
    pub num_constraints: u32,
    pub a: Vec<MatrixCell>,
    pub b: Vec<MatrixCell>,
    pub c: Vec<MatrixCell>,
    pub witnesses: Vec<Vec<String>>,
}
