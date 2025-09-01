use serde::{Deserialize, Serialize};

/// Allocates witnesses for the digital decomposition of the given witnesses
/// into its digits in the given bases.  A log base is specified for each digit
/// (permitting mixed base decompositions). The order of bases is little-endian.
/// Witnesses are grouped by digital place, in the order of the bases,
/// where each group of witnesses is in 1:1 correspondence with
/// witnesses_to_decompose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DigitalDecompositionWitnesses {
    /// The log base of each digit (in little-endian order)
    pub log_bases:                  Vec<usize>,
    /// The number of witnesses to decompose
    pub num_witnesses_to_decompose: usize,
    /// Witness indices of the values to be decomposed
    pub witnesses_to_decompose:     Vec<usize>,
    /// The index of the first witness written to
    pub first_witness_idx:          usize,
    /// The number of witnesses written to
    pub num_witnesses:              usize,
}
