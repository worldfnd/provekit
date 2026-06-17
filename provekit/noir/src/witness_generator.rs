use {
    noirc_abi::Abi,
    provekit_common::utils::serde_jsonify,
    serde::{Deserialize, Serialize},
    std::num::NonZeroU32,
};

// TODO: Handling of the return value for the verifier.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirWitnessGenerator {
    // Note: Abi uses an [internally tagged] enum format in Serde, which is not compatible
    // with some schemaless formats like Postcard.
    // [internally-tagged]: https://serde.rs/enum-representations.html
    // TODO: serializes the ABI as a json string. Something like CBOR might be better.
    #[serde(with = "serde_jsonify")]
    pub(crate) abi: Abi,

    /// ACIR witness index to R1CS witness index
    /// Index zero is reserved for constant one, so we can use `NonZeroU32`
    pub(crate) witness_map: Vec<Option<NonZeroU32>>,
}

impl NoirWitnessGenerator {
    /// Construct from a precomputed ABI and ACIR→R1CS witness index map.
    ///
    /// The program-derived construction logic (deriving the ABI and witness
    /// map from a compiled circuit) lives in the `provekit-r1cs-compiler`
    /// frontend; this is the plain field-setting constructor it calls.
    #[must_use]
    pub fn new(abi: Abi, witness_map: Vec<Option<NonZeroU32>>) -> Self {
        Self { abi, witness_map }
    }

    pub fn abi(&self) -> &Abi {
        &self.abi
    }
}

impl PartialEq for NoirWitnessGenerator {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.abi) == format!("{:?}", other.abi)
            && self.witness_map == other.witness_map
    }
}
