use {
    crate::utils::serde_jsonify,
    noirc_abi::Abi,
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
    pub abi: Abi,

    /// ACIR witness index to R1CS witness index
    /// Index zero is reserved for constant one, so we can use `NonZeroU32`
    pub witness_map: Vec<Option<NonZeroU32>>,
}

impl NoirWitnessGenerator {
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
