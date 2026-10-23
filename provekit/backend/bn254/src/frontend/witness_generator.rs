use {
    noirc_abi::Abi,
    provekit_common::utils::serde_cborify,
    serde::{Deserialize, Serialize},
    std::num::NonZeroU32,
};

// TODO: Handling of the return value for the verifier.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirWitnessGenerator {
    // Note: Abi uses an [internally tagged] enum format in Serde, which is not compatible
    // with some schemaless formats like Postcard.
    // [internally-tagged]: https://serde.rs/enum-representations.html
    #[serde(with = "serde_cborify")]
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

#[cfg(test)]
mod tests {
    use {
        super::*,
        acir::circuit::ErrorSelector,
        noirc_abi::{AbiErrorType, AbiParameter, AbiReturnType, AbiType, AbiVisibility, Sign},
        std::collections::BTreeMap,
    };

    #[derive(Deserialize)]
    struct RawAbi {
        abi: Vec<u8>,
    }

    fn make_test_abi() -> Abi {
        let point = AbiType::Struct {
            path:   "main::Point".to_string(),
            fields: vec![
                ("x".to_string(), AbiType::Field),
                ("y".to_string(), AbiType::Integer {
                    sign:  Sign::Signed,
                    width: 64,
                }),
            ],
        };
        Abi {
            parameters:  vec![
                AbiParameter {
                    name:       "point".to_string(),
                    typ:        point.clone(),
                    visibility: AbiVisibility::Private,
                },
                AbiParameter {
                    name:       "items".to_string(),
                    typ:        AbiType::Array {
                        length: 3,
                        typ:    Box::new(AbiType::Tuple {
                            fields: vec![AbiType::Boolean, AbiType::String { length: 5 }],
                        }),
                    },
                    visibility: AbiVisibility::Public,
                },
            ],
            return_type: Some(AbiReturnType {
                abi_type:   AbiType::Integer {
                    sign:  Sign::Unsigned,
                    width: 32,
                },
                visibility: AbiVisibility::Public,
            }),
            error_types: BTreeMap::from([
                (ErrorSelector::new(1), AbiErrorType::FmtString {
                    length:     4,
                    item_types: vec![AbiType::Field],
                }),
                (ErrorSelector::new(2), AbiErrorType::Custom(point)),
                (ErrorSelector::new(u64::MAX), AbiErrorType::String {
                    string: "bad input".to_string(),
                }),
            ]),
        }
    }

    #[test]
    fn abi_is_stored_as_cbor_in_postcard() {
        let generator = NoirWitnessGenerator {
            abi:         make_test_abi(),
            witness_map: vec![NonZeroU32::new(1), None, NonZeroU32::new(7)],
        };
        let serialized = postcard::to_allocvec(&generator).unwrap();

        let raw: RawAbi = postcard::from_bytes(&serialized).unwrap();
        let abi: Abi = ciborium::from_reader(raw.abi.as_slice()).unwrap();
        assert_eq!(format!("{:?}", generator.abi), format!("{abi:?}"));

        let deserialized: NoirWitnessGenerator = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(generator, deserialized);
    }
}
