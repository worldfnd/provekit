use {
    crate::{
        utils::{noir_to_native, serde_jsonify},
        FieldElement,
    },
    anyhow::{anyhow, bail, ensure, Context, Result},
    ark_ff::PrimeField,
    noirc_abi::{
        input_parser::{Format, InputValue},
        Abi, AbiType,
    },
    noirc_artifacts::program::ProgramArtifact,
    serde::{Deserialize, Serialize},
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    std::num::NonZeroU32,
    tracing::instrument,
};

// TODO: Handling of the return value for the verifier.

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoirWitnessGenerator {
    // Note: Abi uses an [internally tagged] enum format in Serde, which is not compatible
    // with some schemaless formats like Postcard.
    // [internally-tagged]: https://serde.rs/enum-representations.html
    // TODO: serializes the ABI as a json string. Something like CBOR might be better.
    #[serde(with = "serde_jsonify")]
    abi: Abi,

    /// ACIR witness index to R1CS witness index
    /// Index zero is reserved for constant one, so we can use `NonZeroU32`
    witness_map: Vec<Option<NonZeroU32>>,
}

impl NoirWitnessGenerator {
    pub fn new(
        program: &ProgramArtifact,
        mut witness_map: Vec<Option<NonZeroU32>>,
        r1cs_witnesses: usize,
    ) -> Self {
        let abi = program.abi.clone();
        assert!(witness_map
            .iter()
            .filter_map(|n| *n)
            .all(|n| (n.get() as usize) < r1cs_witnesses));

        // Take only the prefix of witness map relevant for Noir inputs
        let num_inputs = abi.field_count() as usize;
        witness_map.truncate(num_inputs);
        Self { abi, witness_map }
    }

    pub fn witness_map(&self) -> &[Option<NonZeroU32>] {
        &self.witness_map
    }

    pub fn abi(&self) -> &Abi {
        &self.abi
    }

    /// Noir inputs are in order at the start of the witness vector
    #[instrument(skip_all, fields(size = toml.len()))]
    pub fn input_from_toml(&self, toml: &str) -> Result<Vec<FieldElement>> {
        // Parse toml to name -> value map
        let mut input = Format::Toml
            .parse(toml, &self.abi)
            .context("while parsing input toml")?;

        // Prepare witness vector
        let num_inputs = self.abi.field_count() as usize;
        let mut inputs = Vec::with_capacity(num_inputs);

        // Encode to vector of field elements base on Abi type info.
        for param in &self.abi.parameters {
            let value = input
                .remove(&param.name)
                .ok_or_else(|| anyhow!("Missing input {}", &param.name))?
                .clone();
            encode_input(&mut inputs, value, &param.typ)
                .with_context(|| format!("while encoding input for {}", &param.name))?;
        }
        if let Some(name) = input.keys().next() {
            bail!("Extra input {name}");
        }

        Ok(inputs)
    }
}

impl PartialEq for NoirWitnessGenerator {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.abi) == format!("{:?}", other.abi)
            && self.witness_map == other.witness_map
    }
}

/// Recursively encode Noir ABI input to a witness vector
/// See [`noirc_abi::Abi::encode`] for the Noir ABI specification.
fn encode_input(
    input: &mut Vec<FieldElement>,
    value: InputValue,
    abi_type: &AbiType,
) -> Result<()> {
    match (value, abi_type) {
        (InputValue::Field(elem), AbiType::Field) => input.push(noir_to_native(elem)),
        (InputValue::Vec(vec_elements), AbiType::Array { typ, .. }) => {
            for elem in vec_elements {
                encode_input(input, elem, typ)?;
            }
        }
        (InputValue::Vec(vec_elements), AbiType::Tuple { fields }) => {
            for (value, typ) in vec_elements.into_iter().zip(fields) {
                encode_input(input, value, typ)?;
            }
        }
        (InputValue::String(string), AbiType::String { length }) => {
            ensure!(
                string.len() == *length as usize,
                "String length {} does not match expected length {length}",
                string.len()
            );
            let str_as_fields = string
                .bytes()
                .map(|byte| FieldElement::from_be_bytes_mod_order(&[byte]));
            input.extend(str_as_fields);
        }
        (InputValue::Struct(mut object), AbiType::Struct { fields, .. }) => {
            for (field, typ) in fields {
                let value = object
                    .remove(field)
                    .ok_or_else(|| anyhow!("Missing input {field}"))?;
                encode_input(input, value, typ)
                    .with_context(|| format!("while encoding input struct field {field}"))?;
            }
            if let Some(name) = object.keys().next() {
                bail!("Extra input {name}");
            }
        }
        (value, typ) => bail!("Invalid input type, expected {typ:?}, got {value:?}"),
    }
    Ok(())
}

/// Trait which is used to add witness RNG for IOPattern
pub trait WitnessIOPattern {
    /// Schedule absorption of circuit shape (2 scalars): (num_constraints,
    /// num_witnesses).
    fn add_shape(self) -> Self;

    /// Schedule absorption of `num_pub_inputs` public input scalars.
    fn add_public_inputs(self, num_pub_inputs: usize) -> Self;

    /// Schedule absorption of `num_challenges` Fiat–Shamir challenges for
    /// LogUp/Spice.
    fn add_logup_challenges(self, num_challenges: usize) -> Self;
}

impl<IOPattern> WitnessIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_shape(self) -> Self {
        self.add_scalars(2, "shape")
    }

    fn add_public_inputs(self, num_pub_inputs: usize) -> Self {
        if num_pub_inputs > 0 {
            self.add_scalars(num_pub_inputs, "pub_inputs")
        } else {
            self
        }
    }

    fn add_logup_challenges(self, num_challenges: usize) -> Self {
        if num_challenges > 0 {
            self.challenge_scalars(num_challenges, "wb:challenges")
        } else {
            self
        }
    }
}
