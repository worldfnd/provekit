use {
    crate::{utils::serde_ark, FieldElement},
    ark_ff::PrimeField,
    serde::{Deserialize, Deserializer, Serialize},
    std::collections::HashMap,
};

type FieldKey = [u64; 4];

#[inline(always)]
fn field_to_key(value: FieldElement) -> FieldKey {
    value.into_bigint().0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interner {
    #[serde(with = "serde_ark")]
    values:    Vec<FieldElement>,
    #[serde(skip)]
    index_map: HashMap<FieldKey, usize>,
}

impl<'de> Deserialize<'de> for Interner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct InternerData {
            #[serde(with = "serde_ark")]
            values: Vec<FieldElement>,
        }

        let data = InternerData::deserialize(deserializer)?;

        let mut index_map = HashMap::with_capacity(data.values.len());
        for (index, &value) in data.values.iter().enumerate() {
            index_map.insert(field_to_key(value), index);
        }

        Ok(Self {
            values: data.values,
            index_map,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternedFieldElement(usize);

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    pub fn new() -> Self {
        Self {
            values:    Vec::new(),
            index_map: HashMap::new(),
        }
    }

    pub fn intern(&mut self, value: FieldElement) -> InternedFieldElement {
        let key = field_to_key(value);

        if let Some(&index) = self.index_map.get(&key) {
            return InternedFieldElement(index);
        }

        let index = self.values.len();
        self.values.push(value);
        self.index_map.insert(key, index);
        InternedFieldElement(index)
    }

    pub fn get(&self, el: InternedFieldElement) -> Option<FieldElement> {
        self.values.get(el.0).copied()
    }

    pub fn rebuild_index_map(&mut self) {
        self.index_map.clear();
        self.index_map.reserve(self.values.len());
        for (index, &value) in self.values.iter().enumerate() {
            self.index_map.insert(field_to_key(value), index);
        }
    }
}
