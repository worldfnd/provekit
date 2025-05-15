use {
    crate::{utils::serde_ark, FieldElement},
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interner {
    #[serde(with = "serde_ark")]
    values: Vec<FieldElement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternedFieldElement(usize);

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Interning is slow in favour of faster lookups.
    pub fn intern(&mut self, value: FieldElement) -> InternedFieldElement {
        // Deduplicate
        if let Some(index) = self.values.iter().position(|v| *v == value) {
            return InternedFieldElement(index);
        }

        // Insert
        let index = self.values.len();
        self.values.push(value);
        InternedFieldElement(index)
    }

    pub fn get(&self, el: InternedFieldElement) -> Option<FieldElement> {
        self.values.get(el.0).copied()
    }
}
