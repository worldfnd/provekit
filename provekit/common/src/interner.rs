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

    /// Borrow the deduplicated values array. Used by mmap-format writers
    /// that need the raw bytes.
    pub fn values_raw(&self) -> &[FieldElement] {
        &self.values
    }

    /// Construct an Interner from a pre-built values vector. Bypasses the
    /// dedup work in `intern()` — used by mmap-format readers that have
    /// already loaded a deduplicated set of values from disk.
    pub fn from_values(values: Vec<FieldElement>) -> Self {
        Self { values }
    }
}

impl InternedFieldElement {
    /// Construct an InternedFieldElement from a raw index. Used by
    /// mmap-format readers that load the index Vec from raw bytes.
    pub const fn new(idx: usize) -> Self {
        Self(idx)
    }

    /// Inner index value.
    pub const fn index(&self) -> usize {
        self.0
    }
}
