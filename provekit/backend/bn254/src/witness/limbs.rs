//! `Limbs`: fixed-capacity, `Copy` array of witness indices with push-based
//! construction.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum number of limbs supported.
pub const MAX_LIMBS: usize = 32;

/// A fixed-capacity `Copy` array of witness indices, indexed by limb position.
///
/// Construction uses `push()` to append elements sequentially, preventing
/// uninitialized access. Slots beyond `len` are never reachable through the
/// public API.
#[derive(Clone, Copy)]
pub struct Limbs {
    data: [usize; MAX_LIMBS],
    len:  usize,
}

impl Limbs {
    /// Create an empty `Limbs`. Use [`Self::push`] to add elements.
    pub fn new() -> Self {
        Self {
            data: [0; MAX_LIMBS],
            len:  0,
        }
    }

    /// Append a witness index. Panics if capacity (`MAX_LIMBS`) is exceeded.
    pub fn push(&mut self, value: usize) {
        assert!(
            self.len < MAX_LIMBS,
            "Limbs overflow: cannot push beyond {MAX_LIMBS} elements"
        );
        self.data[self.len] = value;
        self.len += 1;
    }

    /// Create a single-limb `Limbs` wrapping one witness index.
    pub fn single(value: usize) -> Self {
        let mut l = Self::new();
        l.push(value);
        l
    }

    /// View the active limbs as a slice.
    pub fn as_slice(&self) -> &[usize] {
        &self.data[..self.len]
    }

    /// Number of active limbs.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Default for Limbs {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Limbs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice().iter()).finish()
    }
}

impl PartialEq for Limbs {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.data[..self.len] == other.data[..other.len]
    }
}
impl Eq for Limbs {}

impl From<&[usize]> for Limbs {
    fn from(slice: &[usize]) -> Self {
        assert!(
            slice.len() <= MAX_LIMBS,
            "Limbs: slice length {} exceeds MAX_LIMBS ({MAX_LIMBS})",
            slice.len()
        );
        let mut l = Self::new();
        for &v in slice {
            l.push(v);
        }
        l
    }
}

impl std::ops::Index<usize> for Limbs {
    type Output = usize;
    fn index(&self, i: usize) -> &usize {
        assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &self.data[i]
    }
}

impl std::ops::IndexMut<usize> for Limbs {
    fn index_mut(&mut self, i: usize) -> &mut usize {
        assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &mut self.data[i]
    }
}

/// Serialize only the active elements (same wire format as `Vec<usize>`).
impl Serialize for Limbs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

/// Deserialize from a variable-length sequence (same wire format as
/// `Vec<usize>`).
impl<'de> Deserialize<'de> for Limbs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v: Vec<usize> = Vec::deserialize(deserializer)?;
        Ok(Limbs::from(v.as_slice()))
    }
}
