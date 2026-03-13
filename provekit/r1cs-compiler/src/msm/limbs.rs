//! `Limbs`: fixed-capacity, `Copy` array of witness indices.

// ---------------------------------------------------------------------------
// Limbs: fixed-capacity, Copy array of witness indices
// ---------------------------------------------------------------------------

/// Maximum number of limbs supported. Covers all practical field sizes
/// (e.g. a 512-bit modulus with 16-bit limbs = 32 limbs).
pub const MAX_LIMBS: usize = 32;

/// A fixed-capacity array of witness indices, indexed by limb position.
///
/// This type is `Copy`, so it can be passed by value without requiring
/// const generics or dispatch macros. The runtime `len` field tracks how
/// many limbs are actually in use.
#[derive(Clone, Copy)]
pub struct Limbs {
    data: [usize; MAX_LIMBS],
    len:  usize,
}

impl Limbs {
    /// Sentinel value for uninitialized limb slots. Using `usize::MAX`
    /// ensures accidental use of an unfilled slot indexes an absurdly
    /// large witness, causing an immediate out-of-bounds panic.
    const UNINIT: usize = usize::MAX;

    /// Create a new `Limbs` with `len` limbs, all initialized to `UNINIT`.
    pub fn new(len: usize) -> Self {
        assert!(
            len > 0 && len <= MAX_LIMBS,
            "limb count must be 1..={MAX_LIMBS}, got {len}"
        );
        Self {
            data: [Self::UNINIT; MAX_LIMBS],
            len,
        }
    }

    /// Create a single-limb `Limbs` wrapping one witness index.
    pub fn single(value: usize) -> Self {
        let mut l = Self {
            data: [Self::UNINIT; MAX_LIMBS],
            len:  1,
        };
        l.data[0] = value;
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

impl std::ops::Index<usize> for Limbs {
    type Output = usize;
    fn index(&self, i: usize) -> &usize {
        debug_assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &self.data[i]
    }
}

impl std::ops::IndexMut<usize> for Limbs {
    fn index_mut(&mut self, i: usize) -> &mut usize {
        debug_assert!(
            i < self.len,
            "Limbs index {i} out of bounds (len={})",
            self.len
        );
        &mut self.data[i]
    }
}
