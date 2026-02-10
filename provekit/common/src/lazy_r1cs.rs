use {
    crate::{HydratedSparseMatrix, Interner, SparseMatrix, R1CS},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    std::{io::Read, sync::OnceLock},
    xz2::{read::XzDecoder, write::XzEncoder},
};

/// Matrices data that gets compressed/decompressed lazily.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1CSMatrices {
    interner: Interner,
    a:        SparseMatrix,
    b:        SparseMatrix,
    c:        SparseMatrix,
}

/// A lazily-decompressed R1CS constraint system.
///
/// Stores the R1CS matrices in XZ-compressed form and only decompresses
/// them when first accessed. This reduces memory usage during loading since
/// the compressed data is much smaller than the expanded matrices.
pub struct LazyR1CS {
    pub num_public_inputs: usize,
    num_constraints:       usize,
    num_witnesses:         usize,
    compressed_matrices:   Vec<u8>,
    #[allow(clippy::type_complexity)]
    cached:                OnceLock<(Interner, SparseMatrix, SparseMatrix, SparseMatrix)>,
}

impl std::fmt::Debug for LazyR1CS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyR1CS")
            .field("num_public_inputs", &self.num_public_inputs)
            .field("num_constraints", &self.num_constraints)
            .field("num_witnesses", &self.num_witnesses)
            .field("compressed_size", &self.compressed_matrices.len())
            .field("is_decompressed", &self.cached.get().is_some())
            .finish()
    }
}

impl Clone for LazyR1CS {
    fn clone(&self) -> Self {
        Self {
            num_public_inputs:   self.num_public_inputs,
            num_constraints:     self.num_constraints,
            num_witnesses:       self.num_witnesses,
            compressed_matrices: self.compressed_matrices.clone(),
            cached:              OnceLock::new(),
        }
    }
}

impl LazyR1CS {
    /// Create a `LazyR1CS` from an existing `R1CS` by compressing its matrices.
    pub fn from_r1cs(r1cs: R1CS) -> Self {
        let num_public_inputs = r1cs.num_public_inputs;
        let num_constraints = r1cs.num_constraints();
        let num_witnesses = r1cs.num_witnesses();

        let matrices = R1CSMatrices {
            interner: r1cs.interner,
            a:        r1cs.a,
            b:        r1cs.b,
            c:        r1cs.c,
        };

        let serialized =
            postcard::to_allocvec(&matrices).expect("Failed to serialize R1CS matrices");
        let mut compressed = Vec::new();
        {
            let mut encoder = XzEncoder::new(&mut compressed, 6);
            std::io::Write::write_all(&mut encoder, &serialized)
                .expect("Failed to compress R1CS matrices");
            encoder.finish().expect("Failed to finish XZ compression");
        }

        Self {
            num_public_inputs,
            num_constraints,
            num_witnesses,
            compressed_matrices: compressed,
            cached: OnceLock::new(),
        }
    }

    fn ensure_decompressed(&self) -> &(Interner, SparseMatrix, SparseMatrix, SparseMatrix) {
        self.cached.get_or_init(|| {
            let mut decompressed = Vec::new();
            XzDecoder::new(self.compressed_matrices.as_slice())
                .read_to_end(&mut decompressed)
                .expect("Failed to decompress R1CS matrices");

            let matrices: R1CSMatrices =
                postcard::from_bytes(&decompressed).expect("Failed to deserialize R1CS matrices");

            (matrices.interner, matrices.a, matrices.b, matrices.c)
        })
    }

    /// Free the compressed byte buffer once matrices are cached.
    ///
    /// After the first access the decompressed matrices live in `cached`,
    /// so the compressed blob is dead weight. Call this after the first
    /// access to reclaim ~10 MB for a typical circuit.
    pub fn free_compressed(&mut self) {
        // Ensure decompressed first so cached is populated
        self.ensure_decompressed();
        self.compressed_matrices = Vec::new();
    }

    /// Drop the decompressed matrix cache, keeping only the metadata.
    ///
    /// This is useful after the R1CS matrices are no longer needed
    /// (e.g., after sumcheck and weight extraction are complete).
    /// Reclaims ~200+ MB for large circuits.
    ///
    /// **Warning**: After calling this, `a()`, `b()`, `c()` will
    /// re-decompress from the compressed buffer (if it still exists)
    /// or panic (if `free_compressed` was also called).
    pub fn into_shell(self) -> LazyR1CSShell {
        LazyR1CSShell {
            num_public_inputs: self.num_public_inputs,
            num_constraints:   self.num_constraints,
            num_witnesses:     self.num_witnesses,
        }
    }

    #[must_use]
    pub fn a(&self) -> HydratedSparseMatrix<'_> {
        let (interner, a, ..) = self.ensure_decompressed();
        a.hydrate(interner)
    }

    #[must_use]
    pub fn b(&self) -> HydratedSparseMatrix<'_> {
        let (interner, _, b, _) = self.ensure_decompressed();
        b.hydrate(interner)
    }

    #[must_use]
    pub fn c(&self) -> HydratedSparseMatrix<'_> {
        let (interner, _, _, c) = self.ensure_decompressed();
        c.hydrate(interner)
    }

    #[must_use]
    pub const fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    #[must_use]
    pub const fn num_witnesses(&self) -> usize {
        self.num_witnesses
    }

    /// Reconstruct the full `R1CS` from the compressed data.
    ///
    /// This is useful when the original R1CS structure is needed, e.g. for
    /// JSON serialization in gnark input generation.
    pub fn to_r1cs(&self) -> R1CS {
        let (interner, a, b, c) = self.ensure_decompressed();
        R1CS {
            num_public_inputs: self.num_public_inputs,
            interner:          interner.clone(),
            a:                 a.clone(),
            b:                 b.clone(),
            c:                 c.clone(),
        }
    }
}

/// Lightweight shell that only retains R1CS metadata after matrices are freed.
///
/// Created via [`LazyR1CS::into_shell`]. Use this when you need `num_witnesses`
/// / `num_constraints` but no longer need the actual matrices.
pub struct LazyR1CSShell {
    pub num_public_inputs: usize,
    num_constraints:       usize,
    num_witnesses:         usize,
}

impl LazyR1CSShell {
    #[must_use]
    pub const fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    #[must_use]
    pub const fn num_witnesses(&self) -> usize {
        self.num_witnesses
    }
}

/// Serialization format for LazyR1CS.
#[derive(Serialize, Deserialize)]
struct LazyR1CSSerde {
    num_public_inputs:   usize,
    num_constraints:     usize,
    num_witnesses:       usize,
    compressed_matrices: Vec<u8>,
}

impl Serialize for LazyR1CS {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serde_repr = LazyR1CSSerde {
            num_public_inputs:   self.num_public_inputs,
            num_constraints:     self.num_constraints,
            num_witnesses:       self.num_witnesses,
            compressed_matrices: self.compressed_matrices.clone(),
        };
        serde_repr.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LazyR1CS {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serde_repr = LazyR1CSSerde::deserialize(deserializer)?;
        Ok(Self {
            num_public_inputs:   serde_repr.num_public_inputs,
            num_constraints:     serde_repr.num_constraints,
            num_witnesses:       serde_repr.num_witnesses,
            compressed_matrices: serde_repr.compressed_matrices,
            cached:              OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::FieldElement};

    #[test]
    fn test_lazy_r1cs_roundtrip() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(10);
        r1cs.add_constraint(
            &[(FieldElement::from(1u64), 0), (FieldElement::from(2u64), 1)],
            &[(FieldElement::from(3u64), 2)],
            &[(FieldElement::from(4u64), 3)],
        );

        let lazy = LazyR1CS::from_r1cs(r1cs.clone());

        assert_eq!(lazy.num_constraints(), r1cs.num_constraints());
        assert_eq!(lazy.num_witnesses(), r1cs.num_witnesses());
    }

    #[test]
    fn test_lazy_r1cs_serde() {
        let mut r1cs = R1CS::new();
        r1cs.add_witnesses(10);
        r1cs.add_constraint(
            &[(FieldElement::from(1u64), 0)],
            &[(FieldElement::from(2u64), 1)],
            &[(FieldElement::from(3u64), 2)],
        );

        let lazy = LazyR1CS::from_r1cs(r1cs.clone());

        let serialized = postcard::to_allocvec(&lazy).unwrap();
        let deserialized: LazyR1CS = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(deserialized.num_constraints(), r1cs.num_constraints());
        assert_eq!(deserialized.num_witnesses(), r1cs.num_witnesses());
    }
}
