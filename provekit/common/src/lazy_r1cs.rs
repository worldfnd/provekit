use {
    crate::{HydratedSparseMatrix, Interner, SparseMatrix, R1CS},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    std::{io::Read, sync::OnceLock},
};

/// Matrices data that gets compressed/decompressed lazily
#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1CSMatrices {
    interner: Interner,
    a:        SparseMatrix,
    b:        SparseMatrix,
    c:        SparseMatrix,
}

/// A lazily-decompressed R1CS constraint system.
///
/// Stores the R1CS matrices in zstd-compressed form and only decompresses
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
    /// Create a LazyR1CS from an existing R1CS by compressing its matrices.
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
        let compressed = zstd::encode_all(serialized.as_slice(), zstd::DEFAULT_COMPRESSION_LEVEL)
            .expect("Failed to compress R1CS matrices");

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
            zstd::Decoder::new(self.compressed_matrices.as_slice())
                .expect("Failed to create zstd decoder")
                .read_to_end(&mut decompressed)
                .expect("Failed to decompress R1CS matrices");

            let matrices: R1CSMatrices =
                postcard::from_bytes(&decompressed).expect("Failed to deserialize R1CS matrices");

            (matrices.interner, matrices.a, matrices.b, matrices.c)
        })
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

    /// Convert to a full R1CS by decompressing if needed.
    /// This consumes the LazyR1CS.
    pub fn into_r1cs(self) -> R1CS {
        if let Some((interner, a, b, c)) = self.cached.into_inner() {
            R1CS {
                num_public_inputs: self.num_public_inputs,
                interner,
                a,
                b,
                c,
            }
        } else {
            let mut decompressed = Vec::new();
            zstd::Decoder::new(self.compressed_matrices.as_slice())
                .expect("Failed to create zstd decoder")
                .read_to_end(&mut decompressed)
                .expect("Failed to decompress R1CS matrices");

            let matrices: R1CSMatrices =
                postcard::from_bytes(&decompressed).expect("Failed to deserialize R1CS matrices");

            R1CS {
                num_public_inputs: self.num_public_inputs,
                interner:          matrices.interner,
                a:                 matrices.a,
                b:                 matrices.b,
                c:                 matrices.c,
            }
        }
    }

    /// Get a reference to the underlying R1CS, decompressing if needed.
    /// Returns the interner and matrices separately for efficiency.
    pub fn get_matrices(&self) -> (&Interner, &SparseMatrix, &SparseMatrix, &SparseMatrix) {
        let (interner, a, b, c) = self.ensure_decompressed();
        (interner, a, b, c)
    }
}

/// Serialization format for LazyR1CS
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

        let recovered = lazy.into_r1cs();
        assert_eq!(recovered.num_constraints(), r1cs.num_constraints());
        assert_eq!(recovered.num_witnesses(), r1cs.num_witnesses());
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
