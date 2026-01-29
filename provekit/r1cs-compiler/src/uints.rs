use {
    crate::{
        digits::{add_digital_decomposition, DigitalDecompositionWitnessesBuilder},
        noir_to_r1cs::NoirToR1CSCompiler,
    },
    ark_ff::{AdditiveGroup, Field},
    provekit_common::{
        witness::{ConstantTerm, SumTerm, WitnessBuilder},
        FieldElement,
    },
    std::collections::{BTreeMap, HashMap},
};

/// A single-byte witness.
/// Represents a value intended to be in the range [0, 255].
#[derive(Clone, Copy, Debug)]
pub(crate) struct U8 {
    /// Index of the underlying R1CS witness
    pub(crate) idx:           usize,
    /// Whether this witness is already constrained to be a valid byte
    pub(crate) range_checked: bool,
}

impl U8 {
    /// Constructs a U8 wrapper around an existing witness.
    /// Caller is responsible for correctly setting `range_checked`.
    pub(crate) fn new(idx: usize, range_checked: bool) -> Self {
        Self { idx, range_checked }
    }

    /// Creates a constant zero byte.
    /// Adds a constraint to enforce the value is zero.
    pub(crate) fn zero(r1cs_compiler: &mut NoirToR1CSCompiler) -> Self {
        let idx = r1cs_compiler.num_witnesses();
        r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(
            idx,
            FieldElement::ZERO,
        )));
        Self {
            idx,
            range_checked: true,
        }
    }

    /// Creates a constant byte with the given value.
    /// Adds a constraint to enforce the value.
    pub(crate) fn from_const(r1cs_compiler: &mut NoirToR1CSCompiler, value: u8) -> Self {
        let idx = r1cs_compiler.num_witnesses();
        let value_fe = FieldElement::from(value as u64);
        r1cs_compiler.add_witness_builder(WitnessBuilder::Constant(ConstantTerm(idx, value_fe)));

        Self {
            idx,
            range_checked: true,
        }
    }
}

/// A 32-bit word represented as four little-endian bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct U32 {
    pub(crate) bytes: [U8; 4],
}

impl U32 {
    /// Constructs a U32 from four byte witnesses.
    pub(crate) fn new(bytes: [U8; 4]) -> Self {
        Self { bytes }
    }

    /// Decomposes a field element witness into four bytes.
    /// Uses digital decomposition with base 2^8 and enforces
    /// byte-range constraints on each resulting digit.
    pub(crate) fn unpack_u32(
        r1cs_compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        word: usize,
    ) -> U32 {
        let log_bases = vec![8usize; 4];
        let dd = add_digital_decomposition(r1cs_compiler, log_bases, vec![word]);

        let bytes = (0..4)
            .map(|i| {
                let idx = dd.get_digit_witness_index(i, 0);
                range_checks.entry(8).or_default().push(idx);
                U8::new(idx, true)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        U32::new(bytes)
    }

    /// Packs four bytes into a single field element:
    /// value = b0 + 256*b1 + 256^2*b2 + 256^3*b3
    pub(crate) fn pack(
        &self,
        r1cs_compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
    ) -> usize {
        let idx = r1cs_compiler.num_witnesses();

        let mut terms = vec![];
        let mut constraint_terms = vec![];
        let mut multiplier = FieldElement::ONE;

        for byte in self.bytes {
            terms.push(SumTerm(Some(multiplier), byte.idx));
            constraint_terms.push((multiplier, byte.idx));
            multiplier *= FieldElement::from(256u64);
        }

        r1cs_compiler.add_witness_builder(WitnessBuilder::Sum(idx, terms));

        // Constraint: idx = b0 + 256*b1 + 256^2*b2 + 256^3*b3
        r1cs_compiler.r1cs.add_constraint(
            &constraint_terms,
            &[(FieldElement::ONE, r1cs_compiler.witness_one())],
            &[(FieldElement::ONE, idx)],
        );

        // Only range-check the packed U32 if any byte is not already range-checked
        if !self.bytes.iter().all(|b| b.range_checked) {
            range_checks.entry(32).or_default().push(idx);
        }
        idx
    }

    /// Packs four bytes into a single field element, using a cache to avoid
    /// repacking. The cache key is the tuple of 4 byte witness indices.
    pub(crate) fn pack_cached(
        &self,
        r1cs_compiler: &mut NoirToR1CSCompiler,
        range_checks: &mut BTreeMap<u32, Vec<usize>>,
        pack_cache: &mut HashMap<[usize; 4], usize>,
    ) -> usize {
        let key = [
            self.bytes[0].idx,
            self.bytes[1].idx,
            self.bytes[2].idx,
            self.bytes[3].idx,
        ];
        if let Some(&cached_idx) = pack_cache.get(&key) {
            return cached_idx;
        }
        let idx = self.pack(r1cs_compiler, range_checks);
        pack_cache.insert(key, idx);
        idx
    }

    /// Constructs a constant 32-bit word.
    /// Each byte is created independently and is trivially in range.
    pub(crate) fn from_const(r1cs_compiler: &mut NoirToR1CSCompiler, value: u32) -> Self {
        let bytes = [
            U8::from_const(r1cs_compiler, (value & 0xff) as u8),
            U8::from_const(r1cs_compiler, ((value >> 8) & 0xff) as u8),
            U8::from_const(r1cs_compiler, ((value >> 16) & 0xff) as u8),
            U8::from_const(r1cs_compiler, ((value >> 24) & 0xff) as u8),
        ];
        Self { bytes }
    }
}
