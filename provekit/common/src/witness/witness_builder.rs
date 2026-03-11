use {
    crate::{
        utils::{serde_ark, serde_ark_option},
        witness::{
            digits::DigitalDecompositionWitnesses,
            ram::SpiceWitnesses,
            scheduling::{
                LayerScheduler, LayeredWitnessBuilders, SplitError, SplitWitnessBuilders,
                WitnessIndexRemapper, WitnessSplitter,
            },
            ConstantOrR1CSWitness,
        },
        FieldElement, R1CS,
    },
    serde::{Deserialize, Serialize},
    std::{collections::HashSet, num::NonZeroU32},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SumTerm(
    #[serde(with = "serde_ark_option")] pub Option<FieldElement>,
    pub usize,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantTerm(pub usize, #[serde(with = "serde_ark")] pub FieldElement);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessCoefficient(#[serde(with = "serde_ark")] pub FieldElement, pub usize);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductLinearTerm(
    pub usize,
    #[serde(with = "serde_ark")] pub FieldElement,
    #[serde(with = "serde_ark")] pub FieldElement,
);

/// Data for combined table entry inverse computation.
/// Computes: 1 / (sz - lhs - rs*rhs - rs²*and_out - rs³*xor_out)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CombinedTableEntryInverseData {
    pub idx:          usize,
    pub sz_challenge: usize,
    pub rs_challenge: usize,
    pub rs_sqrd:      usize,
    pub rs_cubed:     usize,
    #[serde(with = "serde_ark")]
    pub lhs:          FieldElement,
    #[serde(with = "serde_ark")]
    pub rhs:          FieldElement,
    #[serde(with = "serde_ark")]
    pub and_out:      FieldElement,
    #[serde(with = "serde_ark")]
    pub xor_out:      FieldElement,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Indicates how to solve for a collection of R1CS witnesses in terms of
/// earlier (i.e. already solved for) R1CS witnesses and/or ACIR witness values.
pub enum WitnessBuilder {
    /// Constant value, used for the constant one witness & e.g. static lookups
    /// (witness index, constant value)
    Constant(ConstantTerm),
    /// A witness value carried over from the ACIR circuit (at the specified
    /// ACIR witness index) (includes ACIR inputs and outputs)
    /// (witness index, ACIR witness index)
    Acir(usize, usize),
    /// A linear combination of witness values, where the coefficients are field
    /// elements. First argument is the witness index of the sum.
    /// Vector consists of (optional coefficient, witness index) tuples, one for
    /// each summand. The coefficient is optional, and if it is None, the
    /// coefficient is 1.
    Sum(usize, Vec<SumTerm>),
    /// The product of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    Product(usize, usize, usize),
    /// Solves for the number of times that each memory address occurs in
    /// read-only memory. Arguments: (first witness index, range size,
    /// vector of all witness indices for values purported to be in the range)
    MultiplicitiesForRange(usize, usize, Vec<usize>),
    /// A Fiat-Shamir challenge value
    /// (witness index)
    Challenge(usize),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index),
    /// rs_challenge, value).
    IndexedLogUpDenominator(usize, usize, WitnessCoefficient, usize, usize),
    /// The inverse of the value at a specified witness index
    /// (witness index, operand witness index)
    Inverse(usize, usize),
    /// Safe inverse: like Inverse but handles zero by outputting 0.
    /// Used by compute_is_zero where the input may be zero. Solved in the
    /// Other layer (not batch-inverted), so zero inputs don't poison the batch.
    /// (witness index, operand witness index)
    SafeInverse(usize, usize),
    /// The modular inverse of the value at a specified witness index, modulo
    /// a given prime modulus. Computes a^{-1} mod m using Fermat's little
    /// theorem (a^{m-2} mod m). Unlike Inverse (BN254 field inverse), this
    /// operates as integer modular arithmetic.
    /// (witness index, operand witness index, modulus)
    ModularInverse(usize, usize, #[serde(with = "serde_ark")] FieldElement),
    /// The integer quotient floor(dividend / divisor). Used by reduce_mod to
    /// compute k = floor(v / m) so that v = k*m + result with 0 <= result < m.
    /// Unlike field multiplication by the inverse, this performs true integer
    /// division on the BigInteger representation.
    /// (witness index, dividend witness index, divisor constant)
    IntegerQuotient(usize, usize, #[serde(with = "serde_ark")] FieldElement),
    /// Products with linear operations on the witness indices.
    /// Fields are ProductLinearOperation(witness_idx, (index, a, b), (index, c,
    /// d)) such that we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(usize, ProductLinearTerm, ProductLinearTerm),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (witness index, sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, usize, WitnessCoefficient),
    /// For solving for the inverse of a lookup denominator directly.
    /// Computes 1/(sz_challenge - value_coeff * value).
    /// Fields are (witness index, sz_challenge, (value_coeff, value)).
    LogUpInverse(usize, usize, WitnessCoefficient),
    /// Builds the witnesses values required for the mixed base digital
    /// decomposition of other witness values.
    DigitalDecomposition(DigitalDecompositionWitnesses),
    /// A factor of the multiset check used in read/write memory checking.
    /// Values: (witness index, sz_challenge, rs_challenge, (addr,
    /// addr_witness), value, (timer, timer_witness)) where sz_challenge,
    /// rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes:
    /// sz_challenge - (addr * addr_witness + rs_challenge * value +
    /// rs_challenge * rs_challenge * timer * timer_witness)
    SpiceMultisetFactor(
        usize,
        usize,
        usize,
        WitnessCoefficient,
        usize,
        WitnessCoefficient,
    ),
    /// Splits an 8-bit witness into two parts at a given bit boundary.
    /// Builds witnesses `lo` and `hi` such that: x = lo + hi * 2^k
    /// where `lo` contains the lower `k` bits and `hi` contains the remaining
    /// upper bits. Used for byte-level rotations and shifts.
    BytePartition {
        lo: usize,
        hi: usize,
        x:  usize,
        k:  u8,
    },
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR
    /// solver.)
    SpiceWitnesses(SpiceWitnesses),
    /// A witness value for the denominator of a bin op lookup.
    /// Arguments: `(witness index, sz_challenge, rs_challenge,
    /// rs_challenge_sqrd, lhs, rhs, output)`, where `lhs`, `rhs`, and
    /// `output` are either constant or witness values.
    BinOpLookupDenominator(
        usize,
        usize,
        usize,
        usize,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
    ),
    /// A witness value for the denominator of a combined AND/XOR lookup.
    /// Uses encoding: sz - (lhs + rs*rhs + rs²*and_out + rs³*xor_out)
    /// Arguments: `(witness index, sz_challenge, rs_challenge, rs_sqrd,
    /// rs_cubed, lhs, rhs, and_output, xor_output)`.
    CombinedBinOpLookupDenominator(
        usize,
        usize,
        usize,
        usize,
        usize,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
    ),
    /// Witness values for the number of times that each pair of input values
    /// occurs in the bin op.
    /// Arguments: (first_witness_idx, atomic_bits, pairs)
    /// The table has 2^(2*atomic_bits) entries.
    MultiplicitiesForBinOp(
        usize,
        u32,
        Vec<(ConstantOrR1CSWitness, ConstantOrR1CSWitness)>,
    ),
    /// U32 addition with carry: computes result = (a + b) % 2^32 and carry = (a
    /// + b) / 2^32. Arguments: (result_witness_index, carry_witness_index, a,
    ///   b)
    U32Addition(usize, usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
    /// Variadic 32-bit addition with carry.
    ///   Computes: result = (sum of inputs) mod 2^32, carry  = floor((sum of
    /// inputs) / 2^32) Inputs may be witnesses or constants. This is more
    /// efficient than chaining pairwise U32 additions, as it introduces
    /// only one carry and one modulo constraint.
    U32AdditionMulti(usize, usize, Vec<ConstantOrR1CSWitness>),
    /// AND operation: computes result = a & b
    /// Arguments: (result_witness_index, a, b)
    /// Note: only for 32-bit operands
    And(usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
    /// XOR operation: computes result = a ⊕ b
    /// Arguments: (result_witness_index, a, b)
    /// Note: only for 32-bit operands
    Xor(usize, ConstantOrR1CSWitness, ConstantOrR1CSWitness),
    /// Inverse of combined lookup table entry denominator (constant operands).
    /// Computes: 1 / (sz - lhs - rs*rhs - rs²*and_out - rs³*xor_out)
    CombinedTableEntryInverse(CombinedTableEntryInverseData),
    /// Prover hint for multi-limb modular multiplication: (a * b) mod p.
    /// Given inputs a and b as N-limb vectors (each limb `limb_bits` wide),
    /// and a constant 256-bit modulus p, computes quotient q, remainder r,
    /// and carry witnesses for schoolbook column verification.
    ///
    /// Outputs (4*num_limbs - 2) witnesses starting at output_start:
    ///   [0..N)        q limbs (quotient)
    ///   [N..2N)       r limbs (remainder) — OUTPUT
    ///   [2N..4N-2)    carry witnesses (unsigned-offset)
    MultiLimbMulModHint {
        output_start: usize,
        a_limbs:      Vec<usize>,
        b_limbs:      Vec<usize>,
        modulus:      [u64; 4],
        limb_bits:    u32,
        num_limbs:    u32,
    },
    /// Prover hint for multi-limb modular inverse: a^{-1} mod p.
    /// Given input a as N-limb vector and constant modulus p,
    /// computes the inverse via Fermat's little theorem (a^{p-2} mod p).
    ///
    /// Outputs num_limbs witnesses at output_start: inv limbs.
    MultiLimbModularInverse {
        output_start: usize,
        a_limbs:      Vec<usize>,
        modulus:      [u64; 4],
        limb_bits:    u32,
        num_limbs:    u32,
    },
    /// Prover hint for multi-limb addition quotient: q = floor((a + b) / p).
    /// Given inputs a and b as N-limb vectors, and a constant modulus p,
    /// computes q ∈ {0, 1}.
    ///
    /// Outputs 1 witness at output: q.
    MultiLimbAddQuotient {
        output:    usize,
        a_limbs:   Vec<usize>,
        b_limbs:   Vec<usize>,
        modulus:   [u64; 4],
        limb_bits: u32,
        num_limbs: u32,
    },
    /// Prover hint for multi-limb subtraction borrow: q = (a < b) ? 1 : 0.
    /// Given inputs a and b as N-limb vectors, and a constant modulus p,
    /// computes q ∈ {0, 1} indicating whether a borrow (adding p) is needed.
    ///
    /// Outputs 1 witness at output: q.
    MultiLimbSubBorrow {
        output:    usize,
        a_limbs:   Vec<usize>,
        b_limbs:   Vec<usize>,
        modulus:   [u64; 4],
        limb_bits: u32,
        num_limbs: u32,
    },
    /// Decomposes a packed value into chunks of specified bit-widths.
    /// Given packed value and chunk_bits = [b0, b1, ..., bn]:
    ///   packed = c0 + c1 * 2^b0 + c2 * 2^(b0+b1) + ...
    /// Writes chunk values to output_start..output_start+chunk_bits.len()
    ChunkDecompose {
        output_start: usize,
        packed:       usize,
        chunk_bits:   Vec<u32>,
    },
    /// Prover hint for FakeGLV scalar decomposition.
    /// Given scalar s (from s_lo + s_hi * 2^128) and curve order n,
    /// computes half_gcd(s, n) → (|s1|, |s2|, neg1, neg2) such that:
    ///   (-1)^neg1 * |s1| + (-1)^neg2 * |s2| * s ≡ 0 (mod n)
    ///
    /// Outputs 4 witnesses starting at output_start:
    ///   \[0\] |s1| (128-bit field element)
    ///   \[1\] |s2| (128-bit field element)
    ///   \[2\] neg1 (boolean: 0 or 1)
    ///   \[3\] neg2 (boolean: 0 or 1)
    FakeGLVHint {
        output_start: usize,
        s_lo:         usize,
        s_hi:         usize,
        curve_order:  [u64; 4],
    },
    /// Prover hint for EC scalar multiplication: computes R = \[s\]P.
    /// Given point P = (px, py) and scalar s = s_lo + s_hi * 2^128,
    /// computes R = \[s\]P on the curve with parameter `curve_a` and
    /// field modulus `field_modulus_p`.
    ///
    /// Outputs 2 witnesses at output_start: R_x, R_y.
    EcScalarMulHint {
        output_start:    usize,
        px:              usize,
        py:              usize,
        s_lo:            usize,
        s_hi:            usize,
        curve_a:         [u64; 4],
        field_modulus_p: [u64; 4],
    },
    /// Prover hint for EC point doubling on native field.
    /// Given P = (px, py) and curve parameter `a`, computes:
    ///   lambda = (3*px^2 + a) / (2*py) mod p
    ///   x3 = lambda^2 - 2*px mod p
    ///   y3 = lambda * (px - x3) - py mod p
    ///
    /// Outputs 3 witnesses at output_start: lambda, x3, y3.
    EcDoubleHint {
        output_start:    usize,
        px:              usize,
        py:              usize,
        curve_a:         [u64; 4],
        field_modulus_p: [u64; 4],
    },
    /// Prover hint for EC point addition on native field.
    /// Given P1 = (x1, y1) and P2 = (x2, y2), computes:
    ///   lambda = (y2 - y1) / (x2 - x1) mod p
    ///   x3 = lambda^2 - x1 - x2 mod p
    ///   y3 = lambda * (x1 - x3) - y1 mod p
    ///
    /// Outputs 3 witnesses at output_start: lambda, x3, y3.
    EcAddHint {
        output_start:    usize,
        x1:              usize,
        y1:              usize,
        x2:              usize,
        y2:              usize,
        field_modulus_p: [u64; 4],
    },
    /// Conditional select: output = on_false + flag * (on_true - on_false).
    /// When flag=0, output=on_false; when flag=1, output=on_true.
    /// (output, flag, on_false, on_true)
    SelectWitness {
        output:   usize,
        flag:     usize,
        on_false: usize,
        on_true:  usize,
    },
    /// Boolean OR: output = a + b - a*b = 1 - (1-a)*(1-b).
    /// (output, a, b)
    BooleanOr {
        output: usize,
        a:      usize,
        b:      usize,
    },
    /// Signed-bit decomposition hint for wNAF scalar multiplication.
    /// Given scalar s with num_bits bits, computes sign-bits b_0..b_{n-1}
    /// and skew ∈ {0,1} such that:
    ///   s + skew + (2^n - 1) = Σ b_i * 2^{i+1}
    /// where d_i = 2*b_i - 1 ∈ {-1, +1}.
    ///
    /// Outputs (num_bits + 1) witnesses at output_start:
    ///   [0..num_bits)  b_i sign bits
    ///   [num_bits]     skew (0 if s is odd, 1 if s is even)
    SignedBitHint {
        output_start: usize,
        scalar:       usize,
        num_bits:     usize,
    },
    /// Computes spread(input): interleave bits with zeros.
    /// Output: 0 b_{n-1} 0 b_{n-2} ... 0 b_1 0 b_0
    /// (witness index of output, witness index of input)
    SpreadWitness(usize, usize),
    /// Extracts even or odd bits from a spread sum, decomposed into
    /// byte-sized chunks. Even bits = XOR result, Odd bits = MAJ/AND
    /// result. The sum is computed inline from the provided terms,
    /// avoiding a separate witness allocation.
    SpreadBitExtract {
        output_start: usize,
        chunk_bits:   Vec<u32>,
        sum_terms:    Vec<SumTerm>,
        extract_even: bool,
    },
    /// Spread table multiplicities: counts how many times each input
    /// value appears in the query set.
    /// (first_witness_idx, num_bits, query_input_values)
    /// Table size = 2^num_bits.
    MultiplicitiesForSpread(usize, u32, Vec<ConstantOrR1CSWitness>),
    /// Query-side LogUp denominator for spread table.
    /// Computes: sz - (input + rs * spread_output)
    /// (idx, sz, rs, input, spread_output)
    SpreadLookupDenominator(
        usize,
        usize,
        usize,
        ConstantOrR1CSWitness,
        ConstantOrR1CSWitness,
    ),
    /// Table-side LogUp quotient for spread table.
    /// Computes: multiplicity / (sz - input_val - rs * spread_val)
    SpreadTableQuotient {
        idx:          usize,
        sz:           usize,
        rs:           usize,
        #[serde(with = "serde_ark")]
        input_val:    FieldElement,
        #[serde(with = "serde_ark")]
        spread_val:   FieldElement,
        multiplicity: usize,
    },
}

impl WitnessBuilder {
    /// The number of witness values that this builder writes to the witness
    /// vector.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::MultiplicitiesForRange(_, range_size, _) => *range_size,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.num_witnesses,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.num_witnesses
            }
            WitnessBuilder::MultiplicitiesForBinOp(_, atomic_bits, ..) => {
                2usize.pow(2 * *atomic_bits)
            }
            WitnessBuilder::U32Addition(..) => 2,
            WitnessBuilder::U32AdditionMulti(..) => 2,
            WitnessBuilder::BytePartition { .. } => 2,
            WitnessBuilder::ChunkDecompose { chunk_bits, .. } => chunk_bits.len(),
            WitnessBuilder::SpreadBitExtract { chunk_bits, .. } => chunk_bits.len(),
            WitnessBuilder::MultiplicitiesForSpread(_, num_bits, _) => 1usize << *num_bits,
            WitnessBuilder::MultiLimbMulModHint { num_limbs, .. } => (4 * *num_limbs - 2) as usize,
            WitnessBuilder::MultiLimbModularInverse { num_limbs, .. } => *num_limbs as usize,
            WitnessBuilder::SignedBitHint { num_bits, .. } => *num_bits + 1,
            WitnessBuilder::EcDoubleHint { .. } => 3,
            WitnessBuilder::EcAddHint { .. } => 3,
            WitnessBuilder::FakeGLVHint { .. } => 4,
            WitnessBuilder::EcScalarMulHint { .. } => 2,

            _ => 1,
        }
    }

    /// Constructs a layered execution plan optimized for batch inversion.
    ///
    /// Uses frontier-based scheduling to group operations and minimize
    /// expensive field inversions via Montgomery's batch inversion trick.
    pub fn prepare_layers(witness_builders: &[WitnessBuilder]) -> LayeredWitnessBuilders {
        if witness_builders.is_empty() {
            return LayeredWitnessBuilders { layers: Vec::new() };
        }

        let scheduler = LayerScheduler::new(witness_builders);
        scheduler.build_layers()
    }

    /// Splits witness builders into w1/w2, remaps indices, and schedules both
    /// groups.
    ///
    /// This enables sound challenge generation:
    /// 1. Split builders: w1 = transitive deps of lookups, w2 = challenges +
    ///    dependents
    /// 2. Remap witness indices: w1 → [0, k), w2 → [k, n)
    /// 3. Remap R1CS matrices and ACIR witness map
    /// 4. Schedule both groups with batch inversions
    ///
    /// Returns (SplitWitnessBuilders, remapped R1CS, remapped witness
    /// map)
    pub fn split_and_prepare_layers(
        witness_builders: &[WitnessBuilder],
        r1cs: R1CS,
        witness_map: Vec<Option<NonZeroU32>>,
        acir_public_inputs_indices_set: HashSet<u32>,
    ) -> Result<(SplitWitnessBuilders, R1CS, Vec<Option<NonZeroU32>>, usize), SplitError> {
        if witness_builders.is_empty() {
            return Ok((
                SplitWitnessBuilders {
                    w1_layers: LayeredWitnessBuilders { layers: Vec::new() },
                    w2_layers: LayeredWitnessBuilders { layers: Vec::new() },
                    w1_size:   0,
                },
                r1cs,
                witness_map,
                0,
            ));
        }

        // Step 1: Analyze dependencies and split into w1/w2
        let splitter = WitnessSplitter::new(witness_builders);
        let (w1_indices, w2_indices) = splitter.split_builders(acir_public_inputs_indices_set)?;

        // Step 2: Extract w1 and w2 builders in order
        let w1_builders: Vec<WitnessBuilder> = w1_indices
            .iter()
            .map(|&idx| witness_builders[idx].clone())
            .collect();

        let w2_builders: Vec<WitnessBuilder> = w2_indices
            .iter()
            .map(|&idx| witness_builders[idx].clone())
            .collect();

        // Step 3: Create witness index remapper
        let remapper = WitnessIndexRemapper::new(&w1_builders, &w2_builders);
        let w1_size = remapper.w1_size;

        // Step 4: Remap all builders
        let remapped_w1_builders: Vec<WitnessBuilder> = w1_builders
            .iter()
            .map(|b| remapper.remap_builder(b))
            .collect();

        let remapped_w2_builders: Vec<WitnessBuilder> = w2_builders
            .iter()
            .map(|b| remapper.remap_builder(b))
            .collect();

        // Step 5: Remap R1CS and witness map
        let remapped_r1cs = remapper.remap_r1cs(r1cs);
        let remapped_witness_map = remapper.remap_acir_witness_map(witness_map);

        // Step 6: Schedule both groups independently with batch inversions
        let w1_layers = if remapped_w1_builders.is_empty() {
            LayeredWitnessBuilders { layers: Vec::new() }
        } else {
            let scheduler = LayerScheduler::new(&remapped_w1_builders);
            scheduler.build_layers()
        };

        let w2_layers = if remapped_w2_builders.is_empty() {
            LayeredWitnessBuilders { layers: Vec::new() }
        } else {
            let scheduler = LayerScheduler::new(&remapped_w2_builders);
            scheduler.build_layers()
        };

        let num_challenges = w2_layers
            .layers
            .iter()
            .flat_map(|layer| &layer.witness_builders)
            .filter(|b| matches!(b, WitnessBuilder::Challenge(_)))
            .count();

        Ok((
            SplitWitnessBuilders {
                w1_layers,
                w2_layers,
                w1_size,
            },
            remapped_r1cs,
            remapped_witness_map,
            num_challenges,
        ))
    }
}
