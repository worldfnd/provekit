use {ark_ff::Field, whir::algebra::linear_form::LinearForm};

/// A linear form over two equal witness blocks, without a combined allocation.
///
/// The first coordinate selects a block: `L(s, x) = (1 - s) left(x) + s
/// right(x)`. Each missing branch represents the zero linear form.
pub struct JointLinearForm<F: Field> {
    left:        Option<Box<dyn LinearForm<F>>>,
    right:       Option<Box<dyn LinearForm<F>>>,
    domain_size: usize,
}

impl<F: Field> JointLinearForm<F> {
    /// Combine two linear forms with equal domain sizes.
    ///
    /// # Panics
    ///
    /// Panics if sizes differ, a size is not a nonzero power of two, or their
    /// sum overflows.
    #[must_use]
    pub fn new<L: LinearForm<F>, R: LinearForm<F>>(left: L, right: R) -> Self {
        assert_eq!(
            left.size(),
            right.size(),
            "JointLinearForm: branch sizes must match"
        );
        let domain_size = Self::checked_domain_size(left.size());
        Self {
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            domain_size,
        }
    }

    /// Place a linear form in the first block, with a zero second block.
    ///
    /// # Panics
    ///
    /// Panics if the size is not a nonzero power of two or doubling it
    /// overflows.
    #[must_use]
    pub fn left_only<L: LinearForm<F>>(left: L) -> Self {
        let domain_size = Self::checked_domain_size(left.size());
        Self {
            left: Some(Box::new(left)),
            right: None,
            domain_size,
        }
    }

    /// Place a linear form in the second block, with a zero first block.
    ///
    /// # Panics
    ///
    /// Panics if the size is not a nonzero power of two or doubling it
    /// overflows.
    #[must_use]
    pub fn right_only<R: LinearForm<F>>(right: R) -> Self {
        let domain_size = Self::checked_domain_size(right.size());
        Self {
            left: None,
            right: Some(Box::new(right)),
            domain_size,
        }
    }

    fn checked_domain_size(block_size: usize) -> usize {
        assert!(
            block_size.is_power_of_two(),
            "JointLinearForm: block size must be a nonzero power of two"
        );
        block_size
            .checked_mul(2)
            .expect("JointLinearForm: combined domain size overflows")
    }
}

impl<F: Field> LinearForm<F> for JointLinearForm<F> {
    fn size(&self) -> usize {
        self.domain_size
    }

    fn mle_evaluate(&self, point: &[F]) -> F {
        assert_eq!(
            point.len(),
            self.domain_size.trailing_zeros() as usize,
            "JointLinearForm: point dimension must match the combined domain"
        );
        let (selector, rest) = point
            .split_first()
            .expect("the combined domain has two blocks");
        let left = self
            .left
            .as_ref()
            .map_or(F::ZERO, |form| form.mle_evaluate(rest));
        let right = self
            .right
            .as_ref()
            .map_or(F::ZERO, |form| form.mle_evaluate(rest));
        (F::ONE - selector) * left + *selector * right
    }

    fn accumulate(&self, accumulator: &mut [F], scalar: F) {
        assert_eq!(
            accumulator.len(),
            self.domain_size,
            "JointLinearForm: accumulator size must match the combined domain"
        );
        let (left, right) = accumulator.split_at_mut(self.domain_size / 2);
        if let Some(form) = &self.left {
            form.accumulate(left, scalar);
        }
        if let Some(form) = &self.right {
            form.accumulate(right, scalar);
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::PrefixCovector,
        ark_ff::AdditiveGroup,
        whir::algebra::{fields::Field64, multilinear_extend},
    };

    fn field(value: u64) -> Field64 {
        Field64::from(value)
    }

    fn prefix(values: &[u64], block_size: usize) -> PrefixCovector<Field64> {
        PrefixCovector::new(values.iter().copied().map(field).collect(), block_size)
    }

    fn example() -> JointLinearForm<Field64> {
        JointLinearForm::new(prefix(&[2, 4], 2), prefix(&[10, 14], 2))
    }

    #[test]
    fn selector_zero_reads_the_first_block_and_selector_one_reads_the_second_block() {
        let form = example();

        // At x = 3, the first block evaluates to 8, and the second evaluates to 22.
        assert_eq!(form.size(), 4);
        assert_eq!(form.mle_evaluate(&[field(0), field(3)]), field(8));
        assert_eq!(form.mle_evaluate(&[field(1), field(3)]), field(22));
    }

    #[test]
    fn non_boolean_selector_uses_the_same_linear_combination() {
        let form = example();

        // At s = 2 and x = 3, the result is (1 - 2) * 8 + 2 * 22 = 36.
        assert_eq!(form.mle_evaluate(&[field(2), field(3)]), field(36));
    }

    #[test]
    fn joint_evaluation_matches_the_dense_vector_at_every_boolean_point() {
        let form = JointLinearForm::new(prefix(&[2, 3, 5, 7], 4), prefix(&[11, 13, 17, 19], 4));
        let dense: Vec<_> = [2, 3, 5, 7, 11, 13, 17, 19].map(field).into();

        for index in 0..8 {
            let point = [
                field((index >> 2) & 1),
                field((index >> 1) & 1),
                field(index & 1),
            ];
            assert_eq!(
                form.mle_evaluate(&point),
                dense[index as usize],
                "index {index}"
            );
            assert_eq!(
                form.mle_evaluate(&point),
                multilinear_extend(&dense, &point)
            );
        }
    }

    #[test]
    fn joint_evaluation_matches_the_dense_vector_at_non_boolean_points() {
        let form = JointLinearForm::new(prefix(&[2, 3, 5, 7], 4), prefix(&[11, 13, 17, 19], 4));
        let dense: Vec<_> = [2, 3, 5, 7, 11, 13, 17, 19].map(field).into();

        for point in [[2, 3, 5], [7, 11, 13], [17, 19, 23]] {
            let point = point.map(field);
            assert_eq!(
                form.mle_evaluate(&point),
                multilinear_extend(&dense, &point)
            );
        }
    }

    #[test]
    fn unequal_prefix_lengths_have_separate_zero_padding() {
        let form = JointLinearForm::new(prefix(&[2, 3, 5, 7], 4), prefix(&[11, 13], 4));
        let dense: Vec<_> = [2, 3, 5, 7, 11, 13, 0, 0].map(field).into();
        let mut actual = vec![Field64::ZERO; 8];
        form.accumulate(&mut actual, Field64::ONE);

        assert_eq!(actual, dense);
        for point in [[0, 1, 1], [1, 1, 1], [2, 3, 5]] {
            let point = point.map(field);
            assert_eq!(
                form.mle_evaluate(&point),
                multilinear_extend(&dense, &point)
            );
        }

        // Swapping the blocks preserves each block's padding.
        let swapped = JointLinearForm::new(prefix(&[11, 13], 4), prefix(&[2, 3, 5, 7], 4));
        let mut actual = vec![Field64::ZERO; 8];
        swapped.accumulate(&mut actual, Field64::ONE);
        assert_eq!(actual, [11, 13, 0, 0, 2, 3, 5, 7].map(field));
    }

    #[test]
    fn accumulation_adds_scaled_weights_to_existing_values() {
        let form = example();
        let mut accumulator = [100, 200, 300, 400].map(field);

        form.accumulate(&mut accumulator, field(3));

        assert_eq!(accumulator, [106, 212, 330, 442].map(field));
        form.accumulate(&mut accumulator, Field64::ZERO);
        assert_eq!(accumulator, [106, 212, 330, 442].map(field));
    }

    #[test]
    fn one_branch_forms_leave_the_other_block_unchanged() {
        let left = JointLinearForm::left_only(prefix(&[2, 4], 2));
        let right = JointLinearForm::right_only(prefix(&[10, 14], 2));
        let point = [field(2), field(3)];

        assert_eq!(left.mle_evaluate(&point), -field(8));
        assert_eq!(right.mle_evaluate(&point), field(44));

        let mut left_accumulator = [100, 200, 300, 400].map(field);
        left.accumulate(&mut left_accumulator, field(3));
        assert_eq!(left_accumulator, [106, 212, 300, 400].map(field));

        let mut right_accumulator = [100, 200, 300, 400].map(field);
        right.accumulate(&mut right_accumulator, field(3));
        assert_eq!(right_accumulator, [100, 200, 330, 442].map(field));
    }

    #[test]
    fn one_entry_blocks_need_only_the_selector_coordinate() {
        let form = JointLinearForm::new(prefix(&[2], 1), prefix(&[10], 1));
        assert_eq!(form.mle_evaluate(&[field(3)]), field(26));
    }

    // This form checks sizes without allocating a witness or weight vector.
    struct SizeOnly(usize);

    impl LinearForm<Field64> for SizeOnly {
        fn size(&self) -> usize {
            self.0
        }

        fn mle_evaluate(&self, _point: &[Field64]) -> Field64 {
            unreachable!()
        }

        fn accumulate(&self, _accumulator: &mut [Field64], _scalar: Field64) {
            unreachable!()
        }
    }

    #[test]
    #[should_panic(expected = "branch sizes must match")]
    fn construction_rejects_different_block_sizes() {
        let _ = JointLinearForm::new(SizeOnly(2), SizeOnly(4));
    }

    #[test]
    #[should_panic(expected = "block size must be a nonzero power of two")]
    fn construction_rejects_zero_block_size() {
        let _ = JointLinearForm::left_only(SizeOnly(0));
    }

    #[test]
    #[should_panic(expected = "block size must be a nonzero power of two")]
    fn construction_rejects_non_power_of_two_block_size() {
        let _ = JointLinearForm::right_only(SizeOnly(3));
    }

    #[test]
    #[should_panic(expected = "combined domain size overflows")]
    fn construction_rejects_combined_size_overflow() {
        let _ = JointLinearForm::left_only(SizeOnly(1 << (usize::BITS - 1)));
    }

    #[test]
    #[should_panic(expected = "point dimension must match the combined domain")]
    fn evaluation_rejects_a_missing_selector_coordinate() {
        example().mle_evaluate(&[field(3)]);
    }

    #[test]
    #[should_panic(expected = "point dimension must match the combined domain")]
    fn evaluation_rejects_extra_coordinates() {
        example().mle_evaluate(&[field(2), field(3), field(5)]);
    }

    #[test]
    #[should_panic(expected = "accumulator size must match the combined domain")]
    fn accumulation_rejects_a_short_accumulator() {
        example().accumulate(&mut [Field64::ZERO; 3], Field64::ONE);
    }

    #[test]
    #[should_panic(expected = "accumulator size must match the combined domain")]
    fn accumulation_rejects_a_long_accumulator() {
        example().accumulate(&mut [Field64::ZERO; 5], Field64::ONE);
    }
}
