pub trait ConstraintSink {
    /// Add an R1CS constraint.
    fn add_constraint(
        &mut self,
        a: &[(FieldElement, usize)],
        b: &[(FieldElement, usize)],
        c: &[(FieldElement, usize)],
    );
}
