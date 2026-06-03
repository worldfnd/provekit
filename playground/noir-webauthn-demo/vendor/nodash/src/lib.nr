mod deps {
    pub(crate) use sha256::sha256_var;
}

pub fn sha256<T, let N: u32>(input: T) -> [u8; 32]
where
    T: ArrayOrBoundedVec<u8, N>,
{
    let input = input.as_bounded_vec();
    deps::sha256_var(input.storage(), input.len())
}

trait ArrayOrBoundedVec<T, let N: u32> {
    fn as_bounded_vec(self) -> BoundedVec<T, N>;
}

impl<T, let N: u32> ArrayOrBoundedVec<T, N> for [T; N] {
    fn as_bounded_vec(self) -> BoundedVec<T, N> {
        BoundedVec::from(self)
    }
}

impl<T, let N: u32> ArrayOrBoundedVec<T, N> for BoundedVec<T, N> {
    fn as_bounded_vec(self) -> BoundedVec<T, N> {
        self
    }
}
