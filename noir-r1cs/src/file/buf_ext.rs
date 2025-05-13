use bytes::Buf;

/// Helper trait for [`bytes::Buf`]
pub trait BufExt {
    fn get_bytes<const N: usize>(&mut self) -> [u8; N];
}

impl<T: Buf> BufExt for T {
    fn get_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut buffer = [0; N];
        self.copy_to_slice(&mut buffer);
        buffer
    }
}
