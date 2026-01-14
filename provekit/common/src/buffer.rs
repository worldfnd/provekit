//! Stack-allocated buffer for efficient serialization without heap allocation.
//!
//! This module provides a fixed-size buffer that implements `std::io::Write`,
//! useful for serializing small amounts of data (e.g., Merkle tree leaves)
//! without the overhead of heap allocation.

use std::io::Write;

/// A stack-allocated buffer with a fixed capacity.
///
/// This buffer is optimized for serializing data that fits within `SIZE` bytes.
/// It avoids heap allocation for common cases like Merkle tree leaf hashing,
/// where the input size is typically small and bounded.
///
/// # Type Parameters
/// * `SIZE` - The fixed capacity of the buffer in bytes.
///
/// # Example
/// ```ignore
/// use provekit_common::buffer::StackBuffer;
///
/// const LEAF_BUFFER_SIZE: usize = 528;
/// let mut buf = StackBuffer::<LEAF_BUFFER_SIZE>::new();
/// write!(buf, "hello").unwrap();
/// assert_eq!(buf.as_slice(), b"hello");
/// ```
pub struct StackBuffer<const SIZE: usize> {
    buf: [u8; SIZE],
    pos: usize,
}

impl<const SIZE: usize> StackBuffer<SIZE> {
    /// Creates a new empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; SIZE],
            pos: 0,
        }
    }

    /// Returns the written portion of the buffer as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Returns the number of bytes written to the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Returns true if no bytes have been written.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// Returns the total capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        SIZE
    }

    /// Returns the remaining space available for writing.
    #[inline]
    pub fn remaining(&self) -> usize {
        SIZE - self.pos
    }
}

impl<const SIZE: usize> Default for StackBuffer<SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SIZE: usize> Write for StackBuffer<SIZE> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let available = SIZE - self.pos;
        if data.len() > available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "buffer overflow",
            ));
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_write() {
        let mut buf = StackBuffer::<64>::new();
        buf.write_all(b"hello").unwrap();
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.remaining(), 59);
    }

    #[test]
    fn test_overflow() {
        let mut buf = StackBuffer::<4>::new();
        assert!(buf.write_all(b"hello").is_err());
    }

    #[test]
    fn test_exact_fit() {
        let mut buf = StackBuffer::<5>::new();
        buf.write_all(b"hello").unwrap();
        assert_eq!(buf.remaining(), 0);
    }
}
