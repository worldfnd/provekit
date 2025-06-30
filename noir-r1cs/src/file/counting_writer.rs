use std::io::{Result, Write};

/// Helper to count bytes written to a writer.
pub struct CountingWriter<T: Write> {
    writer: T,
    count:  usize,
}

impl<T: Write> CountingWriter<T> {
    #[must_use]
    pub const fn new(writer: T) -> Self {
        Self { writer, count: 0 }
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl<T: Write> Write for CountingWriter<T> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self.writer.write(buf)?;
        self.count += written;
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}
