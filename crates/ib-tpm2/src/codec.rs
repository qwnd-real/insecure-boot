//! Reading and writing the big-endian fields a TPM 2.0 command is made of.

/// Appends big-endian fields to a buffer that is exactly as long as the command
/// being built, so every write is in bounds by construction.
pub struct Writer<'a> {
    bytes: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    /// Starts writing at the beginning of `bytes`.
    pub const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Appends one byte.
    pub fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    /// Appends a big-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }

    /// Appends a big-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    /// Appends `value` verbatim.
    pub fn bytes(&mut self, value: &[u8]) {
        let end = self.at + value.len();
        self.bytes[self.at..end].copy_from_slice(value);
        self.at = end;
    }
}

/// Reads the big-endian `u32` at `offset`, or [`None`] past the end.
pub fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(size_of::<u32>())?;
    Some(u32::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

/// Reads the big-endian `u16` at `offset`, or [`None`] past the end.
pub fn half(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(size_of::<u16>())?;
    Some(u16::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

/// Reads the byte at `offset`, or [`None`] past the end.
pub fn byte(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}
