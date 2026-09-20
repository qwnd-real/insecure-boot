//! The `ib-config.bin` staged configuration.
//!
//! The installer stages one of these into the boot volume next to the payload
//! and the replay dump, and the loader reads it before it touches anything
//! else. It carries the one number the loader cannot know on its own: the
//! byte offset, within the firmware's `Setup` variable, of the setting that
//! selects the TPM UEFI spec version. That offset differs between firmware
//! vendors and builds, so it is asked of the user at staging time and carried
//! in this file rather than compiled in.
//!
//! All integers are little-endian, and the file is exactly this:
//!
//! ```text
//! offset  length  field
//! 0x00    8       magic             "IBCONFIG"
//! 0x08    4       format version    1
//! 0x0c    2       Setup offset      the TPM UEFI spec version byte
//! ```

#![no_std]

use thiserror::Error;

/// Name the configuration is expected to have in the root directory of a
/// file system.
pub const FILE_NAME: &str = "ib-config.bin";

/// Signature every configuration starts with.
const MAGIC: [u8; 8] = *b"IBCONFIG";

/// Revision of the layout this crate reads and writes.
const VERSION: u32 = 1;

/// Offset of the format version within the file.
const VERSION_AT: usize = MAGIC.len();

/// Offset of the Setup offset within the file.
const SETUP_OFFSET_AT: usize = VERSION_AT + size_of::<u32>();

/// Length of a configuration: the magic, the version, and the Setup offset.
const LENGTH: usize = SETUP_OFFSET_AT + size_of::<u16>();

/// The Setup offset of the TPM UEFI spec version, as staged for the loader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The byte offset, within the firmware's `Setup` variable, of the
    /// setting that selects the TPM UEFI spec version.
    tcg_spec_offset: u16,
}

impl Config {
    /// Builds a configuration carrying `tcg_spec_offset`.
    #[must_use]
    pub const fn new(tcg_spec_offset: u16) -> Self {
        Self { tcg_spec_offset }
    }

    /// The byte offset, within the firmware's `Setup` variable, of the
    /// setting that selects the TPM UEFI spec version.
    #[must_use]
    pub fn tcg_spec_offset(self) -> usize {
        usize::from(self.tcg_spec_offset)
    }

    /// Encodes the wire format.
    #[must_use]
    pub fn to_bytes(self) -> [u8; LENGTH] {
        let mut bytes = [0_u8; LENGTH];
        bytes[..VERSION_AT].copy_from_slice(&MAGIC);
        bytes[VERSION_AT..SETUP_OFFSET_AT].copy_from_slice(&VERSION.to_le_bytes());
        bytes[SETUP_OFFSET_AT..].copy_from_slice(&self.tcg_spec_offset.to_le_bytes());
        bytes
    }

    /// Reads the wire format.
    ///
    /// # Errors
    ///
    /// Fails if the bytes are not the length the format requires, do not
    /// begin with the signature, or were written by an incompatible revision
    /// of the format.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = <&[u8; LENGTH]>::try_from(bytes).map_err(|_| Error::SizeMismatch {
            actual: bytes.len(),
            expected: LENGTH,
        })?;

        if bytes[..VERSION_AT] != MAGIC {
            return Err(Error::NotAConfig);
        }

        let version =
            u32::from_le_bytes(bytes[VERSION_AT..SETUP_OFFSET_AT].try_into().map_err(|_| {
                Error::SizeMismatch {
                    actual: bytes.len(),
                    expected: LENGTH,
                }
            })?);
        if version != VERSION {
            return Err(Error::UnsupportedVersion {
                found: version,
                expected: VERSION,
            });
        }

        let tcg_spec_offset =
            u16::from_le_bytes(bytes[SETUP_OFFSET_AT..].try_into().map_err(|_| {
                Error::SizeMismatch {
                    actual: bytes.len(),
                    expected: LENGTH,
                }
            })?);

        Ok(Self { tcg_spec_offset })
    }
}

/// Why a configuration could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum Error {
    /// The bytes do not begin with the configuration signature.
    #[error("the file does not begin with an ib-config signature")]
    NotAConfig,

    /// The file was written by an incompatible revision of this format.
    #[error("configuration format version {found} is not the supported version {expected}")]
    UnsupportedVersion {
        /// Version the file declares.
        found: u32,
        /// Version this crate implements.
        expected: u32,
    },

    /// The file is not the length the format requires.
    #[error("the configuration is {actual} bytes, but the format is {expected}")]
    SizeMismatch {
        /// Length actually on hand.
        actual: usize,
        /// Length the format requires.
        expected: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{Config, Error, FILE_NAME, LENGTH};

    #[test]
    fn survives_an_encode_decode_round_trip() {
        let config = Config::new(0x1b);
        let bytes = config.to_bytes();
        assert_eq!(bytes.len(), LENGTH);
        assert_eq!(Config::parse(&bytes), Ok(config));
    }

    #[test]
    fn rejects_a_file_that_is_not_the_length_the_format_requires() {
        let bytes = Config::new(0x1b).to_bytes();
        assert!(matches!(
            Config::parse(&bytes[..LENGTH - 1]),
            Err(Error::SizeMismatch { .. })
        ));
        assert!(matches!(
            Config::parse(&bytes[..LENGTH - 9]),
            Err(Error::SizeMismatch { .. })
        ));
    }

    #[test]
    fn rejects_bytes_without_the_signature() {
        let mut bytes = Config::new(0x1b).to_bytes();
        bytes[0] = b'X';
        assert_eq!(Config::parse(&bytes), Err(Error::NotAConfig));
    }

    #[test]
    fn rejects_an_unsupported_format_version() {
        let mut bytes = Config::new(0x1b).to_bytes();
        bytes[8] = 2;
        assert!(matches!(
            Config::parse(&bytes),
            Err(Error::UnsupportedVersion { found: 2, .. })
        ));
    }

    #[test]
    fn names_the_file_the_loader_and_installer_agree_on() {
        assert_eq!(FILE_NAME, "ib-config.bin");
    }
}
