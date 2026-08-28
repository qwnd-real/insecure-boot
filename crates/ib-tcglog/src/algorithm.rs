//! TPM hashing algorithms, as the `TPM_ALG_ID` values a log records.

use core::fmt;

/// A `TPM_ALG_ID` naming the hash a PCR bank and a digest belong to.
///
/// Identifiers this crate does not know are kept rather than rejected: a dump
/// preserves the digests of every bank the log carried, including banks a
/// replay cannot fold itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Algorithm(u16);

impl Algorithm {
    /// `TPM_ALG_SHA1`.
    pub const SHA1: Self = Self(0x0004);

    /// `TPM_ALG_SHA256`.
    pub const SHA256: Self = Self(0x000B);

    /// `TPM_ALG_SHA384`.
    pub const SHA384: Self = Self(0x000C);

    /// `TPM_ALG_SHA512`.
    pub const SHA512: Self = Self(0x000D);

    /// `TPM_ALG_SM3_256`.
    pub const SM3_256: Self = Self(0x0012);

    /// Wraps a raw `TPM_ALG_ID`.
    #[must_use]
    pub const fn from_id(id: u16) -> Self {
        Self(id)
    }

    /// The raw `TPM_ALG_ID`.
    #[must_use]
    pub const fn id(self) -> u16 {
        self.0
    }

    /// Length of a digest this algorithm produces, in bytes, or [`None`] for an
    /// algorithm this crate does not know.
    #[must_use]
    pub const fn digest_size(self) -> Option<usize> {
        match self {
            Self::SHA1 => Some(20),
            Self::SHA256 | Self::SM3_256 => Some(32),
            Self::SHA384 => Some(48),
            Self::SHA512 => Some(64),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SHA1 => f.write_str("SHA-1"),
            Self::SHA256 => f.write_str("SHA-256"),
            Self::SHA384 => f.write_str("SHA-384"),
            Self::SHA512 => f.write_str("SHA-512"),
            Self::SM3_256 => f.write_str("SM3-256"),
            Self(id) => write!(f, "algorithm {id:#06x}"),
        }
    }
}
