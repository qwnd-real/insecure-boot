//! The `tcglog.ib` replay dump: a TCG event log rewritten for firmware.
//!
//! A TCG event log as the firmware publishes it is awkward to read without an
//! allocator. Digest lengths inside a crypto-agile record are only knowable
//! from the algorithm list carried by the very first event, records are
//! variable-length in three independent ways, and the first record uses a
//! different structure from every record after it. A dump replaces that with a
//! flat layout a `no_std` reader can walk in one pass: a fixed-size header, a
//! table of fixed-size bank descriptors, a table of fixed-size event
//! descriptors in log order, and a heap the descriptors point into.
//!
//! Everything a replay needs is present, and nothing the original log carried
//! is dropped:
//!
//! - Every event keeps its PCR index, its `EV_*` type, its event data verbatim,
//!   and the exact ordered list of digests the log recorded for it, so the
//!   original records can be reproduced byte for byte.
//! - Each bank carries the PCR0-7 values the log folds to, so a replay can be
//!   checked against what the platform actually measured.
//! - The startup locality PCR0 was reset with is recorded, because it decides
//!   the value PCR0 starts from and therefore whether extends alone can
//!   reproduce it.
//!
//! Only events for PCR0 through PCR7 are present; a dump describes that
//! subsequence of the log and no more.
//!
//! All integers are little-endian, and every offset is a byte offset from the
//! start of the dump. The layout is spelled out in [`layout`].

#![no_std]

pub mod layout;

mod algorithm;
mod dump;

pub use algorithm::Algorithm;
pub use dump::{Bank, Banks, Digest, Digests, Dump, Event, Events};
pub use layout::{EventFlags, EventType};

use thiserror::Error;

/// Number of platform configuration registers a dump describes, starting at
/// PCR0.
pub const PCR_COUNT: u32 = 8;

/// Name a dump is expected to have in the root directory of a file system.
pub const FILE_NAME: &str = "tcglog.ib";

/// Result of reading a replay dump.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a replay dump could not be read.
#[derive(Clone, Copy, Debug, Error)]
pub enum Error {
    /// The bytes do not begin with the dump signature.
    #[error("the file does not begin with a TCG replay dump signature")]
    NotADump,

    /// The dump was written by an incompatible revision of this format.
    #[error("dump format version {found} is not the supported version {expected}")]
    UnsupportedVersion {
        /// Version the dump declares.
        found: u32,
        /// Version this crate implements.
        expected: u32,
    },

    /// The header is shorter than the format requires, or disagrees with the
    /// format about its own length.
    #[error("the dump header is malformed")]
    MalformedHeader,

    /// The header's total length does not match the number of bytes on hand,
    /// which means the dump was truncated or is followed by something else.
    #[error("the dump declares {declared} bytes but {actual} are present")]
    SizeMismatch {
        /// Length the header declares.
        declared: u32,
        /// Length actually available.
        actual: usize,
    },

    /// A table or heap region a descriptor points at is not inside the dump.
    #[error("the region at {offset:#x} spanning {len:#x} bytes is outside the dump")]
    OutOfBounds {
        /// Offset of the region within the dump.
        offset: u32,
        /// Length of the region in bytes.
        len: u32,
    },

    /// The dump carries no expected PCR values for the requested algorithm.
    #[error("the dump describes no {0} PCR bank")]
    MissingBank(Algorithm),

    /// An event records no digest for the bank being replayed, so there is
    /// nothing to extend it with.
    #[error("the event at index {index} records no {algorithm} digest")]
    MissingDigest {
        /// Position of the event in the dump.
        index: u32,
        /// Algorithm the caller asked for.
        algorithm: Algorithm,
    },

    /// An event names a PCR outside the range a dump covers.
    #[error("an event names PCR {0}, which is outside PCR0-7")]
    PcrOutOfRange(u32),
}
