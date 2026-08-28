//! What can go wrong while writing a dump.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result of a dumping operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a dump could not be produced.
#[derive(Debug, Error)]
pub enum Error {
    /// A file could not be read.
    #[error("cannot read {path}")]
    Read {
        /// File that could not be read.
        path: PathBuf,
        /// Reason the operating system gave.
        #[source]
        source: io::Error,
    },

    /// The dump could not be written.
    #[error("cannot write {path}")]
    Write {
        /// File that could not be written.
        path: PathBuf,
        /// Reason the operating system gave.
        #[source]
        source: io::Error,
    },

    /// A TPM Base Services call failed.
    #[cfg(windows)]
    #[error("the TPM Base Services call {call} returned {code:#010x}")]
    Tbs {
        /// Name of the function that failed.
        call: &'static str,
        /// `TBS_RESULT` the function returned.
        code: u32,
    },

    /// This build has no way to reach the platform's event log by itself.
    #[cfg(not(any(target_os = "linux", windows)))]
    #[error("this platform cannot be read directly; name a log file with --log")]
    UnsupportedPlatform,

    /// The event log does not follow the structure the TCG profile defines.
    #[error("the event log is malformed at offset {offset:#x}: {reason}")]
    MalformedLog {
        /// Offset the parser stopped at.
        offset: usize,
        /// What the parser expected to find there.
        reason: &'static str,
    },

    /// Every bank the log measured into uses a hash this tool cannot compute, so
    /// no expected PCR values could be worked out.
    #[error("the event log declares no hash this tool can compute")]
    NoUsableBank,

    /// The log describes more banks, records or bytes than a dump can address.
    #[error("the event log does not fit the dump format")]
    Unrepresentable,

    /// The dump this tool just wrote does not read back.
    #[error("the dump does not read back correctly")]
    Unreadable(#[from] ib_tcglog::Error),

    /// Replaying the dump does not reproduce the values it records, so it does
    /// not describe the log it was made from.
    #[error("the dump does not replay the {0} bank to the values it records")]
    Inconsistent(ib_tcglog::Algorithm),
}
