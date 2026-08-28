//! What can go wrong on the way through the boot.

use thiserror::Error;

/// Result of one step of the boot.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a step could not be completed.
#[derive(Debug, Error)]
pub enum Error {
    /// The TPM could not be reached.
    #[error("{0}")]
    Tpm(#[from] ib_tpm_crb::Error),

    /// The TPM answered with something that cannot be used.
    #[error("{0}")]
    Reply(#[from] ib_tpm2::ReplyError),

    /// The replay dump cannot be read.
    #[error("the replay dump is unusable: {0}")]
    Dump(#[from] ib_tcglog::Error),

    /// The TCG2 protocol could not be provided.
    #[error("{0}")]
    Tcg2(#[from] ib_tcg2::Error),

    /// A command did not fit the buffer reserved for it.
    #[error("a {0} command does not fit the buffer reserved for it")]
    CommandTooLong(&'static str),

    /// Firmware refused a boot service.
    #[error("firmware refused a boot service: {0}")]
    Uefi(#[from] uefi::Error),
}
