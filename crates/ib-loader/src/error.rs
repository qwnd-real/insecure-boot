//! What can go wrong on the way through the boot.

use thiserror::Error;

use uefi::Status;

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

    /// The staged configuration file cannot be read.
    #[error("the staged configuration is unusable: {0}")]
    Config(#[from] ib_config::Error),

    /// A command did not fit the buffer reserved for it.
    #[error("a {0} command does not fit the buffer reserved for it")]
    CommandTooLong(&'static str),

    /// A file the run depends on is not in the boot volume.
    #[error("the boot volume holds no {0}")]
    MissingArtifact(&'static str),

    /// The firmware keeps no `Setup` variable to reconfigure.
    #[error("the firmware keeps no Setup variable to reconfigure")]
    NoSetupVariable,

    /// The `Setup` variable is too small for the offset the configuration
    /// names.
    #[error("the Setup variable is {len} bytes, too small for offset {offset:#x}")]
    SetupTooSmall {
        /// Length of the `Setup` variable.
        len: usize,
        /// Offset the configuration names.
        offset: usize,
    },

    /// The `Setup` variable holds a value that is neither TCG 1.2 nor
    /// TCG 2.0 at the configured offset.
    #[error("Setup holds {0:#04x} at the configured offset, neither TCG 1.2 nor TCG 2.0")]
    UnexpectedTcgSpec(u8),

    /// The `Setup` variable refused the write, which firmware variable
    /// protection also does.
    #[error(
        "Setup refused the write ({0:?}); if UEFI Variable Runtime Protection (often called \
         \"Password protection of Runtime Variables\") is enabled, disable it in the firmware \
         setup and power-cycle"
    )]
    ProtectedVariables(Status),

    /// A path held characters the firmware's file protocol cannot spell.
    #[error("{0} cannot be spelled for the firmware's file protocol")]
    Name(&'static str),

    /// A path named something the volume serves, but not as a file.
    #[error("the boot volume offers {0}, but not as a file")]
    NotAFile(&'static str),

    /// A file's size cannot be held by an address.
    #[error("the boot volume reports {0} with a size no address can hold")]
    Oversized(&'static str),

    /// A file's contents came back short.
    #[error("the boot volume served only {read} of the {expected} bytes of {path}")]
    PartialRead {
        /// The path whose contents came back short.
        path: &'static str,
        /// How many bytes the volume served.
        read: usize,
        /// How many bytes the file is said to hold.
        expected: usize,
    },

    /// A file took fewer bytes than it was offered.
    #[error("the boot volume took only {written} of the {expected} bytes offered for {path}")]
    PartialWrite {
        /// The path the bytes were offered to.
        path: &'static str,
        /// How many bytes the volume took.
        written: usize,
        /// How many bytes were offered.
        expected: usize,
    },

    /// A buffer for a file's metadata came out too small for it.
    #[error("a metadata buffer for {0} came out too small")]
    Metadata(&'static str),

    /// The payload is not an image this can map.
    #[error("the payload is not a PE32+ image this can map")]
    MalformedPayload,

    /// The payload asks for a relocation type this does not apply.
    #[error("the payload asks for relocation type {0} this does not apply")]
    UnsupportedRelocation(u16),

    /// The boot manager's device path could not be assembled.
    #[error("the boot manager's device path could not be assembled")]
    DevicePath,

    /// The boot manager returned instead of booting Windows.
    #[error("the Windows boot manager returned instead of booting Windows")]
    BootManagerReturned,

    /// Firmware refused a boot service.
    #[error("firmware refused a boot service: {0}")]
    Uefi(#[from] uefi::Error),
}
