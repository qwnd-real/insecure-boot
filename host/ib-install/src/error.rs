//! What can go wrong while staging a boot.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result of a staging operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a boot could not be staged.
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

    /// A file could not be written.
    #[error("cannot write {path}")]
    Write {
        /// File that could not be written.
        path: PathBuf,
        /// Reason the operating system gave.
        #[source]
        source: io::Error,
    },

    /// A file the staging depends on is not in the working directory.
    #[error("cannot find {path} in the working directory")]
    Missing {
        /// File that was expected and not found.
        path: PathBuf,
    },

    /// The payload named on the command line is not an EFI application.
    #[error("{path} is not a .efi file")]
    NotAnEfi {
        /// File that is not an EFI application.
        path: PathBuf,
    },

    /// The loader image is not a PE image this can sign.
    #[error("ib-loader.efi is not a PE image this can sign")]
    MalformedImage,

    /// The signed image is too large for the PE format to name its parts.
    #[error("the signed image is too large for the PE format to name its parts")]
    TooLarge,

    /// The loader image carries no SBAT section, which shim 15.3 and later
    /// refuse to launch anything without.
    #[error("ib-loader.efi carries no SBAT section, which shim 15.3 and later require")]
    NoSbat,

    /// The loader image already carries a signature; this signs clean images
    /// only.
    #[error("ib-loader.efi already carries a signature")]
    AlreadySigned,

    /// The key pair could not be made or used.
    #[error("the MOK key pair is unusable: {0}")]
    Key(#[from] rsa::errors::Error),

    /// The private key's PKCS#8 encoding could not be read or written.
    #[error("the MOK private key is unusable: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),

    /// The public key's encoding could not be written.
    #[error("the MOK public key is unusable: {0}")]
    Spki(#[from] rsa::pkcs8::spki::Error),

    /// The certificate could not be made.
    #[error("the MOK certificate is unusable: {0}")]
    Certificate(#[from] x509_cert::builder::Error),

    /// A signature could not be produced.
    #[error("a signature could not be produced: {0}")]
    Signature(#[from] rsa::signature::Error),

    /// An ASN.1 structure could not be assembled or parsed.
    #[error("an ASN.1 structure is unusable: {0}")]
    Der(#[from] der::Error),

    /// A firmware variable could not be written.
    #[cfg(windows)]
    #[error("writing the {name} firmware variable failed with {code:#010x}")]
    FirmwareVariable {
        /// Name of the variable that was refused.
        name: &'static str,
        /// Error code the firmware interface reported.
        code: u32,
    },

    /// The console this runs in does not hold the privilege firmware
    /// variables need.
    #[cfg(windows)]
    #[error("this tool needs an administrator console holding SeSystemEnvironmentPrivilege")]
    NotElevated,

    /// A program this tool drives reported failure.
    #[cfg(windows)]
    #[error("{program} exited with {code:?}")]
    Command {
        /// Program that failed.
        program: &'static str,
        /// Exit code it reported.
        code: Option<i32>,
    },

    /// The ESP could not be mounted.
    #[cfg(windows)]
    #[error("the EFI System Partition could not be mounted")]
    NoEsp,

    /// The Windows boot manager is not where this expects it, so there is
    /// nothing to replace and restore.
    #[cfg(windows)]
    #[error("the ESP holds no EFI\\Microsoft\\Boot\\bootmgfw.efi")]
    NoBootManager,

    /// Putting the Windows boot manager back after a failed staging failed
    /// too; the machine may not boot until it is restored by hand.
    #[cfg(windows)]
    #[error("restoring the Windows boot manager after the failure below failed too")]
    Restore {
        /// The staging failure that triggered the restore.
        #[source]
        source: Box<Error>,
    },

    /// This build cannot stage a Windows boot, because it is not running on
    /// Windows.
    #[cfg(not(windows))]
    #[error("this tool stages a Windows boot; build and run it on Windows")]
    NotWindows,
}
