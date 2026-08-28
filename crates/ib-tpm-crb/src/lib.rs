//! TPM 2.0 over the TCG Command Response Buffer interface.
//!
//! This is a port of Linux's `drivers/char/tpm/tpm_crb.c`, which implements the
//! interface defined by the TCG PC Client Platform TPM Profile. The register
//! layout, the flag bits, the ordering of every register access and the firmware
//! workarounds are all taken from that driver; what changes is the surrounding
//! plumbing, because there is no device model, no `ioremap` and no scheduler
//! here:
//!
//! - Register blocks are reached directly, since UEFI leaves the address space
//!   identity-mapped until `ExitBootServices`.
//! - Delays and deadlines come from boot services through [`ib_uacpi::time`].
//! - The ACPI start method is invoked by evaluating `_DSM` through uACPI rather
//!   than through ACPICA.
//! - The `tpm_chip` layer is replaced by [`Tpm::transmit`], which reproduces the
//!   command/response handshake `tpm_transmit` drives through the class ops.
//!
//! The ARM start methods cannot work on this target and are handled the way the
//! Linux driver handles them when its ARM support is not compiled in: probing
//! fails rather than pretending the interface is usable.

#![no_std]

mod crb;
mod mmio;
mod regs;
mod table;

pub use crb::Tpm;
pub use table::StartMethod;

use thiserror::Error;

/// Result of a Command Response Buffer operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong talking to a CRB TPM.
#[derive(Debug, Error)]
pub enum Error {
    /// The firmware published a TPM2 table too short to hold the fields the
    /// start method it names requires.
    #[error("the ACPI TPM2 table is {length} bytes, too short for start method {start_method}")]
    TableTooShort {
        /// Length the table's own header reported.
        length: usize,
        /// Start method whose parameters do not fit.
        start_method: StartMethod,
    },

    /// The TPM2 table names a start method this driver does not implement.
    ///
    /// A memory-mapped interface is a TIS device rather than a CRB one, which is
    /// the case Linux answers with `-ENODEV` so its FIFO driver can claim the
    /// device instead.
    #[error("start method {0} is not a Command Response Buffer interface")]
    NotCommandResponseBuffer(StartMethod),

    /// The start method needs firmware entry points that do not exist on this
    /// architecture, so the interface cannot be driven at all.
    #[error("start method {0} needs firmware support this platform does not provide")]
    UnsupportedStartMethod(StartMethod),

    /// `_CRS` described no memory at all, so there is nothing to drive.
    #[error("the MSFT0101 device describes no memory resource")]
    NoMemoryResource,

    /// A register or buffer the control area points at falls outside every memory
    /// resource the device declared.
    #[error("the region at {start:#x} spanning {len:#x} bytes is not addressable")]
    UnmappableRegion {
        /// First address of the region.
        start: u64,
        /// Length of the region in bytes.
        len: u64,
    },

    /// A register block does not start on a 32-bit boundary, so its registers
    /// cannot be accessed at the width the interface requires.
    #[error("the register block at {address:#x} is not 32-bit aligned")]
    MisalignedRegisters {
        /// First address of the block.
        address: u64,
    },

    /// The command and response buffers overlap but disagree about their size,
    /// which the TPM Profile forbids.
    #[error("overlapping command and response buffers differ in size ({command} vs {response})")]
    BufferSizeMismatch {
        /// Size the control area reported for the command buffer.
        command: u32,
        /// Size the control area reported for the response buffer.
        response: u32,
    },

    /// A register did not reach the expected value within its timeout.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),

    /// The control area's status register reports the TPM is unrecoverable.
    #[error("the TPM reports an unrecoverable error")]
    DeviceError,

    /// The command is larger than the command buffer.
    #[error("a {length}-byte command does not fit the {capacity}-byte command buffer")]
    CommandTooLong {
        /// Length of the command that was offered.
        length: usize,
        /// Capacity of the command buffer.
        capacity: u32,
    },

    /// The caller's buffer cannot hold even a response header, or cannot hold the
    /// response the TPM says it produced.
    #[error("a {capacity}-byte buffer cannot hold a {length}-byte response")]
    ResponseTooLong {
        /// Length the response header reported.
        length: usize,
        /// Capacity of the buffer the caller offered.
        capacity: usize,
    },

    /// The response header reports a length shorter than a header.
    #[error("the response header reports an impossible length of {length} bytes")]
    MalformedResponse {
        /// Length the response header reported.
        length: usize,
    },

    /// The TPM cancelled the command instead of completing it.
    #[error("the TPM cancelled the command")]
    Cancelled,

    /// uACPI could not satisfy a request this driver made.
    #[error("ACPI: {0}")]
    Acpi(#[from] ib_uacpi::Error),

    /// The ACPI start method ran but reported failure.
    #[error("the ACPI start method returned {0}")]
    StartMethodFailed(u64),
}
