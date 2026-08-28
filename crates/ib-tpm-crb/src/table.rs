//! The ACPI TPM2 table and the start method it names.
//!
//! Field offsets follow `struct acpi_table_tpm2` and the per-start-method
//! structures that trail it, which Linux spells `tpm2_crb_smc`, `tpm2_crb_ffa`
//! and `tpm2_crb_pluton`. Reading the fields out of a byte slice rather than
//! casting the table to a packed struct keeps the alignment question from
//! arising at all.

use core::fmt;

use crate::{Error, Result};

/// Offset of the 64-bit address of the CRB control area.
const CONTROL_ADDRESS: usize = 40;

/// Offset of the 32-bit start method selector.
const START_METHOD: usize = 48;

/// Length of the table up to and including the start method, which is the
/// smallest table this driver can use.
const FIXED_LEN: usize = 52;

/// Length of the ARM SMC parameter block.
const SMC_LEN: usize = 12;

/// Length of the Arm Firmware Framework parameter block.
const FFA_LEN: usize = 12;

/// Length of the Pluton parameter block, two 64-bit addresses.
const PLUTON_LEN: usize = 16;

/// The start method a TPM2 table names, as defined by the TCG ACPI
/// specification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartMethod {
    /// Start is signalled by evaluating an ACPI control method.
    AcpiStart,
    /// A memory-mapped TIS interface rather than a control-response buffer.
    MemoryMapped,
    /// A control-response buffer started through its own start register.
    CommandBuffer,
    /// A control-response buffer whose start is signalled by an ACPI control
    /// method as well as by the start register.
    CommandBufferWithAcpiStart,
    /// A control-response buffer started through an ARM Secure Monitor Call.
    CommandBufferWithArmSmc,
    /// A control-response buffer with a Microsoft Pluton doorbell.
    CommandBufferWithPluton,
    /// A control-response buffer reached through Arm Firmware Framework
    /// messages.
    CrbWithArmFfa,
    /// A selector this driver does not recognise.
    Unknown(u32),
}

/// Addresses of the Pluton doorbell registers.
#[derive(Clone, Copy)]
pub(crate) struct PlutonAddresses {
    /// Register the driver writes to ask Pluton to run a command.
    pub(crate) start: u64,
    /// Register Pluton writes when it is ready for a command.
    pub(crate) reply: u64,
}

/// The fields of the ACPI TPM2 table this driver uses.
pub(crate) struct Tpm2Table {
    /// Physical address of the CRB control area.
    pub(crate) control_address: u64,
    /// Start method the table names.
    pub(crate) start_method: StartMethod,
    /// Doorbell addresses, for the Pluton start method.
    pub(crate) pluton: Option<PlutonAddresses>,
}

impl StartMethod {
    /// Decodes the selector stored in the table.
    fn from_raw(raw: u32) -> Self {
        match raw {
            2 => Self::AcpiStart,
            6 => Self::MemoryMapped,
            7 => Self::CommandBuffer,
            8 => Self::CommandBufferWithAcpiStart,
            11 => Self::CommandBufferWithArmSmc,
            13 => Self::CommandBufferWithPluton,
            15 => Self::CrbWithArmFfa,
            other => Self::Unknown(other),
        }
    }

    /// The selector as it appears in the table.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::AcpiStart => 2,
            Self::MemoryMapped => 6,
            Self::CommandBuffer => 7,
            Self::CommandBufferWithAcpiStart => 8,
            Self::CommandBufferWithArmSmc => 11,
            Self::CommandBufferWithPluton => 13,
            Self::CrbWithArmFfa => 15,
            Self::Unknown(raw) => raw,
        }
    }

    /// Short name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AcpiStart => "ACPI start",
            Self::MemoryMapped => "memory mapped",
            Self::CommandBuffer => "command buffer",
            Self::CommandBufferWithAcpiStart => "command buffer with ACPI start",
            Self::CommandBufferWithArmSmc => "command buffer with ARM SMC",
            Self::CommandBufferWithPluton => "command buffer with Pluton",
            Self::CrbWithArmFfa => "CRB with Arm FF-A",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether the interface supports the idle and command-ready transitions.
    ///
    /// The methods that drive the TPM entirely through firmware never expose the
    /// request register, so asking them to go idle would hang waiting for a bit
    /// nothing clears.
    pub(crate) const fn has_idle(self) -> bool {
        !matches!(
            self,
            Self::AcpiStart | Self::CommandBufferWithAcpiStart | Self::CommandBufferWithArmSmc
        )
    }

    /// Whether the start register must be written to launch a command.
    pub(crate) const fn uses_start_register(self) -> bool {
        matches!(self, Self::CommandBuffer | Self::MemoryMapped)
    }

    /// Whether launching or cancelling a command goes through the ACPI control
    /// method.
    pub(crate) const fn uses_acpi_start(self) -> bool {
        matches!(self, Self::AcpiStart | Self::CommandBufferWithAcpiStart)
    }
}

impl fmt::Display for StartMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.raw())
    }
}

impl Tpm2Table {
    /// Decodes `bytes`, the whole TPM2 table including its header.
    ///
    /// # Errors
    ///
    /// Fails if the table is shorter than the start method it names requires.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let start_method = read_u32(bytes, START_METHOD)
            .map(StartMethod::from_raw)
            .ok_or(Error::TableTooShort {
                length: bytes.len(),
                start_method: StartMethod::Unknown(0),
            })?;

        let too_short = || Error::TableTooShort {
            length: bytes.len(),
            start_method,
        };

        let control_address = read_u64(bytes, CONTROL_ADDRESS).ok_or_else(too_short)?;
        let parameters = bytes.get(FIXED_LEN..).unwrap_or_default();

        let mut pluton = None;

        match start_method {
            StartMethod::CommandBufferWithArmSmc => {
                if parameters.len() < SMC_LEN {
                    return Err(too_short());
                }
            }
            StartMethod::CrbWithArmFfa => {
                if parameters.len() < FFA_LEN {
                    return Err(too_short());
                }
            }
            StartMethod::CommandBufferWithPluton => {
                if parameters.len() < PLUTON_LEN {
                    return Err(too_short());
                }
                pluton = Some(PlutonAddresses {
                    start: read_u64(parameters, 0).ok_or_else(too_short)?,
                    reply: read_u64(parameters, size_of::<u64>()).ok_or_else(too_short)?,
                });
            }
            _ => {}
        }

        Ok(Self {
            control_address,
            start_method,
            pluton,
        })
    }

    /// Smallest table length this driver can decode, which is Linux's
    /// `sizeof(struct acpi_table_tpm2)`: the ACPICA table structures are
    /// byte-packed, so the platform-specific parameters start here.
    pub(crate) const fn fixed_len() -> usize {
        FIXED_LEN
    }
}

/// Reads a little-endian `u32` at `offset`, or [`None`] past the end.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(size_of::<u32>())?)?;
    Some(u32::from_le_bytes(field.try_into().ok()?))
}

/// Reads a little-endian `u64` at `offset`, or [`None`] past the end.
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let field = bytes.get(offset..offset.checked_add(size_of::<u64>())?)?;
    Some(u64::from_le_bytes(field.try_into().ok()?))
}
