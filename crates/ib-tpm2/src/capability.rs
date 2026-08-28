//! `TPM2_GetCapability`, and the capabilities this crate asks about.
//!
//! Two capability groups are covered: the fixed properties, which are read one
//! at a time, and the PCR allocation, which reports every bank the TPM has
//! allocated along with the PCRs selected in it.

use core::fmt;
use core::str;

use crate::codec::{Writer, byte, half, word};
use crate::{Algorithm, BANK_COUNT_MAX, HEADER_LEN, ReplyError, TAG_NO_SESSIONS, accepted};

/// `TPM_CC_GetCapability`.
const CC_GET_CAPABILITY: u32 = 0x0000_017A;

/// `TPM_CAP_PCRS`, the capability group describing the PCR allocation.
const CAP_PCRS: u32 = 0x0000_0005;

/// `TPM_CAP_TPM_PROPERTIES`, the capability group holding the fixed properties.
const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

/// Longest select field this crate reads, enough for 64 PCRs and so for every
/// platform profile the TCG has published.
const SELECT_LEN_MAX: usize = 8;

/// Length of any `TPM2_GetCapability` this module builds: the header, the
/// capability group, the first property to report and how many to report.
const COMMAND_LEN: usize = HEADER_LEN + 3 * size_of::<u32>();

/// Offset of the capability data a reply carries, past the header and the
/// `moreData` flag.
const CAPABILITY_AT: usize = HEADER_LEN + size_of::<u8>();

/// Offset of the first property's value in a reply about the fixed properties:
/// past the capability group, the property count, and the property's own tag.
const PROPERTY_VALUE_AT: usize = CAPABILITY_AT + 3 * size_of::<u32>();

/// Buffer any command this module builds fits in.
pub const COMMAND_CAPACITY: usize = COMMAND_LEN;

/// Buffer a reply to any command this module builds fits in, which is the PCR
/// allocation of a TPM with every bank the registry defines allocated.
pub const REPLY_CAPACITY: usize = CAPABILITY_AT
    + 2 * size_of::<u32>()
    + BANK_COUNT_MAX * (size_of::<u16>() + size_of::<u8>() + SELECT_LEN_MAX);

/// A fixed property of the TPM, named by its `TPM_PT_*` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Property(u32);

impl Property {
    /// `TPM_PT_MANUFACTURER`, four ASCII characters naming the vendor.
    pub const MANUFACTURER: Self = Self(0x0000_0105);

    /// `TPM_PT_MAX_COMMAND_SIZE`, the largest command the TPM accepts.
    pub const MAX_COMMAND_SIZE: Self = Self(0x0000_011E);

    /// `TPM_PT_MAX_RESPONSE_SIZE`, the largest reply the TPM produces.
    pub const MAX_RESPONSE_SIZE: Self = Self(0x0000_011F);
}

/// The vendor identifier a TPM reports in `TPM_PT_MANUFACTURER`.
#[derive(Clone, Copy, Debug)]
pub struct Manufacturer(u32);

/// Builds a `TPM2_GetCapability` asking for exactly one fixed property, and
/// reports how long the command is.
///
/// Returns [`None`] if `buffer` is smaller than [`COMMAND_CAPACITY`].
pub fn property(buffer: &mut [u8], property: Property) -> Option<usize> {
    command(buffer, CAP_TPM_PROPERTIES, property.0, 1)
}

/// Builds a `TPM2_GetCapability` asking which PCR banks the TPM has allocated,
/// and reports how long the command is.
///
/// Returns [`None`] if `buffer` is smaller than [`COMMAND_CAPACITY`].
pub fn pcrs(buffer: &mut [u8]) -> Option<usize> {
    command(buffer, CAP_PCRS, 0, u32::try_from(BANK_COUNT_MAX).ok()?)
}

/// Reads the value of the one property a [`property`] reply carries.
///
/// # Errors
///
/// Fails if the TPM refused the command, or if the reply stops short of the
/// property.
pub fn value(reply: &[u8]) -> Result<u32, ReplyError> {
    accepted(reply)?;

    word(reply, PROPERTY_VALUE_AT).ok_or(ReplyError::Truncated)
}

/// Reads the vendor identifier out of a [`Property::MANUFACTURER`] reply.
///
/// # Errors
///
/// Fails if the TPM refused the command, or if the reply stops short of the
/// property.
pub fn manufacturer(reply: &[u8]) -> Result<Manufacturer, ReplyError> {
    value(reply).map(Manufacturer)
}

/// Reads the banks a [`pcrs`] reply reports as allocated into `banks`, and
/// reports how many were written.
///
/// A bank counts as allocated when at least one PCR is selected in it, which is
/// how a TPM reports a bank that exists but holds nothing. Banks past the end of
/// `banks` are dropped.
///
/// # Errors
///
/// Fails if the TPM refused the command, or if the reply stops short of a
/// selection it announced.
pub fn banks(reply: &[u8], banks: &mut [Algorithm]) -> Result<usize, ReplyError> {
    accepted(reply)?;

    let mut at = CAPABILITY_AT + size_of::<u32>();
    let count = word(reply, at).ok_or(ReplyError::Truncated)?;
    at += size_of::<u32>();

    let mut found = 0;
    for _ in 0..count {
        let algorithm = half(reply, at).ok_or(ReplyError::Truncated)?;
        at += size_of::<u16>();

        let len = usize::from(byte(reply, at).ok_or(ReplyError::Truncated)?);
        at += size_of::<u8>();

        let end = at.checked_add(len).ok_or(ReplyError::Truncated)?;
        let select = reply.get(at..end).ok_or(ReplyError::Truncated)?;
        at = end;

        if select.iter().any(|byte| *byte != 0)
            && let Some(slot) = banks.get_mut(found)
        {
            *slot = Algorithm::from_id(algorithm);
            found += 1;
        }
    }

    Ok(found)
}

/// Builds a `TPM2_GetCapability` for `capability`, starting at `property` and
/// asking for at most `count` items.
fn command(buffer: &mut [u8], capability: u32, property: u32, count: u32) -> Option<usize> {
    let mut writer = Writer::new(buffer.get_mut(..COMMAND_LEN)?);

    writer.u16(TAG_NO_SESSIONS);
    writer.u32(u32::try_from(COMMAND_LEN).ok()?);
    writer.u32(CC_GET_CAPABILITY);
    writer.u32(capability);
    writer.u32(property);
    writer.u32(count);

    Some(COMMAND_LEN)
}

impl fmt::Display for Manufacturer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The property holds four characters padded with NUL or space, but
        // nothing obliges a vendor to put text there, so anything that is not
        // printable ASCII is shown as the raw value. An embedded NUL matters in
        // particular: the firmware console cannot be handed one.
        let bytes = self.0.to_be_bytes();
        let text = bytes.split(|byte| *byte == 0).next().unwrap_or_default();

        match str::from_utf8(text) {
            Ok(text)
                if text
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ') =>
            {
                f.write_str(text.trim_end())
            }
            _ => write!(f, "{:#010x}", self.0),
        }
    }
}
