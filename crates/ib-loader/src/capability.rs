//! The one TPM 2.0 command this loader sends, and the reply it expects.
//!
//! `TPM2_GetCapability` is used to read the manufacturer property, which is the
//! cheapest way to prove that a command actually travelled through the Command
//! Response Buffer and came back. Field layouts are from the TPM 2.0 Library
//! Specification, Part 3; every field is big-endian.

use core::fmt;
use core::str;

/// `TPM_ST_NO_SESSIONS`, the tag of a command that carries no session area.
const TAG_NO_SESSIONS: u16 = 0x8001;

/// `TPM_CC_GetCapability`.
const CC_GET_CAPABILITY: u32 = 0x0000_017A;

/// `TPM_CAP_TPM_PROPERTIES`, the capability group holding the fixed properties.
const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

/// `TPM_PT_MANUFACTURER`, four ASCII characters naming the vendor.
const PT_MANUFACTURER: u32 = 0x0000_0105;

/// Offset of the response code in a reply header.
const RESPONSE_CODE_AT: usize = 6;

/// Offset of the first property's value in a `TPMS_CAPABILITY_DATA` reply.
///
/// The reply header takes ten bytes, then `moreData` one, the capability selector
/// four, the property count four, and the property's own tag four.
const PROPERTY_VALUE_AT: usize = 23;

/// Response code a TPM returns when it accepted a command.
const RC_SUCCESS: u32 = 0;

/// Length of the command, which its own `size` field has to repeat.
const COMMAND_LEN: u32 = 22;

/// Offset of the command's `size` field.
const SIZE_AT: usize = 2;

/// Offset of the command code.
const CODE_AT: usize = 6;

/// Offset of the capability selector.
const CAPABILITY_AT: usize = 10;

/// Offset of the first property to report.
const PROPERTY_AT: usize = 14;

/// Offset of the count of properties to report.
const COUNT_AT: usize = 18;

/// `TPM2_GetCapability` asking for exactly the manufacturer property.
pub const GET_MANUFACTURER: [u8; COMMAND_LEN as usize] = command();

/// The vendor identifier a TPM reports in `TPM_PT_MANUFACTURER`.
pub struct Manufacturer([u8; 4]);

/// Why a manufacturer query could not be answered.
#[derive(Clone, Copy, Debug)]
pub enum ReplyError {
    /// The reply is shorter than the fields it has to carry.
    Truncated,
    /// The TPM refused the command with this response code.
    Refused(u32),
}

/// Decodes a `TPM2_GetCapability` reply into the manufacturer it reports.
///
/// # Errors
///
/// Fails if the TPM refused the command or if the reply stops short of the
/// property it should contain.
pub fn manufacturer(reply: &[u8]) -> Result<Manufacturer, ReplyError> {
    let code = field(reply, RESPONSE_CODE_AT).ok_or(ReplyError::Truncated)?;
    if code != RC_SUCCESS {
        return Err(ReplyError::Refused(code));
    }

    let value = field(reply, PROPERTY_VALUE_AT).ok_or(ReplyError::Truncated)?;
    Ok(Manufacturer(value.to_be_bytes()))
}

impl fmt::Display for Manufacturer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The field holds four characters padded with NUL or space, but nothing
        // obliges a vendor to put text there, so anything that is not printable
        // ASCII is shown as the raw value. An embedded NUL matters in particular:
        // the firmware console cannot be handed one.
        let text = self.0.split(|byte| *byte == 0).next().unwrap_or_default();

        match str::from_utf8(text) {
            Ok(text)
                if text
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ') =>
            {
                f.write_str(text.trim_end())
            }
            _ => write!(f, "{:#010x}", u32::from_be_bytes(self.0)),
        }
    }
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the reply is truncated"),
            Self::Refused(code) => write!(f, "the TPM returned response code {code:#010x}"),
        }
    }
}

/// Builds the command buffer at compile time.
const fn command() -> [u8; COMMAND_LEN as usize] {
    let mut buffer = [0_u8; COMMAND_LEN as usize];

    let tag = TAG_NO_SESSIONS.to_be_bytes();
    buffer[0] = tag[0];
    buffer[1] = tag[1];

    put(&mut buffer, SIZE_AT, COMMAND_LEN);
    put(&mut buffer, CODE_AT, CC_GET_CAPABILITY);
    put(&mut buffer, CAPABILITY_AT, CAP_TPM_PROPERTIES);
    put(&mut buffer, PROPERTY_AT, PT_MANUFACTURER);
    put(&mut buffer, COUNT_AT, 1);

    buffer
}

/// Writes `value` big-endian at `offset` within the command buffer.
const fn put(buffer: &mut [u8; COMMAND_LEN as usize], offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    buffer[offset] = bytes[0];
    buffer[offset + 1] = bytes[1];
    buffer[offset + 2] = bytes[2];
    buffer[offset + 3] = bytes[3];
}

/// Reads the big-endian `u32` at `offset`, or [`None`] past the end.
fn field(reply: &[u8], offset: usize) -> Option<u32> {
    let bytes = reply.get(offset..offset.checked_add(size_of::<u32>())?)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}
