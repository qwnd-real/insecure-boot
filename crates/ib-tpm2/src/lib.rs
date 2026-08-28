//! TPM 2.0 commands, and the replies they come back with.
//!
//! This is marshalling and nothing else: a command is built into a buffer the
//! caller owns, and a reply is read out of one, so nothing here allocates and
//! nothing here touches a device. Carrying the bytes is
//! [`ib_tpm_crb`](https://docs.rs/ib-tpm-crb)'s job.
//!
//! Field layouts are from the TPM 2.0 Library Specification, Part 3. Every field
//! is big-endian, which is the one thing the encoding keeps consistent.

#![no_std]

pub mod capability;
pub mod pcr;

mod codec;

use codec::word;
use thiserror::Error;

pub use ib_tcglog::Algorithm;

/// Longest digest any bank a TPM 2.0 implements produces.
pub const DIGEST_LEN_MAX: usize = 64;

/// Most PCR banks a TPM 2.0 can have allocated at once, which is as many as the
/// TCG registry defines hashes for.
pub const BANK_COUNT_MAX: usize = 5;

/// `TPM_ST_NO_SESSIONS`, the tag of a command that carries no session area.
pub const TAG_NO_SESSIONS: u16 = 0x8001;

/// `TPM_ST_SESSIONS`, the tag of a command that carries an authorization area.
pub const TAG_SESSIONS: u16 = 0x8002;

/// Length of a command or reply header: a tag, a length and a code.
pub const HEADER_LEN: usize = size_of::<u16>() + 2 * size_of::<u32>();

/// Offset of the code field shared by command and reply headers.
const CODE_AT: usize = size_of::<u16>() + size_of::<u32>();

/// Response code a TPM returns when it accepted a command.
const RC_SUCCESS: u32 = 0;

/// One digest a command carries, and the bank it belongs to.
#[derive(Clone, Copy, Debug)]
pub struct Digest<'a> {
    /// Bank the digest belongs to.
    pub algorithm: Algorithm,
    /// The digest itself.
    pub bytes: &'a [u8],
}

/// Why a reply could not be used.
#[derive(Clone, Copy, Debug, Error)]
pub enum ReplyError {
    /// The reply stops short of a field it has to carry.
    #[error("the reply is truncated")]
    Truncated,

    /// The TPM refused the command with this response code.
    #[error("the TPM returned response code {0:#010x}")]
    Refused(u32),

    /// The TPM accepted the command but answered with nothing to read.
    #[error("the TPM returned no value")]
    Empty,
}

/// Checks a reply header, and reports the response code if the TPM refused the
/// command.
///
/// # Errors
///
/// Fails if the reply is shorter than a header, or reports anything other than
/// success.
pub fn accepted(reply: &[u8]) -> Result<(), ReplyError> {
    match word(reply, CODE_AT) {
        None => Err(ReplyError::Truncated),
        Some(RC_SUCCESS) => Ok(()),
        Some(code) => Err(ReplyError::Refused(code)),
    }
}
