//! `TPM2_PCR_Extend` and `TPM2_PCR_Read`.
//!
//! Extending a PCR takes an authorization area, because the PCR is a handle the
//! command needs authorization for. The PCRs a platform measures into keep the
//! empty authorization value they come up with, so a password session carrying
//! no password is what the TPM expects, and it is what firmware uses as well.

use crate::codec::{Writer, byte, half, word};
use crate::{
    Algorithm, BANK_COUNT_MAX, DIGEST_LEN_MAX, Digest, HEADER_LEN, ReplyError, TAG_NO_SESSIONS,
    TAG_SESSIONS, accepted,
};

/// `TPM_CC_PCR_Extend`.
const CC_PCR_EXTEND: u32 = 0x0000_0182;

/// `TPM_CC_PCR_Read`.
const CC_PCR_READ: u32 = 0x0000_017E;

/// `TPM_RS_PW`, the handle of a password session.
const RS_PW: u32 = 0x4000_0009;

/// Length of a password authorization area, which the command states ahead of
/// it: a session handle, an empty nonce, no session attributes and an empty
/// HMAC, each preceded by its own length where it has one.
const AUTH_LEN: u32 = 9;

/// Bytes of PCR select bits a selection carries, one bit per PCR, PCR0 being the
/// low bit of the first byte.
const SELECT_LEN: u8 = 3;

/// Length of a `TPM2_PCR_Extend` without the digests it carries.
const EXTEND_FIXED_LEN: usize = HEADER_LEN
    + size_of::<u32>() // the PCR handle
    + size_of::<u32>() // the length of the authorization area
    + AUTH_LEN as usize
    + size_of::<u32>(); // the number of digests that follow

/// Length one digest of a `TPM2_PCR_Extend` takes, algorithm included.
const EXTEND_DIGEST_LEN_MAX: usize = size_of::<u16>() + DIGEST_LEN_MAX;

/// Length of a `TPM2_PCR_Read` asking about a single bank.
const READ_LEN: usize = HEADER_LEN
    + size_of::<u32>() // the number of selections that follow
    + size_of::<u16>() // the algorithm of the one selection that does
    + size_of::<u8>() // the length of its select bits
    + SELECT_LEN as usize;

/// Buffer a `TPM2_PCR_Extend` fits in, however many banks it extends at once.
pub const EXTEND_CAPACITY: usize = EXTEND_FIXED_LEN + BANK_COUNT_MAX * EXTEND_DIGEST_LEN_MAX;

/// Buffer a `TPM2_PCR_Read` fits in.
pub const READ_CAPACITY: usize = READ_LEN;

/// Buffer a reply to either command fits in, the larger being the value a
/// `TPM2_PCR_Read` returns: the header, the PCR update counter, the selection the
/// TPM echoes back, and one digest with its length.
pub const REPLY_CAPACITY: usize = HEADER_LEN
    + size_of::<u32>()
    + size_of::<u32>()
    + size_of::<u16>()
    + size_of::<u8>()
    + SELECT_LEN as usize
    + size_of::<u32>()
    + size_of::<u16>()
    + DIGEST_LEN_MAX;

/// Builds a `TPM2_PCR_Extend` that extends `pcr_index` with one digest per bank
/// in `digests`, and reports how long the command is.
///
/// Returns [`None`] if `buffer` cannot hold the command, which for no more than
/// [`BANK_COUNT_MAX`] digests of no more than [`DIGEST_LEN_MAX`] bytes means a
/// buffer smaller than [`EXTEND_CAPACITY`].
pub fn extend(buffer: &mut [u8], pcr_index: u32, digests: &[Digest<'_>]) -> Option<usize> {
    let carried: usize = digests
        .iter()
        .map(|digest| size_of::<u16>() + digest.bytes.len())
        .sum();

    let len = EXTEND_FIXED_LEN.checked_add(carried)?;
    let mut writer = Writer::new(buffer.get_mut(..len)?);

    writer.u16(TAG_SESSIONS);
    writer.u32(u32::try_from(len).ok()?);
    writer.u32(CC_PCR_EXTEND);
    writer.u32(pcr_index);
    writer.u32(AUTH_LEN);
    writer.u32(RS_PW);
    writer.u16(0); // an empty nonce
    writer.u8(0); // no session attributes
    writer.u16(0); // an empty HMAC
    writer.u32(u32::try_from(digests.len()).ok()?);

    for digest in digests {
        writer.u16(digest.algorithm.id());
        writer.bytes(digest.bytes);
    }

    Some(len)
}

/// Builds a `TPM2_PCR_Read` asking for `pcr_index` in the `algorithm` bank, and
/// reports how long the command is.
///
/// One PCR is asked for at a time because a TPM may answer with fewer values
/// than were selected, and a single value needs no such bookkeeping.
///
/// Returns [`None`] if `buffer` is smaller than [`READ_CAPACITY`], or if
/// `pcr_index` is outside the PCRs a selection can name.
pub fn read(buffer: &mut [u8], pcr_index: u32, algorithm: Algorithm) -> Option<usize> {
    let mut select = [0_u8; SELECT_LEN as usize];
    let bits = usize::try_from(pcr_index / u8::BITS).ok()?;
    *select.get_mut(bits)? |= 1 << (pcr_index % u8::BITS);

    let mut writer = Writer::new(buffer.get_mut(..READ_LEN)?);

    writer.u16(TAG_NO_SESSIONS);
    writer.u32(u32::try_from(READ_LEN).ok()?);
    writer.u32(CC_PCR_READ);
    writer.u32(1); // one selection follows
    writer.u16(algorithm.id());
    writer.u8(SELECT_LEN);
    writer.bytes(&select);

    Some(READ_LEN)
}

/// Reads the PCR value out of a `TPM2_PCR_Read` reply.
///
/// # Errors
///
/// Fails if the TPM refused the command, if it answered with no value at all, or
/// if the reply stops short of the value it announced.
pub fn value(reply: &[u8]) -> Result<&[u8], ReplyError> {
    accepted(reply)?;

    // The reply repeats the selection it was asked about before it gets to the
    // values, and how long that is depends on how many banks it names.
    let mut at = HEADER_LEN + size_of::<u32>();
    let selections = word(reply, at).ok_or(ReplyError::Truncated)?;
    at += size_of::<u32>();

    for _ in 0..selections {
        at += size_of::<u16>();
        let bits = byte(reply, at).ok_or(ReplyError::Truncated)?;
        at += size_of::<u8>() + usize::from(bits);
    }

    if word(reply, at).ok_or(ReplyError::Truncated)? == 0 {
        return Err(ReplyError::Empty);
    }
    at += size_of::<u32>();

    let len = usize::from(half(reply, at).ok_or(ReplyError::Truncated)?);
    at += size_of::<u16>();

    let end = at.checked_add(len).ok_or(ReplyError::Truncated)?;
    reply.get(at..end).ok_or(ReplyError::Truncated)
}
