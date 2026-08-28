//! The crypto-agile event log the protocol hands out, and the records it is made
//! of.
//!
//! A log opens with a `TCG_PCR_EVENT`, the record structure that predates crypto
//! agility, whose event data is a `TCG_EfiSpecIDEvent` naming every bank the
//! platform measures into. Every record after it is a `TCG_PCR_EVENT2` carrying
//! one digest per bank. Both are little-endian and neither is aligned.
//!
//! The log is allocated once, with room to spare, and never moves: its address
//! goes to whoever calls `GetEventLog`, and a reallocation would leave them
//! holding a stale pointer. Once the spare room runs out the log reports itself
//! truncated rather than growing.

use alloc::vec;
use alloc::vec::Vec;

use ib_tcglog::{Algorithm, Dump, EventFlags};
use ib_tpm2::Digest;

use crate::{Error, Result};

/// Signature the specification identifier event of a crypto-agile log carries.
const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// Length of the digest field of a `TCG_PCR_EVENT`.
const LEGACY_DIGEST_LEN: usize = 20;

/// `EV_NO_ACTION`, the type of the record that opens a log and of every other
/// record a replay walks past rather than extends.
const EV_NO_ACTION: u32 = 0x0000_0003;

/// Major revision of the PC Client profile a synthesized log declares.
const SPEC_VERSION_MAJOR: u8 = 2;

/// Minor revision of the PC Client profile a synthesized log declares.
const SPEC_VERSION_MINOR: u8 = 0;

/// Errata revision of the PC Client profile a synthesized log declares.
const SPEC_ERRATA: u8 = 0;

/// Width of a `UINTN` as the profile records it: 1 for 32-bit firmware, 2 for
/// 64-bit.
const UINTN_SIZE: u8 = 2;

/// A crypto-agile event log, allocated once and appended to in place.
pub struct Log {
    bytes: Vec<u8>,
    last: Option<usize>,
    truncated: bool,
}

impl Log {
    /// Builds the log the platform starts out with.
    ///
    /// With a `dump` the log is the one that dump was taken from, reproduced
    /// record for record so that whoever reads it sees what the dumped platform
    /// measured. Without one it holds a single specification identifier event
    /// declaring `banks`, which is the least a log can be and still be one.
    ///
    /// `headroom` is how many bytes of room to leave for records measured later.
    ///
    /// # Errors
    ///
    /// Fails if the dump cannot be walked, or if a bank uses a hash of a length
    /// this crate does not know.
    pub fn new(dump: Option<&Dump<'_>>, banks: &[Algorithm], headroom: usize) -> Result<Self> {
        let entries = match dump {
            Some(dump) => replayed(dump)?,
            None => vec![spec_id(banks)?],
        };

        let mut bytes = Vec::new();
        let mut last = None;
        for entry in &entries {
            last = Some(bytes.len());
            bytes.extend_from_slice(entry);
        }

        bytes.reserve_exact(headroom);

        Ok(Self {
            bytes,
            last,
            truncated: false,
        })
    }

    /// Address the log starts at, which is what `GetEventLog` reports.
    #[must_use]
    pub fn address(&self) -> u64 {
        address(self.bytes.as_ptr())
    }

    /// Address of the last record in the log, or zero if it holds none.
    #[must_use]
    pub fn last_entry(&self) -> u64 {
        match self.last {
            None => 0,
            Some(at) => self.address() + at as u64,
        }
    }

    /// Whether a record has been dropped for want of room.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Length of the log in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Room left for further records, in bytes.
    #[must_use]
    pub fn spare(&self) -> usize {
        self.bytes.capacity() - self.bytes.len()
    }

    /// Appends an already encoded record, and reports whether it fitted.
    ///
    /// A record that does not fit marks the log truncated, which is what
    /// `GetEventLog` then reports, and is dropped rather than growing the log out
    /// from under a caller holding its address.
    pub fn append(&mut self, entry: &[u8]) -> bool {
        if entry.len() > self.spare() {
            self.truncated = true;
            return false;
        }

        self.last = Some(self.bytes.len());
        self.bytes.extend_from_slice(entry);

        true
    }
}

/// Encodes a record as the `TCG_PCR_EVENT2` that every record of a crypto-agile
/// log after the first one is.
///
/// # Errors
///
/// Fails if the record carries more digests or more event data than the structure
/// can describe.
pub fn event2(
    pcr_index: u32,
    event_type: u32,
    digests: &[Digest<'_>],
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&pcr_index.to_le_bytes());
    bytes.extend_from_slice(&event_type.to_le_bytes());
    bytes.extend_from_slice(&count(digests.len())?.to_le_bytes());

    for digest in digests {
        bytes.extend_from_slice(&digest.algorithm.id().to_le_bytes());
        bytes.extend_from_slice(digest.bytes);
    }

    bytes.extend_from_slice(&count(data.len())?.to_le_bytes());
    bytes.extend_from_slice(data);

    Ok(bytes)
}

/// Encodes a record as the `TCG_PCR_EVENT` that opens a log, whose single digest
/// field is of a fixed width and so is padded or clipped to it.
///
/// # Errors
///
/// Fails if the record carries more event data than the structure can describe.
pub fn event1(pcr_index: u32, event_type: u32, digest: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut fixed = [0_u8; LEGACY_DIGEST_LEN];
    let len = digest.len().min(LEGACY_DIGEST_LEN);
    if let (Some(room), Some(digest)) = (fixed.get_mut(..len), digest.get(..len)) {
        room.copy_from_slice(digest);
    }

    let mut bytes = Vec::new();

    bytes.extend_from_slice(&pcr_index.to_le_bytes());
    bytes.extend_from_slice(&event_type.to_le_bytes());
    bytes.extend_from_slice(&fixed);
    bytes.extend_from_slice(&count(data.len())?.to_le_bytes());
    bytes.extend_from_slice(data);

    Ok(bytes)
}

/// Reproduces the records of the log `dump` was taken from, in log order.
fn replayed(dump: &Dump<'_>) -> Result<Vec<Vec<u8>>> {
    let mut entries = Vec::new();

    for event in dump.events() {
        let event = event?;

        let mut digests = Vec::new();
        for digest in event.digests() {
            let digest = digest?;
            digests.push(Digest {
                algorithm: digest.algorithm(),
                bytes: digest.bytes(),
            });
        }

        let (pcr_index, event_type) = (event.pcr_index(), event.event_type().id());
        entries.push(if event.flags().contains(EventFlags::LEGACY_ENCODING) {
            let digest = event.digest(Algorithm::SHA1).unwrap_or_default();
            event1(pcr_index, event_type, digest, event.data())?
        } else {
            event2(pcr_index, event_type, &digests, event.data())?
        });
    }

    Ok(entries)
}

/// Builds the specification identifier event a log with no records of its own
/// still has to open with.
fn spec_id(banks: &[Algorithm]) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    data.extend_from_slice(SPEC_ID_SIGNATURE);
    data.extend_from_slice(&0_u32.to_le_bytes()); // no platform class
    data.push(SPEC_VERSION_MINOR);
    data.push(SPEC_VERSION_MAJOR);
    data.push(SPEC_ERRATA);
    data.push(UINTN_SIZE);
    data.extend_from_slice(&count(banks.len())?.to_le_bytes());

    for bank in banks {
        let len = bank.digest_size().ok_or(Error::UnsupportedBank(*bank))?;
        data.extend_from_slice(&bank.id().to_le_bytes());
        data.extend_from_slice(&width(len)?.to_le_bytes());
    }

    data.push(0); // no vendor information

    event1(0, EV_NO_ACTION, &[0; LEGACY_DIGEST_LEN], &data)
}

/// Narrows a count or a length to the width a log records it in.
fn count(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::EventTooLarge(value))
}

/// Narrows a digest length to the width a log records it in.
fn width(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::EventTooLarge(value))
}

/// The address a pointer refers to, which before boot services are exited is the
/// physical address as well.
fn address(pointer: *const u8) -> u64 {
    pointer.addr() as u64
}
