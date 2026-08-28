//! Byte layout of a replay dump.
//!
//! ```text
//! header, 36 bytes at offset 0
//!   0x00  magic             [u8; 8]  "IBTCGLOG"
//!   0x08  version           u32      format revision
//!   0x0c  header_size       u32      36
//!   0x10  total_size        u32      length of the whole dump
//!   0x14  banks_offset      u32      offset of the bank table
//!   0x18  events_offset     u32      offset of the event table
//!   0x1c  event_count       u32      entries in the event table
//!   0x20  startup_locality  u8       locality of the TPM2_Startup that reset PCR0
//!   0x21  bank_count        u8       entries in the bank table
//!   0x22  reserved          [u8; 2]  zero, keeping the header a multiple of four
//!
//! bank table, 8 bytes per entry
//!   0x00  algorithm         u16      TPM_ALG_ID of the bank
//!   0x02  digest_size       u16      digest length of that algorithm
//!   0x04  expected_offset   u32      offset of PCR_COUNT * digest_size bytes,
//!                                    the PCR0..PCR7 values the log folds to
//!
//! event table, 28 bytes per entry, in log order
//!   0x00  pcr_index         u32      0 through 7
//!   0x04  event_type        u32      TCG EV_* event type
//!   0x08  flags             u32      see EventFlags
//!   0x0c  digest_count      u32      digest descriptors for this event
//!   0x10  digests_offset    u32      offset of the first digest descriptor
//!   0x14  data_offset       u32      offset of the event data
//!   0x18  data_size         u32      length of the event data
//!
//! digest descriptor, 8 bytes per entry, contiguous per event, in log order
//!   0x00  algorithm         u16      TPM_ALG_ID of the digest
//!   0x02  digest_size       u16      length of the digest
//!   0x04  digest_offset     u32      offset of the digest bytes
//! ```
//!
//! Digests, event data and expected PCR values live in a heap the tables point
//! into. Nothing obliges those regions to be ordered or unshared, so a reader
//! has to follow the offsets rather than assume adjacency.

use crate::{Algorithm, Error, Result};

use bitflags::bitflags;
use core::fmt;

/// Signature every dump begins with.
pub const MAGIC: [u8; 8] = *b"IBTCGLOG";

/// Format revision this crate reads and writes.
pub const VERSION: u32 = 1;

/// A TCG `EV_*` event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventType(u32);

impl EventType {
    /// `EV_NO_ACTION`, an informational record.
    ///
    /// The TCG PC Client Platform Firmware Profile keeps these out of the PCRs
    /// entirely and leaves their digest fields zero, so a replay has to walk
    /// past them rather than extend them.
    pub const NO_ACTION: Self = Self(0x0000_0003);

    /// Wraps a raw event type.
    #[must_use]
    pub const fn from_id(id: u32) -> Self {
        Self(id)
    }

    /// The raw event type.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.0
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

bitflags! {
    /// How the log encoded an event.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EventFlags: u32 {
        /// The log recorded the event as a `TCG_PCR_EVENT`, the structure that
        /// predates crypto agility and carries a single fixed-width digest,
        /// rather than as a `TCG_PCR_EVENT2`. Normally only the log's leading
        /// specification identifier event is written that way, and reproducing
        /// the log byte for byte means writing it back the same way.
        const LEGACY_ENCODING = 1 << 0;
    }
}

/// Fixed header at the start of a dump.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// Length of the whole dump in bytes.
    pub total_size: u32,
    /// Offset of the bank table.
    pub banks_offset: u32,
    /// Offset of the event table.
    pub events_offset: u32,
    /// Number of entries in the event table.
    pub event_count: u32,
    /// Locality of the `TPM2_Startup` that reset PCR0 on the dumped platform.
    pub startup_locality: u8,
    /// Number of entries in the bank table.
    pub bank_count: u8,
}

impl Header {
    /// Length of an encoded header in bytes.
    pub const SIZE: u32 = 36;

    /// Encodes the header as it appears at the start of a dump.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE as usize] {
        let mut bytes = [0_u8; Self::SIZE as usize];
        let mut writer = Writer::new(&mut bytes);

        writer.bytes(&MAGIC);
        writer.u32(VERSION);
        writer.u32(Self::SIZE);
        writer.u32(self.total_size);
        writer.u32(self.banks_offset);
        writer.u32(self.events_offset);
        writer.u32(self.event_count);
        writer.u8(self.startup_locality);
        writer.u8(self.bank_count);

        bytes
    }

    /// Decodes the header from the start of a dump.
    ///
    /// # Errors
    ///
    /// Fails if the signature or the version does not match, or if the header is
    /// shorter than the format requires.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);

        if reader.bytes(MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(Error::NotADump);
        }

        let version = reader.u32().ok_or(Error::MalformedHeader)?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion {
                found: version,
                expected: VERSION,
            });
        }

        let header_size = reader.u32().ok_or(Error::MalformedHeader)?;
        if header_size != Self::SIZE {
            return Err(Error::MalformedHeader);
        }

        Self::fields(&mut reader).ok_or(Error::MalformedHeader)
    }

    /// Reads the fields that follow the signature, the version and the header
    /// length, all three of which [`Header::decode`] has already consumed.
    fn fields(reader: &mut Reader<'_>) -> Option<Self> {
        Some(Self {
            total_size: reader.u32()?,
            banks_offset: reader.u32()?,
            events_offset: reader.u32()?,
            event_count: reader.u32()?,
            startup_locality: reader.u8()?,
            bank_count: reader.u8()?,
        })
    }
}

/// One entry of the bank table, describing a PCR bank the log measured into.
#[derive(Clone, Copy, Debug)]
pub struct BankEntry {
    /// Hash the bank uses.
    pub algorithm: Algorithm,
    /// Length of a digest in this bank, in bytes.
    pub digest_size: u16,
    /// Offset of the expected PCR0..PCR7 values, `PCR_COUNT` digests in index
    /// order.
    pub expected_offset: u32,
}

impl BankEntry {
    /// Length of an encoded entry in bytes.
    pub const SIZE: u32 = 8;

    /// Encodes the entry.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE as usize] {
        let mut bytes = [0_u8; Self::SIZE as usize];
        let mut writer = Writer::new(&mut bytes);

        writer.u16(self.algorithm.id());
        writer.u16(self.digest_size);
        writer.u32(self.expected_offset);

        bytes
    }

    /// Decodes the entry that starts at the beginning of `bytes`, or [`None`] if
    /// fewer than [`BankEntry::SIZE`] bytes are available.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);

        Some(Self {
            algorithm: Algorithm::from_id(reader.u16()?),
            digest_size: reader.u16()?,
            expected_offset: reader.u32()?,
        })
    }
}

/// One entry of the event table, describing a single record of the log.
#[derive(Clone, Copy, Debug)]
pub struct EventEntry {
    /// PCR the event was measured into.
    pub pcr_index: u32,
    /// Type of the event.
    pub event_type: EventType,
    /// How the log encoded the event.
    pub flags: EventFlags,
    /// Number of digest descriptors the event carries.
    pub digest_count: u32,
    /// Offset of the event's first digest descriptor.
    pub digests_offset: u32,
    /// Offset of the event data.
    pub data_offset: u32,
    /// Length of the event data in bytes.
    pub data_size: u32,
}

impl EventEntry {
    /// Length of an encoded entry in bytes.
    pub const SIZE: u32 = 28;

    /// Encodes the entry.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE as usize] {
        let mut bytes = [0_u8; Self::SIZE as usize];
        let mut writer = Writer::new(&mut bytes);

        writer.u32(self.pcr_index);
        writer.u32(self.event_type.id());
        writer.u32(self.flags.bits());
        writer.u32(self.digest_count);
        writer.u32(self.digests_offset);
        writer.u32(self.data_offset);
        writer.u32(self.data_size);

        bytes
    }

    /// Decodes the entry that starts at the beginning of `bytes`, or [`None`] if
    /// fewer than [`EventEntry::SIZE`] bytes are available.
    ///
    /// Flag bits this revision does not define are dropped rather than rejected,
    /// so a reader keeps working on a dump that records more about an encoding
    /// than it understands.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);

        Some(Self {
            pcr_index: reader.u32()?,
            event_type: EventType::from_id(reader.u32()?),
            flags: EventFlags::from_bits_truncate(reader.u32()?),
            digest_count: reader.u32()?,
            digests_offset: reader.u32()?,
            data_offset: reader.u32()?,
            data_size: reader.u32()?,
        })
    }
}

/// One digest descriptor, pointing at the digest an event recorded for one bank.
#[derive(Clone, Copy, Debug)]
pub struct DigestEntry {
    /// Hash that produced the digest.
    pub algorithm: Algorithm,
    /// Length of the digest in bytes.
    pub digest_size: u16,
    /// Offset of the digest bytes.
    pub digest_offset: u32,
}

impl DigestEntry {
    /// Length of an encoded descriptor in bytes.
    pub const SIZE: u32 = 8;

    /// Encodes the descriptor.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE as usize] {
        let mut bytes = [0_u8; Self::SIZE as usize];
        let mut writer = Writer::new(&mut bytes);

        writer.u16(self.algorithm.id());
        writer.u16(self.digest_size);
        writer.u32(self.digest_offset);

        bytes
    }

    /// Decodes the descriptor that starts at the beginning of `bytes`, or
    /// [`None`] if fewer than [`DigestEntry::SIZE`] bytes are available.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);

        Some(Self {
            algorithm: Algorithm::from_id(reader.u16()?),
            digest_size: reader.u16()?,
            digest_offset: reader.u32()?,
        })
    }
}

/// Writes little-endian fields into a buffer, one after another.
///
/// The buffer is always exactly as long as the layout being written, so the
/// writes are in bounds by construction.
struct Writer<'a> {
    bytes: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    /// Starts writing at the beginning of `bytes`.
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Appends one byte.
    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    /// Appends a little-endian `u16`.
    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    /// Appends a little-endian `u32`.
    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    /// Appends `value` verbatim.
    fn bytes(&mut self, value: &[u8]) {
        let end = self.at + value.len();
        self.bytes[self.at..end].copy_from_slice(value);
        self.at = end;
    }
}

/// Reads little-endian fields out of a buffer, one after another, and stops at
/// the first field the buffer is too short to hold.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `bytes`.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Consumes one byte.
    fn u8(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    /// Consumes a little-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(2)?.try_into().ok()?))
    }

    /// Consumes a little-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }

    /// Consumes `len` bytes verbatim.
    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let value = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(value)
    }
}
