//! Parsing the TCG event log a platform publishes.
//!
//! Two shapes exist. A crypto-agile log opens with a `TCG_PCR_EVENT`, the record
//! structure that predates crypto agility, whose event data is a
//! `TCG_EfiSpecIDEvent` naming every bank the firmware measured into; every
//! record after it is a `TCG_PCR_EVENT2` carrying one digest per bank. A log
//! that opens with anything else is the older shape, where every record is a
//! `TCG_PCR_EVENT` with a single SHA-1 digest.
//!
//! Both are parsed strictly: the log has to end exactly where its last record
//! does, because every interface this tool reads it through reports its length
//! exactly.

use ib_tcglog::{Algorithm, EventFlags, EventType, PCR_COUNT};

use crate::error::{Error, Result};

/// Signature the specification identifier event of a crypto-agile log carries.
const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

/// Signature of the `EV_NO_ACTION` record that names the startup locality.
const STARTUP_LOCALITY_SIGNATURE: &[u8; 16] = b"StartupLocality\0";

/// Length of the digest field of a `TCG_PCR_EVENT`.
const LEGACY_DIGEST_SIZE: usize = 20;

/// Locality `TPM2_Startup` is issued from unless a record says otherwise.
const DEFAULT_STARTUP_LOCALITY: u8 = 0;

/// A parsed event log.
#[derive(Debug)]
pub struct EventLog {
    /// Banks the log measured into, in the order it declared them.
    pub banks: Vec<Bank>,
    /// Locality of the `TPM2_Startup` that reset PCR0.
    pub startup_locality: u8,
    /// Records measured into PCR0 through PCR7, in log order.
    pub records: Vec<Record>,
    /// Records the log held for PCRs outside that range.
    pub skipped: usize,
    /// Whether the log used the crypto-agile record structure.
    pub agile: bool,
}

/// A PCR bank the log measured into.
#[derive(Clone, Copy, Debug)]
pub struct Bank {
    /// Hash the bank uses.
    pub algorithm: Algorithm,
    /// Length of a digest in this bank, in bytes.
    pub digest_size: usize,
}

/// One record of the log.
#[derive(Debug)]
pub struct Record {
    /// PCR the record was measured into.
    pub pcr_index: u32,
    /// Type of the event.
    pub event_type: EventType,
    /// How the log encoded the record.
    pub flags: EventFlags,
    /// Digests the record carries, in the order the log wrote them.
    pub digests: Vec<Digest>,
    /// Event data, exactly as the log carried it.
    pub data: Vec<u8>,
}

/// One digest a record carries.
#[derive(Debug)]
pub struct Digest {
    /// Hash that produced the digest.
    pub algorithm: Algorithm,
    /// The digest itself.
    pub bytes: Vec<u8>,
}

/// Parses the event log `bytes` holds, keeping the records for PCR0 through
/// PCR7.
///
/// # Errors
///
/// Fails if a record is truncated, if a record carries a digest of an algorithm
/// the log never declared, or if anything follows the last record.
pub fn parse(bytes: &[u8]) -> Result<EventLog> {
    let mut reader = Reader::new(bytes);
    let first = legacy_record(&mut reader)?;

    let (banks, agile) = match spec_id_banks(&first.data, 0)? {
        Some(banks) => (banks, true),
        None => (vec![Bank::SHA1], false),
    };

    let mut records = vec![first];
    while !reader.done() {
        records.push(if agile {
            agile_record(&mut reader, &banks)?
        } else {
            legacy_record(&mut reader)?
        });
    }

    let total = records.len();
    records.retain(|record| record.pcr_index < PCR_COUNT);

    Ok(EventLog {
        banks,
        startup_locality: startup_locality(&records).unwrap_or(DEFAULT_STARTUP_LOCALITY),
        skipped: total - records.len(),
        records,
        agile,
    })
}

impl Bank {
    /// The single bank a log that predates crypto agility measures into.
    const SHA1: Self = Self {
        algorithm: Algorithm::SHA1,
        digest_size: LEGACY_DIGEST_SIZE,
    };
}

impl Record {
    /// Whether replaying the log means extending this record into its PCR.
    pub fn extends_pcr(&self) -> bool {
        self.event_type != EventType::NO_ACTION
    }

    /// The digest the record carries for `algorithm`.
    pub fn digest(&self, algorithm: Algorithm) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|digest| digest.algorithm == algorithm)
            .map(|digest| digest.bytes.as_slice())
    }
}

/// Reads one `TCG_PCR_EVENT2`, the record structure of a crypto-agile log.
fn agile_record(reader: &mut Reader<'_>, banks: &[Bank]) -> Result<Record> {
    let at = reader.position();
    let malformed = |reason| Error::MalformedLog { offset: at, reason };

    let pcr_index = reader.u32().ok_or_else(|| malformed("a PCR index"))?;
    let event_type = EventType::from_id(reader.u32().ok_or_else(|| malformed("an event type"))?);
    let count = reader.u32().ok_or_else(|| malformed("a digest count"))?;

    let mut digests = Vec::new();
    for _ in 0..count {
        let id = reader
            .u16()
            .ok_or_else(|| malformed("a digest algorithm"))?;
        let algorithm = Algorithm::from_id(id);
        let size = digest_size(algorithm, banks)
            .ok_or_else(|| malformed("a digest of an algorithm of unknown length"))?;

        digests.push(Digest {
            algorithm,
            bytes: reader
                .bytes(size)
                .ok_or_else(|| malformed("a digest"))?
                .to_vec(),
        });
    }

    Ok(Record {
        pcr_index,
        event_type,
        flags: EventFlags::empty(),
        digests,
        data: event_data(reader, at)?,
    })
}

/// Reads one `TCG_PCR_EVENT`, the record structure that predates crypto agility.
fn legacy_record(reader: &mut Reader<'_>) -> Result<Record> {
    let at = reader.position();
    let malformed = |reason| Error::MalformedLog { offset: at, reason };

    let pcr_index = reader.u32().ok_or_else(|| malformed("a PCR index"))?;
    let event_type = EventType::from_id(reader.u32().ok_or_else(|| malformed("an event type"))?);
    let digest = reader
        .bytes(LEGACY_DIGEST_SIZE)
        .ok_or_else(|| malformed("a digest"))?;

    Ok(Record {
        pcr_index,
        event_type,
        flags: EventFlags::LEGACY_ENCODING,
        digests: vec![Digest {
            algorithm: Algorithm::SHA1,
            bytes: digest.to_vec(),
        }],
        data: event_data(reader, at)?,
    })
}

/// Reads the length-prefixed event data that ends every record.
fn event_data(reader: &mut Reader<'_>, at: usize) -> Result<Vec<u8>> {
    let malformed = |reason| Error::MalformedLog { offset: at, reason };

    let size = reader
        .u32()
        .ok_or_else(|| malformed("an event data length"))?;
    let size = usize::try_from(size).map_err(|_| malformed("a usable event data length"))?;

    Ok(reader
        .bytes(size)
        .ok_or_else(|| malformed("the event data"))?
        .to_vec())
}

/// The banks a `TCG_EfiSpecIDEvent` declares, or [`None`] if `data` is not one.
///
/// `at` is the offset of the record the event data came from, for reporting.
fn spec_id_banks(data: &[u8], at: usize) -> Result<Option<Vec<Bank>>> {
    let mut reader = Reader::new(data);
    if reader.bytes(SPEC_ID_SIGNATURE.len()) != Some(&SPEC_ID_SIGNATURE[..]) {
        return Ok(None);
    }

    let malformed = || Error::MalformedLog {
        offset: at,
        reason: "a complete specification identifier event",
    };

    // platformClass, then specVersionMinor, specVersionMajor, specErrata and
    // uintnSize, none of which affect how the log is read.
    reader.skip(8).ok_or_else(malformed)?;

    let count = reader.u32().ok_or_else(malformed)?;
    let mut banks = Vec::new();
    for _ in 0..count {
        banks.push(Bank {
            algorithm: Algorithm::from_id(reader.u16().ok_or_else(malformed)?),
            digest_size: usize::from(reader.u16().ok_or_else(malformed)?),
        });
    }

    Ok(Some(banks))
}

/// Length of a digest of `algorithm`, preferring the length the log declared for
/// the bank over this tool's own idea of it.
fn digest_size(algorithm: Algorithm, banks: &[Bank]) -> Option<usize> {
    banks
        .iter()
        .find(|bank| bank.algorithm == algorithm)
        .map(|bank| bank.digest_size)
        .or_else(|| algorithm.digest_size())
}

/// The locality an `EV_NO_ACTION` record names, if the log carries one.
fn startup_locality(records: &[Record]) -> Option<u8> {
    records
        .iter()
        .filter(|record| !record.extends_pcr())
        .find_map(|record| {
            let (signature, rest) = record
                .data
                .split_at_checked(STARTUP_LOCALITY_SIGNATURE.len())?;

            (signature == STARTUP_LOCALITY_SIGNATURE)
                .then(|| rest.first().copied())
                .flatten()
        })
}

/// Reads little-endian fields out of a log, one after another, and stops at the
/// first field the log is too short to hold.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `bytes`.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Offset the next field will be read from.
    const fn position(&self) -> usize {
        self.at
    }

    /// Whether every byte has been consumed.
    const fn done(&self) -> bool {
        self.at >= self.bytes.len()
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

    /// Consumes and discards `len` bytes.
    fn skip(&mut self, len: usize) -> Option<()> {
        self.bytes(len).map(|_| ())
    }
}
