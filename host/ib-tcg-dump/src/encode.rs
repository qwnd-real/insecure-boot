//! Encoding a replay dump.
//!
//! Every table is fixed-stride and every variable-length run lives in a heap
//! after them, so the four table bases follow from three counts that are known
//! before anything is written: the number of banks, the number of records, and
//! the total number of digests those records carry. Offsets are therefore
//! absolute from the first pass and nothing has to be patched afterwards.

use ib_tcglog::Algorithm;
use ib_tcglog::layout::{BankEntry, DigestEntry, EventEntry, Header};

use crate::error::{Error, Result};
use crate::tcg::EventLog;

/// The expected PCR values one bank folds to.
#[derive(Debug)]
pub struct Expected {
    /// Hash the bank uses.
    pub algorithm: Algorithm,
    /// Length of a digest in this bank, in bytes.
    pub digest_size: usize,
    /// The PCR0-7 values, in index order, each `digest_size` bytes long.
    pub values: Vec<Vec<u8>>,
}

/// Encodes `log` and the expected values of `banks` as a replay dump.
///
/// # Errors
///
/// Fails if the log describes more banks, records or bytes than the format can
/// address.
pub fn encode(log: &EventLog, banks: &[Expected]) -> Result<Vec<u8>> {
    let digest_count: usize = log.records.iter().map(|record| record.digests.len()).sum();

    let banks_at = u64::from(Header::SIZE);
    let events_at = banks_at + table_size(banks.len(), BankEntry::SIZE);
    let digests_at = events_at + table_size(log.records.len(), EventEntry::SIZE);
    let heap_at = digests_at + table_size(digest_count, DigestEntry::SIZE);

    let mut heap = Vec::new();
    let mut push = |value: &[u8]| -> Result<u32> {
        let at = heap_at + heap.len() as u64;
        heap.extend_from_slice(value);
        narrow(at)
    };

    let mut bank_entries = Vec::with_capacity(banks.len());
    for bank in banks {
        bank_entries.push(BankEntry {
            algorithm: bank.algorithm,
            digest_size: narrow16(bank.digest_size)?,
            expected_offset: push(&bank.values.concat())?,
        });
    }

    let mut event_entries = Vec::with_capacity(log.records.len());
    let mut digest_entries = Vec::with_capacity(digest_count);
    for record in &log.records {
        let digests_offset =
            narrow(digests_at + table_size(digest_entries.len(), DigestEntry::SIZE))?;

        for digest in &record.digests {
            digest_entries.push(DigestEntry {
                algorithm: digest.algorithm,
                digest_size: narrow16(digest.bytes.len())?,
                digest_offset: push(&digest.bytes)?,
            });
        }

        event_entries.push(EventEntry {
            pcr_index: record.pcr_index,
            event_type: record.event_type,
            flags: record.flags,
            digest_count: narrow(record.digests.len() as u64)?,
            digests_offset,
            data_offset: push(&record.data)?,
            data_size: narrow(record.data.len() as u64)?,
        });
    }

    let header = Header {
        total_size: narrow(heap_at + heap.len() as u64)?,
        banks_offset: narrow(banks_at)?,
        events_offset: narrow(events_at)?,
        event_count: narrow(event_entries.len() as u64)?,
        startup_locality: log.startup_locality,
        bank_count: u8::try_from(bank_entries.len()).map_err(|_| Error::Unrepresentable)?,
    };

    let mut bytes = Vec::with_capacity(header.total_size as usize);
    bytes.extend_from_slice(&header.encode());
    bytes.extend(bank_entries.iter().flat_map(BankEntry::encode));
    bytes.extend(event_entries.iter().flat_map(EventEntry::encode));
    bytes.extend(digest_entries.iter().flat_map(DigestEntry::encode));
    bytes.extend_from_slice(&heap);

    Ok(bytes)
}

/// Length of a table of `count` entries of `entry` bytes each.
fn table_size(count: usize, entry: u32) -> u64 {
    count as u64 * u64::from(entry)
}

/// Narrows an offset or length to the width the format stores it in.
fn narrow(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Unrepresentable)
}

/// Narrows a digest length to the width the format stores it in.
fn narrow16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::Unrepresentable)
}
