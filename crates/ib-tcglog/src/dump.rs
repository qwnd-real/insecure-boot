//! Reading a replay dump.
//!
//! [`Dump::parse`] checks the header and the two tables, which is everything a
//! caller needs before it can ask how many events there are or which banks the
//! platform measured into. The heap regions each event points at are checked as
//! that event is reached, so a dump is walked once and no part of it is copied.

use crate::layout::{BankEntry, DigestEntry, EventEntry, EventFlags, EventType, Header};
use crate::{Algorithm, Error, PCR_COUNT, Result};

/// A replay dump, borrowed from the bytes it was read out of.
#[derive(Clone, Copy, Debug)]
pub struct Dump<'a> {
    bytes: &'a [u8],
    header: Header,
}

impl<'a> Dump<'a> {
    /// Parses the dump `bytes` holds.
    ///
    /// # Errors
    ///
    /// Fails if the signature, the version or the declared length do not match,
    /// or if either table falls outside the dump.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = Header::decode(bytes)?;

        if usize::try_from(header.total_size).unwrap_or(usize::MAX) != bytes.len() {
            return Err(Error::SizeMismatch {
                declared: header.total_size,
                actual: bytes.len(),
            });
        }

        let dump = Self { bytes, header };
        dump.table(
            header.banks_offset,
            u32::from(header.bank_count),
            BankEntry::SIZE,
        )?;
        dump.table(header.events_offset, header.event_count, EventEntry::SIZE)?;

        Ok(dump)
    }

    /// Locality of the `TPM2_Startup` that reset PCR0 on the dumped platform.
    ///
    /// PCR0 starts a boot holding this value rather than zero, so a replay that
    /// only extends can reproduce PCR0 exactly when it is zero and cannot when
    /// it is anything else.
    #[must_use]
    pub const fn startup_locality(&self) -> u8 {
        self.header.startup_locality
    }

    /// Number of events the dump carries.
    #[must_use]
    pub const fn event_count(&self) -> u32 {
        self.header.event_count
    }

    /// The bank whose expected PCR values the dump records for `algorithm`.
    ///
    /// # Errors
    ///
    /// Fails if the dump describes no such bank, or if the bank table or the
    /// expected values it points at are malformed.
    pub fn bank(&self, algorithm: Algorithm) -> Result<Bank<'a>> {
        self.banks()
            .find(|bank| {
                bank.as_ref()
                    .is_ok_and(|bank| bank.algorithm() == algorithm)
            })
            .unwrap_or(Err(Error::MissingBank(algorithm)))
    }

    /// The banks the dump records expected PCR values for.
    #[must_use]
    pub const fn banks(&self) -> Banks<'a> {
        Banks {
            dump: *self,
            next: 0,
        }
    }

    /// The events the dump carries, in the order the log recorded them.
    #[must_use]
    pub const fn events(&self) -> Events<'a> {
        Events {
            dump: *self,
            next: 0,
        }
    }

    /// Decodes the `index`th bank of the bank table.
    fn decode_bank(&self, index: u32) -> Result<Bank<'a>> {
        let entry = self.entry(
            self.header.banks_offset,
            index,
            BankEntry::SIZE,
            BankEntry::decode,
        )?;

        // A digest is at most 65535 bytes long, so eight of them cannot overflow.
        let expected = self.region(
            entry.expected_offset,
            u32::from(entry.digest_size) * PCR_COUNT,
        )?;

        Ok(Bank {
            algorithm: entry.algorithm,
            digest_size: usize::from(entry.digest_size),
            expected,
        })
    }

    /// Decodes the `index`th event of the event table, and the heap regions it
    /// points at.
    fn decode_event(&self, index: u32) -> Result<Event<'a>> {
        let entry = self.entry(
            self.header.events_offset,
            index,
            EventEntry::SIZE,
            EventEntry::decode,
        )?;

        if entry.pcr_index >= PCR_COUNT {
            return Err(Error::PcrOutOfRange(entry.pcr_index));
        }

        let data = self.region(entry.data_offset, entry.data_size)?;
        self.table(entry.digests_offset, entry.digest_count, DigestEntry::SIZE)?;

        Ok(Event {
            dump: *self,
            index,
            entry,
            data,
        })
    }

    /// Decodes the `index`th digest descriptor of `event`, and the digest it
    /// points at.
    fn decode_digest(&self, event: &EventEntry, index: u32) -> Result<Digest<'a>> {
        let entry = self.entry(
            event.digests_offset,
            index,
            DigestEntry::SIZE,
            DigestEntry::decode,
        )?;

        Ok(Digest {
            algorithm: entry.algorithm,
            bytes: self.region(entry.digest_offset, u32::from(entry.digest_size))?,
        })
    }

    /// Decodes the `index`th entry of a table of `stride`-byte entries.
    fn entry<T>(
        &self,
        offset: u32,
        index: u32,
        stride: u32,
        decode: fn(&[u8]) -> Option<T>,
    ) -> Result<T> {
        let out_of_bounds = || Error::OutOfBounds {
            offset,
            len: stride,
        };

        let at = index
            .checked_mul(stride)
            .and_then(|skip| offset.checked_add(skip))
            .ok_or_else(out_of_bounds)?;

        decode(self.region(at, stride)?).ok_or_else(out_of_bounds)
    }

    /// Checks that a table of `count` entries of `stride` bytes each fits inside
    /// the dump.
    fn table(&self, offset: u32, count: u32, stride: u32) -> Result<&'a [u8]> {
        let len = count.checked_mul(stride).ok_or(Error::OutOfBounds {
            offset,
            len: stride,
        })?;

        self.region(offset, len)
    }

    /// Resolves the `len` bytes at `offset`, which have to lie inside the dump.
    fn region(&self, offset: u32, len: u32) -> Result<&'a [u8]> {
        let out_of_bounds = || Error::OutOfBounds { offset, len };

        let start = usize::try_from(offset).map_err(|_| out_of_bounds())?;
        let len = usize::try_from(len).map_err(|_| out_of_bounds())?;
        let end = start.checked_add(len).ok_or_else(out_of_bounds)?;

        self.bytes.get(start..end).ok_or_else(out_of_bounds)
    }
}

/// A PCR bank a dump records the expected values of.
#[derive(Clone, Copy, Debug)]
pub struct Bank<'a> {
    algorithm: Algorithm,
    digest_size: usize,
    expected: &'a [u8],
}

impl<'a> Bank<'a> {
    /// Hash the bank uses.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Length of a digest in this bank, in bytes.
    #[must_use]
    pub const fn digest_size(&self) -> usize {
        self.digest_size
    }

    /// The value PCR `index` folds to, or [`None`] past the last PCR the dump
    /// covers.
    #[must_use]
    pub fn expected(&self, index: u32) -> Option<&'a [u8]> {
        let start = usize::try_from(index).ok()?.checked_mul(self.digest_size)?;
        self.expected
            .get(start..start.checked_add(self.digest_size)?)
    }
}

/// One record of the log a dump was made from.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    dump: Dump<'a>,
    index: u32,
    entry: EventEntry,
    data: &'a [u8],
}

impl<'a> Event<'a> {
    /// Position of the event in the dump, counting from the first record.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// PCR the event was measured into.
    #[must_use]
    pub const fn pcr_index(&self) -> u32 {
        self.entry.pcr_index
    }

    /// Type of the event.
    #[must_use]
    pub const fn event_type(&self) -> EventType {
        self.entry.event_type
    }

    /// How the log encoded the event.
    #[must_use]
    pub const fn flags(&self) -> EventFlags {
        self.entry.flags
    }

    /// The event data, exactly as the log carried it.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Whether replaying the log means extending this event into its PCR.
    ///
    /// `EV_NO_ACTION` records are informational and were never measured, so
    /// extending them would produce PCR values the platform never had.
    #[must_use]
    pub fn extends_pcr(&self) -> bool {
        self.event_type() != EventType::NO_ACTION
    }

    /// The digests the log recorded for the event, in the order it recorded them.
    #[must_use]
    pub const fn digests(&self) -> Digests<'a> {
        Digests {
            dump: self.dump,
            event: self.entry,
            next: 0,
        }
    }

    /// The digest the log recorded for `algorithm`.
    ///
    /// # Errors
    ///
    /// Fails if the event carries no digest for that algorithm, or if one of its
    /// digest descriptors is malformed.
    pub fn digest(&self, algorithm: Algorithm) -> Result<&'a [u8]> {
        for digest in self.digests() {
            let digest = digest?;
            if digest.algorithm() == algorithm {
                return Ok(digest.bytes());
            }
        }

        Err(Error::MissingDigest {
            index: self.index,
            algorithm,
        })
    }
}

/// One digest an event recorded, belonging to one bank.
#[derive(Clone, Copy, Debug)]
pub struct Digest<'a> {
    algorithm: Algorithm,
    bytes: &'a [u8],
}

impl<'a> Digest<'a> {
    /// Hash that produced the digest.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The digest itself.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Iterator over the banks a dump describes.
#[derive(Clone, Debug)]
pub struct Banks<'a> {
    dump: Dump<'a>,
    next: u32,
}

impl<'a> Iterator for Banks<'a> {
    type Item = Result<Bank<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        if index >= u32::from(self.dump.header.bank_count) {
            return None;
        }

        self.next = index + 1;
        Some(self.dump.decode_bank(index))
    }
}

/// Iterator over the events a dump carries, in log order.
#[derive(Clone, Debug)]
pub struct Events<'a> {
    dump: Dump<'a>,
    next: u32,
}

impl<'a> Iterator for Events<'a> {
    type Item = Result<Event<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        if index >= self.dump.event_count() {
            return None;
        }

        self.next = index + 1;
        Some(self.dump.decode_event(index))
    }
}

/// Iterator over the digests one event recorded, in log order.
#[derive(Clone, Debug)]
pub struct Digests<'a> {
    dump: Dump<'a>,
    event: EventEntry,
    next: u32,
}

impl<'a> Iterator for Digests<'a> {
    type Item = Result<Digest<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        if index >= self.event.digest_count {
            return None;
        }

        self.next = index + 1;
        Some(self.dump.decode_digest(&self.event, index))
    }
}
