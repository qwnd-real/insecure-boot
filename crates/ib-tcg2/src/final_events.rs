//! The `EFI_TCG2_FINAL_EVENTS_TABLE`.
//!
//! Once the operating system has taken the event log with `GetEventLog`, it has
//! no reason to look at it again, so anything measured after that point would go
//! unnoticed. The final events table is where those records go instead: a
//! configuration table entry, in memory that outlives boot services, holding the
//! `TCG_PCR_EVENT2` records that were logged after the log was handed over.
//!
//! Its address is published to the operating system, so like the log itself it is
//! allocated once and never moves, and it stops accepting records rather than
//! growing.

use core::ptr::{self, NonNull};
use core::slice;

use uefi::boot::{self, MemoryType};
use uefi::{Guid, guid};

use crate::Result;

/// GUID the table is published under in the UEFI configuration table.
static TABLE_GUID: Guid = guid!("1e2ed096-30e2-4254-bd89-863bbef82325");

/// Revision of the table this crate writes.
const VERSION: u64 = 1;

/// Length of the table's header: a version and a record count.
const HEADER_LEN: usize = 2 * size_of::<u64>();

/// Offset of the record count within the header.
const COUNT_AT: usize = size_of::<u64>();

/// The table, and the allocation it lives in.
pub struct FinalEvents {
    base: NonNull<u8>,
    capacity: usize,
    len: usize,
    events: u64,
}

impl FinalEvents {
    /// Allocates an empty table with room for `capacity` bytes in total, and
    /// publishes it in the UEFI configuration table.
    ///
    /// The allocation is runtime services data, which is the memory type a
    /// configuration table entry has to point at if it is still to mean anything
    /// once boot services are gone.
    ///
    /// # Errors
    ///
    /// Fails if firmware cannot allocate the table or refuses to publish it.
    pub fn install(capacity: usize) -> Result<Self> {
        let capacity = capacity.max(HEADER_LEN);
        let base = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, capacity)?;

        // SAFETY: `allocate_pool` just handed back `capacity` bytes that nothing
        // else refers to, so they can be initialized here before any reference to
        // them exists.
        unsafe { base.write_bytes(0, capacity) };

        let mut table = Self {
            base,
            capacity,
            len: HEADER_LEN,
            events: 0,
        };

        table.put(0, &VERSION.to_le_bytes());

        // SAFETY: the table is a live runtime-services-data allocation of
        // `capacity` bytes that this type owns and does not move, and it holds a
        // complete header, so firmware and the operating system after it can read
        // the table for as long as the entry names it.
        unsafe { boot::install_configuration_table(&TABLE_GUID, base.as_ptr().cast()) }?;

        Ok(table)
    }

    /// Address the table starts at.
    #[must_use]
    pub fn address(&self) -> u64 {
        self.base.as_ptr().addr() as u64
    }

    /// Number of records the table holds.
    #[must_use]
    pub const fn events(&self) -> u64 {
        self.events
    }

    /// Room left for further records, in bytes.
    #[must_use]
    pub const fn spare(&self) -> usize {
        self.capacity - self.len
    }

    /// Appends an already encoded record, and reports whether it fitted.
    pub fn append(&mut self, entry: &[u8]) -> bool {
        let Some(end) = self
            .len
            .checked_add(entry.len())
            .filter(|end| *end <= self.capacity)
        else {
            return false;
        };

        let (at, events) = (self.len, self.events + 1);
        self.put(at, entry);
        self.put(COUNT_AT, &events.to_le_bytes());

        self.len = end;
        self.events = events;

        true
    }

    /// Removes the configuration table entry and frees the table.
    ///
    /// # Errors
    ///
    /// Fails if firmware refuses to remove the entry or to free the allocation.
    pub fn uninstall(self) -> Result<()> {
        // Removing an entry means naming its GUID with no table behind it.
        // SAFETY: a null table removes the entry rather than publishing anything,
        // so no memory has to outlive this call.
        unsafe { boot::install_configuration_table(&TABLE_GUID, ptr::null()) }?;

        // SAFETY: the allocation came from `allocate_pool`, the entry that named
        // it is gone, and `self` was the only owner.
        unsafe { boot::free_pool(self.base) }?;

        Ok(())
    }

    /// Copies `value` into the table at `at`, ignoring a write that would not fit
    /// because the caller has already checked that none of them do.
    fn put(&mut self, at: usize, value: &[u8]) {
        let end = at.saturating_add(value.len());
        if let Some(room) = self.bytes().get_mut(at..end) {
            room.copy_from_slice(value);
        }
    }

    /// The allocation as a slice.
    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: `base` points at `capacity` bytes that this type allocated and
        // owns exclusively, and `allocate_pool` returns memory aligned for any
        // type, so a byte slice over all of it is valid and unaliased.
        unsafe { slice::from_raw_parts_mut(self.base.as_ptr(), self.capacity) }
    }
}
