//! Decoding of a device's resource list into physical memory ranges.
//!
//! Only memory-producing descriptors matter to the drivers here, so the two
//! groups Linux's `acpi_dev_resource_memory` and `acpi_dev_resource_address_space`
//! recognise are decoded and everything else is skipped:
//!
//! - the fixed and non-fixed memory descriptors, whose addresses are absolute;
//! - the generic address-space descriptors, whose range is `minimum` through
//!   `maximum`, shifted by the translation offset when the descriptor describes
//!   a bus-producing window rather than a consumed range.

use core::marker::PhantomData;
use core::ptr::NonNull;

use uacpi_sys::{
    UACPI_PRODUCER, UACPI_RANGE_MEMORY, UACPI_RESOURCE_TYPE_ADDRESS16,
    UACPI_RESOURCE_TYPE_ADDRESS32, UACPI_RESOURCE_TYPE_ADDRESS64,
    UACPI_RESOURCE_TYPE_ADDRESS64_EXTENDED, UACPI_RESOURCE_TYPE_END_TAG,
    UACPI_RESOURCE_TYPE_FIXED_MEMORY32, UACPI_RESOURCE_TYPE_MEMORY24, UACPI_RESOURCE_TYPE_MEMORY32,
    uacpi_free_resources, uacpi_get_current_resources, uacpi_namespace_node, uacpi_resource,
    uacpi_resource_address_common, uacpi_resources,
};

use crate::error::{Error, Result, check};

/// Bytes each unit of a 24-bit memory descriptor stands for.
///
/// The descriptor stores addresses shifted right by eight bits, so it can only
/// describe 256-byte-aligned ranges below 16 MiB.
const MEMORY24_UNIT: u64 = 256;

/// An inclusive range of physical addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryRange {
    /// First address in the range.
    start: u64,
    /// Last address in the range.
    end: u64,
}

/// The resource list `_CRS` produced, owned by uACPI until dropped.
pub struct Resources(NonNull<uacpi_resources>);

/// Iterator over the memory ranges in a [`Resources`] list.
pub struct MemoryRanges<'a> {
    /// Next descriptor to inspect, or [`None`] once the end tag was reached.
    next: Option<NonNull<uacpi_resource>>,
    /// Ties the iterator to the list that owns the descriptors it walks.
    owner: PhantomData<&'a Resources>,
}

impl MemoryRange {
    /// Builds a range from its first address and length, rejecting empty ranges
    /// and ranges that would run past the end of the address space.
    fn new(start: u64, len: u64) -> Option<Self> {
        let end = start.checked_add(len.checked_sub(1)?)?;
        Some(Self { start, end })
    }

    /// First address in the range.
    #[must_use]
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Last address in the range.
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Number of addresses in the range.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether `address` falls inside the range.
    #[must_use]
    pub const fn contains(&self, address: u64) -> bool {
        self.start <= address && address <= self.end
    }

    /// Whether `[start, start + len)` falls entirely inside the range.
    #[must_use]
    pub fn covers(&self, start: u64, len: u64) -> bool {
        let Some(last) = len.checked_sub(1).and_then(|last| start.checked_add(last)) else {
            return false;
        };
        self.contains(start) && self.contains(last)
    }
}

impl Resources {
    /// Evaluates and decodes `_CRS` for `device`.
    pub(crate) fn current_for(device: NonNull<uacpi_namespace_node>) -> Result<Self> {
        let mut resources: *mut uacpi_resources = core::ptr::null_mut();

        // SAFETY: the node is live and `resources` is a writable slot for the
        // list uACPI allocates.
        check(unsafe { uacpi_get_current_resources(device.as_ptr(), &raw mut resources) })?;

        NonNull::new(resources)
            .map(Self)
            .ok_or_else(Error::malformed)
    }

    /// The memory ranges the list describes, in the order `_CRS` returned them.
    #[must_use]
    pub fn memory_ranges(&self) -> MemoryRanges<'_> {
        // SAFETY: uACPI keeps the list alive until `uacpi_free_resources`, which
        // only runs when `self` drops.
        let entries = unsafe { self.0.as_ref().entries };

        MemoryRanges {
            next: NonNull::new(entries),
            owner: PhantomData,
        }
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        // SAFETY: the pointer came from `uacpi_get_current_resources` and has not
        // been freed.
        unsafe { uacpi_free_resources(self.0.as_ptr()) };
    }
}

impl Iterator for MemoryRanges<'_> {
    type Item = MemoryRange;

    fn next(&mut self) -> Option<MemoryRange> {
        loop {
            let current = self.next?;

            // SAFETY: descriptors live inside the list `owner` keeps alive, and
            // uACPI guarantees each one is naturally aligned and fully
            // initialized.
            let resource = unsafe { current.as_ref() };

            if resource.type_ == UACPI_RESOURCE_TYPE_END_TAG {
                self.next = None;
                return None;
            }

            // SAFETY: as above; every descriptor but the end tag is followed by
            // another one, and `length` is the distance to it.
            self.next = NonNull::new(unsafe {
                current.cast::<u8>().as_ptr().add(resource.length as usize)
            })
            .map(NonNull::cast::<uacpi_resource>);

            if let Some(range) = decode(resource) {
                return Some(range);
            }
        }
    }
}

/// Extracts the memory range a descriptor describes, if it describes one.
fn decode(resource: &uacpi_resource) -> Option<MemoryRange> {
    // SAFETY: `type_` says which member of the descriptor's body is live, and
    // each arm below reads only the member its own type names.
    unsafe {
        let body = &resource.__bindgen_anon_1;

        match resource.type_ {
            UACPI_RESOURCE_TYPE_MEMORY24 => {
                let memory = body.memory24.as_ref();
                MemoryRange::new(
                    u64::from(memory.minimum) * MEMORY24_UNIT,
                    u64::from(memory.length) * MEMORY24_UNIT,
                )
            }
            UACPI_RESOURCE_TYPE_MEMORY32 => {
                let memory = body.memory32.as_ref();
                MemoryRange::new(u64::from(memory.minimum), u64::from(memory.length))
            }
            UACPI_RESOURCE_TYPE_FIXED_MEMORY32 => {
                let memory = body.fixed_memory32.as_ref();
                MemoryRange::new(u64::from(memory.address), u64::from(memory.length))
            }
            UACPI_RESOURCE_TYPE_ADDRESS16 => {
                let address = body.address16.as_ref();
                decode_space(
                    &address.common,
                    u64::from(address.minimum),
                    u64::from(address.address_length),
                    u64::from(address.translation_offset),
                )
            }
            UACPI_RESOURCE_TYPE_ADDRESS32 => {
                let address = body.address32.as_ref();
                decode_space(
                    &address.common,
                    u64::from(address.minimum),
                    u64::from(address.address_length),
                    u64::from(address.translation_offset),
                )
            }
            UACPI_RESOURCE_TYPE_ADDRESS64 => {
                let address = body.address64.as_ref();
                decode_space(
                    &address.common,
                    address.minimum,
                    address.address_length,
                    address.translation_offset,
                )
            }
            UACPI_RESOURCE_TYPE_ADDRESS64_EXTENDED => {
                let address = body.address64_extended.as_ref();
                decode_space(
                    &address.common,
                    address.minimum,
                    address.address_length,
                    address.translation_offset,
                )
            }
            _ => None,
        }
    }
}

/// Turns a generic address-space descriptor into a memory range.
///
/// Descriptors that describe something other than memory are skipped. A producing
/// descriptor describes a window a bridge forwards, so its addresses are shifted
/// by the translation offset to reach the range as the processor sees it; a
/// consumed range needs no shift.
fn decode_space(
    common: &uacpi_resource_address_common,
    minimum: u64,
    length: u64,
    translation_offset: u64,
) -> Option<MemoryRange> {
    if u32::from(common.type_) != UACPI_RANGE_MEMORY {
        return None;
    }

    let offset = if u32::from(common.direction) == UACPI_PRODUCER {
        translation_offset
    } else {
        0
    };

    MemoryRange::new(minimum.checked_add(offset)?, length)
}
