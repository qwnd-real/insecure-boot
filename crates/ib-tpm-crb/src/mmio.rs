//! Direct access to physically addressed device memory.
//!
//! UEFI leaves the address space identity-mapped for the whole
//! pre-`ExitBootServices` epoch, so a region is nothing more than a base address
//! and a length. Register accesses are volatile loads and stores of exactly the
//! width the TPM Profile specifies, matching Linux's `ioread32`/`iowrite32`;
//! buffer transfers are plain copies, matching `memcpy_toio`/`memcpy_fromio`.

use core::ptr;
use core::sync::atomic::{Ordering, fence};

use crate::{Error, Result};

/// Alignment a region must have for its 32-bit register accessors to be sound.
const REGISTER_ALIGN: u64 = 4;

/// A region of device memory that is known to be addressable in full.
#[derive(Clone, Copy)]
pub(crate) struct Region {
    /// First address of the region.
    base: usize,
    /// Length of the region in bytes.
    len: usize,
}

impl Region {
    /// Claims `[start, start + len)`.
    ///
    /// # Errors
    ///
    /// Fails if the range is empty, wraps the address space, or does not fit in a
    /// pointer.
    pub(crate) fn new(start: u64, len: u64) -> Result<Self> {
        let unmappable = || Error::UnmappableRegion { start, len };

        let last = len
            .checked_sub(1)
            .and_then(|last| start.checked_add(last))
            .ok_or_else(unmappable)?;
        usize::try_from(last).map_err(|_| unmappable())?;

        Ok(Self {
            base: usize::try_from(start).map_err(|_| unmappable())?,
            len: usize::try_from(len).map_err(|_| unmappable())?,
        })
    }

    /// Claims a `len`-byte register block at `start`.
    ///
    /// # Errors
    ///
    /// Fails if the block is not addressable, or if it does not start on a 32-bit
    /// boundary, which [`Region::read32`] and [`Region::write32`] rely on.
    pub(crate) fn registers(start: u64, len: u64) -> Result<Self> {
        if start.is_multiple_of(REGISTER_ALIGN) {
            Self::new(start, len)
        } else {
            Err(Error::MisalignedRegisters { address: start })
        }
    }

    /// The `len`-byte sub-region starting `offset` into this one.
    ///
    /// # Errors
    ///
    /// Fails if the sub-region does not fit inside this region.
    pub(crate) fn subregion(self, offset: usize, len: usize) -> Result<Self> {
        if offset.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::UnmappableRegion {
                start: address(self.base.wrapping_add(offset)),
                len: address(len),
            });
        }

        Self::new(address(self.base + offset), address(len))
    }

    /// Reads the 32-bit register at `offset`.
    ///
    /// # Safety
    ///
    /// The region must come from [`Region::registers`], `offset` must be a
    /// multiple of four, `offset + 4` must not exceed the region's length, and the
    /// register must tolerate being read.
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the region and offset are both 32-bit aligned by this contract"
    )]
    pub(crate) unsafe fn read32(self, offset: usize) -> u32 {
        // SAFETY: the caller guarantees the access lies inside the region, all of
        // which is mapped, and that both the base and the offset are 32-bit
        // aligned, so the pointer is aligned for the load.
        unsafe { ptr::read_volatile(self.pointer(offset).cast::<u32>()) }
    }

    /// Writes the 32-bit register at `offset`.
    ///
    /// # Safety
    ///
    /// As for [`Region::read32`], and the caller must be entitled to cause
    /// whatever the write triggers.
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the region and offset are both 32-bit aligned by this contract"
    )]
    pub(crate) unsafe fn write32(self, offset: usize, value: u32) {
        // SAFETY: as for `read32`.
        unsafe { ptr::write_volatile(self.pointer(offset).cast::<u32>(), value) };
    }

    /// Copies `dst.len()` bytes out of the region, starting at `offset`.
    ///
    /// # Errors
    ///
    /// Fails if the copy would run past the end of the region.
    pub(crate) fn read_bytes(self, offset: usize, dst: &mut [u8]) -> Result<()> {
        let source = self.subregion(offset, dst.len())?;

        // SAFETY: `subregion` established that the whole span lies inside this
        // region, and `dst` is a distinct Rust allocation, so the two cannot
        // overlap.
        unsafe { ptr::copy_nonoverlapping(source.pointer(0), dst.as_mut_ptr(), dst.len()) };

        // Matches the `rmb()` Linux issues after reading device memory, so the
        // bytes are in hand before anything after this observes them.
        fence(Ordering::Acquire);
        Ok(())
    }

    /// Copies `src` into the region, starting at `offset`.
    ///
    /// # Errors
    ///
    /// Fails if the copy would run past the end of the region.
    pub(crate) fn write_bytes(self, offset: usize, src: &[u8]) -> Result<()> {
        let destination = self.subregion(offset, src.len())?;

        // SAFETY: `subregion` established that the whole span lies inside this
        // region, and `src` is a distinct Rust allocation, so the two cannot
        // overlap.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), destination.pointer(0), src.len()) };

        // Matches the `wmb()` Linux issues between filling the command buffer and
        // signalling start, so the device cannot observe a half-written command.
        fence(Ordering::Release);
        Ok(())
    }

    /// Pointer to `offset` within the region.
    fn pointer(self, offset: usize) -> *mut u8 {
        ptr::with_exposed_provenance_mut(self.base.wrapping_add(offset))
    }
}

/// Widens a host-sized value into a physical address, saturating rather than
/// truncating so that a value too large to describe fails a later bounds check
/// instead of aliasing a valid one.
fn address(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
