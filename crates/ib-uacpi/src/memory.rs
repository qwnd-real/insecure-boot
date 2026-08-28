//! Memory primitives: physical address translation and the uACPI heap.
//!
//! UEFI guarantees a flat, identity-mapped address space for the whole
//! pre-`ExitBootServices` epoch, so translating a physical address into a
//! pointer uACPI can dereference is a cast and unmapping is a no-op.
//!
//! The heap primitives forward to the Rust global allocator, which the `uefi`
//! crate binds to the UEFI pool allocator. uACPI frees without telling the host
//! how large the block was, so each block carries its size in a header that
//! sits immediately below the pointer handed out.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr;

use uacpi_sys::{uacpi_phys_addr, uacpi_size};

/// Alignment of every block handed to uACPI.
///
/// uACPI is C code that expects malloc-grade alignment for any type it chooses
/// to place in an allocation; 16 bytes is the widest fundamental alignment on
/// x86-64.
const BLOCK_ALIGN: usize = 16;

/// Bytes reserved below each block to record its size.
///
/// Matching the block alignment keeps the payload aligned, and one `usize` fits
/// comfortably inside it.
const HEADER_LEN: usize = BLOCK_ALIGN;

/// Translates a physical address into a pointer uACPI can dereference.
///
/// Returns null for addresses that do not fit in a pointer, which uACPI treats
/// as a mapping failure.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_map(addr: uacpi_phys_addr, _len: uacpi_size) -> *mut c_void {
    usize::try_from(addr).map_or(ptr::null_mut(), ptr::with_exposed_provenance_mut)
}

/// Releases a mapping made by [`uacpi_kernel_map`].
///
/// Identity mappings are set up by firmware and outlive the application, so
/// there is nothing to undo.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_unmap(_addr: *mut c_void, _len: uacpi_size) {}

/// Allocates `size` bytes for uACPI, or returns null when that is not possible.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_alloc(size: uacpi_size) -> *mut c_void {
    let Some(layout) = layout_for(size) else {
        return ptr::null_mut();
    };

    // SAFETY: `layout` has a non-zero size because it always includes the
    // header.
    let block = unsafe { alloc(layout) };
    if block.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `block` points to at least `HEADER_LEN` writable bytes, which is
    // wider than a `usize`.
    unsafe { block.cast::<usize>().write_unaligned(size) };

    // SAFETY: the allocation is `HEADER_LEN + size` bytes long, so the payload
    // pointer is in bounds (one past the end at worst, when `size` is zero).
    unsafe { block.add(HEADER_LEN) }.cast()
}

/// Frees a block obtained from [`uacpi_kernel_alloc`].
///
/// # Panics
///
/// Panics if the size header below the block no longer describes a valid layout,
/// which can only happen if the header was overwritten.
///
/// # Safety
///
/// `mem` must be null, or a pointer returned by [`uacpi_kernel_alloc`] that has
/// not been freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_free(mem: *mut c_void) {
    if mem.is_null() {
        return;
    }

    // SAFETY: the caller guarantees `mem` came from `uacpi_kernel_alloc`, which
    // places the size header in the `HEADER_LEN` bytes below the payload.
    let block = unsafe { mem.cast::<u8>().sub(HEADER_LEN) };

    // SAFETY: as above, the header was written by `uacpi_kernel_alloc` and the
    // block has not been freed, so it is still initialized and readable.
    let size = unsafe { block.cast::<usize>().read_unaligned() };

    let layout = layout_for(size).expect("this layout was accepted when the block was allocated");

    // SAFETY: `block` and `layout` are exactly the pointer and layout that
    // `uacpi_kernel_alloc` obtained from the global allocator.
    unsafe { dealloc(block, layout) };
}

/// Layout of the allocation that backs a `size`-byte block, header included.
fn layout_for(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(HEADER_LEN)?, BLOCK_ALIGN).ok()
}
