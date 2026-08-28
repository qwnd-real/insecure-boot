//! `SystemIO` and PCI configuration space access.
//!
//! Both address spaces are reached with the x86 `in`/`out` instructions. uACPI
//! requires that an access is issued at exactly the width it asked for, never
//! split into narrower ones, which the [`PortRead`] and [`PortWrite`]
//! implementations guarantee.
//!
//! PCI configuration space uses the legacy 0xCF8/0xCFC mechanism. That covers
//! segment 0 and the first 256 bytes of each function's configuration space;
//! anything beyond needs the ECAM window described by the MCFG table, which
//! nothing in this workspace has a use for yet, so requests outside that reach
//! are refused rather than silently aliased onto the wrong register.

use alloc::boxed::Box;

use uacpi_sys::{
    UACPI_STATUS_INVALID_ARGUMENT, UACPI_STATUS_OK, UACPI_STATUS_UNIMPLEMENTED, uacpi_handle,
    uacpi_io_addr, uacpi_pci_address, uacpi_size, uacpi_status, uacpi_u8, uacpi_u16, uacpi_u32,
};
use x86_64::instructions::port::{PortRead, PortWrite};

/// Number of ports in the x86 `SystemIO` address space.
const IO_SPACE_LEN: u64 = 0x1_0000;

/// Address register of the legacy PCI configuration mechanism.
const CONFIG_ADDRESS: u16 = 0xCF8;

/// Data register of the legacy PCI configuration mechanism.
const CONFIG_DATA: u16 = 0xCFC;

/// Bytes of a function's configuration space reachable through 0xCF8/0xCFC.
const CONFIG_WINDOW: usize = 256;

/// Bit that enables configuration space decoding in the address register.
const CONFIG_ENABLE: u32 = 1 << 31;

/// Highest device number on a PCI bus.
const MAX_DEVICE: uacpi_u8 = 31;

/// Highest function number within a PCI device.
const MAX_FUNCTION: uacpi_u8 = 7;

/// A `SystemIO` range that uACPI holds a handle to.
struct PortRange {
    /// First port in the range.
    base: u16,
    /// Number of ports in the range.
    len: u32,
}

/// A PCI function that uACPI holds a handle to.
struct PciFunction {
    /// Bus number within segment 0.
    bus: uacpi_u8,
    /// Device number on the bus.
    device: uacpi_u8,
    /// Function number within the device.
    function: uacpi_u8,
}

/// Claims the `SystemIO` range at `[base, base + len)`.
///
/// # Safety
///
/// `out_handle` must point to a writable [`uacpi_handle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_map(
    base: uacpi_io_addr,
    len: uacpi_size,
    out_handle: *mut uacpi_handle,
) -> uacpi_status {
    let Ok(len) = u32::try_from(len) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };
    if base.saturating_add(u64::from(len)) > IO_SPACE_LEN {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }
    let Ok(base) = u16::try_from(base) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    let range = Box::into_raw(Box::new(PortRange { base, len }));

    // SAFETY: the caller guarantees a writable destination.
    unsafe { out_handle.write(range.cast()) };
    UACPI_STATUS_OK
}

/// Releases a range claimed by [`uacpi_kernel_io_map`].
///
/// # Safety
///
/// `handle` must come from [`uacpi_kernel_io_map`] and must not be used
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_unmap(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` was produced by `Box::into_raw` on
    // a `Box<PortRange>` and has not been released.
    drop(unsafe { Box::from_raw(handle.cast::<PortRange>()) });
}

/// Reads a byte from `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_read8(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u8,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_read(handle, offset, out_value) }
}

/// Reads a word from `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_read16(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u16,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_read(handle, offset, out_value) }
}

/// Reads a doubleword from `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_read32(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u32,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_read(handle, offset, out_value) }
}

/// Writes a byte to `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_write8(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u8,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_write(handle, offset, in_value) }
}

/// Writes a word to `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_write16(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u16,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_write(handle, offset, in_value) }
}

/// Writes a doubleword to `offset` within a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_io_write32(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u32,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { io_write(handle, offset, in_value) }
}

/// Claims the PCI function at `address`.
///
/// # Safety
///
/// `out_handle` must point to a writable [`uacpi_handle`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_device_open(
    address: uacpi_pci_address,
    out_handle: *mut uacpi_handle,
) -> uacpi_status {
    if address.segment != 0 {
        return UACPI_STATUS_UNIMPLEMENTED;
    }
    if address.device > MAX_DEVICE || address.function > MAX_FUNCTION {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    let function = Box::into_raw(Box::new(PciFunction {
        bus: address.bus,
        device: address.device,
        function: address.function,
    }));

    // SAFETY: the caller guarantees a writable destination.
    unsafe { out_handle.write(function.cast()) };
    UACPI_STATUS_OK
}

/// Releases a function claimed by [`uacpi_kernel_pci_device_open`].
///
/// # Safety
///
/// `handle` must come from [`uacpi_kernel_pci_device_open`] and must not be used
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_device_close(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` was produced by `Box::into_raw` on
    // a `Box<PciFunction>` and has not been released.
    drop(unsafe { Box::from_raw(handle.cast::<PciFunction>()) });
}

/// Reads a byte of configuration space.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_read8(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u8,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_read(handle, offset, out_value) }
}

/// Reads a word of configuration space.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_read16(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u16,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_read(handle, offset, out_value) }
}

/// Reads a doubleword of configuration space.
///
/// # Safety
///
/// `handle` must be live and `out_value` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_read32(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut uacpi_u32,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_read(handle, offset, out_value) }
}

/// Writes a byte of configuration space.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_write8(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u8,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_write(handle, offset, in_value) }
}

/// Writes a word of configuration space.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_write16(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u16,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_write(handle, offset, in_value) }
}

/// Writes a doubleword of configuration space.
///
/// # Safety
///
/// `handle` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_pci_write32(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: uacpi_u32,
) -> uacpi_status {
    // SAFETY: forwarded from this function's own contract.
    unsafe { pci_write(handle, offset, in_value) }
}

/// Reads `T` from a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be a live range from [`uacpi_kernel_io_map`] and `out_value`
/// must be writable.
unsafe fn io_read<T: PortRead>(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut T,
) -> uacpi_status {
    // SAFETY: the caller guarantees a live range handle.
    let Some(port) = (unsafe { port_for::<T>(handle, offset) }) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    // SAFETY: the port lies inside a range uACPI asked to map, so reading it is
    // what the caller requested; the caller guarantees `out_value` is writable.
    unsafe { out_value.write(T::read_from_port(port)) };
    UACPI_STATUS_OK
}

/// Writes `T` to a mapped `SystemIO` range.
///
/// # Safety
///
/// `handle` must be a live range from [`uacpi_kernel_io_map`].
unsafe fn io_write<T: PortWrite>(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: T,
) -> uacpi_status {
    // SAFETY: the caller guarantees a live range handle.
    let Some(port) = (unsafe { port_for::<T>(handle, offset) }) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    // SAFETY: the port lies inside a range uACPI asked to map, so writing it is
    // what the caller requested.
    unsafe { T::write_to_port(port, in_value) };
    UACPI_STATUS_OK
}

/// Resolves `offset` within a mapped range to an absolute port number, rejecting
/// accesses that would fall outside the range.
///
/// # Safety
///
/// `handle` must be a live range from [`uacpi_kernel_io_map`].
unsafe fn port_for<T>(handle: uacpi_handle, offset: uacpi_size) -> Option<u16> {
    // SAFETY: the caller guarantees the handle refers to a live `PortRange`,
    // which lives on the heap until `uacpi_kernel_io_unmap` releases it.
    let range = unsafe { &*handle.cast::<PortRange>() };

    let offset = u32::try_from(offset).ok()?;
    let width = u32::try_from(size_of::<T>()).ok()?;
    if offset.checked_add(width)? > range.len {
        return None;
    }

    u16::try_from(u32::from(range.base) + offset).ok()
}

/// Reads `T` from configuration space.
///
/// # Safety
///
/// `handle` must be a live function from [`uacpi_kernel_pci_device_open`] and
/// `out_value` must be writable.
unsafe fn pci_read<T: PortRead>(
    handle: uacpi_handle,
    offset: uacpi_size,
    out_value: *mut T,
) -> uacpi_status {
    // SAFETY: the caller guarantees a live function handle.
    let Some(port) = (unsafe { select_config::<T>(handle, offset) }) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    // SAFETY: the address register now selects the requested register, and the
    // caller guarantees `out_value` is writable.
    unsafe { out_value.write(T::read_from_port(port)) };
    UACPI_STATUS_OK
}

/// Writes `T` to configuration space.
///
/// # Safety
///
/// `handle` must be a live function from [`uacpi_kernel_pci_device_open`].
unsafe fn pci_write<T: PortWrite>(
    handle: uacpi_handle,
    offset: uacpi_size,
    in_value: T,
) -> uacpi_status {
    // SAFETY: the caller guarantees a live function handle.
    let Some(port) = (unsafe { select_config::<T>(handle, offset) }) else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    // SAFETY: the address register now selects the requested register.
    unsafe { T::write_to_port(port, in_value) };
    UACPI_STATUS_OK
}

/// Points the configuration address register at the register holding `offset` and
/// returns the data port that exposes it.
///
/// Accesses must be naturally aligned and must not leave the 256-byte window,
/// because the mechanism selects a whole doubleword at a time.
///
/// # Safety
///
/// `handle` must be a live function from [`uacpi_kernel_pci_device_open`].
unsafe fn select_config<T>(handle: uacpi_handle, offset: uacpi_size) -> Option<u16> {
    // SAFETY: the caller guarantees the handle refers to a live `PciFunction`,
    // which lives on the heap until `uacpi_kernel_pci_device_close` releases it.
    let function = unsafe { &*handle.cast::<PciFunction>() };

    let width = size_of::<T>();
    if !offset.is_multiple_of(width) || offset.checked_add(width)? > CONFIG_WINDOW {
        return None;
    }
    let offset = u32::try_from(offset).ok()?;

    let address = CONFIG_ENABLE
        | u32::from(function.bus) << 16
        | u32::from(function.device) << 11
        | u32::from(function.function) << 8
        | (offset & !0b11);

    // SAFETY: 0xCF8 is the architectural configuration address register; writing
    // it only selects which doubleword 0xCFC exposes and has no other effect.
    unsafe { u32::write_to_port(CONFIG_ADDRESS, address) };

    u16::try_from(u32::from(CONFIG_DATA) + (offset & 0b11)).ok()
}
