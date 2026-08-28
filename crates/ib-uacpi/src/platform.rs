//! Platform services that are neither memory, time, I/O nor synchronization:
//! locating the ACPI root pointer, reporting AML firmware requests, and the
//! interrupt and deferred-work hooks.

use core::fmt::Write;

use uacpi_sys::{
    UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT, UACPI_FIRMWARE_REQUEST_TYPE_FATAL,
    UACPI_STATUS_INVALID_ARGUMENT, UACPI_STATUS_NOT_FOUND, UACPI_STATUS_OK,
    UACPI_STATUS_UNIMPLEMENTED, uacpi_firmware_request, uacpi_handle, uacpi_interrupt_handler,
    uacpi_phys_addr, uacpi_status, uacpi_u32, uacpi_work_handler, uacpi_work_type,
};
use uefi::system;
use uefi::table::cfg::ConfigTableEntry;

/// Physical address of the Root System Description Pointer.
///
/// UEFI publishes the RSDP through its configuration table rather than leaving it
/// to be scanned for in low memory. The ACPI 2.0 entry is preferred; the 1.0
/// entry is a fallback for firmware that publishes nothing newer.
#[must_use]
pub fn rsdp_address() -> Option<uacpi_phys_addr> {
    let address = system::with_config_table(|entries| {
        let locate = |guid| {
            entries
                .iter()
                .find(|entry| entry.guid == guid)
                .map(|entry| entry.address)
        };
        locate(ConfigTableEntry::ACPI2_GUID).or_else(|| locate(ConfigTableEntry::ACPI_GUID))
    })?;

    uacpi_phys_addr::try_from(address.expose_provenance()).ok()
}

/// Reports the address of the ACPI root pointer to uACPI.
///
/// # Safety
///
/// `out_rsdp_address` must point to a writable [`uacpi_phys_addr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_get_rsdp(
    out_rsdp_address: *mut uacpi_phys_addr,
) -> uacpi_status {
    let Some(address) = rsdp_address() else {
        return UACPI_STATUS_NOT_FOUND;
    };

    // SAFETY: the caller guarantees a writable destination.
    unsafe { out_rsdp_address.write(address) };
    UACPI_STATUS_OK
}

/// Reports an AML `Breakpoint` or `Fatal` operator on the console.
///
/// Neither operator needs the host to act: `Breakpoint` is a debugger hook with
/// no debugger attached, and `Fatal` is the AML author signalling a condition
/// they consider unrecoverable, which says nothing about the loader's own state.
/// Both are worth surfacing, so they are logged and execution continues.
///
/// # Safety
///
/// `request` must point to a readable [`uacpi_firmware_request`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_handle_firmware_request(
    request: *mut uacpi_firmware_request,
) -> uacpi_status {
    // SAFETY: the caller guarantees a readable request.
    let request = unsafe { &*request };

    let _ = system::with_stdout(|stdout| match uacpi_u32::from(request.type_) {
        UACPI_FIRMWARE_REQUEST_TYPE_BREAKPOINT => writeln!(stdout, "[uacpi] AML breakpoint"),
        UACPI_FIRMWARE_REQUEST_TYPE_FATAL => {
            // SAFETY: the request type selects the `fatal` member of the union.
            let fatal = unsafe { request.__bindgen_anon_1.fatal };
            writeln!(
                stdout,
                "[uacpi] AML fatal: type {} code {} arg {}",
                fatal.type_, fatal.code, fatal.arg
            )
        }
        other => writeln!(stdout, "[uacpi] unknown firmware request {other}"),
    });

    UACPI_STATUS_OK
}

/// Refuses to install an interrupt handler.
///
/// uACPI only asks for one to service the SCI, which reduced-hardware mode
/// compiles out, and firmware still owns the interrupt controller while a UEFI
/// application runs.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_install_interrupt_handler(
    _irq: uacpi_u32,
    _handler: uacpi_interrupt_handler,
    _ctx: uacpi_handle,
    _out_irq_handle: *mut uacpi_handle,
) -> uacpi_status {
    UACPI_STATUS_UNIMPLEMENTED
}

/// Counterpart to [`uacpi_kernel_install_interrupt_handler`], which never
/// succeeds, so there is never a handler to remove.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_uninstall_interrupt_handler(
    _handler: uacpi_interrupt_handler,
    _irq_handle: uacpi_handle,
) -> uacpi_status {
    UACPI_STATUS_UNIMPLEMENTED
}

/// Runs deferred work immediately.
///
/// There is no second execution context to defer to, so the work runs on the
/// caller's stack. uACPI only schedules work from the interpreter, so a handler
/// that evaluates AML re-enters it; that is sound here because the locks it takes
/// never block ([`crate::sync`]).
///
/// # Safety
///
/// `handler` must be safe to call with `ctx`, which is what uACPI guarantees for
/// the pair it passes in.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_schedule_work(
    _work_type: uacpi_work_type,
    handler: uacpi_work_handler,
    ctx: uacpi_handle,
) -> uacpi_status {
    let Some(handler) = handler else {
        return UACPI_STATUS_INVALID_ARGUMENT;
    };

    // SAFETY: the caller guarantees the handler accepts this context.
    unsafe { handler(ctx) };
    UACPI_STATUS_OK
}

/// Waits for outstanding deferred work, of which there is never any:
/// [`uacpi_kernel_schedule_work`] finishes before it returns.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_wait_for_work_completion() -> uacpi_status {
    UACPI_STATUS_OK
}
