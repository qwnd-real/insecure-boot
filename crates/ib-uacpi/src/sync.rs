//! Locks and events for a host that owns the processor outright.
//!
//! A UEFI application runs on the boot processor with no other thread in
//! existence, and uACPI is built in reduced-hardware mode so none of its code
//! runs from an interrupt handler. Nothing can therefore contend a mutex or
//! signal an event behind uACPI's back, which collapses these primitives:
//!
//! - Mutex acquisition always succeeds immediately.
//! - Spinlocks reduce to masking interrupts, so that a firmware timer callback
//!   cannot observe a half-updated uACPI structure.
//! - Events only ever see the signals AML itself raised earlier, so a wait that
//!   finds no pending signal can only time out.

use alloc::boxed::Box;
use core::cell::Cell;
use core::ptr;
use core::time::Duration;

use uacpi_sys::{
    UACPI_STATUS_OK, uacpi_bool, uacpi_cpu_flags, uacpi_handle, uacpi_interrupt_state,
    uacpi_status, uacpi_thread_id, uacpi_u16,
};
use x86_64::instructions::interrupts;

use crate::time::stall;

/// Timeout value with which uACPI asks to block until an event is signalled.
const WAIT_FOREVER: uacpi_u16 = 0xFFFF;

/// Identity of the only thread that ever enters uACPI.
///
/// uACPI reserves the all-ones value to mean "no thread", so any other non-null
/// value serves as an identity. The handle is compared, never dereferenced.
const THREAD_ID: usize = 1;

/// Number of outstanding signals behind a uACPI event handle.
struct Event(Cell<u64>);

/// Reports the identity of the calling thread.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_get_thread_id() -> uacpi_thread_id {
    ptr::without_provenance_mut(THREAD_ID)
}

/// Masks interrupts, reporting whether they had been enabled.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_disable_interrupts() -> uacpi_interrupt_state {
    uacpi_interrupt_state::from(mask_interrupts())
}

/// Restores the interrupt flag captured by [`uacpi_kernel_disable_interrupts`].
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_restore_interrupts(state: uacpi_interrupt_state) {
    restore_interrupts(state != 0);
}

/// Creates a mutex.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_mutex() -> uacpi_handle {
    new_cookie()
}

/// Destroys a mutex created by [`uacpi_kernel_create_mutex`].
///
/// # Safety
///
/// `handle` must come from [`uacpi_kernel_create_mutex`] and must not be used
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_free_mutex(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` is an unreleased mutex cookie.
    unsafe { free_cookie(handle) };
}

/// Acquires a mutex, which can never block on this host.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_acquire_mutex(
    _handle: uacpi_handle,
    _timeout: uacpi_u16,
) -> uacpi_status {
    UACPI_STATUS_OK
}

/// Releases a mutex.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_release_mutex(_handle: uacpi_handle) {}

/// Creates a spinlock.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_spinlock() -> uacpi_handle {
    new_cookie()
}

/// Destroys a spinlock created by [`uacpi_kernel_create_spinlock`].
///
/// # Safety
///
/// `handle` must come from [`uacpi_kernel_create_spinlock`] and must not be used
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_free_spinlock(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` is an unreleased spinlock cookie.
    unsafe { free_cookie(handle) };
}

/// Takes a spinlock by masking interrupts, reporting whether they were enabled.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_lock_spinlock(_handle: uacpi_handle) -> uacpi_cpu_flags {
    uacpi_cpu_flags::from(mask_interrupts())
}

/// Releases a spinlock, restoring the interrupt flag `flags` captured.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_unlock_spinlock(_handle: uacpi_handle, flags: uacpi_cpu_flags) {
    restore_interrupts(flags != 0);
}

/// Creates an event with no outstanding signals.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_create_event() -> uacpi_handle {
    Box::into_raw(Box::new(Event(Cell::new(0)))).cast()
}

/// Destroys an event created by [`uacpi_kernel_create_event`].
///
/// # Safety
///
/// `handle` must come from [`uacpi_kernel_create_event`] and must not be used
/// afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_free_event(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` is an unreleased event, so it was
    // produced by `Box::into_raw` on a `Box<Event>`.
    drop(unsafe { Box::from_raw(handle.cast::<Event>()) });
}

/// Records one signal on an event.
///
/// # Safety
///
/// `handle` must be a live event from [`uacpi_kernel_create_event`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_signal_event(handle: uacpi_handle) {
    // SAFETY: the caller guarantees a live event handle.
    let event = unsafe { event(handle) };
    event.0.set(event.0.get().saturating_add(1));
}

/// Discards every outstanding signal on an event.
///
/// # Safety
///
/// `handle` must be a live event from [`uacpi_kernel_create_event`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_reset_event(handle: uacpi_handle) {
    // SAFETY: the caller guarantees a live event handle.
    unsafe { event(handle) }.0.set(0);
}

/// Consumes one signal from an event, waiting up to `timeout` milliseconds.
///
/// Nothing can signal the event while the caller waits, so a wait that finds no
/// pending signal burns the timeout and reports failure. A request to block
/// forever returns immediately instead of hanging the boot.
///
/// # Safety
///
/// `handle` must be a live event from [`uacpi_kernel_create_event`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uacpi_kernel_wait_for_event(
    handle: uacpi_handle,
    timeout: uacpi_u16,
) -> uacpi_bool {
    // SAFETY: the caller guarantees a live event handle.
    let event = unsafe { event(handle) };

    let outstanding = event.0.get();
    if outstanding > 0 {
        event.0.set(outstanding - 1);
        return true;
    }

    if timeout != WAIT_FOREVER {
        stall(Duration::from_millis(u64::from(timeout)));
    }
    false
}

/// Masks interrupts and reports whether they had been enabled.
fn mask_interrupts() -> bool {
    let enabled = interrupts::are_enabled();
    interrupts::disable();
    enabled
}

/// Re-enables interrupts if `enabled` says they were on beforehand.
fn restore_interrupts(enabled: bool) {
    if enabled {
        interrupts::enable();
    }
}

/// Allocates a unique, non-null handle for a lock.
///
/// uACPI only ever compares lock handles, so the pointee is a placeholder; the
/// allocation exists to make every handle distinct.
fn new_cookie() -> uacpi_handle {
    Box::into_raw(Box::new(0_u8)).cast()
}

/// Releases a handle from [`new_cookie`].
///
/// # Safety
///
/// `handle` must come from [`new_cookie`] and must not have been released yet.
unsafe fn free_cookie(handle: uacpi_handle) {
    // SAFETY: the caller guarantees `handle` was produced by `Box::into_raw` on
    // a `Box<u8>` and has not been released.
    drop(unsafe { Box::from_raw(handle.cast::<u8>()) });
}

/// Borrows the event behind a uACPI handle.
///
/// # Safety
///
/// `handle` must be a live event from [`uacpi_kernel_create_event`].
unsafe fn event(handle: uacpi_handle) -> &'static Event {
    // SAFETY: the caller guarantees the handle refers to a live `Event`, which
    // lives on the heap until `uacpi_kernel_free_event` releases it.
    unsafe { &*handle.cast::<Event>() }
}
