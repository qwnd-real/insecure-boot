//! Delays and monotonic time, both derived from UEFI boot services.
//!
//! `Stall` is the only delay boot services offer, so both the microsecond and
//! the millisecond primitive busy-wait through it.
//!
//! Boot services expose no monotonic counter, so the clock is the timestamp
//! counter, whose frequency is measured once against `Stall`. That makes the
//! clock only as accurate as firmware's `Stall`, which is ample for the
//! millisecond-scale timeouts uACPI and device drivers use it for, and it
//! assumes the counter runs at a constant rate — true for every x86-64 part
//! with an invariant TSC, and nothing changes the core frequency while a UEFI
//! application is running.

use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use uacpi_sys::{uacpi_u8, uacpi_u64};
use uefi::boot;

/// Width of the window used to measure the timestamp counter frequency.
///
/// Long enough that firmware `Stall` jitter stays far below a percent of the
/// interval, short enough to be invisible at boot.
const CALIBRATION: Duration = Duration::from_millis(10);

/// Nanoseconds in one second.
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Frequency assumed when the timestamp counter appears not to advance, which
/// would otherwise leave the clock with no usable scale at all.
const FALLBACK_HZ: u64 = 1_000_000_000;

/// Measured frequency of the timestamp counter in hertz, or zero before the
/// first measurement.
static TICKS_PER_SECOND: AtomicU64 = AtomicU64::new(0);

/// Timestamp counter reading taken when the frequency was measured, which is the
/// zero point of [`monotonic`].
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Busy-waits for at least `duration`.
pub fn stall(duration: Duration) {
    boot::stall(duration);
}

/// Time elapsed since the clock was first used.
///
/// Only the difference between two readings is meaningful; the zero point is
/// whenever this module was first touched, not power-on.
#[must_use]
pub fn monotonic() -> Duration {
    Duration::from_nanos(elapsed_nanos())
}

/// Busy-waits for `usec` microseconds.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_stall(usec: uacpi_u8) {
    stall(Duration::from_micros(u64::from(usec)));
}

/// Busy-waits for `msec` milliseconds.
///
/// There is nothing to yield to before `ExitBootServices`, so sleeping and
/// stalling are the same operation.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_sleep(msec: uacpi_u64) {
    stall(Duration::from_millis(msec));
}

/// Reports monotonically increasing nanoseconds for uACPI's timeout bookkeeping.
#[unsafe(no_mangle)]
pub extern "C" fn uacpi_kernel_get_nanoseconds_since_boot() -> uacpi_u64 {
    elapsed_nanos()
}

/// Nanoseconds elapsed since [`EPOCH`], saturating rather than wrapping.
fn elapsed_nanos() -> u64 {
    let hz = ticks_per_second();
    let ticks = timestamp().wrapping_sub(EPOCH.load(Ordering::Relaxed));

    let nanos = u128::from(ticks) * NANOS_PER_SECOND / u128::from(hz);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

/// Frequency of the timestamp counter, measuring it on the first call.
fn ticks_per_second() -> u64 {
    let cached = TICKS_PER_SECOND.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    let start = timestamp();
    boot::stall(CALIBRATION);
    let ticks = timestamp().wrapping_sub(start);

    let micros = u64::try_from(CALIBRATION.as_micros()).unwrap_or(u64::MAX);
    let measured = ticks.saturating_mul(1_000_000) / micros;
    let hz = if measured == 0 { FALLBACK_HZ } else { measured };

    EPOCH.store(start, Ordering::Relaxed);
    TICKS_PER_SECOND.store(hz, Ordering::Relaxed);
    hz
}

/// Current timestamp counter reading.
fn timestamp() -> u64 {
    // SAFETY: RDTSC is unprivileged and present on every x86-64 processor. It
    // reads no memory and has no side effects beyond advancing no state at all.
    unsafe { _rdtsc() }
}
