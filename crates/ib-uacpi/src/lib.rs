//! uACPI running on top of UEFI boot services.
//!
//! This crate supplies every `uacpi_kernel_*` primitive that [`uacpi_sys`]
//! leaves undefined and wraps the parts of the uACPI API that drivers in this
//! workspace need in safe types. Linking it is what makes uACPI usable; the
//! primitives are exported by symbol name rather than called from Rust.
//!
//! # Environment assumptions
//!
//! Every primitive here is written for the pre-`ExitBootServices` epoch of a
//! UEFI application, which pins down several things that a general-purpose host
//! could not assume:
//!
//! - The address space is flat and identity-mapped, so mapping a physical
//!   address is a cast (see [`memory`]).
//! - The application owns the boot processor and no uACPI code runs from an
//!   interrupt, so locks cannot be contended (see [`sync`]).
//! - Firmware owns the SCI and the ACPI global lock, so uACPI is built in
//!   reduced-hardware mode and never asks to install an interrupt handler.
//!
//! Calling any of this after `ExitBootServices` will panic inside the `uefi`
//! crate, because boot services back the delay and console primitives.

#![no_std]

extern crate alloc;

pub mod console;
pub mod memory;
pub mod platform;
pub mod sync;
pub mod time;

mod error;
mod io;
mod namespace;
mod resources;
mod tables;

pub use error::{Error, Result};
pub use namespace::{Device, HardwareId, find_device};
pub use resources::{MemoryRange, MemoryRanges, Resources};
pub use tables::{Table, find_table};

use error::check;

/// Brings uACPI up to the point where AML methods can be evaluated.
///
/// Runs the three initialization stages in the order uACPI requires: interpreter
/// and table setup, loading the DSDT and any SSDTs into the namespace, then
/// running the namespace's `_STA` and `_INI` methods.
///
/// # Errors
///
/// Fails if the firmware publishes no RSDP, if a required table is malformed, or
/// if AML execution fails during namespace initialization.
pub fn init() -> Result<()> {
    // SAFETY: `uacpi_initialize` is the first uACPI entry point called and the
    // host primitives it depends on are all linked in by this crate. A zero
    // flag word selects the default behaviour.
    check(unsafe { uacpi_sys::uacpi_initialize(0) })?;

    // SAFETY: initialization succeeded above, which is the precondition for
    // loading the namespace.
    check(unsafe { uacpi_sys::uacpi_namespace_load() })?;

    // SAFETY: the namespace has been loaded, which is the precondition for
    // running its initialization methods.
    check(unsafe { uacpi_sys::uacpi_namespace_initialize() })
}
