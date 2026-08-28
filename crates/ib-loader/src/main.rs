//! UEFI application entry point for insecure-boot.
//!
//! The image runs before boot services are exited, so the firmware's simple
//! text output protocol (`ConOut`) is still live and the greeting is written
//! straight through it rather than through a logging facade.

#![no_main]
#![no_std]

use uefi::CStr16;
use uefi::prelude::*;
use uefi::proto::console::text::Output;

/// Greeting written to the firmware console.
///
/// `ConOut` advances the cursor to the next line only on carriage-return plus
/// line-feed, so both are part of the literal.
const GREETING: &CStr16 = cstr16!("Hello, World!\r\n");

/// Writes [`GREETING`] to `ConOut` and reports the firmware's own status back
/// to whoever loaded the image.
#[entry]
fn main() -> Status {
    system::with_stdout(write_greeting).map_or_else(|err| err.status(), |()| Status::SUCCESS)
}

/// Writes [`GREETING`] to `stdout`.
fn write_greeting(stdout: &mut Output) -> uefi::Result {
    stdout.output_string(GREETING)
}
