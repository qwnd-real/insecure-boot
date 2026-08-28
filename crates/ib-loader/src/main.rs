//! UEFI application entry point for insecure-boot.
//!
//! Brings ACPI up through uACPI, looks for a TPM 2.0 Command Response Buffer
//! interface, and reports what the interface says about itself on the firmware
//! console. The image runs before boot services are exited, so the console, the
//! delay services and the identity-mapped address space every layer below relies
//! on are all still available.

#![no_main]
#![no_std]

mod capability;

use ib_tpm_crb::Tpm;
use uefi::prelude::*;
use uefi::println;

/// Capacity reserved for a TPM reply.
///
/// The only command this loader sends is answered in 27 bytes; the buffer is
/// rounded up so that a TPM reporting more than it was asked for still fits.
const REPLY_LEN: usize = 64;

/// Reports the state of the platform's ACPI namespace and TPM, and returns a
/// status describing how far it got.
#[entry]
fn main() -> Status {
    println!("insecure-boot: Hello, World!");

    if let Err(error) = ib_uacpi::init() {
        println!("insecure-boot: ACPI bring-up failed: {error}");
        return Status::LOAD_ERROR;
    }

    match report_tpm() {
        Ok(()) => Status::SUCCESS,
        Err(error) => {
            println!("insecure-boot: TPM unusable: {error}");
            Status::DEVICE_ERROR
        }
    }
}

/// Probes the TPM and prints what it reports about itself.
fn report_tpm() -> Result<(), ib_tpm_crb::Error> {
    let Some(mut tpm) = Tpm::probe()? else {
        println!("insecure-boot: no TPM 2.0 command-response-buffer interface");
        return Ok(());
    };

    println!(
        "insecure-boot: TPM on {} using start method {}",
        tpm.hardware_id(),
        tpm.start_method()
    );
    println!("  command buffer: {} bytes", tpm.command_size());
    if let Some(interface_id) = tpm.interface_id() {
        println!("  interface id:   {interface_id:#018x}");
    }

    let mut reply = [0_u8; REPLY_LEN];
    let length = tpm.transmit(&capability::GET_MANUFACTURER, &mut reply)?;

    match capability::manufacturer(&reply[..length]) {
        Ok(manufacturer) => println!("  manufacturer:   {manufacturer}"),
        Err(error) => println!("  manufacturer:   unavailable, {error}"),
    }

    Ok(())
}
