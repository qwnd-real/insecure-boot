//! UEFI application entry point for insecure-boot.
//!
//! Brings ACPI up through uACPI, finds the platform's TPM 2.0 Command Response
//! Buffer interface, replays a `tcglog.ib` dump into PCR0 through PCR7 if one is
//! there to be found, and publishes an `EFI_TCG2_PROTOCOL` over the event log
//! that dump describes. The image runs before boot services are exited, so the
//! console, the delay services, the file systems and the identity-mapped address
//! space every layer below relies on are all still available.

#![no_main]
#![no_std]

extern crate alloc;

mod error;
mod replay;
mod tcg2;

use ib_tcglog::Dump;
use ib_tpm_crb::Tpm;
use ib_tpm2::capability;
use uefi::prelude::*;
use uefi::println;

use crate::error::{Error, Result};

/// Reports the state of the platform's ACPI namespace and TPM, replays the event
/// log if a dump for it is present, publishes the TCG2 protocol over it, and
/// returns a status describing how far it got.
#[entry]
fn main() -> Status {
    println!("insecure-boot: Hello, World!");

    if let Err(error) = ib_uacpi::init() {
        println!("insecure-boot: ACPI bring-up failed: {error}");
        return Status::LOAD_ERROR;
    }

    match run() {
        Ok(()) => Status::SUCCESS,
        Err(error) => {
            println!("insecure-boot: {error}");
            Status::DEVICE_ERROR
        }
    }
}

/// Probes the TPM, replays a dump if there is one, and publishes the TCG2 protocol
/// over the log it describes.
fn run() -> Result<()> {
    let Some(mut tpm) = probe()? else {
        println!("insecure-boot: no TPM 2.0 command-response-buffer interface");
        return Ok(());
    };

    let bytes = replay::find();
    if bytes.is_none() {
        println!(
            "insecure-boot: no {} in the root of any file system",
            ib_tcglog::FILE_NAME
        );
    }

    let dump = bytes.as_deref().map(Dump::parse).transpose()?;

    if let Some(dump) = &dump {
        replay::run(&mut tpm, dump)?;
    }

    let tcg2 = tcg2::install(tpm, dump.as_ref())?;
    tcg2::exercise(&tcg2)?;

    // The protocol's functions live in this image, so it cannot outlive it. An
    // application that returns is unloaded, which would leave the table pointing
    // at freed memory; a loader that hands control on instead leaves it installed.
    tcg2.uninstall()?;
    println!("insecure-boot: EFI_TCG2_PROTOCOL withdrawn before the image unloads");

    Ok(())
}

/// Probes the TPM, prints what it reports about itself, and hands it over.
fn probe() -> Result<Option<Tpm>> {
    let Some(mut tpm) = Tpm::probe()? else {
        return Ok(None);
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

    let mut command = [0_u8; capability::COMMAND_CAPACITY];
    let mut reply = [0_u8; capability::REPLY_CAPACITY];

    let len = capability::property(&mut command, capability::Property::MANUFACTURER)
        .ok_or(Error::CommandTooLong("TPM2_GetCapability"))?;
    let len = tpm.transmit(&command[..len], &mut reply)?;

    match capability::manufacturer(reply.get(..len).unwrap_or_default()) {
        Ok(manufacturer) => println!("  manufacturer:   {manufacturer}"),
        Err(error) => println!("  manufacturer:   unavailable, {error}"),
    }

    Ok(Some(tpm))
}
