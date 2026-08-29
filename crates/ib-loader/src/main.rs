//! UEFI application entry point for insecure-boot.
//!
//! Runs once, out of the shim the host tool has put in the Windows boot
//! manager's place: restores the original `bootmgfw.efi`, consumes the payload
//! and the `tcglog.ib` replay dump staged in the boot volume, brings ACPI up
//! through uACPI, replays the dump into PCR0 through PCR7 over the platform's
//! TPM 2.0 Command Response Buffer interface if there is one, and publishes an
//! `EFI_TCG2_PROTOCOL` over the event log that dump describes. The payload is
//! mapped and run by hand — it is unsigned, so `LoadImage` would refuse it —
//! and the restored boot manager is then started from its own path. The image
//! runs before boot services are exited, so the console, the delay services,
//! the file systems and the identity-mapped address space every layer below
//! relies on are all still available.

#![no_main]
#![no_std]

extern crate alloc;

mod bootmgfw;
mod error;
mod fs;
mod payload;
mod replay;
mod sbat;
mod tcg2;

use core::time::Duration;

use ib_tcglog::Dump;
use ib_tpm_crb::Tpm;
use ib_tpm2::capability;
use uefi::prelude::*;
use uefi::println;

use crate::error::{Error, Result};

/// Where the host tool stages the payload in the boot volume.
const PAYLOAD_NAME: &str = r"\ib-load.efi";

/// How long an error is left on the console before the image gives up.
const ERROR_STALL: Duration = Duration::from_secs(5);

/// Reports the state of the platform's ACPI namespace and TPM, restores the
/// Windows boot manager, replays the event log if a dump for it is present,
/// publishes the TCG2 protocol over it, runs the payload, and starts the boot
/// manager.
#[entry]
fn main() -> Status {
    println!("insecure-boot: Hello, World!");

    if let Err(error) = ib_uacpi::init() {
        println!("insecure-boot: ACPI bring-up failed: {error}");
        boot::stall(ERROR_STALL);
        return Status::LOAD_ERROR;
    }

    match run() {
        Ok(()) => Status::SUCCESS,
        Err(error) => {
            println!("insecure-boot: {error}");
            boot::stall(ERROR_STALL);
            Status::DEVICE_ERROR
        }
    }
}

/// Restores the boot manager, consumes the staged artifacts and the shim
/// chain that reached them, publishes the TCG2 protocol if the platform has a
/// TPM, runs the payload, and starts the boot manager.
///
/// The TCG2 protocol the payload sees is withdrawn only if control comes back:
/// the boot manager starting Windows takes it away with the image instead.
fn run() -> Result<()> {
    let mut volume = fs::open()?;

    bootmgfw::restore(&mut volume)?;

    let payload = volume.read(PAYLOAD_NAME)?;
    let dump_bytes = volume.read_optional(ib_tcglog::FILE_NAME)?;
    if dump_bytes.is_none() {
        println!(
            "insecure-boot: no {} in the root of the boot volume",
            ib_tcglog::FILE_NAME
        );
    }

    volume.wipe(PAYLOAD_NAME)?;
    if dump_bytes.is_some() {
        volume.wipe(ib_tcglog::FILE_NAME)?;
    }
    volume.wipe(bootmgfw::BACKUP)?;
    volume.wipe(bootmgfw::MOK_MANAGER)?;
    volume.wipe(bootmgfw::RENAMED_LOADER)?;

    let dump = dump_bytes.as_deref().map(Dump::parse).transpose()?;

    let mut tcg2 = None;
    if let Some(mut tpm) = probe()? {
        if let Some(dump) = &dump {
            replay::run(&mut tpm, dump)?;
        }

        let instance = tcg2::install(tpm, dump.as_ref())?;
        tcg2::exercise(&instance)?;
        tcg2 = Some(instance);
    } else {
        println!("insecure-boot: no TPM 2.0 command-response-buffer interface");
    }

    let outcome = tail(&payload);

    // The protocol's functions live in this image, so it cannot outlive it.
    // An application that returns is unloaded, which would leave the table
    // pointing at freed memory; a loader that hands control on instead leaves
    // it installed. This is the coming-back path.
    if let Some(tcg2) = tcg2 {
        tcg2.uninstall()?;
        println!("insecure-boot: EFI_TCG2_PROTOCOL withdrawn before the image unloads");
    }

    outcome
}

/// Runs the payload, then starts the restored boot manager.
fn tail(payload: &[u8]) -> Result<()> {
    payload::run(payload)?;
    bootmgfw::start()
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
