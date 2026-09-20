//! Stages a one-shot insecure-boot run on a Windows machine's ESP.
//!
//! The loader is signed with a machine owner key, an enrollment request for
//! that key is written for `MokManager` to ask about on the next boot, and the
//! ESP is staged: the dump and the payload in its root, the Windows boot
//! manager backed up beside them, and a shim chain in the boot manager's
//! place that runs the signed loader as `grubx64.efi`. Nothing runs that the
//! user has not confirmed in `MokManager` first. The key pair is kept in the
//! working directory — `mok.key` and `mok.der` — so later runs sign with the
//! key that has already been enrolled.

mod error;
#[cfg(windows)]
mod esp;
#[cfg(windows)]
mod firmware;
mod mok;
mod sign;

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use crate::error::{Error, Result};
use crate::mok::Mok;

/// The loader this run signs and stages.
const LOADER: &str = "ib-loader.efi";

/// The shim this run puts in the boot manager's place.
const SHIM: &str = "shimx64.efi";

/// The `MokManager` the shim runs to ask about the key.
const MOK_MANAGER: &str = "mmx64.efi";

/// The offset within `Setup` where AMI firmware keeps the TPM UEFI spec
/// version, which an empty answer at the prompt takes.
const DEFAULT_TCG_SPEC_OFFSET: u16 = 0x1b;

/// Command line this tool accepts.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    /// The EFI application the staged boot runs once.
    payload: PathBuf,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();

    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Checks the working directory holds everything this run needs, signs the
/// loader, and stages the boot.
fn run(arguments: &Arguments) -> Result<()> {
    preflight(arguments)?;

    let mok = mok::load_or_generate()?;

    let signed = sign::sign(&read(LOADER)?, &mok)?;
    println!(
        "ib-install: signed {LOADER}, {} bytes with its signature",
        signed.len()
    );

    stage(arguments, &mok, &signed)
}

/// Probes the firmware's variable protection, asks where the TPM UEFI spec
/// version sits in `Setup`, writes the enrollment request, and stages the
/// ESP: the part only Windows can do.
///
/// # Errors
///
/// Fails if the firmware refuses variable writes, the enrollment request, or
/// any part of the staging.
#[cfg(windows)]
fn stage(arguments: &Arguments, mok: &Mok, signed: &[u8]) -> Result<()> {
    firmware::probe()?;

    let config = ib_config::Config::new(ask_setup_offset()?);

    let request = mok::signature_list(mok.cert());
    mok::enroll(mok, &request)?;

    let esp = esp::mount()?;
    esp.deploy(&arguments.payload, signed, config)?;

    println!(
        "ib-install: staged; the ESP stays mounted at {}:\\",
        esp.letter()
    );
    println!("  next boot: MokManager asks for the password and whether to enroll the key");
    println!(
        "  the boot after: the loader flips TCG UEFI spec version to TCG 1.2 and resets, if it was TCG 2.0"
    );
    println!("  the boot after that: the loader runs once, restores Windows, and boots it");

    Ok(())
}

/// Asks for the byte offset, within `Setup`, of the TPM UEFI spec version
/// setting. AMI firmware keeps it at [`DEFAULT_TCG_SPEC_OFFSET`], which is
/// what an empty answer takes.
///
/// # Errors
///
/// Fails if the console input cannot be read.
#[cfg(windows)]
fn ask_setup_offset() -> Result<u16> {
    println!("ib-install: the loader flips the TPM UEFI spec version through the Setup variable");
    println!("  byte offset of \"TPM UEFI Spec Version\" within Setup");

    loop {
        print!("  offset [default 0x{DEFAULT_TCG_SPEC_OFFSET:X}]: ");
        io::stdout().flush().map_err(Error::Input)?;

        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(Error::Input)?;

        let answer = line.trim();
        if answer.is_empty() {
            return Ok(DEFAULT_TCG_SPEC_OFFSET);
        }

        if let Some(offset) = parse_offset(answer) {
            return Ok(offset);
        }
        println!("  not an offset I can read; hexadecimal like 1b or 0x1b, or decimal like 27");
    }
}

/// Parses an offset answer: `0x1b` as hexadecimal, otherwise decimal with a
/// hexadecimal fallback, because `1b` reads as hexadecimal to anyone typing
/// an offset.
#[cfg(windows)]
fn parse_offset(answer: &str) -> Option<u16> {
    if let Some(hex) = answer
        .strip_prefix("0x")
        .or_else(|| answer.strip_prefix("0X"))
    {
        return u16::from_str_radix(hex, 16).ok();
    }

    answer
        .parse::<u16>()
        .ok()
        .or_else(|| u16::from_str_radix(answer, 16).ok())
}

/// The same, where there is no firmware to talk to.
#[cfg(not(windows))]
fn stage(_arguments: &Arguments, _mok: &Mok, _signed: &[u8]) -> Result<()> {
    Err(Error::NotWindows)
}

/// Checks that the working directory holds everything this run needs, and
/// that the payload named on the command line is an EFI application.
///
/// # Errors
///
/// Fails if any of them is missing.
fn preflight(arguments: &Arguments) -> Result<()> {
    for name in [ib_tcglog::FILE_NAME, LOADER, SHIM, MOK_MANAGER] {
        if !Path::new(name).exists() {
            return Err(Error::Missing {
                path: PathBuf::from(name),
            });
        }
    }

    let extension = arguments
        .payload
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("efi"));

    if !arguments.payload.exists() || !extension {
        return Err(Error::NotAnEfi {
            path: arguments.payload.clone(),
        });
    }

    Ok(())
}

/// Reads a whole file, naming it if that fails.
///
/// # Errors
///
/// Fails if the file cannot be read.
fn read(name: &str) -> Result<Vec<u8>> {
    let path = Path::new(name);
    std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

/// Widens ASCII for the interfaces that take wide strings.
#[cfg(windows)]
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// Prints an error and everything that caused it.
fn report(error: &Error) {
    eprintln!("ib-install: {error}");

    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
