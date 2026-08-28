//! Writes a `tcglog.ib` replay dump from the platform's TCG event log.
//!
//! The dump carries every record the log holds for PCR0 through PCR7 along with
//! the PCR values those records fold to, so firmware can replay the measurements
//! and check that it arrived where the platform did. Reading the log needs
//! administrative rights on both operating systems this runs on.

mod encode;
mod error;
mod fold;
mod source;
mod tcg;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ib_tcglog::{Dump, PCR_COUNT};

use crate::encode::Expected;
use crate::error::{Error, Result};

/// Command line this tool accepts.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Arguments {
    /// Where to write the dump.
    #[arg(default_value = ib_tcglog::FILE_NAME)]
    output: PathBuf,

    /// Read the event log from this file rather than from the running platform.
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,
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

/// Reads the log, works out what it folds to, and writes the dump.
fn run(arguments: &Arguments) -> Result<()> {
    let raw = match &arguments.log {
        Some(path) => source::read_file(path)?,
        None => source::read_log()?,
    };

    println!(
        "ib-tcg-dump: read {} bytes of event log from {}",
        raw.bytes.len(),
        raw.origin
    );

    let log = tcg::parse(&raw.bytes)?;
    println!(
        "  encoding:         {}",
        if log.agile {
            "crypto-agile"
        } else {
            "one SHA-1 digest per record"
        }
    );
    println!("  startup locality: {}", log.startup_locality);
    println!(
        "  records:          {} for PCR0-7, {} for other PCRs",
        log.records.len(),
        log.skipped
    );

    let banks = expected(&log);
    if banks.is_empty() {
        return Err(Error::NoUsableBank);
    }

    let bytes = encode::encode(&log, &banks)?;
    check(&bytes, &banks)?;
    for bank in &banks {
        show(bank);
    }

    std::fs::write(&arguments.output, &bytes).map_err(|source| Error::Write {
        path: arguments.output.clone(),
        source,
    })?;

    println!(
        "ib-tcg-dump: wrote {} bytes to {}",
        bytes.len(),
        arguments.output.display()
    );

    Ok(())
}

/// Folds every bank the log declared, reporting the ones that cannot be folded.
fn expected(log: &tcg::EventLog) -> Vec<Expected> {
    let mut banks = Vec::new();

    for bank in &log.banks {
        let Some(values) = fold::fold(*bank, &log.records, log.startup_locality) else {
            let reason = if fold::supported(bank.algorithm) {
                "a measured record carries no digest for it"
            } else {
                "this tool cannot compute that hash"
            };

            println!("  {} bank: no expected values, {reason}", bank.algorithm);
            continue;
        };

        banks.push(Expected {
            algorithm: bank.algorithm,
            digest_size: bank.digest_size,
            values,
        });
    }

    banks
}

/// Reads the dump back and replays it, to prove it describes the log it was
/// written from.
fn check(bytes: &[u8], banks: &[Expected]) -> Result<()> {
    let dump = Dump::parse(bytes)?;

    for expected in banks {
        let bank = dump.bank(expected.algorithm)?;

        let mut extends = Vec::new();
        for event in dump.events() {
            let event = event?;
            if event.extends_pcr() {
                extends.push((event.pcr_index(), event.digest(expected.algorithm)?));
            }
        }

        let values = fold::replay(
            expected.algorithm,
            bank.digest_size(),
            dump.startup_locality(),
            &extends,
        )
        .ok_or(Error::Inconsistent(expected.algorithm))?;

        for (index, value) in (0..PCR_COUNT).zip(&values) {
            if bank.expected(index) != Some(value.as_slice()) {
                return Err(Error::Inconsistent(expected.algorithm));
            }
        }
    }

    Ok(())
}

/// Prints the values one bank folds to, and how they compare with the PCRs the
/// running TPM currently holds.
fn show(bank: &Expected) {
    println!(
        "  {} bank, {} bytes per digest:",
        bank.algorithm, bank.digest_size
    );

    for (index, value) in (0..PCR_COUNT).zip(&bank.values) {
        println!("    PCR{index}  {}", hex(value));
    }

    match source::live_pcrs(bank.algorithm) {
        None => println!("    the running system does not publish these PCRs"),
        Some(live) if live == bank.values => println!("    matches the PCRs of the running TPM"),
        Some(live) => {
            let first = (0..PCR_COUNT)
                .zip(&live)
                .zip(&bank.values)
                .find(|((_, live), folded)| live != folded)
                .map(|((index, _), _)| index);

            match first {
                Some(index) => println!("    differs from the running TPM from PCR{index} on"),
                None => println!("    differs from the running TPM"),
            }
        }
    }
}

/// Formats a digest the way it is usually quoted.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Prints an error and everything that caused it.
fn report(error: &Error) {
    eprintln!("ib-tcg-dump: {error}");

    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
