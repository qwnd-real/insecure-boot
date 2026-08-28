//! Replaying a `tcglog.ib` dump into the platform's PCR0 through PCR7.
//!
//! The dump is looked for in the root directory of every file system the
//! firmware knows about, and the first one that yields it wins. Its events are
//! extended in log order, which is the only order that reproduces the values the
//! platform it was taken from ended up with, and the PCRs are then read back and
//! compared against the values the dump records.
//!
//! A replay lands on those values only when nothing has extended the PCRs yet.
//! Firmware that measures its own boot gets there first on real hardware, so the
//! comparison is reported rather than enforced.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use ib_tcglog::{Algorithm, Bank, Dump, PCR_COUNT};
use ib_tpm_crb::Tpm;
use ib_tpm2::{Digest, pcr};
use uefi::boot::{self, SearchType};
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, RegularFile};
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::{CStr16, Identify, println};

use crate::error::{Error, Result};

/// Bank the replay extends and checks.
///
/// Every TPM 2.0 platform profile requires a SHA-256 bank, and it is the one a
/// crypto-agile log is certain to carry digests for.
const BANK: Algorithm = Algorithm::SHA256;

/// Length of a buffer holding the dump's name as UCS-2, including the terminator
/// the firmware expects.
const NAME_CAPACITY: usize = ib_tcglog::FILE_NAME.len() + 1;

/// Reads the first dump found in the root directory of any file system the
/// firmware knows about.
#[must_use]
pub fn find() -> Option<Vec<u8>> {
    let mut buffer = [0_u16; NAME_CAPACITY];
    let name = CStr16::from_str_with_buf(ib_tcglog::FILE_NAME, &mut buffer).ok()?;

    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID)).ok()?;

    handles.iter().find_map(|handle| {
        let mut file_system = boot::open_protocol_exclusive::<SimpleFileSystem>(*handle).ok()?;
        let mut root = file_system.open_volume().ok()?;
        let file = root
            .open(name, FileMode::Read, FileAttribute::empty())
            .ok()?;

        contents(file.into_regular_file()?)
    })
}

/// Replays `dump` into the TPM, and reports how far the result agrees with what
/// the dump says the platform measured.
///
/// # Errors
///
/// Fails if the dump cannot be walked, or if the TPM refuses a command.
pub fn run(tpm: &mut Tpm, dump: &Dump<'_>) -> Result<()> {
    let bank = dump.bank(BANK)?;

    println!(
        "insecure-boot: replaying {} events from {}",
        dump.event_count(),
        ib_tcglog::FILE_NAME
    );
    println!(
        "  bank:             {}, {} bytes per digest",
        bank.algorithm(),
        bank.digest_size()
    );
    println!("  startup locality: {}", dump.startup_locality());
    if dump.startup_locality() != 0 {
        println!("  PCR0 was reset to that locality, which extending cannot reproduce");
    }

    survey(tpm, &bank)?;
    let extended = extend(tpm, dump, &bank)?;
    println!(
        "  extended:         {extended} of {} events",
        dump.event_count()
    );

    compare(tpm, &bank)
}

/// Reports whether anything has extended the PCRs yet, since only a TPM whose
/// PCRs are still at their reset values can end up holding the dump's.
fn survey(tpm: &mut Tpm, bank: &Bank<'_>) -> Result<()> {
    let mut used = None;
    for index in 0..PCR_COUNT {
        if value(tpm, index, bank.algorithm())?
            .iter()
            .any(|byte| *byte != 0)
        {
            used = Some(index);
            break;
        }
    }

    match used {
        None => println!("  the PCRs are all zero, so the replay starts where the platform did"),
        Some(index) => println!("  PCR{index} is already non-zero, so the replay starts above it"),
    }

    Ok(())
}

/// Extends every event the dump records into the PCR it names, in log order, and
/// reports how many were extended.
fn extend(tpm: &mut Tpm, dump: &Dump<'_>, bank: &Bank<'_>) -> Result<u32> {
    let mut command = [0_u8; pcr::EXTEND_CAPACITY];
    let mut reply = [0_u8; pcr::REPLY_CAPACITY];
    let mut extended = 0;

    for event in dump.events() {
        let event = event?;
        if !event.extends_pcr() {
            continue;
        }

        let digests = [Digest {
            algorithm: bank.algorithm(),
            bytes: event.digest(bank.algorithm())?,
        }];

        let len = pcr::extend(&mut command, event.pcr_index(), &digests)
            .ok_or(Error::CommandTooLong("TPM2_PCR_Extend"))?;

        let len = tpm.transmit(&command[..len], &mut reply)?;
        ib_tpm2::accepted(reply.get(..len).unwrap_or_default())?;

        extended += 1;
    }

    Ok(extended)
}

/// Reads PCR0 through PCR7 back and reports which of them the replay landed on.
fn compare(tpm: &mut Tpm, bank: &Bank<'_>) -> Result<()> {
    let mut matched = 0;

    for index in 0..PCR_COUNT {
        let held = value(tpm, index, bank.algorithm())?;
        let recorded = bank.expected(index);

        if recorded == Some(held.as_slice()) {
            matched += 1;
            continue;
        }

        println!("  PCR{index} holds    {}", Hex(&held));
        match recorded {
            Some(recorded) => println!("       the dump {}", Hex(recorded)),
            None => println!("       the dump records no value for it"),
        }
    }

    println!("  {matched} of {PCR_COUNT} PCRs hold the value the dump records");

    Ok(())
}

/// Reads the value PCR `index` currently holds in the `algorithm` bank.
fn value(tpm: &mut Tpm, index: u32, algorithm: Algorithm) -> Result<Vec<u8>> {
    let mut command = [0_u8; pcr::READ_CAPACITY];
    let mut reply = [0_u8; pcr::REPLY_CAPACITY];

    let len =
        pcr::read(&mut command, index, algorithm).ok_or(Error::CommandTooLong("TPM2_PCR_Read"))?;
    let len = tpm.transmit(&command[..len], &mut reply)?;

    Ok(pcr::value(reply.get(..len).unwrap_or_default())?.to_vec())
}

/// Reads a whole file into memory.
fn contents(mut file: RegularFile) -> Option<Vec<u8>> {
    let info = file.get_boxed_info::<FileInfo>().ok()?;
    let len = usize::try_from(info.file_size()).ok()?;

    let mut bytes = vec![0_u8; len];
    (file.read(&mut bytes).ok()? == len).then_some(bytes)
}

/// Prints a digest the way it is usually quoted.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}
