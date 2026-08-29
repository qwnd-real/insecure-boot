//! Installing the `EFI_TCG2_PROTOCOL`, and proving that it answers.
//!
//! The protocol is exercised through the firmware's own protocol database rather
//! than through the instance directly: it is opened on the handle it was
//! installed on, and the search a consumer makes by GUID is checked to find that
//! handle, so what gets tested is what a consumer would reach.

use ib_tcg2::Tcg2;
use ib_tcglog::Dump;
use ib_tpm_crb::Tpm;
use uefi::boot;
use uefi::println;
use uefi::proto::tcg::v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg};
use uefi::proto::tcg::{EventType, PcrIndex};

use crate::error::Result;

/// PCR a self-test measurement goes into.
///
/// The platform profile sets PCR16 aside for debugging and draws no conclusion
/// from what it holds, so measuring into it proves the path works without
/// disturbing anything that matters.
const TEST_PCR: PcrIndex = PcrIndex(16);

/// What the self-test measures, which is the sort of string a boot stage records
/// to say that it ran.
const TEST_ACTION: &[u8] = b"insecure-boot self test";

/// Installs the protocol and reports what it publishes.
///
/// # Errors
///
/// Fails if the TPM cannot be questioned, if the dump cannot be turned into a log,
/// or if firmware refuses to publish the protocol.
pub fn install(tpm: Tpm, dump: Option<&Dump<'_>>) -> Result<Tcg2> {
    let tcg2 = Tcg2::install(tpm, dump)?;

    let instance = tcg2.instance();
    let capability = instance.capability();
    let displaced = tcg2.displaced();
    let (log, log_len, log_spare) = instance.log();
    let (table, events, table_spare) = instance.final_events();

    println!("insecure-boot: EFI_TCG2_PROTOCOL installed");
    println!(
        "  displaced:      {} of {} EFI_TCG_PROTOCOL, {} of {} EFI_TCG2_PROTOCOL",
        displaced.v1_removed, displaced.v1_found, displaced.v2_removed, displaced.v2_found
    );
    println!(
        "  revision:       {}.{}",
        capability.protocol_version.major, capability.protocol_version.minor
    );
    println!(
        "  banks:          {} active, bitmap {:#010x}",
        capability.number_of_pcr_banks,
        capability.active_pcr_banks.bits()
    );
    println!(
        "  command sizes:  {} in, {} out",
        capability.max_command_size, capability.max_response_size
    );
    println!("  event log:      {log_len} bytes at {log:#018x}, {log_spare} spare");
    println!("  final events:   {events} records at {table:#018x}, {table_spare} spare");

    Ok(tcg2)
}

/// Calls every entry point the way a consumer would, and reports what came back.
///
/// Collecting the event log is what starts the final events table, so the
/// measurement that follows lands in both and the table's record count is read
/// afterwards to show that it did.
///
/// # Errors
///
/// Fails if firmware cannot find the protocol, or if an entry point that ought to
/// answer refuses to.
pub fn exercise(tcg2: &Tcg2) -> Result<()> {
    {
        // A consumer reaches the protocol by searching for its GUID, and what
        // that search must find is this one: a firmware interface left in place
        // would hand the consumer the firmware's log instead of this one's.
        let found = boot::get_handle_for_protocol::<Tcg>()?;
        if found != tcg2.handle() {
            println!(
                "insecure-boot: a search by GUID still finds an interface this could not take away"
            );
        }

        let mut tcg = boot::open_protocol_exclusive::<Tcg>(tcg2.handle())?;

        let capability = tcg.get_capability()?;
        println!("insecure-boot: the installed protocol answers a consumer");
        println!(
            "  GetCapability:  revision {}.{}, TPM present {}, {} banks",
            capability.protocol_version.major,
            capability.protocol_version.minor,
            capability.tpm_present(),
            capability.number_of_pcr_banks
        );

        let banks = tcg.get_active_pcr_banks()?;
        println!("  GetActivePcrBanks: bitmap {:#010x}", banks.bits());

        match tcg.set_active_pcr_banks(banks) {
            Err(error) => println!("  SetActivePcrBanks: refused, {error}"),
            Ok(()) => println!("  SetActivePcrBanks: accepted, which it should not be"),
        }

        match tcg.get_result_of_set_active_pcr_banks()? {
            None => println!("  GetResultOfSetActivePcrBanks: nothing pending"),
            Some(response) => println!("  GetResultOfSetActivePcrBanks: {response:#010x}"),
        }

        let before = records(&mut tcg)?;
        measure(&mut tcg)?;
        let after = records(&mut tcg)?;

        println!("  GetEventLog:    {before} records, {after} after a measurement");
    }

    // The log has been collected by now, so anything measured after it also went
    // into the table the operating system reads once boot services are gone.
    let (table, events, spare) = tcg2.instance().final_events();
    println!("  final events:   {events} records at {table:#018x}, {spare} spare");

    Ok(())
}

/// Measures the self-test action into the debug PCR, logging it as an action
/// event.
fn measure(tcg: &mut Tcg) -> Result<()> {
    let event = PcrEventInputs::new_in_box(TEST_PCR, EventType::EFI_ACTION, TEST_ACTION)?;

    tcg.hash_log_extend_event(HashLogExtendEventFlags::empty(), TEST_ACTION, &event)?;

    Ok(())
}

/// Number of records the protocol's event log holds, counted by walking it the
/// way a consumer parses it.
fn records(tcg: &mut Tcg) -> Result<usize> {
    Ok(tcg.get_event_log_v2()?.iter().count())
}
