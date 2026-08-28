//! Probing and the command handshake for a Command Response Buffer interface.
//!
//! Every register access, its ordering, and each firmware workaround follows
//! Linux's `tpm_crb.c`; the function names below name the routine they came from.

use core::ffi::CStr;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

use ib_uacpi::{Device, HardwareId, MemoryRange, Resources, find_device, find_table, time};

use crate::mmio::Region;
use crate::regs::{
    Cancel, CtrlReq, CtrlSts, HEAD_LEN, Head, LocCtrl, LocState, Start, TAIL_LEN, Tail,
};
use crate::table::{PlutonAddresses, StartMethod, Tpm2Table};
use crate::{Error, Result};

/// Signature of the ACPI table that describes a TPM 2.0 interface.
const TPM2_SIGNATURE: &CStr = c"TPM2";

/// Hardware identifier of the ACPI device that companions a CRB interface.
const CRB_HID: &CStr = c"MSFT0101";

/// GUID of the `_DSM` function that implements the ACPI start method.
///
/// This is 6bbf6cab-5463-4714-b7cd-f0203c0368d4 in the mixed-endian byte order
/// ACPI uses for GUID buffers: the first three fields little-endian, the rest as
/// written.
const ACPI_START_GUID: [u8; 16] = [
    0xAB, 0x6C, 0xBF, 0x6B, 0x63, 0x54, 0x14, 0x47, 0xB7, 0xCD, 0xF0, 0x20, 0x3C, 0x03, 0x68, 0xD4,
];

/// Revision the ACPI start method's `_DSM` interface is defined at.
const ACPI_START_REVISION: u64 = 1;

/// Function index of the ACPI start method within its `_DSM` interface.
const ACPI_START_INDEX: u64 = 1;

/// Memory resources a compliant interface may declare.
const MAX_RESOURCES: usize = 3;

/// `TPM2_TIMEOUT_C`, the budget for a control-area handshake.
const TIMEOUT_C: Duration = Duration::from_millis(200);

/// Budget for the Pluton doorbell to accept a start request.
const PLUTON_START_TIMEOUT: Duration = Duration::from_millis(200);

/// Interval between polls of a control-area register.
const POLL_INTERVAL: Duration = Duration::from_micros(50);

/// Length of one Pluton doorbell register.
const DOORBELL_LEN: u64 = 4;

/// Value Pluton leaves in its reply register when it is ready for a command.
const PLUTON_READY: u32 = 1;

/// Value written to the Pluton start register to ring the doorbell.
const PLUTON_RING: u32 = 1;

/// `TPM2_DURATION_LONG`, the budget for a command to complete.
const COMMAND_DURATION: Duration = Duration::from_secs(2);

/// `TPM_TIMEOUT_POLL`, the interval between polls while a command is in flight.
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Length of a TPM command or response header.
const TPM_HEADER_LEN: usize = 10;

/// Offset of the length field within a TPM response header.
const RESPONSE_LENGTH_AT: usize = 2;

/// Bytes of a response read before its length is known.
///
/// A whole quadword, so that the remaining reads stay aligned.
const RESPONSE_PREFIX: usize = 8;

/// Memory resources a device declared, in `_CRS` order.
type Ranges = [Option<MemoryRange>; MAX_RESOURCES];

/// A TPM 2.0 device behind a Command Response Buffer interface.
pub struct Tpm {
    /// Registers and the ACPI device behind them.
    interface: Interface,
    /// The command buffer.
    command: Region,
    /// The response buffer, which may be the command buffer.
    response: Region,
    /// Usable capacity of the command buffer.
    command_size: u32,
}

/// The parts of the interface that can be driven before the buffers are known.
struct Interface {
    /// Start method the TPM2 table named.
    start_method: StartMethod,
    /// The companion ACPI device, which carries the ACPI start method.
    device: Device,
    /// `_HID` of that device.
    hardware_id: HardwareId,
    /// Locality registers, absent when firmware laid the control area out so that
    /// they cannot be located.
    head: Option<Head>,
    /// The control area.
    tail: Tail,
    /// Pluton doorbell, for the interfaces that have one.
    pluton: Option<Pluton>,
}

/// The pair of single-register doorbells a Pluton interface adds.
#[derive(Clone, Copy)]
struct Pluton {
    /// Register written to ask Pluton to run the command.
    start: Region,
    /// Register Pluton writes when it is ready for a command.
    reply: Region,
}

impl Tpm {
    /// Looks for a CRB TPM described by the ACPI TPM2 table and the `MSFT0101`
    /// device, and brings its register blocks and buffers into reach.
    ///
    /// Reports [`None`] when the platform has no TPM 2.0 interface at all, which
    /// means either table or device is missing.
    ///
    /// # Errors
    ///
    /// Fails if the interface exists but cannot be driven: a malformed or
    /// truncated TPM2 table, a start method this platform cannot invoke, a
    /// control area outside the memory the device declared, or a register that
    /// does not settle within its timeout.
    pub fn probe() -> Result<Option<Self>> {
        let Some(table) = find_table(TPM2_SIGNATURE)? else {
            return Ok(None);
        };

        let bytes = table.bytes();
        if bytes.len() < Tpm2Table::fixed_len() {
            return Err(Error::TableTooShort {
                length: bytes.len(),
                start_method: StartMethod::Unknown(0),
            });
        }
        let info = Tpm2Table::parse(bytes)?;

        let Some(device) = find_device(CRB_HID)? else {
            return Ok(None);
        };

        Self::attach(&info, device).map(Some)
    }

    /// The start method the TPM2 table named.
    #[must_use]
    pub const fn start_method(&self) -> StartMethod {
        self.interface.start_method
    }

    /// The `_HID` of the ACPI device behind the interface.
    #[must_use]
    pub fn hardware_id(&self) -> &str {
        self.interface.hardware_id.as_str()
    }

    /// Usable capacity of the command buffer, in bytes.
    #[must_use]
    pub const fn command_size(&self) -> u32 {
        self.command_size
    }

    /// Value of `TPM_INTERFACE_ID_x`, when the locality registers were located.
    #[must_use]
    pub fn interface_id(&self) -> Option<u64> {
        self.interface.head.map(Head::interface_id)
    }

    /// Runs `command` and writes the reply into `response`, reporting its length.
    ///
    /// Reproduces the sequence `tpm_transmit` drives through the CRB class ops:
    /// take the locality, make the command buffer ready, send, poll until the
    /// start register clears, receive, then idle and hand the locality back.
    ///
    /// # Errors
    ///
    /// Fails if the command does not fit the buffer, if the TPM reports an
    /// unrecoverable error, if it cancels the command, or if it does not answer
    /// within the command duration.
    pub fn transmit(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize> {
        self.interface.request_locality()?;
        let result = self.exchange(command, response);

        // The cleanup path discards its own failures so that the outcome of the
        // command itself is what surfaces, which is what the Linux driver does.
        let _ = self.interface.go_idle();
        let _ = self.interface.relinquish_locality();

        result
    }

    /// Builds a driver for the interface `info` describes on `device`.
    fn attach(info: &Tpm2Table, device: Device) -> Result<Self> {
        if info.start_method == StartMethod::MemoryMapped {
            return Err(Error::NotCommandResponseBuffer(info.start_method));
        }

        // Linux reaches these two interfaces through firmware entry points that
        // only exist on Arm: a Secure Monitor Call and the FF-A driver. Neither
        // can be invoked here, so there is no way to signal a start, and probing
        // says so rather than waiting for the first command to fail.
        if info.start_method == StartMethod::CrbWithArmFfa
            || info.start_method == StartMethod::CommandBufferWithArmSmc
        {
            return Err(Error::UnsupportedStartMethod(info.start_method));
        }

        let hardware_id = device.hardware_id()?;
        let resources = device.resources()?;
        let ranges = collect_ranges(&resources)?;

        let interface = Interface {
            start_method: info.start_method,
            device,
            hardware_id,
            head: locate_head(info.start_method, &ranges, info.control_address)?,
            tail: Tail::new(info.control_address)?,
            pluton: info.pluton.map(Pluton::new).transpose()?,
        };

        interface.request_locality()?;

        // Works around a PTT defect: the device has to be awake before registers
        // it may not retain can be read.
        if let Err(error) = interface.cmd_ready() {
            let _ = interface.relinquish_locality();
            return Err(error);
        }

        let mapped = map_buffers(&interface, &ranges);

        let _ = interface.go_idle();
        let _ = interface.relinquish_locality();

        let (command, response, command_size) = mapped?;
        Ok(Self {
            interface,
            command,
            response,
            command_size,
        })
    }

    /// The part of [`Tpm::transmit`] that runs with the locality held.
    fn exchange(&self, command: &[u8], response: &mut [u8]) -> Result<usize> {
        self.interface.cmd_ready()?;
        self.send(command)?;

        let deadline = time::monotonic() + COMMAND_DURATION;
        loop {
            if self.interface.is_complete() {
                return self.receive(response);
            }
            if self.interface.is_cancelled() {
                return Err(Error::Cancelled);
            }

            time::stall(COMMAND_POLL_INTERVAL);

            // Matches the `rmb()` that ends each iteration of the Linux poll
            // loop, so the next read of the start register is a fresh one.
            fence(Ordering::Acquire);

            if time::monotonic() >= deadline {
                break;
            }
        }

        let _ = self.interface.cancel();
        Err(Error::Timeout("the TPM to complete the command"))
    }

    /// Places `command` in the buffer and signals start, `crb_send`.
    fn send(&self, command: &[u8]) -> Result<()> {
        // Clear the cancel register so this command does not inherit a cancel
        // left over from the previous one.
        self.interface.tail.set_ctrl_cancel(Cancel::empty());

        if command.len() > self.command_size as usize {
            return Err(Error::CommandTooLong {
                length: command.len(),
                capacity: self.command_size,
            });
        }

        // Pluton hands the command buffer back after every command, so it has to
        // be reacquired for each one.
        if self.interface.pluton.is_some() {
            self.interface.cmd_ready()?;
        }

        // Writing the buffer ends with a release fence, so the device cannot see
        // a half-written command once start is signalled.
        self.command.write_bytes(0, command)?;

        // The PTT in fourth-generation Core parts advertises only the ACPI start
        // method but in practice also needs the start register written, so an
        // MSFT0101 device gets the register write whatever the table said.
        if self.interface.start_method.uses_start_register()
            || self.interface.hardware_id.as_str().as_bytes() == CRB_HID.to_bytes()
        {
            self.interface.tail.set_ctrl_start(Start::INVOKE);
        }

        if self.interface.start_method.uses_acpi_start() {
            self.interface.acpi_start()?;
        }

        self.interface.pluton_doorbell(false)
    }

    /// Reads the reply out of the response buffer, `crb_recv`.
    fn receive(&self, response: &mut [u8]) -> Result<usize> {
        // The caller has to be able to hold at least a header, the shortest reply
        // a TPM can produce.
        if response.len() < TPM_HEADER_LEN {
            return Err(Error::ResponseTooLong {
                length: TPM_HEADER_LEN,
                capacity: response.len(),
            });
        }

        // This bit means the TPM is in a condition it cannot be recovered from.
        if self.interface.tail.ctrl_sts().contains(CtrlSts::ERROR) {
            return Err(Error::DeviceError);
        }

        self.response
            .read_bytes(0, &mut response[..RESPONSE_PREFIX])?;

        let length = response
            .get(RESPONSE_LENGTH_AT..RESPONSE_LENGTH_AT + size_of::<u32>())
            .and_then(|field| field.try_into().ok())
            .map(u32::from_be_bytes)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(Error::MalformedResponse { length: 0 })?;

        if length < TPM_HEADER_LEN {
            return Err(Error::MalformedResponse { length });
        }
        if length > response.len() {
            return Err(Error::ResponseTooLong {
                length,
                capacity: response.len(),
            });
        }

        if let Some(rest) = response.get_mut(RESPONSE_PREFIX..length) {
            self.response.read_bytes(RESPONSE_PREFIX, rest)?;
        }

        Ok(length)
    }
}

impl Interface {
    /// Asks the TPM to make the command buffer usable, `__crb_cmd_ready`.
    ///
    /// The start methods that drive the TPM entirely through firmware never
    /// expose the request register, so there is nothing to ask.
    fn cmd_ready(&self) -> Result<()> {
        self.request(CtrlReq::CMD_READY, "the command buffer to become ready")
    }

    /// Asks the TPM to release the command buffer, `__crb_go_idle`.
    fn go_idle(&self) -> Result<()> {
        self.request(CtrlReq::GO_IDLE, "the TPM to go idle")
    }

    /// Writes `request` to the request register and waits for the TPM to clear it.
    fn request(&self, request: CtrlReq, what: &'static str) -> Result<()> {
        if !self.start_method.has_idle() {
            return Ok(());
        }

        self.tail.set_ctrl_req(request);
        self.pluton_doorbell(true)?;

        if wait_until(TIMEOUT_C, || {
            self.tail.ctrl_req().intersection(request).is_empty()
        }) {
            Ok(())
        } else {
            Err(Error::Timeout(what))
        }
    }

    /// Takes ownership of the interface, `__crb_request_locality`.
    fn request_locality(&self) -> Result<()> {
        let Some(head) = self.head else {
            return Ok(());
        };

        head.set_loc_ctrl(LocCtrl::REQUEST_ACCESS);

        let assigned = LocState::LOC_ASSIGNED | LocState::TPM_REG_VALID_STS;
        if wait_until(TIMEOUT_C, || head.loc_state_matches(assigned, assigned)) {
            Ok(())
        } else {
            Err(Error::Timeout("the locality to be assigned"))
        }
    }

    /// Gives ownership of the interface back, `__crb_relinquish_locality`.
    fn relinquish_locality(&self) -> Result<()> {
        let Some(head) = self.head else {
            return Ok(());
        };

        head.set_loc_ctrl(LocCtrl::RELINQUISH);

        let mask = LocState::LOC_ASSIGNED | LocState::TPM_REG_VALID_STS;
        if wait_until(TIMEOUT_C, || {
            head.loc_state_matches(mask, LocState::TPM_REG_VALID_STS)
        }) {
            Ok(())
        } else {
            Err(Error::Timeout("the locality to be released"))
        }
    }

    /// Rings the Pluton doorbell, `crb_try_pluton_doorbell`.
    ///
    /// Interfaces without a doorbell have nothing to do. `wait_for_acceptance`
    /// additionally waits for Pluton to clear the start register, which the
    /// readiness transitions need and sending a command does not.
    fn pluton_doorbell(&self, wait_for_acceptance: bool) -> Result<()> {
        let Some(pluton) = self.pluton else {
            return Ok(());
        };

        if !wait_until(TIMEOUT_C, || pluton.reply() == PLUTON_READY) {
            return Err(Error::Timeout("the Pluton reply register"));
        }

        pluton.ring();

        if !wait_for_acceptance {
            return Ok(());
        }

        if wait_until(PLUTON_START_TIMEOUT, || pluton.pending() == 0) {
            Ok(())
        } else {
            Err(Error::Timeout("Pluton to accept the start request"))
        }
    }

    /// Whether the TPM has finished the command in flight, `crb_status`.
    fn is_complete(&self) -> bool {
        !self.tail.ctrl_start().contains(Start::INVOKE)
    }

    /// Whether the TPM cancelled the command in flight, `crb_req_canceled`.
    fn is_cancelled(&self) -> bool {
        self.tail.ctrl_cancel().contains(Cancel::INVOKE)
    }

    /// Asks the TPM to abandon the command in flight, `crb_cancel`.
    fn cancel(&self) -> Result<()> {
        self.tail.set_ctrl_cancel(Cancel::INVOKE);

        if self.start_method.uses_acpi_start() {
            self.acpi_start()?;
        }
        Ok(())
    }

    /// Signals start through the ACPI control method, `crb_do_acpi_start`.
    fn acpi_start(&self) -> Result<()> {
        let returned = self.device.eval_dsm_integer(
            &ACPI_START_GUID,
            ACPI_START_REVISION,
            ACPI_START_INDEX,
        )?;

        if returned == 0 {
            Ok(())
        } else {
            Err(Error::StartMethodFailed(returned))
        }
    }
}

impl Pluton {
    /// Claims the doorbell registers at the addresses the TPM2 table gave.
    fn new(addresses: PlutonAddresses) -> Result<Self> {
        Ok(Self {
            start: Region::registers(addresses.start, DOORBELL_LEN)?,
            reply: Region::registers(addresses.reply, DOORBELL_LEN)?,
        })
    }

    /// Value Pluton last left in its reply register.
    fn reply(self) -> u32 {
        // SAFETY: `new` built the region as exactly this one 32-bit register.
        unsafe { self.reply.read32(0) }
    }

    /// Value of the start register, which Pluton clears once it accepts.
    fn pending(self) -> u32 {
        // SAFETY: as for `reply`.
        unsafe { self.start.read32(0) }
    }

    /// Rings the doorbell.
    fn ring(self) {
        // SAFETY: as for `reply`; writing this register is what the doorbell is.
        unsafe { self.start.write32(0, PLUTON_RING) };
    }
}

/// Polls `ready` until it holds, for at most `timeout`, `crb_wait_for_reg_32`.
///
/// The condition is retested once more after the deadline passes, so a register
/// that settled during the last interval is still noticed.
fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = time::monotonic() + timeout;

    loop {
        if ready() {
            return true;
        }

        time::stall(POLL_INTERVAL);

        if time::monotonic() >= deadline {
            return ready();
        }
    }
}

/// Collects the memory the device declared, `crb_check_resource`.
///
/// A compliant interface declares at most three memory resources; Linux warns
/// about and then ignores any beyond that, and so does this.
fn collect_ranges(resources: &Resources) -> Result<Ranges> {
    let mut ranges: Ranges = [None; MAX_RESOURCES];

    for range in resources.memory_ranges() {
        if let Some(slot) = ranges.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(range);
        }
    }

    if ranges[0].is_none() {
        return Err(Error::NoMemoryResource);
    }

    Ok(ranges)
}

/// Locates the locality registers that sit ahead of the control area.
///
/// The declared memory normally starts at the head block and runs through the
/// control area as one region, so the head is exactly one block below the control
/// address. Anything else is the layout Linux reports as a firmware bug and then
/// carries on without, which leaves the locality transitions as no-ops.
///
/// The two other start methods Linux tests here, the memory-mapped interface and
/// CRB over FF-A, cannot reach this point: [`Tpm::attach`] rejects both.
fn locate_head(
    start_method: StartMethod,
    ranges: &Ranges,
    control_address: u64,
) -> Result<Option<Head>> {
    if start_method != StartMethod::CommandBuffer {
        return Ok(None);
    }

    let Some(range) = enclosing(ranges, control_address, TAIL_LEN) else {
        return Ok(None);
    };
    if range.start().checked_add(HEAD_LEN) != Some(control_address) {
        return Ok(None);
    }

    Head::new(range.start()).map(Some)
}

/// Reads the buffer addresses and sizes out of the control area, the second half
/// of `crb_map_io`.
fn map_buffers(interface: &Interface, ranges: &Ranges) -> Result<(Region, Region, u32)> {
    let command_address = interface.tail.command_address();
    let command_size = clamp_to_declared(ranges, command_address, interface.tail.command_size());
    let command = Region::new(command_address, u64::from(command_size))?;

    let response_address = interface.tail.response_address()?;
    let response_size = clamp_to_declared(ranges, response_address, interface.tail.response_size());

    if command_address != response_address {
        let response = Region::new(response_address, u64::from(response_size))?;
        return Ok((command, response, command_size));
    }

    // The TPM Profile requires overlapping command and response buffers to be
    // the same size, so firmware that says otherwise cannot be trusted about
    // either.
    if command_size != response_size {
        return Err(Error::BufferSizeMismatch {
            command: command_size,
            response: response_size,
        });
    }

    Ok((command, command, command_size))
}

/// Clamps a buffer size to the resource that declares it, `crb_fixup_cmd_size`.
///
/// Works around firmware whose control area reports a buffer larger than the
/// region it declared in `_CRS`; the declared region is the one to trust, which
/// leaves such a platform unable to send large commands.
fn clamp_to_declared(ranges: &Ranges, start: u64, size: u32) -> u32 {
    if size == 0 {
        return 0;
    }

    let Some(range) = containing(ranges, start) else {
        return size;
    };
    if range.covers(start, u64::from(size)) {
        return size;
    }

    u32::try_from(range.end() - start + 1).unwrap_or(size)
}

/// The declared resource that holds all of `[start, start + len)`.
fn enclosing(ranges: &Ranges, start: u64, len: u64) -> Option<MemoryRange> {
    ranges
        .iter()
        .flatten()
        .copied()
        .find(|range| range.covers(start, len))
}

/// The declared resource that holds `address`.
fn containing(ranges: &Ranges, address: u64) -> Option<MemoryRange> {
    ranges
        .iter()
        .flatten()
        .copied()
        .find(|range| range.contains(address))
}
