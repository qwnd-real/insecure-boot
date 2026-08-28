//! The CRB control area's register blocks and their flag bits.
//!
//! Offsets come from `struct crb_regs_head` and `struct crb_regs_tail` in Linux's
//! `tpm_crb.c`, which are byte-packed, so every offset below is the running sum
//! of the field widths that precede it.

use bitflags::bitflags;

use crate::Result;
use crate::mmio::Region;

/// Length of the head block, up to and including `ctrl_ext`.
pub(crate) const HEAD_LEN: u64 = 0x40;

/// Length of the tail block, up to and including `ctrl_rsp_pa`.
pub(crate) const TAIL_LEN: u64 = 0x30;

/// Registers of the locality block that precedes the control area.
#[derive(Clone, Copy)]
enum HeadReg {
    /// `TPM_LOC_STATE_x`, which locality owns the interface.
    LocState = 0x00,
    /// `TPM_LOC_CTRL_x`, requests and releases locality ownership.
    LocCtrl = 0x08,
    /// Low half of `TPM_INTERFACE_ID_x`, which identifies the interface.
    IntfIdLow = 0x30,
    /// High half of `TPM_INTERFACE_ID_x`.
    IntfIdHigh = 0x34,
}

/// Registers of the control area itself.
#[derive(Clone, Copy)]
enum TailReg {
    /// `TPM_CRB_CTRL_REQ_x`, asks the TPM to become ready or to go idle.
    Req = 0x00,
    /// `TPM_CRB_CTRL_STS_x`, reports fatal errors and the idle state.
    Sts = 0x04,
    /// `TPM_CRB_CTRL_CANCEL_x`, cancels the command in flight.
    Cancel = 0x08,
    /// `TPM_CRB_CTRL_START_x`, launches the command in the buffer.
    Start = 0x0C,
    /// `TPM_CRB_CTRL_CMD_SIZE_x`, capacity of the command buffer.
    CmdSize = 0x18,
    /// `TPM_CRB_CTRL_CMD_LADDR_x`, low half of the command buffer address.
    CmdPaLow = 0x1C,
    /// `TPM_CRB_CTRL_CMD_HADDR_x`, high half of the command buffer address.
    CmdPaHigh = 0x20,
    /// `TPM_CRB_CTRL_RSP_SIZE_x`, capacity of the response buffer.
    RspSize = 0x24,
    /// `TPM_CRB_CTRL_RSP_ADDR_x`, full address of the response buffer.
    RspPa = 0x28,
}

bitflags! {
    /// Bits of `TPM_LOC_STATE_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct LocState: u32 {
        /// A locality currently owns the interface.
        const LOC_ASSIGNED = 1 << 1;
        /// The register block holds valid values.
        const TPM_REG_VALID_STS = 1 << 7;
    }

    /// Bits of `TPM_LOC_CTRL_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct LocCtrl: u32 {
        /// Ask for ownership of the interface.
        const REQUEST_ACCESS = 1 << 0;
        /// Give up ownership of the interface.
        const RELINQUISH = 1 << 1;
    }

    /// Bits of `TPM_CRB_CTRL_REQ_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct CtrlReq: u32 {
        /// Ask the TPM to make the command buffer usable.
        const CMD_READY = 1 << 0;
        /// Ask the TPM to release the command buffer and idle.
        const GO_IDLE = 1 << 1;
    }

    /// Bits of `TPM_CRB_CTRL_STS_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct CtrlSts: u32 {
        /// The TPM is in an unrecoverable condition.
        const ERROR = 1 << 0;
        /// The TPM is idle.
        const TPM_IDLE = 1 << 1;
    }

    /// Bits of `TPM_CRB_CTRL_START_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Start: u32 {
        /// Run the command sitting in the command buffer.
        const INVOKE = 1 << 0;
    }

    /// Bits of `TPM_CRB_CTRL_CANCEL_x`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Cancel: u32 {
        /// Cancel the command in flight.
        const INVOKE = 1 << 0;
    }
}

/// The locality registers ahead of the control area.
#[derive(Clone, Copy)]
pub(crate) struct Head(Region);

/// The control area registers.
#[derive(Clone, Copy)]
pub(crate) struct Tail(Region);

impl Head {
    /// Claims the head block at `base`.
    ///
    /// # Errors
    ///
    /// Fails if the block is not addressable.
    pub(crate) fn new(base: u64) -> Result<Self> {
        Region::registers(base, HEAD_LEN).map(Self)
    }

    /// Current value of `TPM_LOC_STATE_x`, masked to the bits this driver knows.
    pub(crate) fn loc_state(self) -> LocState {
        LocState::from_bits_truncate(self.read(HeadReg::LocState))
    }

    /// Whether `TPM_LOC_STATE_x` holds `expected` in the bits of `mask`.
    pub(crate) fn loc_state_matches(self, mask: LocState, expected: LocState) -> bool {
        self.loc_state().intersection(mask) == expected
    }

    /// Writes `TPM_LOC_CTRL_x`.
    pub(crate) fn set_loc_ctrl(self, value: LocCtrl) {
        self.write(HeadReg::LocCtrl, value.bits());
    }

    /// Value of `TPM_INTERFACE_ID_x`, both halves.
    pub(crate) fn interface_id(self) -> u64 {
        let low = self.read(HeadReg::IntfIdLow);
        let high = self.read(HeadReg::IntfIdHigh);
        u64::from(high) << 32 | u64::from(low)
    }

    /// Reads a register of the head block.
    fn read(self, reg: HeadReg) -> u32 {
        // SAFETY: `new` built a region spanning the whole head block, and every
        // register offset lies inside it. None of them has a side effect.
        unsafe { self.0.read32(reg as usize) }
    }

    /// Writes a register of the head block.
    fn write(self, reg: HeadReg, value: u32) {
        // SAFETY: as for `read`. Writing the locality control register is what
        // requesting and relinquishing locality means, which is the caller's
        // intent.
        unsafe { self.0.write32(reg as usize, value) };
    }
}

impl Tail {
    /// Claims the control area at `base`.
    ///
    /// # Errors
    ///
    /// Fails if the control area is not addressable.
    pub(crate) fn new(base: u64) -> Result<Self> {
        Region::registers(base, TAIL_LEN).map(Self)
    }

    /// Current value of `TPM_CRB_CTRL_REQ_x`.
    pub(crate) fn ctrl_req(self) -> CtrlReq {
        CtrlReq::from_bits_truncate(self.read(TailReg::Req))
    }

    /// Writes `TPM_CRB_CTRL_REQ_x`.
    pub(crate) fn set_ctrl_req(self, value: CtrlReq) {
        self.write(TailReg::Req, value.bits());
    }

    /// Current value of `TPM_CRB_CTRL_STS_x`.
    pub(crate) fn ctrl_sts(self) -> CtrlSts {
        CtrlSts::from_bits_truncate(self.read(TailReg::Sts))
    }

    /// Current value of `TPM_CRB_CTRL_CANCEL_x`.
    pub(crate) fn ctrl_cancel(self) -> Cancel {
        Cancel::from_bits_truncate(self.read(TailReg::Cancel))
    }

    /// Writes `TPM_CRB_CTRL_CANCEL_x`.
    pub(crate) fn set_ctrl_cancel(self, value: Cancel) {
        self.write(TailReg::Cancel, value.bits());
    }

    /// Current value of `TPM_CRB_CTRL_START_x`.
    pub(crate) fn ctrl_start(self) -> Start {
        Start::from_bits_truncate(self.read(TailReg::Start))
    }

    /// Writes `TPM_CRB_CTRL_START_x`.
    pub(crate) fn set_ctrl_start(self, value: Start) {
        self.write(TailReg::Start, value.bits());
    }

    /// Capacity the control area reports for the command buffer.
    pub(crate) fn command_size(self) -> u32 {
        self.read(TailReg::CmdSize)
    }

    /// Address the control area reports for the command buffer.
    pub(crate) fn command_address(self) -> u64 {
        let high = self.read(TailReg::CmdPaHigh);
        let low = self.read(TailReg::CmdPaLow);
        u64::from(high) << 32 | u64::from(low)
    }

    /// Capacity the control area reports for the response buffer.
    pub(crate) fn response_size(self) -> u32 {
        self.read(TailReg::RspSize)
    }

    /// Address the control area reports for the response buffer.
    ///
    /// The register is a single 64-bit field, which Linux reads as eight bytes
    /// rather than as two doublewords.
    ///
    /// # Errors
    ///
    /// Fails only if the region is shorter than the control area, which
    /// [`Tail::new`] rules out.
    pub(crate) fn response_address(self) -> Result<u64> {
        let mut bytes = [0_u8; size_of::<u64>()];
        self.0.read_bytes(TailReg::RspPa as usize, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Reads a register of the control area.
    fn read(self, reg: TailReg) -> u32 {
        // SAFETY: `new` built a region spanning the whole control area, and every
        // register offset lies inside it. None of them has a side effect.
        unsafe { self.0.read32(reg as usize) }
    }

    /// Writes a register of the control area.
    fn write(self, reg: TailReg, value: u32) {
        // SAFETY: as for `read`. Each of these registers exists to be written to
        // drive the interface, which is exactly the caller's intent.
        unsafe { self.0.write32(reg as usize, value) };
    }
}
