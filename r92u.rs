// SPDX-License-Identifier: GPL-2.0
//! r92u - RTL8192SU USB WiFi driver initialisation logic.

use kernel::{bindings, prelude::*}; //

use crate::cfg80211::Wiphy; //
use crate::netdev::{NetDev, WirelessDev}; //
use crate::sta::{R92suKey, R92suSta}; //

extern "C" {
    fn rust_helper_submit_one_tx_urb(
        udev: *mut bindings::usb_device,
        endpoint: u8,
        data: *const u8,
        len: usize,
    ) -> i32;
}
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TX_URB_COUNT: usize = 16;
const MAX_RX_URB_COUNT: usize = 8;
const RX_BUFFER_SIZE: usize = 8192;

// Register addresses (subset)
const REG_SYS_FUNC_EN: u16 = 0x0002;
const REG_AFE_PLL_CTRL: u16 = 0x0028;
const REG_SYS_CLK_CTRL: u16 = 0x0008;
const REG_SYS_CLKR: u16 = 0x0008;
const REG_CR: u16 = 0x0040; // Command Register (CMDR)

const MAX_TRACKED_REGS: usize = 16;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum R92suError {
    NoSuitableEndpoints,
    UrbAllocFailed,
    QueueInitFailed,
    RegisterWriteFailed,
    FirmwareUploadFailed(&'static str),
    DeviceNotFound,
    Io(&'static str),
}

impl kernel::fmt::Display for R92suError {
    fn fmt(&self, f: &mut kernel::fmt::Formatter<'_>) -> kernel::fmt::Result {
        match self {
            R92suError::NoSuitableEndpoints => write!(f, "No suitable USB bulk endpoints found"),
            R92suError::UrbAllocFailed => write!(f, "Failed to allocate URBs"),
            R92suError::QueueInitFailed => write!(f, "TX/RX queue initialisation failed"),
            R92suError::RegisterWriteFailed => write!(f, "Hardware register write failed"),
            R92suError::FirmwareUploadFailed(msg) => write!(f, "Firmware upload failed: {msg}"),
            R92suError::DeviceNotFound => write!(f, "USB device not found"),
            R92suError::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl From<R92suError> for kernel::error::Error {
    fn from(_: R92suError) -> kernel::error::Error {
        kernel::error::code::EIO
    }
}

pub type Result<T> = core::result::Result<T, R92suError>;

// ---------------------------------------------------------------------------
// USB vendor control request constants (from usb.h in the C reference driver)
// ---------------------------------------------------------------------------

// requesttype for USB_TYPE_VENDOR | USB_RECIP_DEVICE transfers.
const VENQT_READ: u8 = 0xC0; // direction: IN
const VENQT_WRITE: u8 = 0x40; // direction: OUT
                              // bRequest for the Realtek vendor command.
const VENQT_CMD_REQ: u8 = 0x05;
// wIndex is always zero for register access.
const VENQT_CMD_IDX: u16 = 0x00;
// Control-transfer timeout in milliseconds (USB_CTRL_{GET,SET}_TIMEOUT in C).
const USB_CTRL_TIMEOUT: i32 = 5000;

/// Read one byte from a hardware register via USB vendor control transfer.
///
/// Returns `0xff` on failure, matching the C driver's fallback value on EFUSE
/// retry exhaustion.
///
/// # Safety
///
/// `udev` must be a valid, non-null pointer to a `struct usb_device` that
/// remains alive for the duration of this call (i.e., called from probe or
/// disconnect context before the device is freed).
pub unsafe fn hw_read8(udev: *mut bindings::usb_device, addr: u16) -> u8 {
    let mut buf = [0xffu8];
    // SAFETY: caller guarantees `udev` is valid; `buf` lives for the duration
    // of this call and `usb_control_msg_recv` copies data into it internally
    // via a DMA-safe temporary buffer, so no alignment constraints apply.
    let ret = unsafe {
        bindings::usb_control_msg_recv(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_READ,
            addr,
            VENQT_CMD_IDX,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            1,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_read8({:#06x}) failed: {}\n", addr, ret);
        0xff
    } else {
        buf[0]
    }
}

/// Read four bytes (little-endian) from a hardware register via USB vendor
/// control transfer.
///
/// Returns `0xffff_ffff` on failure.
///
/// # Safety
///
/// `udev` must be valid; same requirements as [`hw_read8`].
pub unsafe fn hw_read32(udev: *mut bindings::usb_device, addr: u16) -> u32 {
    let mut buf = [0xffu8; 4];
    // SAFETY: caller guarantees `udev` is valid.
    let ret = unsafe {
        bindings::usb_control_msg_recv(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_READ,
            addr,
            VENQT_CMD_IDX,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            4,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_read32({:#06x}) failed: {}\n", addr, ret);
        0xffff_ffff
    } else {
        u32::from_le_bytes(buf)
    }
}

/// Write one byte to a hardware register via USB vendor control transfer.
///
/// Errors are logged but not returned — mirrors the C driver's `WARN_ONCE`
/// approach in `r92su_write_helper`.
///
/// # Safety
///
/// `udev` must be valid; same requirements as [`hw_read8`].
pub unsafe fn hw_write8(udev: *mut bindings::usb_device, addr: u16, val: u8) {
    let buf = [val];
    // SAFETY: caller guarantees `udev` is valid; `usb_control_msg_send` copies
    // from `buf` into a DMA-safe temporary buffer internally.
    let ret = unsafe {
        bindings::usb_control_msg_send(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_WRITE,
            addr,
            VENQT_CMD_IDX,
            buf.as_ptr() as *const core::ffi::c_void,
            1,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_write8({:#06x}) failed: {}\n", addr, ret);
    }
}

/// Read two bytes (little-endian) from a hardware register via USB vendor
/// control transfer.
///
/// Returns `0xffff` on failure.
///
/// # Safety
///
/// `udev` must be valid; same requirements as [`hw_read8`].
pub unsafe fn hw_read16(udev: *mut bindings::usb_device, addr: u16) -> u16 {
    let mut buf = [0xffu8; 2];
    let ret = unsafe {
        bindings::usb_control_msg_recv(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_READ,
            addr,
            VENQT_CMD_IDX,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            2,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_read16({:#06x}) failed: {}\n", addr, ret);
        0xffff
    } else {
        u16::from_le_bytes(buf)
    }
}

/// Write four bytes (little-endian) to a hardware register via USB vendor
/// control transfer.
///
/// # Safety
///
/// `udev` must be valid; same requirements as [`hw_read8`].
pub unsafe fn hw_write32(udev: *mut bindings::usb_device, addr: u16, val: u32) {
    let buf = val.to_le_bytes();
    let ret = unsafe {
        bindings::usb_control_msg_send(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_WRITE,
            addr,
            VENQT_CMD_IDX,
            buf.as_ptr() as *const core::ffi::c_void,
            4,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_write32({:#06x}) failed: {}\n", addr, ret);
    }
}

/// Write two bytes to a hardware register via USB vendor control transfer.
///
/// # Safety
///
/// `udev` must be valid; same requirements as [`hw_read8`].
pub unsafe fn hw_write16(udev: *mut bindings::usb_device, addr: u16, val: u16) {
    let buf = val.to_le_bytes();
    let ret = unsafe {
        bindings::usb_control_msg_send(
            udev,
            0,
            VENQT_CMD_REQ,
            VENQT_WRITE,
            addr,
            VENQT_CMD_IDX,
            buf.as_ptr() as *const core::ffi::c_void,
            2,
            USB_CTRL_TIMEOUT,
            bindings::GFP_KERNEL,
        )
    };
    if ret < 0 {
        pr_warn!("r92su: hw_write16({:#06x}) failed: {}\n", addr, ret);
    }
}

/// Millisecond delay.
pub fn mdelay(ms: u32) {
    // Use udelay in a loop for millisecond delays.
    // SAFETY: This is a simple delay function with no safety requirements.
    for _ in 0..ms {
        unsafe { bindings::udelay(1000) };
    }
}

/// Microsecond delay.
pub fn udelay(us: u32) {
    // SAFETY: This is a simple delay function with no safety requirements.
    unsafe { bindings::udelay(us as _) };
}

// ---------------------------------------------------------------------------
// Chip revision (mirrors enum r92su_chip_revision_t)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ChipRev {
    Fpga = 0,
    ACut = 1,
    BCut = 2,
    CCut = 3,
}

impl ChipRev {
    /// Human-readable label (mirrors `rev_to_string[]` in main.c).
    pub fn as_str(self) -> &'static str {
        match self {
            ChipRev::Fpga => "FPGA",
            ChipRev::ACut => "A CUT",
            ChipRev::BCut => "B CUT",
            ChipRev::CCut => "C CUT",
        }
    }
}

// ---------------------------------------------------------------------------
// RF type (mirrors enum r92su_rf_type_t)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RfType {
    T1R1 = 0x11,
    T1R2 = 0x12,
    T2R2 = 0x22,
}

impl RfType {
    /// Human-readable label (mirrors `rf_to_string()` in main.c).
    pub fn as_str(self) -> &'static str {
        match self {
            RfType::T1R1 => "1T1R",
            RfType::T1R2 => "1T2R",
            RfType::T2R2 => "2T2R",
        }
    }
}

// ---------------------------------------------------------------------------
// EEPROM type (mirrors enum r92su_eeprom_type)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EepromType {
    Eeprom93C46 = 0,
    BootEfuse = 2,
}

// ---------------------------------------------------------------------------
// EEPROM data (mirrors struct r92su_eeprom, stored as a flat byte image)
//
// The physical EFUSE is sparse (512-byte store with descriptors); the driver
// reconstructs the logical 128-byte EEPROM image from it.  All offsets below
// match eeprom.h in the C reference driver.
// ---------------------------------------------------------------------------

pub const ETH_ALEN: usize = 6;
pub const EEPROM_SIZE: usize = 128;

// Byte offsets within the logical EEPROM image.
const EEPROM_ID_OFFSET: usize = 0;
const EEPROM_MAC_OFFSET: usize = 18;
const EEPROM_BOARD_TYPE_OFFSET: usize = 84;

pub struct Eeprom {
    /// Raw 128-byte EEPROM image reconstructed from EFUSE sparse blocks.
    /// Filled with `0xff` until the device is probed successfully.
    pub raw: [u8; EEPROM_SIZE],
}

impl Eeprom {
    fn new() -> Self {
        Self {
            raw: [0xffu8; EEPROM_SIZE],
        }
    }

    /// EEPROM signature word at offset 0 (little-endian).
    /// Must equal `RTL8190_EEPROM_ID` (0x8129) for a valid image.
    pub fn id(&self) -> u16 {
        u16::from_le_bytes([self.raw[EEPROM_ID_OFFSET], self.raw[EEPROM_ID_OFFSET + 1]])
    }

    /// Permanent MAC address at EEPROM offset 18–23.
    pub fn mac_addr(&self) -> [u8; ETH_ALEN] {
        let mut mac = [0u8; ETH_ALEN];
        mac.copy_from_slice(&self.raw[EEPROM_MAC_OFFSET..EEPROM_MAC_OFFSET + ETH_ALEN]);
        mac
    }

    /// Board type byte at EEPROM offset 84, used to derive `RfType`.
    pub fn board_type(&self) -> u8 {
        self.raw[EEPROM_BOARD_TYPE_OFFSET]
    }
}

// ---------------------------------------------------------------------------
// 2.4 GHz band descriptor (mirrors struct ieee80211_supported_band)
// ---------------------------------------------------------------------------

pub struct Band2GHz {
    pub n_channels: usize,
    pub n_bitrates: usize,
    /// Whether HT is enabled (ht_cap.ht_supported).
    pub ht_supported: bool,
    /// MCS rx_mask[1] — non-zero for 2-stream configs.
    pub rx_mask_1: u8,
    /// MCS rx_highest (Mbps).
    pub rx_highest: u16,
}

impl Band2GHz {
    fn new() -> Self {
        Self {
            n_channels: 0,
            n_bitrates: 0,
            ht_supported: false,
            rx_mask_1: 0x00,
            rx_highest: 150,
        }
    }
}

// ---------------------------------------------------------------------------
// Device state (mirrors enum r92su_state_t)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum State {
    Dead = 0,
    Unload = 1,
    Probe = 2,
    Stop = 3,
    Init = 4,
    Open = 5,
    Connected = 6,
}

impl R92suDevice {
    pub fn is_stopped(&self) -> bool {
        self.state == State::Stop
    }

    pub fn is_initializing(&self) -> bool {
        self.state == State::Init
    }

    pub fn is_open(&self) -> bool {
        matches!(self.state, State::Open | State::Connected)
    }

    pub fn set_state(&mut self, new_state: State) {
        pr_debug!("r92su: state {:?} -> {:?}\n", self.state, new_state);
        self.state = new_state;
    }
}

// ---------------------------------------------------------------------------
// USB endpoint descriptor (mirrors usb_endpoint_descriptor)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    Bulk,
    Interrupt,
    Isochronous,
    Control,
}

#[derive(Debug, Clone, Copy)]
pub struct UsbEndpoint {
    pub address: u8,
    pub direction: EndpointDirection,
    pub ep_type: EndpointType,
    pub max_packet_size: u16,
}

// ---------------------------------------------------------------------------
// URB — USB Request Block
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Urb {
    pub id: usize,
    pub endpoint: UsbEndpoint,
    pub buffer: KVec<u8>,
    pub status: UrbStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrbStatus {
    Idle,
    Pending,
    Complete,
    Error,
}

impl Urb {
    fn new(id: usize, endpoint: UsbEndpoint, buf_size: usize) -> Self {
        Self {
            id,
            endpoint,
            buffer: if buf_size > 0 {
                KVec::from_elem(0u8, buf_size, GFP_KERNEL).unwrap_or_else(|_| KVec::new())
            } else {
                KVec::new()
            },
            status: UrbStatus::Idle,
        }
    }
}

// ---------------------------------------------------------------------------
// TX / RX queues
// ---------------------------------------------------------------------------

pub struct TxQueue {
    pub urbs: KVec<Urb>,
    pub pending: KVec<usize>, // indices into `urbs`
}

pub struct RxQueue {
    pub urbs: KVec<Urb>,
}

impl TxQueue {
    fn new() -> Self {
        Self {
            urbs: KVec::with_capacity(MAX_TX_URB_COUNT, GFP_KERNEL).unwrap_or_else(|_| KVec::new()),
            pending: KVec::new(),
        }
    }

    /// Push a frame onto the TX queue (returns the URB id used).
    pub fn enqueue(&mut self, data: &[u8]) -> Option<usize> {
        let idle = self.urbs.iter().position(|u| u.status == UrbStatus::Idle)?;
        let urb = &mut self.urbs[idle];
        urb.buffer[..data.len()].copy_from_slice(data);
        urb.status = UrbStatus::Pending;
        let _ = self.pending.push(idle, GFP_KERNEL);
        Some(urb.id)
    }
}

impl RxQueue {
    fn new() -> Self {
        Self {
            urbs: KVec::with_capacity(MAX_RX_URB_COUNT, GFP_KERNEL).unwrap_or_else(|_| KVec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Hardware register interface (simulated)
// ---------------------------------------------------------------------------

pub struct HwRegs {
    data: [(u16, u8); MAX_TRACKED_REGS],
    len: usize,
}

impl HwRegs {
    fn new() -> Self {
        Self {
            data: [(0, 0); MAX_TRACKED_REGS],
            len: 0,
        }
    }

    pub fn write8(&mut self, reg: u16, val: u8) -> Result<()> {
        pr_debug!("REG[{:#06x}] <- {:#04x}\n", reg, val);
        for i in 0..self.len {
            if self.data[i].0 == reg {
                self.data[i].1 = val;
                return Ok(());
            }
        }
        if self.len < MAX_TRACKED_REGS {
            self.data[self.len] = (reg, val);
            self.len += 1;
            Ok(())
        } else {
            Err(R92suError::RegisterWriteFailed)
        }
    }

    pub fn read8(&self, reg: u16) -> u8 {
        for i in 0..self.len {
            if self.data[i].0 == reg {
                return self.data[i].1;
            }
        }
        0
    }
}

// ---------------------------------------------------------------------------
// Debug ring buffer (mirrors r92su_debug from debugfs.h)
// ---------------------------------------------------------------------------

const R92SU_DEBUG_RING_SIZE: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DebugMemType {
    Mem8 = 0,
    Mem16 = 1,
    Mem32 = 2,
}

#[derive(Clone, Copy)]
pub struct DebugMemRbe {
    pub reg: u32,
    pub value: u32,
    pub mem_type: DebugMemType,
}

pub struct Debug {
    pub ring: [DebugMemRbe; R92SU_DEBUG_RING_SIZE],
    pub ring_head: usize,
    pub ring_tail: usize,
    pub ring_len: usize,
}

impl Debug {
    fn new() -> Self {
        Self {
            ring: [DebugMemRbe {
                reg: 0,
                value: 0,
                mem_type: DebugMemType::Mem8,
            }; R92SU_DEBUG_RING_SIZE],
            ring_head: 0,
            ring_tail: 0,
            ring_len: 0,
        }
    }

    pub fn add_read(&mut self, reg: u32, value: u32, mem_type: DebugMemType) {
        self.ring[self.ring_tail] = DebugMemRbe {
            reg,
            value,
            mem_type,
        };
        self.ring_tail = (self.ring_tail + 1) % R92SU_DEBUG_RING_SIZE;
        if self.ring_len < R92SU_DEBUG_RING_SIZE {
            self.ring_len += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Device struct — owns all initialised state
// ---------------------------------------------------------------------------

pub struct R92suDevice {
    pub vendor_id: u16,
    pub product_id: u16,

    // ── netdev / wdev — dropped before wiphy (field declaration order) ────────
    //
    // `NetDev` holds `ndev->ieee80211_ptr` pointing into `WirelessDev`, so
    // `NetDev` must be dropped first.  Rust drops fields in declaration order,
    // so declare `netdev` before `wdev`, and both before `wiphy`.
    /// Owned `struct net_device *`, allocated by `r92su_setup` via
    /// `alloc_netdev_mqs`.  Registered by `r92su_register`.
    pub netdev: Option<NetDev>,

    /// Owned `struct wireless_dev *`, allocated by `r92su_setup`.  Links the
    /// `net_device` to the `wiphy`; must outlive `netdev`.
    pub wdev: Option<WirelessDev>,

    /// Owned wiphy allocated by `r92su_alloc` via `wiphy_new`.
    ///
    /// `None` until `r92su_alloc` completes; `Some` for the lifetime of the
    /// device.  Dropped (via `wiphy_free`) when `R92suDevice` is dropped.
    pub wiphy: Option<Wiphy>,

    pub bulk_in: Option<UsbEndpoint>,
    pub bulk_out: Option<UsbEndpoint>,

    pub tx_queue: TxQueue,
    pub rx_queue: RxQueue,

    pub regs: HwRegs,

    /// Raw USB device pointer — set during probe from `interface_to_usbdev()`.
    /// Valid from probe until `r92su_disconnect`; must not be used after that.
    pub udev: *mut bindings::usb_device,

    pub fw_loaded: bool,
    pub rx_alignment: usize,

    pub state: State,

    // Fields initialised by r92su_setup().
    pub chip_rev: ChipRev,
    pub rf_type: RfType,
    pub disable_ht: bool,
    pub eeprom: Eeprom,
    pub eeprom_type: EepromType,
    /// Permanent MAC address — copied from eeprom.mac_addr by r92su_setup().
    pub mac_addr: [u8; ETH_ALEN],
    pub band_2ghz: Band2GHz,
    // Fields set by r92su_register() / cleared by r92su_unregister().
    pub wiphy_registered: bool,
    pub debugfs_registered: bool,
    /// Pointer to debugfs dentry (created by rust_helper_debugfs_create).
    pub debugfs_dentry: *mut core::ffi::c_void,

    /// Debug ring buffer for register I/O tracing (mirrors r92su->debug).
    pub debug: Debug,

    // Wiphy / cfg80211 configuration — set by r92su_alloc().
    /// NL80211_IFTYPE_* value for the primary interface (wdev.iftype).
    pub iftype: u32,
    /// Bitmask of supported NL80211_IFTYPE_* values (wiphy->interface_modes).
    pub interface_modes: u32,
    /// Maximum number of SSIDs for a scan request (wiphy->max_scan_ssids).
    pub max_scan_ssids: u8,
    /// Maximum scan IE length in bytes (wiphy->max_scan_ie_len).
    pub max_scan_ie_len: u16,
    /// True once a scan completes (mirrors init_completion(&r92su->scan_done)).
    pub scan_done: bool,
    /// True while the periodic service delayed-work is armed (r92su_hw_init).
    pub service_work_scheduled: bool,

    /// H2C command sequence counter (7-bit, wraps at 128).
    ///
    /// Initialised to 1 by `cmd_init`; incremented on every `h2c_submit` call.
    /// Mirrors `r92su->h2c_seq` in the C driver.
    pub h2c_seq: u8,

    // ── Station table (mirrors r92su->sta_list / sta_num / sta_generation) ────
    /// Linear list of known stations (firmware MACID space: 0–31).
    pub sta_list: KVec<R92suSta>,
    /// Current number of entries in `sta_list`.
    pub sta_num: usize,
    /// Incremented on every add or remove; used by `get_station` / `dump_station`.
    pub sta_generation: u32,

    // ── C2H event state ───────────────────────────────────────────────────────
    /// Expected C2H sequence number; tracks `r92su->c2h_seq` in the C driver.
    pub c2h_seq: u8,
    /// Current CPWM (power management state) value reported by firmware.
    pub cpwm: u8,
    /// CPWM toggle bit — compared against the previous value to detect a stuck
    /// firmware (mirrors `r92su->cpwm_tog`).
    pub cpwm_tog: u8,

    /// Raw BSS blobs accumulated during a site survey.
    ///
    /// Each entry is the bytes of an `h2cc2h_bss` struct (FCS already stripped)
    /// queued by `c2h_survey_event`.  The cfg80211 ops layer drains this list
    /// after `scan_done` is set.
    pub add_bss_pending: KVec<KVec<u8>>,

    /// Raw bytes of the last `c2h_join_bss_event` payload.
    ///
    /// Set by `c2h_join_bss_event`; consumed by the cfg80211 connect result
    /// handler once the connect workqueue item fires.
    pub connect_result: Option<KVec<u8>>,

    // ── RX path state ─────────────────────────────────────────────────────────
    /// Processed 802.11 frames ready for delivery to the network stack.
    ///
    /// Frames are pushed here by `rx::rx_deliver()`.  Once `netif_rx()` Rust
    /// bindings are available this queue will be drained inline.
    pub pending_rx: KVec<KVec<u8>>,

    /// Count of successfully delivered RX frames.
    pub rx_packets: u64,
    /// Count of received bytes (payload only, post-FCS strip).
    pub rx_bytes: u64,
    /// Count of frames dropped in the RX path.
    pub rx_dropped: u64,
    /// A-MPDU reference number for radiotap; incremented on each FAGGR frame.
    pub ampdu_reference: u32,

    // ── TX statistics ─────────────────────────────────────────────────────────
    /// Count of successfully submitted TX frames.
    pub tx_packets: u64,
    /// Count of transmitted bytes (payload only, excluding TX descriptor).
    pub tx_bytes: u64,
    /// Count of frames dropped in the TX path.
    pub tx_dropped: u64,
    /// Number of TX URBs currently pending completion.
    pub tx_pending_urbs: core::sync::atomic::AtomicU32,

    /// Firmware image — set during probe so that ndo_open can upload it.
    pub firmware: &'static [u8],

    // ── Key management ────────────────────────────────────────────────────────
    /// Group (broadcast/multicast) keys — indexed by cfg80211 key index 0–3.
    ///
    /// Mirrors `bss_priv->group_key[]` from the C reference.
    pub group_keys: [Option<KBox<R92suKey>>; 4],
    /// Default multicast key index (updated by `set_default_key` with multicast=true).
    pub def_multi_key_idx: u8,
    /// Default unicast key index (updated by `set_default_key` with unicast=true).
    pub def_uni_key_idx: u8,

    // ── Connection state ──────────────────────────────────────────────────────
    /// BSSID of the currently associated AP (zeroed when not connected).
    pub bssid: [u8; 6],
    /// Current operating channel (1–14 for 2.4 GHz; default 1).
    pub channel: u8,
    /// IEs sent in the most recent connect request (stored for cfg80211_connect_result).
    pub connect_req_ie: KVec<u8>,
    /// SSID from the most recent connect request (used for BSS lookup in join result).
    pub connect_ssid: [u8; 32],
    /// Length of `connect_ssid` (0 when no connect is pending).
    pub connect_ssid_len: usize,
    /// Raw pointer to the `struct net_device` associated with this interface.
    ///
    /// Set by `r92su_register` after `register_netdev` succeeds.  Used by the
    /// RX delivery path to call `netif_rx` without a wiphy lookup.
    pub netdev_ptr: *mut core::ffi::c_void,
}

impl R92suDevice {
    pub fn new(vendor_id: u16, product_id: u16) -> Self {
        Self {
            vendor_id,
            product_id,
            netdev: None,
            wdev: None,
            wiphy: None,
            bulk_in: None,
            bulk_out: None,
            tx_queue: TxQueue::new(),
            rx_queue: RxQueue::new(),
            regs: HwRegs::new(),
            udev: core::ptr::null_mut(),
            fw_loaded: false,
            rx_alignment: 0,
            state: State::Probe,
            chip_rev: ChipRev::BCut,
            rf_type: RfType::T1R1,
            disable_ht: false,
            eeprom: Eeprom::new(),
            eeprom_type: EepromType::BootEfuse,
            mac_addr: [0u8; ETH_ALEN],
            band_2ghz: Band2GHz::new(),
            wiphy_registered: false,
            debugfs_registered: false,
            debugfs_dentry: core::ptr::null_mut(),
            debug: Debug::new(),
            iftype: 0,
            interface_modes: 0,
            max_scan_ssids: 0,
            max_scan_ie_len: 0,
            scan_done: false,
            service_work_scheduled: false,
            h2c_seq: 0,
            sta_list: KVec::new(),
            sta_num: 0,
            sta_generation: 0,
            c2h_seq: 0,
            cpwm: 0,
            cpwm_tog: 0,
            add_bss_pending: KVec::new(),
            connect_result: None,
            pending_rx: KVec::new(),
            rx_packets: 0,
            rx_bytes: 0,
            rx_dropped: 0,
            ampdu_reference: 0,
            tx_packets: 0,
            tx_bytes: 0,
            tx_dropped: 0,
            tx_pending_urbs: core::sync::atomic::AtomicU32::new(0),
            firmware: &[],
            group_keys: [None, None, None, None],
            def_multi_key_idx: 0,
            def_uni_key_idx: 0,
            bssid: [0u8; 6],
            channel: 1,
            connect_req_ie: KVec::new(),
            connect_ssid: [0u8; 32],
            connect_ssid_len: 0,
            netdev_ptr: core::ptr::null_mut(),
        }
    }
}

// ---------------------------------------------------------------------------
// r92su_usb_init — the main entry point
// ---------------------------------------------------------------------------

/// Initialise the RTL8192SU USB device.
///
/// Mirrors the C kernel function `r92su_usb_init()`:
///   1. Validate vendor / product IDs
///   2. Discover bulk IN / OUT endpoints
///   3. Allocate TX URBs
///   4. Allocate RX URBs
///   5. Initialise TX / RX queues
///   6. Bootstrap hardware registers
///   7. Upload firmware
pub fn r92su_usb_init(
    dev: &mut R92suDevice,
    endpoints: &[UsbEndpoint],
    _firmware: &[u8],
) -> Result<()> {
    pr_debug!(
        "r92su_usb_init: starting for {:04x}:{:04x}\n",
        dev.vendor_id,
        dev.product_id
    );

    // ── Step 1: endpoint discovery ───────────────────────────────────────────
    discover_endpoints(dev, endpoints).map_err(|e| {
        pr_err!("r92su_usb_init: endpoint discovery failed: {}\n", e);
        e
    })?;
    pr_debug!(
        "r92su_usb_init: endpoints OK  in={:#04x}  out={:#04x}\n",
        dev.bulk_in.unwrap().address,
        dev.bulk_out.unwrap().address
    );

    // ── Steps 2 & 3: allocate TX and RX URBs ──────────────────────────────────
    alloc_tx_urbs(dev).map_err(|e| {
        pr_err!("r92su_usb_init: TX URB allocation failed: {}\n", e);
        e
    })?;
    alloc_rx_urbs(dev).map_err(|e| {
        pr_err!("r92su_usb_init: RX URB allocation failed: {}\n", e);
        e
    })?;
    pr_debug!(
        "r92su_usb_init: URBs allocated  tx={}  rx={}\n",
        dev.tx_queue.urbs.len(),
        dev.rx_queue.urbs.len()
    );

    // ── Step 4: hardware register bootstrap ──────────────────────────────────
    hw_register_init(dev).map_err(|e| {
        pr_err!("r92su_usb_init: hardware register init failed: {}\n", e);
        e
    })?;
    pr_debug!("r92su_usb_init: hardware registers bootstrapped\n");

    dev.set_state(State::Stop);
    pr_debug!("r92su_usb_init: initialisation complete\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2 — endpoint discovery
// ---------------------------------------------------------------------------

fn discover_endpoints(dev: &mut R92suDevice, endpoints: &[UsbEndpoint]) -> Result<()> {
    for ep in endpoints {
        if ep.ep_type != EndpointType::Bulk {
            continue;
        }
        match ep.direction {
            EndpointDirection::In if dev.bulk_in.is_none() => dev.bulk_in = Some(*ep),
            EndpointDirection::Out if dev.bulk_out.is_none() => dev.bulk_out = Some(*ep),
            _ => {}
        }
    }

    if dev.bulk_in.is_none() || dev.bulk_out.is_none() {
        return Err(R92suError::NoSuitableEndpoints);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps 3 & 4 — URB allocation
// ---------------------------------------------------------------------------

fn alloc_tx_urbs(dev: &mut R92suDevice) -> Result<()> {
    let ep = dev.bulk_out.ok_or(R92suError::UrbAllocFailed)?;
    for i in 0..MAX_TX_URB_COUNT {
        // TX buffers are filled on demand.
        dev.tx_queue
            .urbs
            .push(Urb::new(i, ep, 0), GFP_KERNEL)
            .map_err(|_| R92suError::UrbAllocFailed)?;
    }
    if dev.tx_queue.urbs.len() != MAX_TX_URB_COUNT {
        return Err(R92suError::UrbAllocFailed);
    }
    Ok(())
}

fn alloc_rx_urbs(dev: &mut R92suDevice) -> Result<()> {
    let ep = dev.bulk_in.ok_or(R92suError::UrbAllocFailed)?;
    for i in 0..MAX_RX_URB_COUNT {
        // Pre-allocate receive buffers so the USB host can DMA directly into them.
        dev.rx_queue
            .urbs
            .push(Urb::new(i, ep, RX_BUFFER_SIZE), GFP_KERNEL)
            .map_err(|_| R92suError::UrbAllocFailed)?;
    }
    if dev.rx_queue.urbs.len() != MAX_RX_URB_COUNT {
        return Err(R92suError::UrbAllocFailed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6 — hardware register bootstrap
// ---------------------------------------------------------------------------

fn hw_register_init(dev: &mut R92suDevice) -> Result<()> {
    // Enable system functions (MAC, BB, RF)
    dev.regs.write8(REG_SYS_FUNC_EN, 0xE3)?;

    // AFE PLL: enable crystal oscillator
    dev.regs.write8(REG_AFE_PLL_CTRL, 0x80)?;

    // System clock: switch to PLL output
    dev.regs.write8(REG_SYS_CLK_CTRL, 0xA3)?;

    // Command register: enable TX/RX path
    dev.regs.write8(REG_CR, 0xFF)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// BulkWriteResult — aggregated outcome of a multi-chunk bulk-out write
// ---------------------------------------------------------------------------

/// Outcome of [`bulk_out_write_multi`].
///
/// All chunks are attempted; failures are collected rather than causing an
/// early return, so the caller sees the full picture in one pass.
pub struct BulkWriteResult {
    /// Number of chunks successfully queued.
    pub queued: usize,
    /// `(chunk_index, error)` for every chunk that could not be queued.
    pub errors: KVec<(usize, R92suError)>,
}

impl BulkWriteResult {
    fn new() -> Self {
        Self {
            queued: 0,
            errors: KVec::new(),
        }
    }

    /// Returns `true` when every chunk was queued without error.
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// fw_bulk_write — synchronous bulk-out for firmware upload
// ---------------------------------------------------------------------------

/// Send `data` to the device via a synchronous `usb_bulk_msg` call.
///
/// Used exclusively during firmware upload, where an async URB pool would add
/// unnecessary complexity.  The call blocks until the transfer completes or
/// times out (5 s).
///
/// # Safety
///
/// `dev.udev` must be a valid, non-null `*mut usb_device` and `dev.bulk_out`
/// must be populated (both are guaranteed when called from firmware upload
/// after endpoint discovery).
pub fn fw_bulk_write(dev: &mut R92suDevice, data: &[u8]) -> Result<()> {
    let ep = dev
        .bulk_out
        .ok_or(R92suError::Io("no bulk-out endpoint for fw upload"))?;

    // usb_bulk_msg requires a kernel-heap buffer (DMA-safe); copy `data` there.
    let mut buf = KVec::from_elem(0u8, data.len(), GFP_KERNEL)
        .map_err(|_| R92suError::FirmwareUploadFailed("out of memory for fw buf"))?;
    buf[..].copy_from_slice(data);

    let mut actual: i32 = 0;

    // Compute the USB pipe value, equivalent to usb_sndbulkpipe(udev, ep):
    //   (PIPE_BULK << 30) | (dev->devnum << 8) | (endpoint << 15)
    // Direction bit is 0 (USB_DIR_OUT) for a send pipe.
    //
    // SAFETY: `dev.udev` is a valid pointer; reading `devnum` is a plain
    // integer field access with no aliasing hazard.
    let devnum = unsafe { (*dev.udev).devnum as u32 };
    let pipe = (bindings::PIPE_BULK << 30) | (devnum << 8) | ((ep.address as u32) << 15);

    // SAFETY: `dev.udev` is valid (guaranteed by caller context); `buf` is
    // heap-allocated and lives for the duration of this blocking call;
    // `actual` is a local stack variable whose address is valid.
    let ret = unsafe {
        bindings::usb_bulk_msg(
            dev.udev,
            pipe,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            data.len() as i32,
            &mut actual,
            5000, // 5 s timeout
        )
    };

    if ret < 0 {
        pr_err!(
            "r92su: fw_bulk_write: usb_bulk_msg failed (ep={:#04x} len={} ret={})\n",
            ep.address,
            data.len(),
            ret
        );
        return Err(R92suError::FirmwareUploadFailed("usb_bulk_msg failed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bulk_out_write — submit a bulk-out URB for transmission
//
// Mirrors r92su_usb_tx() from the reference driver:
//   usb_fill_bulk_urb(urb, udev, usb_sndbulkpipe(udev, ep), data, len,
//                     r92su_tx_usb_cb, skb)
//   urb->transfer_flags |= URB_ZERO_PACKET
//   usb_anchor_urb(urb, &r92su->tx_wait)
//   r92su_tx_schedule(r92su)  →  usb_submit_urb()
// ---------------------------------------------------------------------------

/// Submit a single bulk-out write using a TX URB from the pool.
///
/// Equivalent kernel code:
/// ```c
/// usb_fill_bulk_urb(urb, udev, usb_sndbulkpipe(udev, ep),
///                   data, len, r92su_tx_usb_cb, skb);
/// urb->transfer_flags |= URB_ZERO_PACKET;
/// usb_anchor_urb(urb, &r92su->tx_wait);
/// r92su_tx_schedule(r92su);
/// ```
pub fn bulk_out_write(dev: &mut R92suDevice, data: &[u8]) -> Result<()> {
    let Some(ep) = dev.bulk_out else {
        return Err(R92suError::Io("no bulk-out endpoint"));
    };

    if ep.ep_type != EndpointType::Bulk || ep.direction != EndpointDirection::Out {
        return Err(R92suError::Io("endpoint is not bulk-out"));
    }

    // SAFETY: dev.udev is valid (set during probe, lives until disconnect);
    // data is a valid slice that will be copied into the URB buffer by the C code.
    dev.tx_pending_urbs
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    let ret =
        unsafe { rust_helper_submit_one_tx_urb(dev.udev, ep.address, data.as_ptr(), data.len()) };

    if ret < 0 {
        dev.tx_pending_urbs
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
        pr_err!(
            "bulk_out_write: rust_helper_submit_one_tx_urb failed (ep={:#04x} len={} ret={})\n",
            ep.address,
            data.len(),
            ret
        );
        return Err(R92suError::Io("failed to submit TX URB"));
    }

    pr_debug!(
        "bulk_out_write: submitted {} bytes on ep={:#04x}\n",
        data.len(),
        ep.address
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// bulk_out_write_multi — submit multiple chunks, collecting all errors
// ---------------------------------------------------------------------------

/// Submit every chunk in `chunks` via [`bulk_out_write`], collecting failures
/// rather than returning on the first error.
///
/// Returns a [`BulkWriteResult`] that reports how many chunks were queued and
/// the full list of `(chunk_index, error)` pairs for any that failed.  The
/// caller can inspect `result.is_ok()` for the success fast-path, or iterate
/// `result.errors` to log or act on individual failures.
fn bulk_out_write_multi<'a>(
    dev: &mut R92suDevice,
    chunks: impl IntoIterator<Item = &'a [u8]>,
) -> BulkWriteResult {
    let mut result = BulkWriteResult::new();
    for (i, chunk) in chunks.into_iter().enumerate() {
        match bulk_out_write(dev, chunk) {
            Ok(()) => result.queued += 1,
            Err(e) => {
                pr_err!("bulk_out_write_multi: chunk {} failed: {}\n", i, e);
                // Best-effort: ignore push failure — the error is already logged.
                let _ = result.errors.push((i, e), GFP_KERNEL);
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Hardware setup functions (mirroring hw.c)
// ---------------------------------------------------------------------------

pub fn hw_early_mac_setup(dev: &mut R92suDevice) -> Result<()> {
    // Clear RPWM to ensure driver and fw are back in the initial state
    unsafe { hw_write8(dev.udev, REG_USB_HRPWM, PS_ACTIVE) };

    // For B and C cuts, do full hardware initialization
    match dev.chip_rev {
        ChipRev::BCut | ChipRev::CCut => {
            usb_init_b_and_c_cut(dev)?;
        }
        _ => {
            pr_warn!("r92su: unsupported chip revision for early setup\n");
        }
    }

    pr_debug!("r92su_hw_early_mac_setup: early MAC setup complete\n");
    Ok(())
}

/// Initialize hardware for B and C cut chips.
/// Mirrors r92su_usb_init_b_and_c_cut() from hw.c
fn usb_init_b_and_c_cut(dev: &mut R92suDevice) -> Result<()> {
    // Prevent EFUSE leakage
    unsafe {
        hw_write8(dev.udev, REG_EFUSE_TEST + 3, 0xb0);
    }
    mdelay(20);
    unsafe {
        hw_write8(dev.udev, REG_EFUSE_TEST + 3, 0x30);
    }

    // Set control path switch to HW control and reset digital core,
    // CPU core and MAC I/O core.
    let mut tmp16 = unsafe { hw_read16(dev.udev, REG_SYS_CLKR) };
    if tmp16 & SYS_FWHW_SEL as u16 != 0 {
        tmp16 &= !(SYS_SWHW_SEL as u16 | SYS_FWHW_SEL as u16);
        // Set failed, return to prevent hang.
        if !hal_set_sysclk(dev, tmp16) {
            return Err(R92suError::Io("failed to set sysclk"));
        }
    }

    // Reset MAC-IO and CPU and Core Digital BIT(10)/11/15
    let mut tmp8 = unsafe { hw_read8(dev.udev, REG_SYS_FUNC_EN + 1) };
    tmp8 &= 0x73;
    unsafe { hw_write8(dev.udev, REG_SYS_FUNC_EN + 1, tmp8) };
    // Wait for BIT 10/11/15 to pull high automatically
    mdelay(1);

    unsafe {
        hw_write8(dev.udev, REG_SPS0_CTRL + 1, 0x53);
        hw_write8(dev.udev, REG_SPS0_CTRL, 0x57);

        // Enable AFE Macro Block's Bandgap
        tmp8 = hw_read8(dev.udev, REG_AFE_MISC);
        hw_write8(dev.udev, REG_AFE_MISC, tmp8 | AFE_BGEN);
    }
    mdelay(1);

    unsafe {
        // Enable AFE Mbias
        tmp8 = hw_read8(dev.udev, REG_AFE_MISC);
        hw_write8(
            dev.udev,
            REG_AFE_MISC,
            tmp8 | AFE_BGEN | AFE_MBEN | AFE_MISC_I32_EN,
        );
    }
    mdelay(1);

    unsafe {
        // Enable LDOA15 block
        tmp8 = hw_read8(dev.udev, REG_LDOA15_CTRL);
        hw_write8(dev.udev, REG_LDOA15_CTRL, tmp8 | LDA15_EN);

        // Enable LDOV12D block
        tmp8 = hw_read8(dev.udev, REG_LDOV12D_CTRL);
        hw_write8(dev.udev, REG_LDOV12D_CTRL, tmp8 | LDV12_EN);

        // Set Digital Vdd to Retention isolation Path
        tmp16 = hw_read16(dev.udev, REG_SYS_ISO_CTRL);
        hw_write16(dev.udev, REG_SYS_ISO_CTRL, tmp16 | (ISO_PWC_DV2RP as u16));

        // For warm reboot NIC disappear bug (Engineer Packet CP test Enable).
        tmp16 = hw_read16(dev.udev, REG_SYS_FUNC_EN);
        hw_write16(dev.udev, REG_SYS_FUNC_EN, tmp16 | 0x2000);

        // Support 64k IMEM
        tmp8 = hw_read8(dev.udev, REG_SYS_ISO_CTRL + 1);
        hw_write8(dev.udev, REG_SYS_ISO_CTRL + 1, tmp8 & 0x68);

        // Enable AFE clock source
        tmp8 = hw_read8(dev.udev, REG_AFE_XTAL_CTRL);
        hw_write8(dev.udev, REG_AFE_XTAL_CTRL, tmp8 | 0x01);
    }
    mdelay(2);

    unsafe {
        tmp8 = hw_read8(dev.udev, REG_AFE_XTAL_CTRL + 1);
        hw_write8(dev.udev, REG_AFE_XTAL_CTRL + 1, tmp8 & 0xfb);

        // Enable AFE PLL Macro Block.
        // Read once; use same base value for all three writes (C driver behavior).
        udelay(200);
        let pll_base = hw_read8(dev.udev, REG_AFE_PLL_CTRL);
        hw_write8(dev.udev, REG_AFE_PLL_CTRL, pll_base | 0x11);
    }
    udelay(500);

    unsafe {
        // Divider reset: hold BIT(6) for 500 µs.
        let pll_base = hw_read8(dev.udev, REG_AFE_PLL_CTRL);
        hw_write8(dev.udev, REG_AFE_PLL_CTRL, pll_base | 0x51);
    }
    udelay(500);

    unsafe {
        // Release divider reset.
        let pll_base = hw_read8(dev.udev, REG_AFE_PLL_CTRL);
        hw_write8(dev.udev, REG_AFE_PLL_CTRL, (pll_base & !0x40) | 0x11);
    }
    udelay(500);

    // Release isolation AFE PLL & MD
    unsafe {
        tmp8 = hw_read8(dev.udev, REG_SYS_ISO_CTRL);
        hw_write8(dev.udev, REG_SYS_ISO_CTRL, tmp8 & 0xee);

        // Switch to 40MHz clock
        hw_write8(dev.udev, REG_SYS_CLKR, 0x00);

        // Disable CPU clock and 80MHz SSC
        tmp8 = hw_read8(dev.udev, REG_SYS_CLKR);
        hw_write8(dev.udev, REG_SYS_CLKR, tmp8 | 0xa0);

        // Enable MAC clock (BIT(11) | BIT(12)).
        tmp16 = hw_read16(dev.udev, REG_SYS_CLKR);
        tmp16 |= SYS_MAC_CLK_EN | 0x1000;
        if !hal_set_sysclk(dev, tmp16) {
            return Err(R92suError::Io("failed to enable MAC clock"));
        }

        hw_write8(dev.udev, REG_PMC_FSM, 0x02);

        // Enable Core digital and IOREG R/W
        tmp16 = hw_read16(dev.udev, REG_SYS_FUNC_EN);
        hw_write16(dev.udev, REG_SYS_FUNC_EN, tmp16 | FEN_DCORE);

        // Enable REG_EN
        tmp16 = hw_read16(dev.udev, REG_SYS_FUNC_EN);
        hw_write16(dev.udev, REG_SYS_FUNC_EN, tmp16 | FEN_MREGEN);

        // Switch control path to FW
        tmp16 = hw_read16(dev.udev, REG_SYS_CLKR);
        tmp16 |= SYS_FWHW_SEL;
        tmp16 &= !SYS_SWHW_SEL;
        if !hal_set_sysclk(dev, tmp16) {
            return Err(R92suError::Io("failed to switch to FW control"));
        }

        // Enable TX/RX
        hw_write16(
            dev.udev,
            REG_CR,
            (HCI_TXDMA_EN
                | HCI_RXDMA_EN
                | TXDMA_EN
                | RXDMA_EN
                | FW2HW_EN
                | DDMA_EN
                | MACTXEN
                | MACRXEN
                | SCHEDULE_EN
                | BB_GLB_RSTN
                | BBRSTN) as u16,
        );

        // Fix USB RX FIFO error
        tmp8 = hw_read8(dev.udev, REG_USB_AGG_TO);
        hw_write8(dev.udev, REG_USB_AGG_TO, tmp8 | 0x80);

        // Disable CPU clock
        tmp16 = hw_read16(dev.udev, REG_SYS_CLKR);
        tmp16 &= !(SYS_CPU_CLKSEL as u16);
        if !hal_set_sysclk(dev, tmp16) {
            return Err(R92suError::Io("failed to disable CPU clock"));
        }

        // Fix 8051 ROM incorrect code operation
        hw_write8(dev.udev, REG_USB_MAGIC, USB_MAGIC_BIT7);
    }

    // Wait for TxDMA ready before firmware download.
    // TXDMA_INIT_VALUE = IMEM_CHK_RPT | EXT_IMEM_CHK_RPT = BIT(1) | BIT(3) = 0x0a
    const TXDMA_INIT_VALUE: u8 = 0x0a;
    let mut tries = 20;
    loop {
        let tmp8 = unsafe { hw_read8(dev.udev, REG_TCR) };
        if (tmp8 & TXDMA_INIT_VALUE) == TXDMA_INIT_VALUE {
            break;
        }
        udelay(5);
        tries -= 1;
        if tries == 0 {
            pr_err!("r92su: TXDMA_INIT_VALUE timed out! TCR={:#04x}\n", tmp8);
            // Reset TxDMA so it can accept firmware.
            let cr = unsafe { hw_read8(dev.udev, REG_CR) };
            unsafe { hw_write8(dev.udev, REG_CR, cr & !(TXDMA_EN as u8)) };
            udelay(2);
            unsafe { hw_write8(dev.udev, REG_CR, cr | (TXDMA_EN as u8)) };
            break;
        }
    }

    pr_debug!("r92su: B/C cut hardware init complete\n");
    Ok(())
}

/// Set system clock - mirrors r92su_halset_sysclk
fn hal_set_sysclk(dev: &mut R92suDevice, clk_set: u16) -> bool {
    unsafe {
        hw_write16(dev.udev, REG_SYS_CLKR, clk_set);
    }
    udelay(400);

    let clk = unsafe { hw_read16(dev.udev, REG_SYS_CLKR) as u16 };

    if clk_set & ((SYS_SWHW_SEL as u16) | (SYS_FWHW_SEL as u16)) == 0 {
        return true;
    }

    (clk & (SYS_FWHW_SEL as u16)) == (clk_set & (SYS_FWHW_SEL as u16))
}

/// Transmit a pre-formatted command frame over the USB bulk-out endpoint.
///
/// Called by `cmd.rs` to deliver an H2C frame that has already been
/// assembled (TX descriptor + H2C header + payload).  Mirrors the
/// `r92su_usb_tx(r92su, skb, RTL8712_H2CCMD)` call in `r92su_h2c_submit()`.
pub fn usb_tx_cmd(dev: &mut R92suDevice, frame: &[u8]) -> Result<()> {
    bulk_out_write(dev, frame)
}

pub fn cmd_init(_dev: &mut R92suDevice) {
    // Sequence counter is reset by crate::cmd::cmd_init(); this stub keeps
    // the old call-site in r92u_open.rs working until it is updated to call
    // the real function from cmd.rs.
    pr_debug!("r92su_cmd_init: command subsystem initialized\n");
}

const REG_TCR: u16 = 0x0044;
// REG_RCR is used by the simulated HwRegs in upload_finish; the real USB address
// for direct hardware access is REG_RCR_ADDR.
const REG_RCR: u16 = 0x0400;
/// Real USB vendor-control address for the Receive Configuration Register.
///
/// RTL8712_CMDCTRL_ + 0x0008 = 0x10250040 + 0x0008 = 0x10250048.
/// The USB wValue field carries the lower 16 bits: 0x0048.
const REG_RCR_ADDR: u16 = 0x0048;
const REG_RXFLTMAP0: u16 = 0x0116; // RTL8712_FIFOCTRL_ + 0x76
const REG_RXFLTMAP1: u16 = 0x0118; // RTL8712_FIFOCTRL_ + 0x78
const REG_RXFLTMAP2: u16 = 0x011a; // RTL8712_FIFOCTRL_ + 0x7A
const REG_IOCMD_CTRL: u16 = 0x0370; // RTL8712_IOCMD_ + 0x00
const REG_LBKMD_SEL: u16 = 0x04a7;
const REG_PBP: u16 = 0x0004;
const REG_RXDMA_RXCTRL: u16 = 0x0c60;
const REG_RXDMA_AGG_PG_TH: u16 = 0x0c5b;
const REG_USB_DMA_AGG_TO: u16 = 0x0c5c;
const REG_USB_AGG_TO: u16 = 0x0c58;
const REG_TXPAUSE: u16 = 0x0522;
const REG_MAC_PINMUX_CTRL: u16 = 0x0e08;
const REG_GPIO_IO_SEL: u16 = 0x0c02;
const REG_GPIO_CTRL: u16 = 0x0c00;

// Additional registers used in hw_early_mac_setup
const REG_EFUSE_TEST: u16 = 0x0034;
const REG_SPS0_CTRL: u16 = 0x0011;
const REG_AFE_MISC: u16 = 0x0010;
const REG_LDOA15_CTRL: u16 = 0x0020;
const REG_LDOV12D_CTRL: u16 = 0x0021;
const REG_AFE_XTAL_CTRL: u16 = 0x0026;
const REG_SYS_ISO_CTRL: u16 = 0x0000;
const REG_USB_HRPWM: u16 = 0x0fe8;
const REG_USB_MAGIC: u16 = 0x0fe7;
const REG_PMC_FSM: u16 = 0x0004;

// AFE bits
const AFE_BGEN: u8 = 0x01;
const AFE_MBEN: u8 = 0x02;
const AFE_MISC_I32_EN: u8 = 0x08;

// LDO bits
const LDA15_EN: u8 = 0x01;
const LDV12_EN: u8 = 0x01;

// ISO bits
const ISO_MD2PP: u8 = 0x01;
const ISO_PA2PCIE: u8 = 0x08;
const ISO_PLL2MD: u8 = 0x10;
const ISO_PWC_DV2RP: u16 = 0x0800;

// SYS_CLKR bits
const SYS_CLKSEL_80M: u8 = 0x01;
const SYS_PS_CLKSEL: u8 = 0x02;
const SYS_CPU_CLKSEL: u8 = 0x04;
const SYS_MAC_CLK_EN: u16 = 0x0800;
const SYS_SWHW_SEL: u16 = 0x4000;
const SYS_FWHW_SEL: u16 = 0x8000;

// SYS_FUNC_EN bits
const FEN_CPUEN: u16 = 0x0400;
const FEN_DCORE: u16 = 0x0800;
const FEN_MREGEN: u16 = 0x8000;

// CR bits
const HCI_TXDMA_EN: u16 = 0x0004;
const HCI_RXDMA_EN: u16 = 0x0008;
const TXDMA_EN: u16 = 0x0010;
const RXDMA_EN: u16 = 0x0020;
const FW2HW_EN: u16 = 0x0040;
const DDMA_EN: u16 = 0x0080;
const MACTXEN: u16 = 0x0100;
const MACRXEN: u16 = 0x0200;
const SCHEDULE_EN: u16 = 0x0400;
const BB_GLB_RSTN: u16 = 0x1000;
const BBRSTN: u16 = 0x2000;

// Power states
const PS_ACTIVE: u8 = 0x00;
const PS_RADIO_OFF: u8 = 0x01;

// USB magic
const USB_MAGIC_BIT7: u8 = 0x80;

const PBP_PAGE_128B: u8 = 0x00;
const RXDMA_AGG_EN: u8 = 0x80;
const LBK_NORMAL: u8 = 0x01;
const GPIOMUX_EN: u8 = 0x80;
const GPIOSEL_GPIO: u8 = 0x00;

const STOPBK: u16 = 0x0001;
const STOPBE: u16 = 0x0002;
const STOPVI: u16 = 0x0004;
const STOPVO: u16 = 0x0008;
const STOPMGT: u16 = 0x0010;
const STOPHIGH: u16 = 0x0020;
const STOPHCCA: u16 = 0x0040;

const HAL_8192S_HW_GPIO_WPS_BIT: u8 = 0x10;

const TCR_ICV: u32 = 0x00000001;

// ---------------------------------------------------------------------------
// RCR bit values for direct hardware access (hw_mac_set_rx_filter).
//
// These match the C reference (reg.h), using the physical bit positions in
// the RTL8712 Receive Configuration Register.  They are distinct from the
// RCR_* constants above which are used with the simulated `HwRegs` and
// carry different (incorrect) bit assignments.
// ---------------------------------------------------------------------------
const RCR_HW_AAP: u32 = 1 << 0; // Accept All Physical dest
const RCR_HW_AB: u32 = 1 << 1; // Accept Broadcast
const RCR_HW_AM: u32 = 1 << 2; // Accept Multicast
const RCR_HW_APM: u32 = 1 << 3; // Accept Physical Match
const RCR_HW_APWRMGT: u32 = 1 << 4; // Accept power-mgmt frames
const RCR_HW_AICV: u32 = 1 << 7; // Accept ICV-error frames
const RCR_HW_APP_ICV: u32 = 1 << 16; // Append ICV to Rx
const RCR_HW_APP_MIC: u32 = 1 << 17; // Append MIC to Rx
const RCR_HW_ADF: u32 = 1 << 18; // Accept Data Frames
const RCR_HW_ACF: u32 = 1 << 19; // Accept Control Frames
const RCR_HW_AMF: u32 = 1 << 20; // Accept Management Frames
const RCR_HW_CBSSID: u32 = 1 << 23; // Check BSSID
const RCR_HW_APP_PHYST_STAFF: u32 = 1 << 24; // Append PHY status
const RCR_HW_APP_PHYST_RXFF: u32 = 1 << 25; // Append PHY status RxFF
const RCR_HW_APPFCS: u32 = 1 << 31; // Append FCS
const RCR_APP_PHYST_RXFF: u32 = 0x40000000;
const RCR_APP_ICV: u32 = 0x20000000;
const RCR_APP_MIC: u32 = 0x10000000;
const RCR_ADF: u32 = 0x00000020;
const RCR_ACF: u32 = 0x00000010;
const RCR_AMF: u32 = 0x00000008;
const RCR_AAP: u32 = 0x00000001;
const RCR_CBSSID: u32 = 0x00000004;
const RCR_APPFCS: u32 = 0x00000040;
const RCR_APWRMGT: u32 = 0x00000080;
const RCR_AICV: u32 = 0x00000100;
const RCR_AB: u32 = 0x00000002;
const RCR_AM: u32 = 0x00000004;
const RCR_APM: u32 = 0x00000080;
const RCR_APP_PHYST_STAFF: u32 = 0x00000200;

/// Issue a firmware I/O command and wait for completion.
///
/// Writes `cmd` to `REG_IOCMD_CTRL` then polls until the register reads back
/// as zero (firmware acknowledges).  Times out after 25 × 20 ms = 500 ms.
///
/// Mirrors `r92su_fw_iocmd()` from `cmd.c`.
pub fn fw_iocmd(dev: &mut R92suDevice, cmd: u32) -> Result<()> {
    unsafe { hw_write32(dev.udev, REG_IOCMD_CTRL, cmd) };
    let mut tries = 25u32;
    loop {
        mdelay(20);
        tries -= 1;
        if tries == 0 {
            return Err(R92suError::Io("fw_iocmd timed out"));
        }
        let val = unsafe { hw_read32(dev.udev, REG_IOCMD_CTRL) };
        if val == 0 {
            break;
        }
    }
    Ok(())
}

/// Configure the hardware RX packet filter.
///
/// Sets RCR, RXFLTMAP0/1/2 to accept the appropriate frame types for the
/// current operating mode.
///
/// Mirrors `r92su_hw_mac_set_rx_filter()` from `hw.c`.
pub fn hw_mac_set_rx_filter(
    dev: &mut R92suDevice,
    data: bool,
    all_mgt: bool,
    ctrl: bool,
    monitor: bool,
) -> Result<()> {
    let mut rcr = unsafe { hw_read32(dev.udev, REG_RCR_ADDR) };

    if data {
        rcr |= RCR_HW_ADF;
    } else {
        rcr &= !RCR_HW_ADF;
    }
    if ctrl {
        rcr |= RCR_HW_ACF;
    } else {
        rcr &= !RCR_HW_ACF;
    }

    rcr |= RCR_HW_AMF;

    if monitor {
        rcr |= RCR_HW_AAP | RCR_HW_CBSSID;
    } else {
        rcr &= !(RCR_HW_AAP | RCR_HW_CBSSID);
    }

    rcr |= RCR_HW_APPFCS
        | RCR_HW_APWRMGT
        | RCR_HW_APP_MIC
        | RCR_HW_APP_ICV
        | RCR_HW_AICV
        | RCR_HW_AB
        | RCR_HW_AM
        | RCR_HW_APM
        | RCR_HW_APP_PHYST_STAFF;

    unsafe { hw_write32(dev.udev, REG_RCR_ADDR, rcr) };

    // RXFLTMAP: a cleared bit allows that frame subtype through.
    unsafe {
        hw_write16(dev.udev, REG_RXFLTMAP2, if data { 0 } else { 0xffff });
        hw_write16(dev.udev, REG_RXFLTMAP1, if ctrl { 0 } else { 0xffff });
        // RXFLTMAP0 affects firmware scan; set to let beacon/probe frames through.
        hw_write16(dev.udev, REG_RXFLTMAP0, if all_mgt { 0 } else { 0x3f3f });
    }

    Ok(())
}

fn upload_finish(dev: &mut R92suDevice) -> Result<()> {
    let mut cr = dev.regs.read8(REG_TCR as u16) as u32;
    cr &= !TCR_ICV;
    dev.regs.write8(REG_TCR as u16, cr as u8)?;

    let mut rcr = dev.regs.read8(REG_RCR as u16) as u32;
    rcr |= RCR_APP_PHYST_RXFF | RCR_APP_ICV | RCR_APP_MIC;
    dev.regs.write8(REG_RCR as u16, rcr as u8)?;

    dev.regs.write8(REG_LBKMD_SEL, LBK_NORMAL)?;
    dev.rx_alignment = 128;
    Ok(())
}

fn macconfig_after_fwdownload(dev: &mut R92suDevice) -> Result<()> {
    let tmp16 = dev.regs.read8(REG_TXPAUSE as u16) as u16;
    let cleared =
        tmp16 & !(STOPBK | STOPBE | STOPVI | STOPVO | STOPMGT | STOPHIGH | STOPHCCA | 0x0080);
    dev.regs.write8(REG_TXPAUSE as u16, cleared as u8)?;
    Ok(())
}

fn usb_final_macconfig(dev: &mut R92suDevice) -> Result<()> {
    let tmp = dev.regs.read8(REG_PBP);
    dev.regs.write8(REG_PBP, tmp | PBP_PAGE_128B)?;
    dev.rx_alignment = 128;

    let tmp = dev.regs.read8(REG_RXDMA_RXCTRL);
    dev.regs.write8(REG_RXDMA_RXCTRL, tmp | RXDMA_AGG_EN)?;

    dev.regs.write8(REG_RXDMA_AGG_PG_TH, 48)?;
    dev.regs.write8(REG_USB_DMA_AGG_TO, 0x04)?;

    let tmp = dev.regs.read8(REG_USB_AGG_TO);
    dev.regs.write8(REG_USB_AGG_TO, tmp | 0x80)?;
    Ok(())
}

fn wps_cfg_inputmethod(dev: &mut R92suDevice) -> Result<()> {
    dev.regs
        .write8(REG_MAC_PINMUX_CTRL, GPIOMUX_EN | GPIOSEL_GPIO)?;
    let mut u1tmp = dev.regs.read8(REG_GPIO_IO_SEL);
    u1tmp &= !HAL_8192S_HW_GPIO_WPS_BIT;
    dev.regs.write8(REG_GPIO_IO_SEL, u1tmp)?;
    Ok(())
}

pub fn hw_late_mac_setup(dev: &mut R92suDevice) -> Result<()> {
    upload_finish(dev)?;
    macconfig_after_fwdownload(dev)?;
    usb_final_macconfig(dev)?;
    wps_cfg_inputmethod(dev)?;
    pr_debug!("r92su_hw_late_mac_setup: late MAC setup complete\n");
    Ok(())
}

pub fn init_mac(dev: &mut R92suDevice) -> Result<()> {
    // Configure hardware RX filter: accept data + management, no control, no monitor.
    // Mirrors r92su_hw_mac_set_rx_filter(r92su, data=true, all_mgt=false, ctrl=false, mntr=false).
    hw_mac_set_rx_filter(dev, true, false, false, false).map_err(|e| {
        pr_err!("r92su_init_mac: hw_mac_set_rx_filter failed: {}\n", e);
        e
    })?;

    // Enable 40 MHz mode (bit 9), STBC (bit 10), video mode to 96B AP (bit 8).
    // Mirrors: r92su_fw_iocmd(r92su, 0xf4000700)
    fw_iocmd(dev, 0xf4000700).map_err(|e| {
        pr_err!("r92su_init_mac: fw_iocmd failed: {}\n", e);
        e
    })?;

    // Set operation mode to infrastructure (station).
    crate::cmd::h2c_set_opmode(dev, crate::cmd::OpMode::Infra).map_err(|e| {
        pr_err!("r92su_init_mac: h2c_set_opmode failed: {}\n", e);
        e
    })?;

    // Set MAC address from EEPROM.
    let mac = dev.mac_addr;
    crate::cmd::h2c_set_mac_addr(dev, &mac).map_err(|e| {
        pr_err!("r92su_init_mac: h2c_set_mac_addr failed: {}\n", e);
        e
    })?;

    // Set initial channel.
    let ch = dev.channel as u32;
    crate::cmd::h2c_set_channel(dev, ch).map_err(|e| {
        pr_err!("r92su_init_mac: h2c_set_channel failed: {}\n", e);
        e
    })?;

    pr_debug!("r92su_init_mac: MAC initialized (channel={})\n", ch);
    dev.set_state(State::Init);
    Ok(())
}
