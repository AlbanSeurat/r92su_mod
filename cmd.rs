// SPDX-License-Identifier: GPL-2.0
//! H2C (Host-to-Chip) command interface for RTL8192SU.
//!
//! Mirrors `cmd.c` / `cmd.h` and the structure definitions in `h2cc2h.h` from
//! the C reference driver.
//!
//! # Frame layout
//!
//! Every command sent over the USB bulk-out (command endpoint) looks like:
//!
//! ```text
//! ┌─────────────────┬──────────────────┬──────────────────────────┐
//! │ TX_DESC (32 B)  │ H2C header (8 B) │ payload (8-byte aligned) │
//! └─────────────────┴──────────────────┴──────────────────────────┘
//! ```
//!
//! The TX descriptor carries the total length of everything after it, the
//! offset (always 32), and the command queue selector (`QSLT_CMD = 0x13`).
//! The H2C header carries the command code, a 7-bit sequence number, and
//! the aligned payload length.

use kernel::prelude::*; //

use crate::r92u::{usb_tx_cmd, R92suDevice, Result}; //

// ---------------------------------------------------------------------------
// Frame-layout constants (mirrors def.h / cmd.c)
// ---------------------------------------------------------------------------

/// Size of the TX descriptor prepended to every outgoing USB frame.
const TX_DESC_SIZE: usize = 32;

/// Size of the H2C/C2H command header (`struct h2cc2h`).
const H2CC2H_HDR_LEN: usize = 8;

/// Command queue selector value used in the TX descriptor.
const QSLT_CMD: u32 = 0x13;

// ---------------------------------------------------------------------------
// Encryption algorithm identifiers (mirrors `enum r92su_enc_alg` in def.h)
// ---------------------------------------------------------------------------

/// Encryption algorithm as used by the firmware command interface.
///
/// Mirrors `enum r92su_enc_alg` from `def.h`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncAlg {
    None = 0,
    Wep40 = 1,
    Tkip = 2,
    TkipWtmic = 3,
    AesCcmp = 4,
    Wep104 = 5,
}

/// Bytes of key material the firmware expects for each algorithm.
///
/// Mirrors `r92su_enc_alg_len[]` from `cmd.c`.  TKIP only uploads the first
/// 16 bytes (the encryption key); the MIC keys are not uploaded.
const ENC_ALG_KEY_LEN: [usize; 6] = [
    0,  // None
    5,  // Wep40  (WLAN_KEY_LEN_WEP40)
    16, // Tkip   (first 16 bytes only)
    16, // TkipWtmic
    16, // AesCcmp (WLAN_KEY_LEN_CCMP)
    13, // Wep104  (WLAN_KEY_LEN_WEP104)
];

// ---------------------------------------------------------------------------
// Authentication mode enums (mirrors h2cc2h.h)
// ---------------------------------------------------------------------------

/// Authentication mode sent to the firmware in `h2c_set_auth`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMode {
    Open = 0,
    Shared = 1,
    Auth8021x = 2,
}

/// WPA key management mode.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Auth1x {
    Psk = 0,
    Eap = 1,
}

// ---------------------------------------------------------------------------
// Operation mode (mirrors `enum h2c_op_modes` in h2cc2h.h)
// ---------------------------------------------------------------------------

/// Operation mode sent via `H2C_SETOPMODE_CMD`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpMode {
    Auto = 0,
    AdHoc = 1,
    Infra = 2,
    Monitor = 3,
}

// ---------------------------------------------------------------------------
// Power-save modes (mirrors `enum r92su_power_mgnt` in h2cc2h.h)
// ---------------------------------------------------------------------------

/// Power-save mode requested via `H2C_SETPWRMODE_CMD`.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsMode {
    Active = 0,
    Min = 1,
    Max = 2,
    Dtim = 3,
    Voip = 4,
    UapsdWmm = 5,
    Uapsd = 6,
    Ibss = 7,
    WowWlan = 8,
    RadioOff = 9,
    CardDisable = 10,
}

// ---------------------------------------------------------------------------
// H2C command codes (mirrors `enum fw_h2c_cmd` in h2cc2h.h)
// ---------------------------------------------------------------------------

/// H2C command identifiers understood by the RTL8712 firmware.
///
/// Mirrors `enum fw_h2c_cmd` in `h2cc2h.h`.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FwH2cCmd {
    ReadMacreg = 0,
    WriteMacreg = 1,
    ReadBb = 2,
    WriteBb = 3,
    ReadRf = 4,
    WriteRf = 5,
    ReadEeprom = 6,
    WriteEeprom = 7,
    ReadEfuse = 8,
    WriteEfuse = 9,
    ReadCam = 10,
    WriteCam = 11,
    SetBcnItv = 12,
    SetMbidCfg = 13,
    JoinBss = 14,
    Disconnect = 15,
    CreateBss = 16,
    SetOpMode = 17,
    SiteSurvey = 18,
    SetAuth = 19,
    SetKey = 20,
    SetStaKey = 21,
    SetAssocSta = 22,
    DelAssocSta = 23,
    SetStaPwrState = 24,
    SetBasicRate = 25,
    GetBasicRate = 26,
    SetDataRate = 27,
    GetDataRate = 28,
    SetPhyInfo = 29,
    GetPhyInfo = 30,
    SetPhy = 31,
    GetPhy = 32,
    ReadRssi = 33,
    ReadGain = 34,
    SetAtim = 35,
    SetPwrMode = 36,
    JoinBssRpt = 37,
    SetRaTable = 38,
    GetRaTable = 39,
    GetCcxReport = 40,
    GetDtmReport = 41,
    GetTxRateStats = 42,
    SetUsbSuspend = 43,
    SetH2cLbk = 44,
    AddBaReq = 45,
    SetChannel = 46,
    SetTxPower = 47,
    SwitchAntenna = 48,
    SetXtalCap = 49,
    SetSingleCarrierTx = 50,
    SetSingleTone = 51,
    SetCarrierSuppressionTx = 52,
    SetContinuousTx = 53,
    SwitchBw = 54,
    TxBeacon = 55,
    SetPowerTracking = 56,
    AmsduToAmpdu = 57,
    SetMacAddress = 58,
    DisconnectCtrl = 59,
    SetChannelPlan = 60,
    DisconnectCtrlEx = 61,
    GetH2cLbk = 62,
    SetPwrParam = 63,
    WowWlanControl = 64,
    SetProbeReqExtraIe = 65,
    SetAssocReqExtraIe = 66,
    SetProbeRspExtraIe = 67,
    SetAssocRspExtraIe = 68,
    GetCurrentDataRate = 69,
    GetTxRetryCnt = 70,
    GetRxRetryCnt = 71,
    GetBcnOkCnt = 72,
    GetBcnErrCnt = 73,
    GetCurrentTxPower = 74,
    SetDig = 75,
    SetRa = 76,
    SetPt = 77,
    ReadRssiCmd = 78,
}

// ---------------------------------------------------------------------------
// H2C payload structs (mirrors h2cc2h.h, all #[repr(C, packed)])
// ---------------------------------------------------------------------------

/// Set MAC address (`H2C_SET_MAC_ADDRESS_CMD`).
#[repr(C, packed)]
pub struct H2cSetMac {
    pub mac_addr: [u8; 6],
}

/// Set operation mode (`H2C_SETOPMODE_CMD`).
#[repr(C, packed)]
pub struct H2cOpMode {
    pub mode: u8,
    _pad: [u8; 3],
}

/// Set channel (`H2C_SETCHANNEL_CMD`).
#[repr(C, packed)]
pub struct H2cSetChannel {
    pub channel: u32, // little-endian
}

/// Site survey command (`H2C_SITESURVEY_CMD`).
#[repr(C, packed)]
pub struct H2cSiteSurvey {
    /// 0 = passive, 1 = active.
    pub active: u32, // little-endian
    pub bsslimit: u32,  // 1–48, little-endian
    pub ssidlen: u32,   // little-endian
    pub ssid: [u8; 33], // IEEE80211_MAX_SSID_LEN + 1
}

/// Disconnect command (`H2C_DISCONNECT_CMD`).
#[repr(C, packed)]
pub struct H2cDisconnect {
    _rsvd: u32,
}

/// Authentication mode (`H2C_SETAUTH_CMD`).
#[repr(C, packed)]
pub struct H2cAuth {
    pub mode: u8,
    pub auth_1x: u8, // 0 = PSK, 1 = EAP
    _pad: [u8; 2],
}

/// Group key (`H2C_SETKEY_CMD`).
#[repr(C, packed)]
pub struct H2cKey {
    pub algorithm: u8, // EncAlg
    pub key_id: u8,
    pub group_key: u8, // 0 = unicast, 1 = group
    pub key: [u8; 16],
}

/// Pairwise (station) key (`H2C_SETSTAKEY_CMD`).
#[repr(C, packed)]
pub struct H2cStaKey {
    pub mac_addr: [u8; 6],
    pub algorithm: u8, // EncAlg
    pub key: [u8; 16],
}

/// BlockAck request (`H2C_ADDBA_REQ_CMD`).
#[repr(C, packed)]
pub struct H2cAddBaReq {
    pub tid: u32, // little-endian
}

/// Power mode (`H2C_SETPWRMODE_CMD`).
#[repr(C, packed)]
pub struct H2cSetPowerMode {
    pub mode: u8,
    pub flag_low_traffic_en: u8,
    pub flag_lpnav_en: u8,
    pub flag_rf_low_snr_en: u8,
    pub flag_dps_en: u8,
    pub bcn_rx_en: u8,
    pub bcn_pass_cnt: u8,
    pub bcn_to: u8,
    pub bcn_itv: u16, // little-endian
    pub app_itv: u8,
    pub awake_bcn_itv: u8,
    pub smart_ps: u8,
    pub bcn_pass_time: u8,
}

// ---------------------------------------------------------------------------
// BSS descriptor for connect / create-BSS commands (mirrors h2cc2h_bss)
// ---------------------------------------------------------------------------

/// FH network configuration sub-struct.
#[repr(C, packed)]
pub struct H2c11FhNetworkConfig {
    pub length: u32,
    pub hop_pattern: u32,
    pub hop_set: u32,
    pub dwell_time: u32,
}

/// Network configuration sub-struct.
#[repr(C, packed)]
pub struct H2cNetworkConfig {
    pub length: u32,
    pub beacon_period: u32,
    pub atim_window: u32,
    pub frequency: u32,
    pub fh_config: H2c11FhNetworkConfig,
}

/// Extended rates (16 bytes).
#[repr(C, packed)]
pub struct H2cExtRates {
    pub rates: [u8; 16],
}

/// SSID sub-struct.
#[repr(C, packed)]
pub struct H2cSsid {
    pub length: u32, // little-endian
    pub ssid: [u8; 32],
}

/// Fixed IEs (timestamp + beacon interval + capabilities).
#[repr(C, packed)]
pub struct H2cFixedIes {
    pub timestamp: u64,  // little-endian
    pub beacon_int: u16, // little-endian
    pub caps: u16,       // little-endian
                         // Variable IEs follow in memory — not modelled here.
}

/// Full BSS descriptor sent with `H2C_JOINBSS_CMD` / `H2C_CREATEBSS_CMD`.
///
/// Mirrors `struct h2cc2h_bss` from `h2cc2h.h`.
#[repr(C, packed)]
pub struct H2cc2hBss {
    pub length: u32, // little-endian — total struct + IEs
    pub bssid: [u8; 6],
    _padding: [u8; 2],
    pub ssid: H2cSsid,
    pub privacy: u32,  // little-endian
    pub rssi: u32,     // little-endian
    pub net_type: u32, // little-endian (h2c_network_type)
    pub config: H2cNetworkConfig,
    pub mode: u32, // little-endian (h2c_network_infrastruct_mode)
    pub rates: H2cExtRates,
    pub ie_length: u32, // little-endian
    pub ies: H2cFixedIes,
}

// ---------------------------------------------------------------------------
// Size assertions — mirrors __check_h2cc2h__ from h2cc2h.h
// ---------------------------------------------------------------------------

const _: () = {
    assert!(core::mem::size_of::<H2cSetChannel>() == 4);
    assert!(core::mem::size_of::<H2cDisconnect>() == 4);
    assert!(core::mem::size_of::<H2cOpMode>() == 4);
    assert!(core::mem::size_of::<H2cAddBaReq>() == 4);
    assert!(core::mem::size_of::<H2cSetMac>() == 6);
    assert!(core::mem::size_of::<H2cSetPowerMode>() == 14);
    assert!(core::mem::size_of::<H2cExtRates>() == 16);
    assert!(core::mem::size_of::<H2cKey>() == 19);
    assert!(core::mem::size_of::<H2cStaKey>() == 23);
    assert!(core::mem::size_of::<H2cSiteSurvey>() == 45);
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Round `n` up to the next multiple of `align` (must be a power of two).
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Reinterpret a `#[repr(C, packed)]` struct as its raw bytes.
///
/// # Safety
///
/// `T` must be `#[repr(C, packed)]` and must not contain any pointer types.
/// All byte patterns must be valid for `T` (trivially true for integer fields).
unsafe fn as_bytes<T: Sized>(t: &T) -> &[u8] {
    // SAFETY: caller guarantees T is repr(C, packed); byte slice covers the
    // exact allocation of *t.
    unsafe { core::slice::from_raw_parts(t as *const T as *const u8, core::mem::size_of::<T>()) }
}

// ---------------------------------------------------------------------------
// TX-descriptor bit-field helpers (mirrors def.h macros)
// ---------------------------------------------------------------------------

/// Set a bit field within a little-endian `u32` word.
#[inline]
fn set_bits_le(dw: &mut [u8; 4], shift: u32, len: u32, val: u32) {
    let mut word = u32::from_le_bytes(*dw);
    let mask = ((1u32 << len).wrapping_sub(1)) << shift;
    word = (word & !mask) | ((val << shift) & mask);
    *dw = word.to_le_bytes();
}

/// Build the 32-byte TX descriptor for an H2C command frame.
///
/// Mirrors `__r92su_tx_fill_header()` + `r92su_tx_fill_header()` in `cmd.c`
/// with `QSLT_CMD` as the queue selector and first=last=own=1.
fn build_tx_desc(buf: &mut [u8; TX_DESC_SIZE], pkt_size: usize) {
    // DW0: pkt_size [15:0] | offset [23:16] | last_seg [26] | first_seg [27] | own [31]
    let mut dw0 = [0u8; 4];
    set_bits_le(&mut dw0, 0, 16, pkt_size as u32);
    set_bits_le(&mut dw0, 16, 8, TX_DESC_SIZE as u32);
    set_bits_le(&mut dw0, 26, 1, 1); // last_seg
    set_bits_le(&mut dw0, 27, 1, 1); // first_seg
    set_bits_le(&mut dw0, 31, 1, 1); // own
    buf[0..4].copy_from_slice(&dw0);

    // DW1: queue_sel [12:8]
    let mut dw1 = [0u8; 4];
    set_bits_le(&mut dw1, 8, 5, QSLT_CMD);
    buf[4..8].copy_from_slice(&dw1);
    // DW2–DW7 remain zero.
}

// ---------------------------------------------------------------------------
// cmd_init — initialise the command sequence counter
// ---------------------------------------------------------------------------

/// Initialise the H2C command subsystem.
///
/// Mirrors `r92su_cmd_init()` from `cmd.c`.  Must be called once after the
/// device is probed and before any H2C commands are submitted.
pub fn cmd_init(dev: &mut R92suDevice) {
    dev.h2c_seq = 1;
    pr_debug!("r92su: cmd_init: H2C sequence reset to 1\n");
}

// ---------------------------------------------------------------------------
// h2c_submit — the core transmit path for H2C frames
// ---------------------------------------------------------------------------

/// Build and transmit a complete H2C command frame.
///
/// Mirrors `r92su_h2c_submit()` from `cmd.c`.  The `payload` slice must
/// already be padded to a multiple of [`H2CC2H_HDR_LEN`] bytes by the caller
/// (use [`h2c_copy`] for the simple case).
///
/// Frame layout:
/// ```text
/// [TX_DESC 32B][H2C_HDR 8B][payload (padded)]
/// ```
pub fn h2c_submit(dev: &mut R92suDevice, payload: &[u8], cmd: FwH2cCmd) -> Result<()> {
    let pkt_size = H2CC2H_HDR_LEN + payload.len(); // after TX desc
    let total = TX_DESC_SIZE + pkt_size;

    let mut buf: KVec<u8> = KVec::from_elem(0u8, total, GFP_KERNEL)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

    // Build TX descriptor.
    let mut tx_desc_arr = [0u8; TX_DESC_SIZE];
    build_tx_desc(&mut tx_desc_arr, pkt_size);
    buf[0..TX_DESC_SIZE].copy_from_slice(&tx_desc_arr);

    // Build H2C header at TX_DESC_SIZE offset.
    //
    // struct h2cc2h layout (8 bytes, packed):
    //   __le16  len          [0..2]  — aligned payload size
    //   u8      event        [2]     — command code
    //   u8      cmd_seq      [3]     — sequence (bit 7 = "last fragment")
    //   u8      agg_num      [4]     — 0
    //   u8      unkn         [5]     — 0
    //   __le16  agg_total    [6..8]  — 0
    let h2c_len = (payload.len() as u16).to_le_bytes();
    let seq = dev.h2c_seq | 0x80; // last=true
    dev.h2c_seq = dev.h2c_seq.wrapping_add(1) & 0x7F;

    let hdr_off = TX_DESC_SIZE;
    buf[hdr_off] = h2c_len[0];
    buf[hdr_off + 1] = h2c_len[1];
    buf[hdr_off + 2] = cmd as u8;
    buf[hdr_off + 3] = seq;
    // bytes 4–7 remain zero (agg_num, unkn, agg_total_len).

    // Copy payload.
    let payload_off = TX_DESC_SIZE + H2CC2H_HDR_LEN;
    buf[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    usb_tx_cmd(dev, &buf)
}

// ---------------------------------------------------------------------------
// h2c_copy — pad a struct payload and call h2c_submit
// ---------------------------------------------------------------------------

/// Copy `data` into a padded buffer and submit it as command `cmd`.
///
/// Mirrors `r92su_h2c_copy()` from `cmd.c`.  Payload is zero-padded to the
/// next multiple of [`H2CC2H_HDR_LEN`] (8 bytes).  If `data.len()` is already
/// a multiple of 8 an extra 8 bytes of zeros are appended — this matches the
/// C driver's behaviour exactly.
fn h2c_copy(dev: &mut R92suDevice, cmd: FwH2cCmd, data: &[u8]) -> Result<()> {
    let len = data.len();
    let rest = H2CC2H_HDR_LEN - (len % H2CC2H_HDR_LEN);
    let padded_len = len + rest;

    let mut payload: KVec<u8> = KVec::from_elem(0u8, padded_len, GFP_KERNEL)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;
    payload[..len].copy_from_slice(data);
    // Remaining bytes are already zero from from_elem.

    h2c_submit(dev, &payload, cmd)
}

// ---------------------------------------------------------------------------
// Public command wrappers
// ---------------------------------------------------------------------------

/// Set the device MAC address.
///
/// Mirrors `r92su_h2c_set_mac_addr()`.
pub fn h2c_set_mac_addr(dev: &mut R92suDevice, addr: &[u8; 6]) -> Result<()> {
    let args = H2cSetMac { mac_addr: *addr };
    // SAFETY: H2cSetMac is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetMacAddress, unsafe { as_bytes(&args) })
}

/// Set the operation mode (station / IBSS / auto).
///
/// Mirrors `r92su_h2c_set_opmode()`.
pub fn h2c_set_opmode(dev: &mut R92suDevice, mode: OpMode) -> Result<()> {
    let args = H2cOpMode {
        mode: mode as u8,
        _pad: [0; 3],
    };
    // SAFETY: H2cOpMode is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetOpMode, unsafe { as_bytes(&args) })
}

/// Set the current channel.
///
/// Mirrors `r92su_h2c_set_channel()`.
pub fn h2c_set_channel(dev: &mut R92suDevice, channel: u32) -> Result<()> {
    let args = H2cSetChannel {
        channel: channel.to_le(),
    };
    // SAFETY: H2cSetChannel is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetChannel, unsafe { as_bytes(&args) })
}

/// Initiate a site survey (scan).
///
/// Pass `ssid = None` for a passive broadcast scan, or `Some((ssid_bytes,
/// ssid_len))` for a directed active scan.
///
/// Mirrors `r92su_h2c_survey()`.
pub fn h2c_survey(dev: &mut R92suDevice, ssid: Option<(&[u8], usize)>) -> Result<()> {
    let mut args = H2cSiteSurvey {
        active: 0u32.to_le(),
        bsslimit: 48u32.to_le(),
        ssidlen: 0u32.to_le(),
        ssid: [0u8; 33],
    };

    if let Some((ssid_bytes, ssid_len)) = ssid {
        args.active = 1u32.to_le();
        args.ssidlen = (ssid_len as u32).to_le();
        let copy_len = ssid_len.min(32).min(ssid_bytes.len());
        args.ssid[..copy_len].copy_from_slice(&ssid_bytes[..copy_len]);
    }

    // SAFETY: H2cSiteSurvey is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SiteSurvey, unsafe { as_bytes(&args) })
}

/// Send a disconnect command to the firmware.
///
/// Mirrors `r92su_h2c_disconnect()`.
pub fn h2c_disconnect(dev: &mut R92suDevice) -> Result<()> {
    let args = H2cDisconnect { _rsvd: 0 };
    // SAFETY: H2cDisconnect is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::Disconnect, unsafe { as_bytes(&args) })
}

/// Send a join-BSS or create-BSS command.
///
/// `bss` is the BSS descriptor (excluding variable IEs).  `join = true` means
/// join an existing BSS; `join = false` creates an IBSS.  `ie` is optional
/// extra IE data appended after the fixed BSS struct.
///
/// Mirrors `r92su_h2c_connect()`.
pub fn h2c_connect(
    dev: &mut R92suDevice,
    bss: &mut H2cc2hBss,
    join: bool,
    ie: Option<&[u8]>,
) -> Result<()> {
    let bss_size = core::mem::size_of::<H2cc2hBss>();
    let ie_len = ie.map_or(0, |s| s.len());

    // The ie_length field also includes 12 fixed bytes (TSF/beacon/caps).
    bss.ie_length = (12u32 + ie_len as u32).to_le();

    // Payload = BSS struct + IE data (no extra trailing padding here; h2c_submit
    // will receive the exact padded buffer we build).
    let raw_len = bss_size + ie_len;
    let rest = H2CC2H_HDR_LEN - (raw_len % H2CC2H_HDR_LEN);
    let padded_len = raw_len + rest;

    let mut payload: KVec<u8> = KVec::from_elem(0u8, padded_len, GFP_KERNEL)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

    // SAFETY: H2cc2hBss is #[repr(C, packed)] with no pointer fields.
    payload[..bss_size].copy_from_slice(unsafe { as_bytes(bss) });
    if let Some(ie_bytes) = ie {
        payload[bss_size..bss_size + ie_len].copy_from_slice(ie_bytes);
    }

    // Record total payload length in the BSS length field.
    let total_payload_le = (raw_len as u32).to_le_bytes();
    payload[..4].copy_from_slice(&total_payload_le);

    let cmd = if join {
        FwH2cCmd::JoinBss
    } else {
        FwH2cCmd::CreateBss
    };
    h2c_submit(dev, &payload, cmd)
}

/// Install a group (broadcast/multicast) encryption key.
///
/// Mirrors `r92su_h2c_set_key()`.
pub fn h2c_set_key(
    dev: &mut R92suDevice,
    algo: EncAlg,
    key_id: u8,
    group_key: bool,
    keydata: &[u8],
) -> Result<()> {
    let key_len = ENC_ALG_KEY_LEN[algo as usize];
    if keydata.len() < key_len {
        return Err(crate::r92u::R92suError::Io("key data too short"));
    }

    let mut args = H2cKey {
        algorithm: algo as u8,
        key_id,
        group_key: group_key as u8,
        key: [0u8; 16],
    };
    args.key[..key_len].copy_from_slice(&keydata[..key_len]);

    // SAFETY: H2cKey is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetKey, unsafe { as_bytes(&args) })
}

/// Install a pairwise (station unicast) encryption key.
///
/// Mirrors `r92su_h2c_set_sta_key()`.
pub fn h2c_set_sta_key(
    dev: &mut R92suDevice,
    algo: EncAlg,
    mac_addr: &[u8; 6],
    keydata: &[u8],
) -> Result<()> {
    let key_len = ENC_ALG_KEY_LEN[algo as usize];
    if keydata.len() < key_len {
        return Err(crate::r92u::R92suError::Io("key data too short"));
    }

    let mut args = H2cStaKey {
        mac_addr: *mac_addr,
        algorithm: algo as u8,
        key: [0u8; 16],
    };
    args.key[..key_len].copy_from_slice(&keydata[..key_len]);

    // SAFETY: H2cStaKey is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetStaKey, unsafe { as_bytes(&args) })
}

/// Set authentication mode.
///
/// Mirrors `r92su_h2c_set_auth()`.
pub fn h2c_set_auth(dev: &mut R92suDevice, mode: AuthMode, auth_1x: Auth1x) -> Result<()> {
    let args = H2cAuth {
        mode: mode as u8,
        auth_1x: auth_1x as u8,
        _pad: [0; 2],
    };
    // SAFETY: H2cAuth is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetAuth, unsafe { as_bytes(&args) })
}

/// Request a BlockAck (A-MPDU) session for the given TID.
///
/// Mirrors `r92su_h2c_start_ba()`.
pub fn h2c_start_ba(dev: &mut R92suDevice, tid: u32) -> Result<()> {
    let args = H2cAddBaReq { tid: tid.to_le() };
    // SAFETY: H2cAddBaReq is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::AddBaReq, unsafe { as_bytes(&args) })
}

/// Set firmware power-save mode.
///
/// Mirrors `r92su_h2c_set_power_mode()`.
pub fn h2c_set_power_mode(dev: &mut R92suDevice, ps_mode: u8, smart_ps: u8) -> Result<()> {
    let args = H2cSetPowerMode {
        mode: ps_mode,
        flag_low_traffic_en: 0,
        flag_lpnav_en: 0,
        flag_rf_low_snr_en: 0,
        flag_dps_en: 0,
        bcn_rx_en: 0,
        bcn_pass_cnt: 0,
        bcn_to: 0,
        bcn_itv: 0u16.to_le(),
        app_itv: 0,
        awake_bcn_itv: 0,
        smart_ps,
        bcn_pass_time: 0,
    };
    // SAFETY: H2cSetPowerMode is #[repr(C, packed)] with no pointer fields.
    h2c_copy(dev, FwH2cCmd::SetPwrMode, unsafe { as_bytes(&args) })
}
