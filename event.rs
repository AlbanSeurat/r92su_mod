// SPDX-License-Identifier: GPL-2.0
//! event - RTL8192SU C2H (Chip-to-Host) firmware event dispatch.
//!
//! Mirrors `r92su/event.c` from the C reference driver. The firmware sends
//! asynchronous events back to the host by prepending an 8-byte C2H header to
//! inbound USB packets. This module parses the header, checks the sequence
//! counter, and dispatches to per-event handlers.
//!
//! Entry point: [`r92su_c2h_event`].

use kernel::prelude::*;

use crate::connect;
use crate::r92u::{R92suDevice, State};
use crate::scan;
use crate::sta; //

// ── Constants ─────────────────────────────────────────────────────────────────

/// Size of the C2H header (struct h2cc2h in def.h).
pub const C2H_HDR_LEN: usize = 8;

/// Frame Check Sequence length stripped from survey BSS payloads.
const FCS_LEN: usize = 4;

/// NL80211_IFTYPE_STATION — numeric value used to check `dev.iftype`.
const NL80211_IFTYPE_STATION: u32 = 2;

/// Power-state toggle bit (PS_TOG = BIT(7) in h2cc2h.h).
const PS_TOG: u8 = 0x80;

/// Power-state field mask (bits 0–4 of the CPWM byte).
const PS_STATE_MASK: u8 = 0x17;

// ── C2H header ────────────────────────────────────────────────────────────────

/// Parsed representation of the 8-byte `struct h2cc2h` header.
///
/// The firmware places this at the start of every C2H event packet (i.e.
/// immediately after the 24-byte RX descriptor).  All multi-byte fields are
/// little-endian.
#[derive(Clone, Copy)]
pub struct C2hHdr {
    /// Length in bytes of the payload that follows (i.e. `data[]`).
    pub len: u16,
    /// Event type — one of [`FwC2hEvent`].
    pub event: u8,
    /// Sequence number sent by the firmware (mirrors `h2cc2h->cmd_seq`).
    pub cmd_seq: u8,
    /// Aggregation count (unused in current handlers).
    pub agg_num: u8,
    pub _unkn: u8,
    /// Total length including all aggregated events.
    pub agg_total_len: u16,
}

impl C2hHdr {
    /// Parse a C2H header from the first [`C2H_HDR_LEN`] bytes of `data`.
    ///
    /// Returns `None` if `data` is too short.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < C2H_HDR_LEN {
            return None;
        }
        Some(Self {
            len: u16::from_le_bytes([data[0], data[1]]),
            event: data[2],
            cmd_seq: data[3],
            agg_num: data[4],
            _unkn: data[5],
            agg_total_len: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

// ── FwC2hEvent ────────────────────────────────────────────────────────────────

/// Firmware C2H event codes (`enum fw_c2h_event` in h2cc2h.h).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FwC2hEvent {
    ReadMacReg = 0,
    ReadBb = 1,
    ReadRf = 2,
    ReadEeprom = 3,
    ReadEfuse = 4,
    ReadCam = 5,
    GetBasicRate = 6,
    GetDataRate = 7,
    Survey = 8,
    SurveyDone = 9,
    JoinBss = 10,
    AddSta = 11,
    DelSta = 12,
    AtimDone = 13,
    TxReport = 14,
    CcxReport = 15,
    DtmReport = 16,
    TxRateStats = 17,
    C2hLbk = 18,
    FwDbg = 19,
    C2hFeedback = 20,
    AddBa = 21,
    Hbcn = 22,
    ReportPwrState = 23,
    WpsPbc = 24,
    AddBaReport = 25,
}

impl FwC2hEvent {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ReadMacReg),
            1 => Some(Self::ReadBb),
            2 => Some(Self::ReadRf),
            3 => Some(Self::ReadEeprom),
            4 => Some(Self::ReadEfuse),
            5 => Some(Self::ReadCam),
            6 => Some(Self::GetBasicRate),
            7 => Some(Self::GetDataRate),
            8 => Some(Self::Survey),
            9 => Some(Self::SurveyDone),
            10 => Some(Self::JoinBss),
            11 => Some(Self::AddSta),
            12 => Some(Self::DelSta),
            13 => Some(Self::AtimDone),
            14 => Some(Self::TxReport),
            15 => Some(Self::CcxReport),
            16 => Some(Self::DtmReport),
            17 => Some(Self::TxRateStats),
            18 => Some(Self::C2hLbk),
            19 => Some(Self::FwDbg),
            20 => Some(Self::C2hFeedback),
            21 => Some(Self::AddBa),
            22 => Some(Self::Hbcn),
            23 => Some(Self::ReportPwrState),
            24 => Some(Self::WpsPbc),
            25 => Some(Self::AddBaReport),
            _ => None,
        }
    }
}

// ── C2H payload structures ────────────────────────────────────────────────────
//
// All structs are `#[repr(C, packed)]` and mirror the C counterparts in
// h2cc2h.h.  Size assertions guard against layout drift.

/// Payload for `C2H_SURVEY_DONE_EVENT` (`struct c2h_survery_done_event`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct C2hSurveyDone {
    bss_cnt: u32,
}
const _: () = assert!(core::mem::size_of::<C2hSurveyDone>() == 4);

/// Payload for `C2H_ADD_STA_EVENT` (`struct c2h_add_sta_event`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct C2hAddSta {
    mac_addr: [u8; 6],
    _padding: [u8; 2],
    aid: u32,
}
const _: () = assert!(core::mem::size_of::<C2hAddSta>() == 12);

/// Payload for `C2H_DEL_STA_EVENT` (`struct c2h_del_sta_event`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct C2hDelSta {
    mac_addr: [u8; 6],
    _padding: [u8; 2],
}
const _: () = assert!(core::mem::size_of::<C2hDelSta>() == 8);

/// Payload for `C2H_ADDBA_REPORT_EVENT` (`struct c2h_add_ba_event`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct C2hAddBa {
    mac_addr: [u8; 6],
    ssn: u16,
    tid: u8,
}
const _: () = assert!(core::mem::size_of::<C2hAddBa>() == 9);

/// Payload for `C2H_REPORT_PWR_STATE_EVENT` (`struct c2h_pwr_state_event`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct C2hPwrState {
    mode: u8,
    state: u8,
    _rsvd: u16,
}
const _: () = assert!(core::mem::size_of::<C2hPwrState>() == 4);

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Attempt to read a packed C2H payload struct from the start of `data`.
///
/// Returns a copy of the struct, or `None` if `data` is too short.
///
/// # Safety
///
/// `T` must be `#[repr(C, packed)]` with no padding bytes that would result in
/// undefined behaviour when read from an arbitrary byte slice.
unsafe fn parse_payload<T: Copy>(data: &[u8]) -> Option<T> {
    let sz = core::mem::size_of::<T>();
    if data.len() < sz {
        return None;
    }
    // SAFETY: `data` is at least `sz` bytes; `T` is packed so any alignment
    // is valid; the region pointed to is valid for `sz` bytes of read.
    Some(unsafe { core::ptr::read_unaligned(data.as_ptr() as *const T) })
}

// ── Per-event handlers ────────────────────────────────────────────────────────

fn c2h_fwdbg_event(payload: &[u8]) {
    if !payload.is_empty() {
        // Log up to 64 bytes of the firmware debug string.
        let len = payload.len().min(64);
        pr_debug!("r92su fwdbg: {} bytes\n", len);
    }
}

fn c2h_survey_event(dev: &mut R92suDevice, payload: &[u8], raw_len: u16) {
    // The payload begins with an `h2cc2h_bss` structure (ndis_wlan_bssid_ex).
    // sizeof(h2cc2h_bss) is larger than we need to inspect here — we just
    // store the raw bytes (minus the trailing FCS) so the cfg80211 ops layer
    // can call cfg80211_inform_bss() when the scan completes.

    let data_len = raw_len as usize;
    if data_len <= FCS_LEN || payload.len() < data_len {
        pr_err!("r92su: survey event with bad length {}\n", data_len);
        return;
    }
    let bss_bytes = &payload[..data_len - FCS_LEN];

    // Store the raw BSS blob for later delivery to cfg80211.
    let mut entry: KVec<u8> = KVec::new();
    if entry.extend_from_slice(bss_bytes, GFP_ATOMIC).is_err() {
        pr_warn!("r92su: could not allocate BSS entry (OOM)\n");
        return;
    }
    if dev.add_bss_pending.push(entry, GFP_ATOMIC).is_err() {
        pr_warn!("r92su: could not queue BSS entry (OOM)\n");
    }
}

fn c2h_survey_done_event(dev: &mut R92suDevice) {
    pr_debug!("r92su: SurveyDone event received from firmware\n");
    if !dev.is_open() {
        pr_debug!("r92su: SurveyDone ignored, device not open\n");
        return;
    }
    dev.scan_done = true;
    pr_debug!("r92su: survey done, invoking complete_scan\n");

    // Complete the cfg80211 scan.
    scan::complete_scan(dev);
}

fn c2h_join_bss_event(dev: &mut R92suDevice, payload: &[u8], raw_len: u16) {
    if dev.connect_result.is_some() {
        // Already have a pending result — ignore duplicate.
        return;
    }
    let copy_len = (raw_len as usize).min(payload.len());
    let mut v: KVec<u8> = KVec::new();
    if v.extend_from_slice(&payload[..copy_len], GFP_ATOMIC)
        .is_err()
    {
        pr_warn!("r92su: could not store connect result (OOM)\n");
        return;
    }
    dev.connect_result = Some(v);
    pr_debug!("r92su: join BSS result stored ({} bytes)\n", copy_len);

    // Schedule process-context delivery to cfg80211.  cfg80211_connect_result
    // must not be called from softirq context, so we defer via a workqueue.
    connect::schedule_join_result(dev);
}

fn c2h_add_sta_event(dev: &mut R92suDevice, payload: &[u8]) {
    // SAFETY: C2hAddSta is repr(C, packed) with no padding hazards.
    let ev = match unsafe { parse_payload::<C2hAddSta>(payload) } {
        Some(e) => e,
        None => {
            pr_err!("r92su: add_sta event too short\n");
            return;
        }
    };
    let aid = u32::from_le(ev.aid) as usize;
    // mac_id == aid for peer stations in the firmware model.
    if let Err(_) = dev.sta_alloc(&ev.mac_addr, aid, aid) {
        pr_err!("r92su: failed to alloc station {}\n", aid);
    }
}

fn c2h_del_sta_event(dev: &mut R92suDevice, payload: &[u8]) {
    // SAFETY: C2hDelSta is repr(C, packed) with no padding hazards.
    let ev = match unsafe { parse_payload::<C2hDelSta>(payload) } {
        Some(e) => e,
        None => {
            pr_err!("r92su: del_sta event too short\n");
            return;
        }
    };

    if dev.iftype == NL80211_IFTYPE_STATION {
        // In STA mode the "del sta" event means we've been disconnected.
        dev.connect_result = None;
        dev.connect_req_ie.clear();
        dev.scan_done = false;
        pr_debug!("r92su: disconnected from BSS\n");
    } else {
        // AP/IBSS mode: remove the station from the table.
        if let Some(sta) = dev.sta_by_mac(&ev.mac_addr) {
            let mac_id = sta.mac_id;
            dev.sta_del(mac_id);
        }
    }
}

fn c2h_report_pwr_state_event(dev: &mut R92suDevice, payload: &[u8]) {
    // SAFETY: C2hPwrState is repr(C, packed) with no padding hazards.
    let ev = match unsafe { parse_payload::<C2hPwrState>(payload) } {
        Some(e) => e,
        None => {
            pr_err!("r92su: pwr_state event too short\n");
            return;
        }
    };

    let cpwm_tog = ev.state & PS_TOG;

    if dev.cpwm_tog == cpwm_tog {
        pr_err!(
            "r92su: firmware stuck, CPWM not updated (stuck at {:#x})\n",
            cpwm_tog
        );
    }

    dev.cpwm = ev.state & PS_STATE_MASK;
    dev.cpwm_tog = cpwm_tog;
}

fn c2h_addba_report_event(dev: &mut R92suDevice, payload: &[u8]) {
    // SAFETY: C2hAddBa is repr(C, packed) with no padding hazards.
    let ev = match unsafe { parse_payload::<C2hAddBa>(payload) } {
        Some(e) => e,
        None => {
            pr_err!("r92su: addba_report event too short\n");
            return;
        }
    };
    let ssn = u16::from_le(ev.ssn);

    if let Some(sta) = dev.sta_by_mac_mut(&ev.mac_addr) {
        sta::sta_alloc_tid(sta, ev.tid, ssn);
    }
}

// ── Public dispatch ────────────────────────────────────────────────────────────

/// Dispatch a firmware C2H event received from the RX path.
///
/// `data` must be the raw bytes of the event starting at the C2H header
/// (i.e. 8-byte `struct h2cc2h` followed by the payload).  The RX descriptor
/// bytes should already have been stripped before calling this function.
///
/// Mirrors `r92su_c2h_event()` in `event.c`.
pub fn r92su_c2h_event(dev: &mut R92suDevice, data: &[u8]) {
    let hdr = match C2hHdr::parse(data) {
        Some(h) => h,
        None => {
            pr_err!("r92su: c2h event too short ({} bytes)\n", data.len());
            return;
        }
    };

    // Sequence check — mirrors the C driver's sequence tracking.
    if dev.c2h_seq != hdr.cmd_seq {
        pr_debug!(
            "r92su: c2h out of sequence: expected {}, got {}\n",
            dev.c2h_seq,
            hdr.cmd_seq
        );
        dev.c2h_seq = hdr.cmd_seq.wrapping_add(1);
    } else {
        dev.c2h_seq = dev.c2h_seq.wrapping_add(1);
    }

    let payload = &data[C2H_HDR_LEN..];

    pr_debug!("r92su: c2h event={:#x} len={}\n", hdr.event, hdr.len);

    let event = match FwC2hEvent::from_u8(hdr.event) {
        Some(e) => e,
        None => {
            pr_err!("r92su: unknown c2h event {:#x}\n", hdr.event);
            dev.set_state(State::Dead);
            return;
        }
    };

    match event {
        FwC2hEvent::FwDbg => c2h_fwdbg_event(payload),
        FwC2hEvent::Survey => c2h_survey_event(dev, payload, hdr.len),
        FwC2hEvent::SurveyDone => c2h_survey_done_event(dev),
        FwC2hEvent::JoinBss => c2h_join_bss_event(dev, payload, hdr.len),
        FwC2hEvent::AddSta => c2h_add_sta_event(dev, payload),
        FwC2hEvent::DelSta => c2h_del_sta_event(dev, payload),
        FwC2hEvent::AtimDone => { /* no-op */ }
        FwC2hEvent::ReportPwrState => c2h_report_pwr_state_event(dev, payload),
        FwC2hEvent::WpsPbc => { /* no-op */ }
        FwC2hEvent::AddBaReport => c2h_addba_report_event(dev, payload),
        _ => {
            // Silently ignore read-register echoes and other unhandled events.
            pr_debug!("r92su: unhandled c2h event {:?}\n", event);
        }
    }
}
