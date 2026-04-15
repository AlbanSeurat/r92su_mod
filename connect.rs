// SPDX-License-Identifier: GPL-2.0
//! connect - RTL8192SU cfg80211 connect/disconnect operations.
//!
//! Implements the `.connect` and `.disconnect` cfg80211 ops and the deferred
//! workqueue handler that reports join-BSS results back to cfg80211.
//!
//! # Connect flow
//!
//! 1. `connect_callback` (process context, called by cfg80211):
//!    - Extract SSID, BSSID, IEs from `cfg80211_connect_params`
//!    - Find the matching BSS in the last scan cache (`dev.add_bss_pending`)
//!    - Send `H2C_JOINBSS_CMD` via [`cmd::h2c_connect`]
//!
//! 2. Firmware sends `C2H_JOIN_BSS_EVENT` to host (USB completion, softirq)
//!    - [`event::c2h_join_bss_event`] stores the raw result in `dev.connect_result`
//!    - Calls [`schedule_join_result`] which schedules the work item
//!
//! 3. `join_result_process` (process context, workqueue):
//!    - Reads `dev.connect_result`
//!    - Calls `cfg80211_connect_result` to inform the wireless subsystem

use core::ffi::{c_int, c_void};
use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::cmd::{self, H2cc2hBss};
use crate::power_mgmt;
use crate::r92u::{R92suDevice, State};

// ── C helpers ─────────────────────────────────────────────────────────────────

extern "C" {
    fn rust_helper_set_cfg80211_ops_connect(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_disconnect(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, u16) -> c_int>,
    );

    fn rust_helper_cfg80211_connect_result(
        ndev: *mut c_void,
        wiphy: *mut c_void,
        bssid: *const u8,
        ssid: *const u8,
        ssid_len: usize,
        req_ie: *const u8,
        req_ie_len: usize,
        resp_ie: *const u8,
        resp_ie_len: usize,
        status: u16,
    );

    fn rust_helper_cfg80211_disconnected(ndev: *mut c_void, reason: u16);

    fn rust_helper_netif_carrier_on(ndev: *mut c_void);

    fn rust_helper_netif_tx_wake_all_queues(ndev: *mut c_void);

    fn rust_helper_schedule_join_result(dev_ptr: *mut c_void, fn_ptr: extern "C" fn(*mut c_void));

    fn rust_helper_cfg80211_connect_params_get(
        sme: *mut c_void,
        ssid_out: *mut u8,
        ssid_len_out: *mut usize,
        bssid_out: *mut u8,
        ie_out: *mut u8,
        ie_len_out: *mut usize,
        ie_buf_len: usize,
        auth_type_out: *mut u32,
        privacy_out: *mut u32,
        wpa_versions_out: *mut u32,
    ) -> c_int;

    fn rust_helper_get_netdev_ptr(wiphy: *mut c_void) -> *mut c_void;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// IEEE 802.11 element IDs
const WLAN_EID_HT_CAPABILITY: u8 = 45;
const WLAN_EID_VENDOR_SPECIFIC: u8 = 221;

/// WMM OUI (Microsoft)
const WMM_OUI: [u8; 3] = [0x00, 0x50, 0xf2];

/// Build HT capability IE for RTL8192SU.
///
/// Mirrors `r92su_ht_update()` from main.c.
/// Uses reasonable defaults for RTL8192SU (single stream, short GI, etc.)
fn build_ht_ie(_dev: &R92suDevice) -> Option<[u8; 26]> {
    // HT Capability IE:
    // Element ID (1) + Length (1) + HT Capability Info (2) + A-MPDU Params (1) + MCS Set (16)
    let mut ie = [0u8; 26];
    ie[0] = WLAN_EID_HT_CAPABILITY;
    ie[1] = 24; // Length

    // HT Capability Info (little-endian):
    // - LDPC coding capability
    // - Channel width 40 MHz supported
    // - GF (Greenfield) not supported
    // - Short GI for 20MHz and 40MHz
    // - Max AMSDU size 7935 bytes
    // - DSSS/CCK 40MHz support
    let cap_info: u16 = 0x018f; // HT-capable, 40MHz, short GI, max AMSDU
    ie[2] = (cap_info & 0xff) as u8;
    ie[3] = ((cap_info >> 8) & 0xff) as u8;

    // A-MPDU Parameters:
    // max A-MPDU length exponent = 1 (8K)
    // minimum A-MPDU start spacing = 0
    ie[4] = 0x01;

    // Supported MCS Set (16 bytes):
    // Rx MCS mask: 0xff (MCS 0-7, single stream)
    // Tx not defined, all 0
    ie[5] = 0xff; // MCS[0-7]
    ie[6] = 0x00; // MCS[8-15]

    // Rest of MCS set (bytes 7-15) and extended cap + beamforming = 0

    // RX HT Capabilities (4 bytes) - zero
    ie[22] = 0;
    ie[23] = 0;
    ie[24] = 0;
    ie[25] = 0;

    Some(ie)
}

/// Build WMM IE for QoS.
///
/// Mirrors `r92su_wmm_update()` from main.c.
fn build_wmm_ie() -> [u8; 9] {
    [
        0xDD, // Element ID = WLAN_EID_VENDOR_SPECIFIC
        0x07, // Length = 7
        0x00, 0x50, 0xf2, // Microsoft OUI
        0x02, // OUI Type = WMM
        0x00, // WMM Subtype = Information Element
        0x01, // WME Version
        0x00, // WME QoS Info
    ]
}

/// Find the first BSS in `add_bss_pending` whose BSSID matches `target_bssid`.
///
/// Returns the index into `add_bss_pending`, or `None` if no match.
fn find_bss_by_bssid(dev: &R92suDevice, target_bssid: &[u8; 6]) -> Option<usize> {
    const BSSID_OFFSET: usize = 4;
    for (i, bss_bytes) in dev.add_bss_pending.iter().enumerate() {
        if bss_bytes.len() >= BSSID_OFFSET + 6 {
            if &bss_bytes[BSSID_OFFSET..BSSID_OFFSET + 6] == target_bssid.as_ref() {
                return Some(i);
            }
        }
    }
    None
}

/// Find the first BSS in `add_bss_pending` whose SSID matches.
///
/// SSID is at offset 12 (ssid.length: u32) + offset 16 (ssid.ssid: [u8; 32]).
fn find_bss_by_ssid(dev: &R92suDevice, ssid: &[u8]) -> Option<usize> {
    const SSID_LEN_OFFSET: usize = 12;
    const SSID_BYTES_OFFSET: usize = 16;
    for (i, bss_bytes) in dev.add_bss_pending.iter().enumerate() {
        if bss_bytes.len() < SSID_BYTES_OFFSET + 32 {
            continue;
        }
        let stored_len = u32::from_le_bytes([
            bss_bytes[SSID_LEN_OFFSET],
            bss_bytes[SSID_LEN_OFFSET + 1],
            bss_bytes[SSID_LEN_OFFSET + 2],
            bss_bytes[SSID_LEN_OFFSET + 3],
        ]) as usize;
        let stored_len = stored_len.min(32);
        if stored_len == ssid.len()
            && &bss_bytes[SSID_BYTES_OFFSET..SSID_BYTES_OFFSET + stored_len] == ssid
        {
            return Some(i);
        }
    }
    None
}

// ── cfg80211 .connect ─────────────────────────────────────────────────────────

extern "C" fn connect_callback(wiphy: *mut c_void, _ndev: *mut c_void, sme: *mut c_void) -> c_int {
    // SAFETY: wiphy is a valid struct wiphy *; private area layout is [*mut R92suDevice][band].
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if dev_ptr.is_null() {
        pr_warn!("r92su: connect callback with null device pointer\n");
        return -19; // -ENODEV
    }
    // SAFETY: dev_ptr is valid for the USB interface lifetime.
    let dev = unsafe { &mut *dev_ptr };

    if !dev.is_open() {
        pr_err!("r92su: connect called but device is not open\n");
        return -5; // -EIO
    }

    // ── Extract connect parameters from cfg80211 ──────────────────────────────
    let mut ssid = [0u8; 32];
    let mut ssid_len: usize = 0;
    let mut bssid = [0u8; 6];
    let mut ie_buf = [0u8; 256];
    let mut ie_len: usize = 0;
    let mut auth_type: u32 = 0;
    let mut privacy: u32 = 0;
    let mut wpa_versions: u32 = 0;

    // SAFETY: sme is a valid cfg80211_connect_params * from cfg80211; output
    // buffers are valid for the sizes we pass.
    let ret = unsafe {
        rust_helper_cfg80211_connect_params_get(
            sme,
            ssid.as_mut_ptr(),
            &mut ssid_len,
            bssid.as_mut_ptr(),
            ie_buf.as_mut_ptr(),
            &mut ie_len,
            ie_buf.len(),
            &mut auth_type,
            &mut privacy,
            &mut wpa_versions,
        )
    };
    if ret != 0 {
        pr_err!("r92su: connect_params_get failed\n");
        return -22; // -EINVAL
    }

    // ── Send authentication mode to firmware ─────────────────────────────────
    // For WPA/WPA2 connections, we must tell the firmware we're using PSK.
    // Mirrors r92su_connect_set_auth() from main.c.
    let (auth_mode, auth_1x) = if wpa_versions > 0 {
        // WPA detected — use 802.1X auth mode with PSK key management
        (cmd::AuthMode::Auth8021x, cmd::Auth1x::Psk)
    } else if auth_type == 2 {
        // NL80211_AUTHTYPE_SHARED_KEY
        (cmd::AuthMode::Shared, cmd::Auth1x::Psk)
    } else {
        // Open system (or automatic without WPA)
        (cmd::AuthMode::Open, cmd::Auth1x::Psk)
    };
    if let Err(e) = cmd::h2c_set_auth(dev, auth_mode, auth_1x) {
        pr_warn!("r92su: connect: h2c_set_auth failed: {:?}\n", e);
    }

    // ── Locate the BSS in the scan cache ─────────────────────────────────────
    let bss_idx = if bssid != [0u8; 6] {
        find_bss_by_bssid(dev, &bssid).or_else(|| find_bss_by_ssid(dev, &ssid[..ssid_len]))
    } else {
        find_bss_by_ssid(dev, &ssid[..ssid_len])
    };

    let bss_idx = match bss_idx {
        Some(i) => i,
        None => {
            pr_err!(
                "r92su: connect: BSS not found in scan cache (ssid_len={})\n",
                ssid_len
            );
            return -2; // -ENOENT
        }
    };

    // ── Prepare state ─────────────────────────────────────────────────────────
    // Store the BSSID, SSID, and request IEs for the join result callback.
    dev.bssid = bssid;
    dev.connect_ssid = ssid;
    dev.connect_ssid_len = ssid_len;
    dev.connect_result = None;

    let _ = dev.connect_req_ie.clear();
    if ie_len > 0 {
        // Ignore OOM here — req_ie is informational only.
        let _ = dev
            .connect_req_ie
            .extend_from_slice(&ie_buf[..ie_len], GFP_ATOMIC);
    }

    // ── Build IEs with HT and WMM injection ───────────────────────────────────
    // Inject HT and WMM IEs into the association request.
    // Mirrors r92su_ht_update() and r92su_wmm_update() from main.c.
    let mut combined_ie = [0u8; 512];
    let mut combined_len = 0usize;

    // Copy existing IEs from cfg80211
    if ie_len > 0 {
        let copy_len = (ie_len).min(512);
        combined_ie[..copy_len].copy_from_slice(&ie_buf[..copy_len]);
        combined_len = copy_len;
    }

    // Inject WMM IE first (vendor-specific, 8 bytes)
    let wmm_ie = build_wmm_ie();
    if combined_len + wmm_ie.len() < 512 {
        combined_ie[combined_len..combined_len + wmm_ie.len()].copy_from_slice(&wmm_ie);
        combined_len += wmm_ie.len();
    }

    // Inject HT Capability IE (26 bytes)
    if let Some(ht_ie) = build_ht_ie(dev) {
        if combined_len + ht_ie.len() < 512 {
            combined_ie[combined_len..combined_len + ht_ie.len()].copy_from_slice(&ht_ie);
            combined_len += ht_ie.len();
        }
    }

    let ie_opt: Option<&[u8]> = if combined_len > 0 {
        Some(&combined_ie[..combined_len])
    } else {
        None
    };

    // ── Send H2C_JOINBSS_CMD ──────────────────────────────────────────────────
    // Reinterpret the raw BSS bytes as H2cc2hBss.
    //
    // SAFETY: bss_bytes were populated by the firmware Survey event and have the
    // same layout as H2cc2hBss (#[repr(C, packed)]).  We read an unaligned copy.
    let bss_bytes = &dev.add_bss_pending[bss_idx];
    let bss_struct_size = core::mem::size_of::<H2cc2hBss>();
    if bss_bytes.len() < bss_struct_size {
        pr_err!(
            "r92su: BSS data too short ({} < {})\n",
            bss_bytes.len(),
            bss_struct_size
        );
        return -22; // -EINVAL
    }
    let mut bss: H2cc2hBss =
        unsafe { core::ptr::read_unaligned(bss_bytes.as_ptr() as *const H2cc2hBss) };

    match cmd::h2c_connect(dev, &mut bss, true, ie_opt) {
        Ok(()) => {
            pr_info!(
                "r92su: H2C_JOINBSS_CMD sent (ssid_len={} privacy={})\n",
                ssid_len,
                privacy
            );
            0
        }
        Err(e) => {
            pr_err!("r92su: h2c_connect failed: {:?}\n", e);
            -5 // -EIO
        }
    }
}

// ── cfg80211 .disconnect ──────────────────────────────────────────────────────

extern "C" fn disconnect_callback(wiphy: *mut c_void, ndev: *mut c_void, reason: u16) -> c_int {
    // SAFETY: wiphy is a valid struct wiphy *.
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if dev_ptr.is_null() {
        return -19; // -ENODEV
    }
    // SAFETY: dev_ptr is valid for the USB interface lifetime.
    let dev = unsafe { &mut *dev_ptr };

    pr_info!("r92su: disconnect callback reason={}\n", reason);

    let _ = cmd::h2c_disconnect(dev);
    dev.set_state(State::Open);
    dev.connect_result = None;
    // Remove the AP station entry (mac_id 0) that was added on join.
    dev.sta_del(0);
    dev.bssid = [0u8; 6];
    dev.connect_ssid = [0u8; 32];
    dev.connect_ssid_len = 0;
    let _ = dev.connect_req_ie.clear();

    // Notify cfg80211 that we have disconnected.
    // SAFETY: ndev is the net_device passed by cfg80211; it is valid here.
    unsafe { rust_helper_cfg80211_disconnected(ndev, reason) };
    0
}

// ── Join-result workqueue handler ─────────────────────────────────────────────

/// Process the stored join-BSS result and report it to cfg80211.
///
/// Invoked from a kernel workqueue (process context) after `schedule_join_result`
/// is called from the softirq RX path.
extern "C" fn join_result_process(dev_ptr: *mut c_void) {
    if dev_ptr.is_null() {
        return;
    }
    // SAFETY: dev_ptr was stored during device allocation and is valid for the
    // USB interface lifetime.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };

    // Retrieve the net_device and wiphy pointers.
    let wiphy_ptr = match dev.wiphy.as_ref() {
        Some(w) => w.as_ptr(),
        None => {
            pr_warn!("r92su: join result process with no wiphy\n");
            return;
        }
    };
    // SAFETY: wiphy is valid; the helper iterates wdev_list which is
    // protected by the RTNL lock inside cfg80211.
    let ndev = unsafe { rust_helper_get_netdev_ptr(wiphy_ptr) };
    if ndev.is_null() {
        pr_warn!("r92su: join result process with no netdev\n");
        return;
    }

    // The connect_result buffer contains a raw `c2h_join_bss_event`:
    //   offset  0: head        (u32)
    //   offset  4: tail        (u32)
    //   offset  8: network_type (u32)
    //   offset 12: fixed       (u32)
    //   offset 16: last_scanned (u32)
    //   offset 20: aid         (u32)
    //   offset 24: join_result (u32) — nonzero means firmware joined successfully
    //   offset 28: h2cc2h_bss  — BSSID is at +4 within the bss struct, i.e. offset 32
    const C2H_JOIN_BSS_HDR_LEN: usize = 28;
    const BSSID_IN_BSS_OFFSET: usize = 4;
    const BSSID_FIELD_OFFSET: usize = C2H_JOIN_BSS_HDR_LEN + BSSID_IN_BSS_OFFSET; // 32
    let bssid = match dev.connect_result.as_ref() {
        Some(r) if r.len() >= BSSID_FIELD_OFFSET + 6 => {
            let mut b = [0u8; 6];
            b.copy_from_slice(&r[BSSID_FIELD_OFFSET..BSSID_FIELD_OFFSET + 6]);
            b
        }
        _ => dev.bssid,
    };

    let (req_ie_ptr, req_ie_len) = if dev.connect_req_ie.is_empty() {
        (core::ptr::null(), 0usize)
    } else {
        (dev.connect_req_ie.as_ptr(), dev.connect_req_ie.len())
    };

    // Variable IEs in the join-BSS payload start at:
    //   c2h_join_bss_event header (28) + h2cc2h_bss fixed part (128) = 156.
    const VARIABLE_IES_OFFSET: usize = C2H_JOIN_BSS_HDR_LEN + 128; // 156
    let (resp_ie_ptr, resp_ie_len) = match dev.connect_result.as_ref() {
        Some(r) if r.len() > VARIABLE_IES_OFFSET => (
            // SAFETY: r is a valid KVec with len > VARIABLE_IES_OFFSET.
            unsafe { r.as_ptr().add(VARIABLE_IES_OFFSET) },
            r.len() - VARIABLE_IES_OFFSET,
        ),
        _ => (core::ptr::null(), 0usize),
    };

    // Check join_result at offset 24 of c2h_join_bss_event.  The field is
    // nonzero when the firmware successfully joined the BSS.
    const JOIN_RESULT_OFFSET: usize = 24;
    let firmware_joined = match dev.connect_result.as_ref() {
        Some(r) if r.len() >= JOIN_RESULT_OFFSET + 4 => {
            u32::from_le_bytes([
                r[JOIN_RESULT_OFFSET],
                r[JOIN_RESULT_OFFSET + 1],
                r[JOIN_RESULT_OFFSET + 2],
                r[JOIN_RESULT_OFFSET + 3],
            ]) != 0
        }
        _ => false,
    };

    let status: u16 = if firmware_joined {
        dev.set_state(State::Connected);

        // Update dev.bssid with the firmware-confirmed BSSID so that
        // tx_from_ethernet uses the real AP address (Addr1) in every TX frame.
        // Without this, connections initiated by SSID (without an explicit BSSID)
        // leave dev.bssid as all-zeros, causing the AP to discard all TX frames.
        dev.bssid = bssid;

        // The AP is station 0 in the RTL8192SU firmware.  Register it in the
        // station table so that add_key can find it when the pairwise PTK is
        // installed during the 4-way handshake.
        // AID is at offset 20 in the c2h_join_bss_event payload.
        const AID_OFFSET: usize = 20;
        let aid = match dev.connect_result.as_ref() {
            Some(r) if r.len() >= AID_OFFSET + 4 => u32::from_le_bytes([
                r[AID_OFFSET],
                r[AID_OFFSET + 1],
                r[AID_OFFSET + 2],
                r[AID_OFFSET + 3],
            ]) as usize,
            _ => 0,
        };
        dev.assoc_id = aid as u16;
        power_mgmt::set_assoc_id(dev, aid as u16);

        if let Err(e) = dev.sta_alloc(&bssid, 0, aid) {
            pr_warn!("r92su: join_result: could not alloc AP station: {:?}\n", e);
        }

        if let Err(e) = cmd::h2c_set_power_mode(dev, 1, 0) {
            pr_warn!("r92su: failed to set power mode: {:?}\n", e);
        }
        // Signal carrier up and start TX queues so the EAPOL 4-way
        // handshake frames can flow in both directions.
        // SAFETY: ndev is valid for the duration of this call.
        unsafe {
            rust_helper_netif_carrier_on(ndev);
            rust_helper_netif_tx_wake_all_queues(ndev);
        }
        pr_info!("r92su: join BSS succeeded — reporting connected\n");
        0 // WLAN_STATUS_SUCCESS
    } else {
        pr_warn!("r92su: join BSS failed — reporting failure\n");
        1 // WLAN_STATUS_UNSPECIFIED_FAILURE
    };

    let ssid_ptr = if dev.connect_ssid_len > 0 {
        dev.connect_ssid.as_ptr()
    } else {
        core::ptr::null()
    };

    // SAFETY: ndev and wiphy are valid; bssid/ssid/ie pointers are valid for this
    // call's duration (bssid and ssid are on-stack / in-dev; IEs reference KVec data).
    unsafe {
        rust_helper_cfg80211_connect_result(
            ndev,
            wiphy_ptr,
            bssid.as_ptr(),
            ssid_ptr,
            dev.connect_ssid_len,
            req_ie_ptr,
            req_ie_len,
            resp_ie_ptr,
            resp_ie_len,
            status,
        );
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Schedule `join_result_process` to run in a kernel workqueue.
///
/// Called from `c2h_join_bss_event` in softirq context after storing the raw
/// join-BSS payload in `dev.connect_result`.
pub fn schedule_join_result(dev: &mut R92suDevice) {
    let dev_ptr = dev as *mut R92suDevice as *mut c_void;
    // SAFETY: join_result_process is a valid extern "C" function pointer.
    unsafe { rust_helper_schedule_join_result(dev_ptr, join_result_process) };
}

/// Initialise the connect subsystem and register callbacks with cfg80211.
pub fn init() {
    // SAFETY: connect_callback and disconnect_callback are valid extern "C" fns.
    unsafe {
        rust_helper_set_cfg80211_ops_connect(Some(connect_callback));
        rust_helper_set_cfg80211_ops_disconnect(Some(disconnect_callback));
    }
    pr_info!("r92su: connect subsystem initialized\n");
}
