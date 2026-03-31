// SPDX-License-Identifier: GPL-2.0
//! Scan implementation - cfg80211 scan operations.

use core::ffi::{c_int, c_void};

use kernel::bindings;
use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::cmd;
use crate::r92u::R92suDevice;

extern "C" {
    fn rust_helper_set_cfg80211_ops_scan(
        scan_fn: Option<extern "C" fn(wiphy: *mut c_void, request: *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_abort_scan(
        abort_fn: Option<extern "C" fn(wiphy: *mut c_void, wdev: *mut c_void)>,
    );

    fn rust_helper_cfg80211_scan_done(request: *mut c_void, aborted: bool);

    fn rust_helper_cfg80211_inform_bss_data(
        wiphy: *mut c_void,
        channel: *mut c_void,
        bssid: *const u8,
        tsf: u64,
        capability: u16,
        beacon_interval: u16,
        ie: *const u8,
        ielen: usize,
        gfp: i32,
    ) -> *mut c_void;

    fn rust_helper_cfg80211_put_bss(wiphy: *mut c_void, bss: *mut c_void);

    fn rust_helper_ieee80211_channel_to_frequency(chan: c_int, band: c_int) -> c_int;

    fn rust_helper_wiphy_get_channel(wiphy: *mut c_void, ch_num: u8) -> *mut c_void;
}

const GFP_KERNEL_FAILBACK: i32 = 0x20;

// The current pending scan request, used to complete the scan.
static mut PENDING_SCAN_REQUEST: *mut c_void = core::ptr::null_mut();

extern "C" fn scan_callback(wiphy: *mut c_void, request: *mut c_void) -> c_int {
    pr_info!(
        "r92su: scan_callback entered (wiphy={:p} request={:p})\n",
        wiphy,
        request
    );

    // Recover the device pointer from the first slot of the wiphy private area.
    // The private area layout is: [*mut R92suDevice][ieee80211_supported_band].
    // wiphy_priv() itself is never null for a valid wiphy; we must check the
    // stored value (the device pointer written by r92su_alloc).
    // SAFETY: wiphy is a valid struct wiphy *; the private area is at least
    // sizeof(void*) bytes and was written during device allocation.
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if dev_ptr.is_null() {
        pr_warn!("r92su: scan callback with null device pointer\n");
        return -1;
    }

    // SAFETY: dev_ptr was written during KBox allocation and is valid for the
    // lifetime of the USB interface.
    let dev: &mut R92suDevice = unsafe { &mut *dev_ptr };

    // Store the request pointer so we can complete it later.
    // SAFETY: This is set in the scan callback, cleared when scan completes.
    unsafe {
        PENDING_SCAN_REQUEST = request;
    }

    // Clear any previous BSS data.
    dev.add_bss_pending.clear();
    dev.scan_done = false;

    // Parse SSID from scan request if provided.
    // The scan_request struct contains:
    //   n_ssids: number of SSIDs to scan
    //   ssids: array of {ssid, ssid_len}
    // For now, do a broadcast scan (ssid = None).
    let ssid = None;

    pr_info!("r92su: sending h2c_survey to firmware\n");

    // Send the survey command to firmware.
    // SAFETY: dev is valid and h2c_survey writes H2C commands to USB.
    match cmd::h2c_survey(dev, ssid) {
        Ok(()) => {
            pr_info!("r92su: h2c_survey sent, waiting for SurveyDone event\n");
            0
        }
        Err(e) => {
            pr_err!("r92su: failed to start scan: {:?}\n", e);
            unsafe {
                PENDING_SCAN_REQUEST = core::ptr::null_mut();
            }
            -1
        }
    }
}

extern "C" fn abort_scan_callback(wiphy: *mut c_void, _wdev: *mut c_void) {
    pr_info!("r92su: abort scan callback invoked\n");

    // Recover the device pointer from the wiphy private area (see scan_callback).
    // SAFETY: same invariants as scan_callback.
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if !dev_ptr.is_null() {
        // SAFETY: dev_ptr is valid for the lifetime of the USB interface.
        let dev: &mut R92suDevice = unsafe { &mut *dev_ptr };
        dev.scan_done = false;
    }

    // Clear the pending request.
    // SAFETY: We own this pointer and are now aborting the scan.
    unsafe {
        if !PENDING_SCAN_REQUEST.is_null() {
            rust_helper_cfg80211_scan_done(PENDING_SCAN_REQUEST, true);
            PENDING_SCAN_REQUEST = core::ptr::null_mut();
        }
    }
}

/// Complete a pending scan with the results from firmware.
///
/// Called when firmware reports `SurveyDone` event.
pub fn complete_scan(dev: &mut R92suDevice) {
    pr_info!("r92su: complete_scan entered\n");

    // SAFETY: Checked for null below.
    let request = unsafe { PENDING_SCAN_REQUEST };
    if request.is_null() {
        pr_info!("r92su: complete_scan called but no pending request\n");
        return;
    }

    // Get the wiphy from the device.
    let wiphy = match &dev.wiphy {
        Some(w) => w.as_ptr(),
        None => {
            pr_warn!("r92su: complete_scan with no wiphy\n");
            return;
        }
    };

    // Process all BSS entries from firmware.
    let bss_count = dev.add_bss_pending.len();
    pr_info!("r92su: reporting {} BSS entries to cfg80211\n", bss_count);
    for bss_data in dev.add_bss_pending.iter() {
        // Display the SSID for each BSS entry before reporting to cfg80211.
        // h2cc2h_bss layout: length(4) + bssid(6) + padding(2) + ssid_len(4) + ssid(32).
        // ssid_len is at offset 12, ssid bytes are at offset 16.
        const SSID_LEN_OFFSET: usize = 12;
        const SSID_BYTES_OFFSET: usize = 16;
        const MAX_SSID_LEN: usize = 32;
        if bss_data.len() >= SSID_BYTES_OFFSET + MAX_SSID_LEN {
            let ssid_len = u32::from_le_bytes([
                bss_data[SSID_LEN_OFFSET],
                bss_data[SSID_LEN_OFFSET + 1],
                bss_data[SSID_LEN_OFFSET + 2],
                bss_data[SSID_LEN_OFFSET + 3],
            ]) as usize;
            let ssid_len = ssid_len.min(MAX_SSID_LEN);
            let ssid_bytes = &bss_data[SSID_BYTES_OFFSET..SSID_BYTES_OFFSET + ssid_len];
            // Print as hex bytes; cfg80211/iw will decode the UTF-8/ASCII.
            pr_info!(
                "r92su: BSS SSID ({} bytes): {:02x?}\n",
                ssid_len,
                ssid_bytes
            );
        }
        inform_bss(wiphy, bss_data);
    }

    // Keep add_bss_pending intact so the connect callback can look up the BSS.
    // It is cleared at the start of the next scan (in scan_callback).

    pr_info!(
        "r92su: calling cfg80211_scan_done (request={:p})\n",
        request
    );

    // Notify cfg80211 that scan is complete.
    // SAFETY: request was saved from the scan callback and is valid here.
    unsafe {
        rust_helper_cfg80211_scan_done(request, false);
        PENDING_SCAN_REQUEST = core::ptr::null_mut();
    }

    dev.scan_done = false;
    pr_info!("r92su: scan completed\n");
}

/// Inform cfg80211 about a discovered BSS.
///
/// `bss_data` contains the raw bytes from the firmware survey event.
fn inform_bss(wiphy: *mut c_void, bss_data: &[u8]) {
    if bss_data.len() < 64 {
        pr_warn!("r92su: BSS data too short: {}\n", bss_data.len());
        return;
    }

    // Parse the BSS structure (mirrors H2cc2hBss / ndis_wlan_bssid_ex).
    // Key offsets (all little-endian u32 unless noted):
    //   0:   length (total struct + variable IEs)
    //   4:   bssid  [u8; 6]
    //   12:  ssid.length (u32)
    //   16:  ssid.ssid   [u8; 32]
    //   52:  rssi
    //   72:  config.frequency (channel number, 1-14)
    //   112: ie_length (= sizeof(H2cFixedIes) + variable IE bytes)
    //   116: H2cFixedIes { timestamp(8), beacon_int(2), caps(2) }
    //   128: variable IEs (802.11 TLV format, excluding SSID which is above)

    let bssid_offset = 4;
    let ssid_len_offset = 12;
    let ssid_bytes_offset = 16;
    let rssi_offset = 52;
    let ie_length_offset = 112;
    // config.frequency is at offset 72 (after length/beacon_period/atim_window at 60/64/68).
    let freq_offset = 72;

    // SAFETY: We check bounds before accessing offsets.
    let bssid_ptr = unsafe { bss_data.as_ptr().add(bssid_offset) };
    let rssi = u32::from_le_bytes([
        bss_data[rssi_offset],
        bss_data[rssi_offset + 1],
        bss_data[rssi_offset + 2],
        bss_data[rssi_offset + 3],
    ]);

    // Get ie_length (includes H2cFixedIes = 12 bytes, so subtract to get variable IE len)
    const FIXED_IES_SIZE: usize = 12;
    let ie_length = if bss_data.len() > ie_length_offset {
        let raw_ie_len = u32::from_le_bytes([
            bss_data[ie_length_offset],
            bss_data[ie_length_offset + 1],
            bss_data[ie_length_offset + 2],
            bss_data[ie_length_offset + 3],
        ]) as usize;
        raw_ie_len.saturating_sub(FIXED_IES_SIZE)
    } else {
        0
    };

    // Capability is at offset 126 (H2cFixedIes.caps).
    let capability = u16::from_le_bytes([bss_data[126], bss_data[127]]);

    // Beacon interval is at offset 124 (H2cFixedIes.beacon_int).
    let beacon_interval = u16::from_le_bytes([bss_data[124], bss_data[125]]);

    // Build combined IEs: prepend a proper SSID IE (type=0) from the fixed SSID
    // field, then append the firmware's variable IEs.  The firmware stores SSID
    // in a fixed struct field (offset 12–48) and does NOT include an SSID IE in
    // the variable section.  Without a synthesised SSID IE, cfg80211 stores the
    // BSS with an empty SSID, causing cfg80211_get_bss() to fail during connect.
    const VARIABLE_IES_OFFSET: usize = 128;
    // Extract SSID from fixed field.
    let fixed_ssid_len = if bss_data.len() >= ssid_bytes_offset + 32 {
        u32::from_le_bytes([
            bss_data[ssid_len_offset],
            bss_data[ssid_len_offset + 1],
            bss_data[ssid_len_offset + 2],
            bss_data[ssid_len_offset + 3],
        ]) as usize
    } else {
        0
    };
    let fixed_ssid_len = fixed_ssid_len.min(32);

    // Combine SSID IE + variable IEs into a fixed-size stack buffer.
    // Max SSID IE = 2 + 32 = 34 bytes; cap variable IEs at 512 bytes.
    const VAR_IE_CAP: usize = 512;
    let mut combined_buf = [0u8; 34 + VAR_IE_CAP];
    let mut combined_len = 0usize;

    // Synthesise SSID IE.
    if fixed_ssid_len > 0 && bss_data.len() >= ssid_bytes_offset + fixed_ssid_len {
        combined_buf[0] = 0; // SSID element ID
        combined_buf[1] = fixed_ssid_len as u8;
        combined_buf[2..2 + fixed_ssid_len]
            .copy_from_slice(&bss_data[ssid_bytes_offset..ssid_bytes_offset + fixed_ssid_len]);
        combined_len = 2 + fixed_ssid_len;
    }

    // Append variable IEs from firmware.
    let var_ie_len = ie_length.min(VAR_IE_CAP);
    if var_ie_len > 0 && bss_data.len() >= VARIABLE_IES_OFFSET + var_ie_len {
        combined_buf[combined_len..combined_len + var_ie_len]
            .copy_from_slice(&bss_data[VARIABLE_IES_OFFSET..VARIABLE_IES_OFFSET + var_ie_len]);
        combined_len += var_ie_len;
    }

    let ies_ptr = if combined_len > 0 {
        combined_buf.as_ptr()
    } else {
        core::ptr::null()
    };

    // Extract frequency from BSS data (at offset 72 within the config struct).
    // The firmware reports the channel number (1-14) in this field for 2.4GHz.
    let freq = if bss_data.len() > freq_offset + 3 {
        u32::from_le_bytes([
            bss_data[freq_offset],
            bss_data[freq_offset + 1],
            bss_data[freq_offset + 2],
            bss_data[freq_offset + 3],
        ])
    } else {
        0
    };

    // Convert frequency to channel number.
    // If freq is 0 or invalid, default to channel 1.
    let ch_num: u8 = if freq > 0 && freq <= 14 {
        freq as u8
    } else {
        1
    };

    // Get the channel from wiphy bands.
    let channel = find_channel(wiphy, ch_num);

    // Convert RSSI to signal strength (dBm).
    // RTL8192SU reports RSSI as a raw value; convert to dBm.
    let _signal = (rssi as i32 / 2) - 100;

    // SAFETY: All pointers are derived from valid bss_data slice.
    let gfp: i32 = bindings::GFP_KERNEL
        .try_into()
        .unwrap_or(GFP_KERNEL_FAILBACK);
    let bss = unsafe {
        rust_helper_cfg80211_inform_bss_data(
            wiphy,
            channel,
            bssid_ptr,
            0, // TSF
            capability,
            beacon_interval,
            ies_ptr,
            combined_len,
            gfp,
        )
    };

    if !bss.is_null() {
        // Release the reference we got from cfg80211_inform_bss_data.
        // SAFETY: wiphy and bss are valid; bss was just returned by inform_bss_data.
        unsafe { rust_helper_cfg80211_put_bss(wiphy, bss) };
    }
}

/// Find an ieee80211_channel for the given channel number from wiphy bands.
fn find_channel(wiphy: *mut c_void, ch_num: u8) -> *mut c_void {
    // Use the helper to get the channel from wiphy bands.
    // SAFETY: wiphy is valid, ch_num is a simple integer.
    unsafe { rust_helper_wiphy_get_channel(wiphy, ch_num) }
}

/// Initialise the scan subsystem and register callbacks with cfg80211.
pub fn init() {
    // Register the scan callback.
    // SAFETY: scan_callback is a valid extern "C" function.
    unsafe {
        rust_helper_set_cfg80211_ops_scan(Some(scan_callback));
        rust_helper_set_cfg80211_ops_abort_scan(Some(abort_scan_callback));
    }

    pr_info!("r92su: scan subsystem initialized\n");
}
