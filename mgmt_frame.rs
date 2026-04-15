// SPDX-License-Identifier: GPL-2.0
//! mgmt_frame - RTL8192SU cfg80211 management frame registration and transmission.
//!
//! Implements the `.mgmt_tx` and `.update_mgmt_frame_registrations` cfg80211 ops.
//!
//! This is called by wpa_supplicant to:
//! 1. Register interest in receiving certain management frame types (action frames)
//! 2. Transmit management frames (like action frames)
//!
//! The RTL8192SU hardware does not support receiving specific mgmt frame types in
//! hardware, so frame registration is a stub. Frame transmission uses the existing
//! TX path via `tx::r92su_tx()`.

use core::ffi::c_void;
use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::r92u::R92suDevice;
use crate::tx;

// ── C helpers ─────────────────────────────────────────────────────────────────

extern "C" {
    fn rust_helper_set_cfg80211_ops_update_mgmt_frame_registrations(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void)>,
    );

    fn rust_helper_set_cfg80211_ops_mgmt_tx(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut u64) -> c_int>,
    );

    fn rust_helper_cfg80211_mgmt_tx_status(
        wdev: *mut c_void,
        cookie: u64,
        buf: *const u8,
        len: usize,
        ack: bool,
        gfp: c_int,
    );
}

// ── cfg80211 .update_mgmt_frame_registrations ────────────────────────────────

extern "C" fn mgmt_frame_register_callback(
    _wiphy: *mut c_void,
    _wdev: *mut c_void,
    _upd: *mut c_void,
) {
    pr_debug!("r92su: update_mgmt_frame_registrations called\n");
}

// ── cfg80211 .mgmt_tx ────────────────────────────────────────────────────────

extern "C" fn mgmt_tx_callback(
    wiphy: *mut c_void,
    _wdev: *mut c_void,
    params: *mut c_void,
    cookie_out: *mut u64,
) -> c_int {
    // Recover device pointer from wiphy private data.
    let dev_ptr = wiphy_priv(wiphy) as *mut *mut R92suDevice;
    if dev_ptr.is_null() {
        pr_err!("r92su: mgmt_tx: dev_ptr is null\n");
        return -1;
    }

    // SAFETY: dev_ptr is valid for the duration of this call; we're in a
    // cfg80211 callback where the device won't be freed.
    let dev = unsafe { &mut *(*dev_ptr) };

    // The params pointer is a cfg80211_mgmt_tx_params struct.
    // We need to access the buf and len fields.
    // struct cfg80211_mgmt_tx_params {
    //     struct ieee80211_channel *chan;
    //     bool offchan;
    //     unsigned int wait;
    //     const u8 *buf;
    //     size_t len;
    //     bool no_cck;
    //     bool dont_wait_for_ack;
    //     ...
    // }
    //
    // On 64-bit: chan(8), offchan(1+7pad), wait(4), buf(8), len(8), no_cck(1+7pad), dont_wait_for_ack(1+7pad), ...
    // Fields are at offsets: chan=0, offchan=8, wait=12, buf=16, len=24

    let params = params as *const c_void;
    if params.is_null() {
        pr_err!("r92su: mgmt_tx: params is null\n");
        return -1;
    }

    // SAFETY: We know params is valid and points to at least 32 bytes.
    // Extract buf and len from the struct at known offsets.
    let buf_ptr: *const u8 = unsafe { *(params.cast::<*const u8>().add(16)) };
    let len: usize = unsafe {
        *(params
            .cast::<usize>()
            .add(24 / core::mem::size_of::<usize>()))
    };

    if buf_ptr.is_null() || len == 0 {
        pr_err!("r92su: mgmt_tx: invalid buf/len\n");
        return -1;
    }

    // Generate a simple cookie (use address of buffer as unique ID).
    let cookie = buf_ptr as u64;

    // Write cookie back to caller.
    // SAFETY: cookie_out is a valid pointer provided by cfg80211.
    unsafe { cookie_out.write(cookie) };

    pr_debug!("r92su: mgmt_tx: len={}, cookie={:#x}\n", len, cookie);

    // Validate frame is at least a management frame (minimum 24-byte header).
    if len < 24 {
        pr_err!("r92su: mgmt_tx: frame too short (len={})\n", len);
        // Still report tx status for the frame.
        unsafe {
            rust_helper_cfg80211_mgmt_tx_status(
                _wdev, cookie, buf_ptr, len, false, 0, // GFP_KERNEL = 0
            )
        };
        return 0;
    }

    // SAFETY: We have a valid buffer pointer and length.
    let frame = unsafe { core::slice::from_raw_parts(buf_ptr, len) };

    // Check frame type from the FC field (first 2 bytes, little-endian).
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let frame_type = fc & 0xFC; // Mask off subtype
    pr_debug!(
        "r92su: mgmt_tx: frame_control=0x{:04x}, type=0x{:02x}\n",
        fc,
        frame_type
    );

    // For ACTION frames (type = 0x00D0 = WLAN_FC_STYPE_ACTION), we transmit them.
    // Other frame types we also handle (probe response, etc).
    // The driver should transmit any management frame passed to it.

    // Use mac_id 0 for broadcast (default BSS).
    let mac_id = 0;

    // Attempt to transmit the frame via the TX path.
    // Note: This is a blocking call that submits the URB and waits for completion.
    let tx_result = tx::r92su_tx(dev, frame, mac_id);

    let ack = tx_result.is_ok();
    if !ack {
        pr_warn!("r92su: mgmt_tx: tx failed: {:?}\n", tx_result);
    }

    // Report tx status to cfg80211/wpa_supplicant.
    // SAFETY: buf_ptr is valid, len is correct, _wdev is valid.
    unsafe {
        rust_helper_cfg80211_mgmt_tx_status(
            _wdev, cookie, buf_ptr, len, ack, 0, // GFP_KERNEL
        )
    };

    0
}

// ── Initialisation ─────────────────────────────────────────────────────────--

/// Initialise the mgmt_tx and update_mgmt_frame_registrations callbacks.
pub fn init() {
    // SAFETY: These set function pointers in the static r92su_cfg80211_ops
    // which is only ever accessed from cfg80211 after it's been registered.
    unsafe {
        rust_helper_set_cfg80211_ops_update_mgmt_frame_registrations(Some(
            mgmt_frame_register_callback,
        ));
        rust_helper_set_cfg80211_ops_mgmt_tx(Some(mgmt_tx_callback));
    }
    pr_debug!(
        "r92su: mgmt_tx and update_mgmt_frame_registrations cfg80211 operations initialized\n"
    );
}
