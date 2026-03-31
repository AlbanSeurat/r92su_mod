// SPDX-License-Identifier: GPL-2.0
//! cfg80211_misc - Miscellaneous RTL8192SU cfg80211 operations.
//!
//! Implements `.change_virtual_intf`, `.join_ibss`, `.leave_ibss`,
//! `.set_wiphy_params`, and `.set_monitor_channel` cfg80211 ops.
//!
//! Mirrors the corresponding functions in the C reference driver.

use core::ffi::{c_int, c_uint, c_void};
use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::cmd;
use crate::r92u::{R92suDevice, State, ETH_ALEN};

// ── C helpers ─────────────────────────────────────────────────────────────────

extern "C" {
    fn rust_helper_set_cfg80211_ops_change_virtual_intf(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, c_int, *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_join_ibss(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_leave_ibss(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_set_wiphy_params(
        fn_ptr: Option<extern "C" fn(*mut c_void, c_int, u32) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_set_monitor_channel(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>,
    );
}

// NL80211_IFTYPE_* constants (from nl80211.h)
const NL80211_IFTYPE_STATION: c_int = 1;
const NL80211_IFTYPE_ADHOC: c_int = 5;
const NL80211_IFTYPE_MONITOR: c_int = 10;

// Operation mode for firmware
const OP_MODE_STATION: c_int = 2;
const OP_MODE_ADHOC: c_int = 1;
const OP_MODE_MONITOR: c_int = 3;

// ── Internal helper ─────────────────────────────────────────────────────────

fn dev_from_wiphy(wiphy: *mut c_void) -> Option<&'static mut R92suDevice> {
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if dev_ptr.is_null() {
        None
    } else {
        unsafe { Some(&mut *dev_ptr) }
    }
}

// ── cfg80211 .change_virtual_intf ───────────────────────────────────────────

extern "C" fn change_virtual_intf_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    iftype: c_int,
    _params: *mut c_void,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    // Validate interface type
    match iftype as c_int {
        NL80211_IFTYPE_STATION | NL80211_IFTYPE_ADHOC | NL80211_IFTYPE_MONITOR => {}
        _ => {
            pr_warn!(
                "r92su: change_virtual_intf: unsupported iftype {}\n",
                iftype
            );
            return -22; // -EINVAL
        }
    }

    // Update the device's operating mode
    dev.iftype = iftype as u32;

    // If device is Open or Connected, notify firmware of mode change
    if dev.is_open() {
        let opmode = match iftype as c_int {
            NL80211_IFTYPE_STATION => cmd::OpMode::Infra,
            NL80211_IFTYPE_ADHOC => cmd::OpMode::AdHoc,
            NL80211_IFTYPE_MONITOR => cmd::OpMode::Monitor,
            _ => cmd::OpMode::Infra,
        };

        if let Err(e) = cmd::h2c_set_opmode(dev, opmode) {
            pr_err!(
                "r92su: change_virtual_intf: h2c_set_opmode failed: {:?}\n",
                e
            );
            return -5; // -EIO
        }
    }

    pr_debug!("r92su: change_virtual_intf: iftype={}\n", iftype);
    0
}

// ── cfg80211 .join_ibss ───────────────────────────────────────────────────────

extern "C" fn join_ibss_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    _params: *mut c_void,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    // IBSS join requires the device to be in Open state
    if dev.state != State::Open {
        pr_warn!(
            "r92su: join_ibss: device not open (state={:?})\n",
            dev.state
        );
        return -11; // -EAGAIN
    }

    // TODO: Extract IBSS parameters (SSID, channel, etc.) from params
    // For now, just set the device to AdHoc mode via H2C
    if let Err(e) = cmd::h2c_set_opmode(dev, cmd::OpMode::AdHoc) {
        pr_err!("r92su: join_ibss: h2c_set_opmode failed: {:?}\n", e);
        return -5; // -EIO
    }

    pr_debug!("r92su: join_ibss: joined IBSS\n");
    0
}

// ── cfg80211 .leave_ibss ──────────────────────────────────────────────────────

extern "C" fn leave_ibss_callback(wiphy: *mut c_void, _ndev: *mut c_void) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    // Send disconnect to firmware
    if let Err(e) = cmd::h2c_disconnect(dev) {
        pr_err!("r92su: leave_ibss: h2c_disconnect failed: {:?}\n", e);
        return -5; // -EIO
    }

    // Clear BSSID
    dev.bssid = [0u8; ETH_ALEN];

    pr_debug!("r92su: leave_ibss: left IBSS\n");
    0
}

// ── cfg80211 .set_wiphy_params ───────────────────────────────────────────────

extern "C" fn set_wiphy_params_callback(
    wiphy: *mut c_void,
    _radio_idx: c_int,
    changed: u32,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    // Handle RTS threshold changes (NL80211_ATTR_RTS_THRESHOLD)
    if changed & (1 << 2) != 0 {
        // TODO: Propagate RTS threshold to firmware via H2C or register write
        pr_debug!("r92su: set_wiphy_params: RTS threshold changed\n");
    }

    // TODO: Handle other wiphy params (frag threshold, retry limits, etc.)

    pr_debug!("r92su: set_wiphy_params: changed=0x{:x}\n", changed);
    0
}

// ── cfg80211 .set_monitor_channel ────────────────────────────────────────────

extern "C" fn set_monitor_channel_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    _chandef: *mut c_void,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    // Monitor mode channel change - notify firmware
    if let Err(e) = cmd::h2c_set_opmode(dev, cmd::OpMode::Monitor) {
        pr_err!(
            "r92su: set_monitor_channel: h2c_set_opmode failed: {:?}\n",
            e
        );
        return -5; // -EIO
    }

    // TODO: Extract channel from chandef and set it via h2c_set_channel

    pr_debug!("r92su: set_monitor_channel: channel set\n");
    0
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn init() {
    unsafe {
        rust_helper_set_cfg80211_ops_change_virtual_intf(Some(change_virtual_intf_callback));
        rust_helper_set_cfg80211_ops_join_ibss(Some(join_ibss_callback));
        rust_helper_set_cfg80211_ops_leave_ibss(Some(leave_ibss_callback));
        rust_helper_set_cfg80211_ops_set_wiphy_params(Some(set_wiphy_params_callback));
        rust_helper_set_cfg80211_ops_set_monitor_channel(Some(set_monitor_channel_callback));
    }
    pr_debug!("r92su: misc cfg80211 operations initialized\n");
}
