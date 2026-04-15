// SPDX-License-Identifier: GPL-2.0
//! Power management (set_power_mgmt) for RTL8192SU.
//!
//! Implements the `.set_power_mgmt` cfg80211 callback to allow userspace
//! (wpa_supplicant) to enable/disable power save mode.
//!
//! When power save is enabled, we inform the firmware via H2C_SET_STA_PWR_STATE_CMD
//! so it can respond to PS-Poll frames from the AP.

use core::ffi::{c_int, c_void};

use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::cmd::{h2c_set_power_mode, h2c_set_sta_pwr_state, PsMode};
use crate::r92u::R92suDevice;

extern "C" {
    fn rust_helper_set_cfg80211_ops_set_power_mgmt(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, bool, c_int) -> c_int>,
    );
}

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

/// Handle power management configuration from userspace.
///
/// Called when wpa_supplicant enables or disables power save mode.
/// The timeout parameter is ignored (driver chooses dynamic PS timeout).
///
/// Note: We don't actually enable PS immediately - we just record the setting.
/// PS is enabled when the station enters power save (via change_station callback).
extern "C" fn set_power_mgmt_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    enabled: bool,
    _timeout: c_int,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    dev.ps_enabled = enabled;

    if enabled {
        pr_debug!("r92su: power save enabled (timeout=driver choice)\n");
    } else {
        pr_debug!("r92su: power save disabled\n");
    }

    0
}

/// Apply power save state to the firmware.
///
/// Called when the station's power save state changes (e.g., after
/// association or when entering/leaving power save mode).
pub fn apply_ps_state(dev: &mut R92suDevice) {
    if dev.bssid == [0u8; 6] {
        return;
    }

    let bssid = dev.bssid;
    let aid = dev.assoc_id;

    if dev.ps_enabled && aid != 0 {
        if let Err(e) = h2c_set_sta_pwr_state(dev, aid as u8, 1, &bssid) {
            pr_warn!("r92su: failed to set PS state (enabled): {:?}\n", e);
        }
        if let Err(e) = h2c_set_power_mode(dev, PsMode::Min as u8, 1) {
            pr_warn!("r92su: failed to set power mode: {:?}\n", e);
        }
        pr_debug!("r92su: PS state enabled (aid={})\n", aid);
    } else {
        if let Err(e) = h2c_set_sta_pwr_state(dev, aid as u8, 0, &bssid) {
            pr_warn!("r92su: failed to set PS state (disabled): {:?}\n", e);
        }
        if let Err(e) = h2c_set_power_mode(dev, PsMode::Active as u8, 0) {
            pr_warn!("r92su: failed to set power mode: {:?}\n", e);
        }
        pr_debug!("r92su: PS state disabled\n");
    }
}

/// Update association ID when connection completes.
///
/// Called from the connect result handler to store the AID and apply
/// power save settings if power save was previously enabled.
pub fn set_assoc_id(dev: &mut R92suDevice, aid: u16) {
    dev.assoc_id = aid;
    if dev.ps_enabled {
        apply_ps_state(dev);
    }
}

/// Enable power save on the device.
///
/// Called when the station enters power save (e.g., after some idle time).
/// This is triggered by mac80211 sending nullfunc frames or PS-Poll.
pub fn enable_ps(dev: &mut R92suDevice) {
    if dev.bssid == [0u8; 6] || dev.assoc_id == 0 {
        return;
    }

    let bssid = dev.bssid;
    let aid = dev.assoc_id;

    if let Err(e) = h2c_set_sta_pwr_state(dev, aid as u8, 1, &bssid) {
        pr_warn!("r92su: enable_ps: failed to set sta pwr state: {:?}\n", e);
    }
    if let Err(e) = h2c_set_power_mode(dev, PsMode::Min as u8, 1) {
        pr_warn!("r92su: enable_ps: failed to set power mode: {:?}\n", e);
    }
    pr_debug!("r92su: PS enabled\n");
}

/// Disable power save on the device.
///
/// Called when the station wakes up (sends data or receives a beacon with no TIM).
pub fn disable_ps(dev: &mut R92suDevice) {
    if dev.bssid == [0u8; 6] || dev.assoc_id == 0 {
        return;
    }

    let bssid = dev.bssid;
    let aid = dev.assoc_id;

    if let Err(e) = h2c_set_sta_pwr_state(dev, aid as u8, 0, &bssid) {
        pr_warn!("r92su: disable_ps: failed to set sta pwr state: {:?}\n", e);
    }
    if let Err(e) = h2c_set_power_mode(dev, PsMode::Active as u8, 0) {
        pr_warn!("r92su: disable_ps: failed to set power mode: {:?}\n", e);
    }
    pr_debug!("r92su: PS disabled\n");
}

// ── Public API ─────────────────────────────────────────────────────────────────

pub fn init() {
    unsafe {
        rust_helper_set_cfg80211_ops_set_power_mgmt(Some(set_power_mgmt_callback));
    }
    pr_debug!("r92su: power management initialized\n");
}
