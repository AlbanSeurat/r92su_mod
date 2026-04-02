// SPDX-License-Identifier: GPL-2.0
//! keys - RTL8192SU cfg80211 key management operations.
//!
//! Implements the `.add_key`, `.del_key`, and `.set_default_key` cfg80211 ops.
//!
//! # Key storage
//!
//! - Pairwise (unicast) keys are stored in `sta.sta_key` for the matching
//!   station entry.
//! - Group (broadcast/multicast) keys are stored in `dev.group_keys[idx]`.
//! - Default key indices are tracked in `dev.def_uni_key_idx` and
//!   `dev.def_multi_key_idx`.
//!
//! # Firmware upload
//!
//! Keys are uploaded to firmware via [`cmd::h2c_set_key`] (group) or
//! [`cmd::h2c_set_sta_key`] (pairwise), mirroring `r92su_internal_add_key`
//! in `main.c:349`.

use core::ffi::{c_int, c_void};
use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::cmd::{self, EncAlg};
use crate::r92u::{R92suDevice, State};
use crate::sta;

// ── C helpers ─────────────────────────────────────────────────────────────────

extern "C" {
    fn rust_helper_set_cfg80211_ops_add_key(
        fn_ptr: Option<
            extern "C" fn(
                *mut c_void,
                *mut c_void,
                c_int,
                u8,
                bool,
                *const u8,
                *const c_void,
            ) -> c_int,
        >,
    );

    fn rust_helper_set_cfg80211_ops_del_key(
        fn_ptr: Option<
            extern "C" fn(*mut c_void, *mut c_void, c_int, u8, bool, *const u8) -> c_int,
        >,
    );

    fn rust_helper_set_cfg80211_ops_set_default_key(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, c_int, u8, bool, bool) -> c_int>,
    );

    fn rust_helper_key_params_get(
        params: *const c_void,
        cipher_out: *mut u32,
        key_out: *mut u8,
        key_len_out: *mut usize,
        key_buf_len: usize,
        seq_out: *mut u8,
        seq_len_out: *mut usize,
        seq_buf_len: usize,
    ) -> c_int;
}

// ── Internal helper ───────────────────────────────────────────────────────────

/// Extract device pointer from wiphy private area.
fn dev_from_wiphy(wiphy: *mut c_void) -> Option<&'static mut R92suDevice> {
    // SAFETY: wiphy is a valid struct wiphy *; private area holds *mut R92suDevice.
    let dev_ptr = unsafe {
        let slot = wiphy_priv(wiphy) as *mut *mut R92suDevice;
        slot.read()
    };
    if dev_ptr.is_null() {
        None
    } else {
        // SAFETY: dev_ptr is valid for the USB interface lifetime.
        Some(unsafe { &mut *dev_ptr })
    }
}

// ── cfg80211 .add_key ─────────────────────────────────────────────────────────

/// Called by cfg80211 when wpa_supplicant installs a key after (re)association.
///
/// Mirrors `r92su_add_key` / `r92su_internal_add_key` (`main.c:944, 349`).
extern "C" fn add_key_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    _link_id: c_int,
    key_index: u8,
    pairwise: bool,
    mac_addr: *const u8,
    params: *const c_void,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => {
            pr_warn!("r92su: add_key with null device pointer\n");
            return -19; // -ENODEV
        }
    };

    if dev.state != State::Connected {
        pr_warn!("r92su: add_key called but device is not connected\n");
        return -11; // -EAGAIN
    }

    // ── Extract key_params from cfg80211 ─────────────────────────────────────
    let mut cipher: u32 = 0;
    let mut key_buf = [0u8; 32];
    let mut key_len: usize = 0;
    let mut seq_buf = [0u8; 16];
    let mut seq_len: usize = 0;

    // SAFETY: params is a valid const struct key_params * from cfg80211.
    let ret = unsafe {
        rust_helper_key_params_get(
            params,
            &mut cipher,
            key_buf.as_mut_ptr(),
            &mut key_len,
            key_buf.len(),
            seq_buf.as_mut_ptr(),
            &mut seq_len,
            seq_buf.len(),
        )
    };
    if ret != 0 {
        pr_err!("r92su: add_key: key_params_get failed\n");
        return -22; // -EINVAL
    }

    let peer: [u8; 6] = if !mac_addr.is_null() {
        // SAFETY: mac_addr points to a valid ETH_ALEN-byte array from cfg80211.
        let mut a = [0u8; 6];
        unsafe { core::ptr::copy_nonoverlapping(mac_addr, a.as_mut_ptr(), 6) };
        a
    } else {
        [0u8; 6]
    };

    // ── Allocate R92suKey ─────────────────────────────────────────────────────
    let new_key = match sta::key_alloc(cipher, key_index, &peer, pairwise, &key_buf[..key_len]) {
        Ok(k) => k,
        Err(e) => {
            pr_err!("r92su: add_key: key_alloc failed: {:?}\n", e);
            return -22; // -EINVAL
        }
    };

    // ── Upload to firmware and store ──────────────────────────────────────────
    if pairwise {
        // Pairwise key: send H2C_SETSTAKEY_CMD, store in station entry.
        match cmd::h2c_set_sta_key(dev, new_key.algo, &peer, &key_buf[..key_len]) {
            Ok(()) => {}
            Err(e) => {
                pr_err!("r92su: add_key: h2c_set_sta_key failed: {:?}\n", e);
                return -5; // -EIO
            }
        }

        // Find station and store the pairwise key.
        let sta_found = dev.sta_list.iter_mut().any(|sta| sta.mac_addr == peer);
        if !sta_found {
            pr_warn!(
                "r92su: add_key: pairwise key for unknown station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]
            );
            return -22; // -EINVAL
        }
        for sta in dev.sta_list.iter_mut() {
            if sta.mac_addr == peer {
                sta.sta_key = Some(new_key);
                break;
            }
        }
    } else {
        // Group key: send H2C_SETKEY_CMD, store in group_keys[idx].
        let idx = key_index as usize;
        if idx >= dev.group_keys.len() {
            pr_err!("r92su: add_key: key_index {} out of range\n", idx);
            return -22; // -EINVAL
        }
        match cmd::h2c_set_key(dev, new_key.algo, key_index, true, &key_buf[..key_len]) {
            Ok(()) => {}
            Err(e) => {
                pr_err!("r92su: add_key: h2c_set_key failed: {:?}\n", e);
                return -5; // -EIO
            }
        }
        // Replace any existing group key in this slot.
        dev.group_keys[idx] = Some(new_key);
    }

    pr_debug!(
        "r92su: add_key idx={} pairwise={} cipher={:#010x}\n",
        key_index,
        pairwise,
        cipher
    );
    0
}

// ── cfg80211 .del_key ─────────────────────────────────────────────────────────

/// Called by cfg80211 when a key is removed (e.g. on disconnect or rekey).
///
/// Mirrors `r92su_del_key` (`main.c:967`).
extern "C" fn del_key_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    _link_id: c_int,
    key_index: u8,
    pairwise: bool,
    mac_addr: *const u8,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => {
            pr_warn!("r92su: del_key with null device pointer\n");
            return -19; // -ENODEV
        }
    };

    pr_debug!(
        "r92su: del_key idx={} pairwise={} state={:?}\n",
        key_index,
        pairwise,
        dev.state
    );

    let peer: [u8; 6] = if !mac_addr.is_null() {
        let mut a = [0u8; 6];
        // SAFETY: mac_addr points to a valid ETH_ALEN-byte array from cfg80211.
        unsafe { core::ptr::copy_nonoverlapping(mac_addr, a.as_mut_ptr(), 6) };
        a
    } else {
        [0u8; 6]
    };

    if pairwise {
        if dev.state != State::Connected {
            return -11; // -EAGAIN
        }

        // Check if we should skip the firmware notification.
        // If the station has a key that was never uploaded, just return success.
        let skip_fw_notify = dev
            .sta_list
            .iter()
            .any(|sta| sta.mac_addr == peer && matches!(sta.sta_key, Some(ref k) if !k.uploaded));

        if !skip_fw_notify {
            if let Err(e) = cmd::h2c_set_sta_key(dev, EncAlg::None, &peer, &[]) {
                pr_err!("r92su: del_key: h2c_set_sta_key(None) failed: {:?}\n", e);
                return -5; // -EIO
            }
        }

        // Now clear the key from the station entry.
        for sta in dev.sta_list.iter_mut() {
            if sta.mac_addr == peer {
                sta.sta_key = None;
                break;
            }
        }
        pr_debug!("r92su: del_key pairwise idx={}\n", key_index);
    } else {
        if dev.state != State::Connected {
            pr_debug!(
                "r92su: del_key group idx={} not connected, returning -EAGAIN\n",
                key_index
            );
            return -11; // -EAGAIN
        }

        let idx = key_index as usize;
        if idx >= dev.group_keys.len() {
            pr_debug!(
                "r92su: del_key group idx={} out of range (max {}), ignoring\n",
                idx,
                dev.group_keys.len() - 1
            );
            return 0;
        }

        let should_delete = dev.group_keys[idx]
            .as_ref()
            .map_or(false, |key| key.uploaded);

        if should_delete {
            if let Err(e) = cmd::h2c_set_key(dev, EncAlg::None, key_index, true, &[]) {
                pr_err!("r92su: del_key: h2c_set_key(None) failed: {:?}\n", e);
                return -5; // -EIO
            }
        }
        dev.group_keys[idx] = None;
        pr_debug!("r92su: del_key group idx={}\n", key_index);
    }

    pr_debug!("r92su: del_key idx={} pairwise={}\n", key_index, pairwise);
    0
}

// ── cfg80211 .set_default_key ─────────────────────────────────────────────────

/// Called by cfg80211 to designate which group key is the default TX key.
///
/// Mirrors `r92su_set_default_key` (`main.c:1054`).
extern "C" fn set_default_key_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    _link_id: c_int,
    key_index: u8,
    unicast: bool,
    multicast: bool,
) -> c_int {
    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => {
            pr_warn!("r92su: set_default_key with null device pointer\n");
            return -19; // -ENODEV
        }
    };

    if dev.state != State::Connected {
        return -11; // -EAGAIN
    }

    if unicast {
        dev.def_uni_key_idx = key_index;
    }
    if multicast {
        dev.def_multi_key_idx = key_index;
    }

    pr_debug!(
        "r92su: set_default_key idx={} unicast={} multicast={}\n",
        key_index,
        unicast,
        multicast
    );
    0
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Register key management callbacks with cfg80211.
///
/// Called during USB probe, after wiphy and netdev are set up.
pub fn init() {
    // SAFETY: the three callback functions are valid extern "C" fn pointers.
    unsafe {
        rust_helper_set_cfg80211_ops_add_key(Some(add_key_callback));
        rust_helper_set_cfg80211_ops_del_key(Some(del_key_callback));
        rust_helper_set_cfg80211_ops_set_default_key(Some(set_default_key_callback));
    }
    pr_debug!("r92su: key management initialized\n");
}
