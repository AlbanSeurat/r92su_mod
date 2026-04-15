// SPDX-License-Identifier: GPL-2.0
//! station_info - RTL8192SU cfg80211 station information operations.
//!
//! Implements the `.get_station` and `.dump_station` cfg80211 ops.
//!
//! These callbacks provide station statistics to userspace tools like `iw` and
//! `wpa_supplicant`.  Mirrors `r92su_get_station` / `r92su_sta_set_sinfo` in the
//! C reference driver.

use core::ffi::{c_int, c_void};
use core::ptr;

use kernel::prelude::*;

use crate::cfg80211::wiphy_priv;
use crate::r92u::{R92suDevice, ETH_ALEN};

extern "C" {
    fn rust_helper_set_cfg80211_ops_get_station(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *const u8, *mut c_void) -> c_int>,
    );

    fn rust_helper_set_cfg80211_ops_dump_station(
        fn_ptr: Option<
            extern "C" fn(*mut c_void, *mut c_void, c_int, *mut u8, *mut c_void) -> c_int,
        >,
    );

    fn rust_helper_set_cfg80211_ops_change_station(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *const u8, *mut c_void) -> c_int>,
    );

    fn rust_helper_station_info_set(
        sinfo: *mut c_void,
        rx_packets: u64,
        rx_bytes: u64,
        tx_packets: u64,
        tx_bytes: u64,
        rx_rate: u32,
        rx_rate_flags: u32,
        tx_rate: u32,
        tx_rate_flags: u32,
        signal: u8,
    );
}

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

// ── Helper to fill station_info ─────────────────────────────────────────────

fn sta_set_sinfo(sinfo: *mut c_void, sta: &crate::sta::R92suSta) {
    let rx_rate = sta.last_rx_rate;
    let rx_rate_flags = sta.last_rx_rate_flag;
    let tx_rate = 0; // Not tracked in current implementation
    let tx_rate_flags = 0;
    let signal = (sta.signal + 256) as u8; // Convert dBm to unsigned

    unsafe {
        rust_helper_station_info_set(
            sinfo,
            0, // rx_packets - not tracked per-station
            0, // rx_bytes - not tracked per-station
            0, // tx_packets - not tracked per-station
            0, // tx_bytes - not tracked per-station
            rx_rate,
            rx_rate_flags,
            tx_rate,
            tx_rate_flags,
            signal,
        );
    }
}

// ── cfg80211 .get_station ───────────────────────────────────────────────────

extern "C" fn get_station_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    mac: *const u8,
    sinfo: *mut c_void,
) -> c_int {
    if mac.is_null() || sinfo.is_null() {
        return -22; // -EINVAL
    }

    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    let mut peer = [0u8; ETH_ALEN];
    unsafe { ptr::copy_nonoverlapping(mac, peer.as_mut_ptr(), ETH_ALEN) };

    let sta =
        match dev.sta_by_mac(&peer) {
            Some(s) => s,
            None => {
                pr_warn!(
                "r92su: get_station: unknown station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]
            );
                return -19; // -ENODEV
            }
        };

    sta_set_sinfo(sinfo, sta);

    pr_debug!(
        "r92su: get_station: station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}\n",
        peer[0],
        peer[1],
        peer[2],
        peer[3],
        peer[4],
        peer[5],
        sta.signal
    );

    0
}

// ── cfg80211 .dump_station ───────────────────────────────────────────────────

extern "C" fn dump_station_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    idx: c_int,
    mac: *mut u8,
    sinfo: *mut c_void,
) -> c_int {
    if mac.is_null() || sinfo.is_null() {
        return -22; // -EINVAL
    }

    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    let i = idx as usize;

    let sta = match dev.sta_by_idx(i) {
        Some(s) => s,
        None => return -19, // -ENODEV (no more stations)
    };

    sta_set_sinfo(sinfo, sta);

    // Copy MAC address to output parameter
    unsafe {
        ptr::copy_nonoverlapping(sta.mac_addr.as_ptr(), mac, ETH_ALEN);
    }

    pr_debug!(
        "r92su: dump_station: idx={} station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        i,
        sta.mac_addr[0],
        sta.mac_addr[1],
        sta.mac_addr[2],
        sta.mac_addr[3],
        sta.mac_addr[4],
        sta.mac_addr[5]
    );

    0
}

// ── cfg80211 .change_station ──────────────────────────────────────────────────

const NL80211_STA_FLAG_AUTHORIZED: u32 = 5;

extern "C" fn change_station_callback(
    wiphy: *mut c_void,
    _ndev: *mut c_void,
    mac: *const u8,
    params: *mut c_void,
) -> c_int {
    if mac.is_null() || params.is_null() {
        return -22; // -EINVAL
    }

    let dev = match dev_from_wiphy(wiphy) {
        Some(d) => d,
        None => return -19, // -ENODEV
    };

    let mut peer = [0u8; ETH_ALEN];
    unsafe { ptr::copy_nonoverlapping(mac, peer.as_mut_ptr(), ETH_ALEN) };

    // Read sta_flags_mask and sta_flags_set from station_parameters.
    // struct station_parameters {
    //     u32 sta_flags_mask, sta_flags_set;
    //     ...
    // }
    let sta_flags_mask: u32 = unsafe {
        let ptr = params as *const u32;
        ptr.read()
    };
    let sta_flags_set: u32 = unsafe {
        let ptr = params.add(1) as *const u32;
        ptr.read()
    };

    // Check if AUTHORIZED flag is being set (bit 5 = 1<<5 = 0x20)
    let authorize_bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    if (sta_flags_mask & authorize_bit) != 0 && (sta_flags_set & authorize_bit) != 0 {
        // wpa_supplicant is marking the station as authorized (4-way handshake complete).
        // For RTL8192SU in STA mode, we just acknowledge this.
        pr_debug!(
            "r92su: change_station: station {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} authorized\n",
            peer[0],
            peer[1],
            peer[2],
            peer[3],
            peer[4],
            peer[5]
        );
        return 0;
    }

    // For any other station parameter changes, just return success.
    0
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn init() {
    unsafe {
        rust_helper_set_cfg80211_ops_get_station(Some(get_station_callback));
        rust_helper_set_cfg80211_ops_dump_station(Some(dump_station_callback));
        rust_helper_set_cfg80211_ops_change_station(Some(change_station_callback));
    }
    pr_debug!("r92su: station info operations initialized\n");
}
