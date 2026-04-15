// SPDX-License-Identifier: GPL-2.0
//! tdls - RTL8192SU TDLS (802.11z) support.
//!
//! Implements the `.tdls_mgmt` and `.tdls_oper` cfg80211 ops.
//!
//! TDLS (Tunneled Direct Link Setup) allows direct peer-to-peer communication
//! between two devices without going through the AP. The RTL8192SU hardware does
//! not have native TDLS support, so we report the capability to cfg80211 and
//! handle TDLS operations by requesting userspace (wpa_supplicant) to perform
//! the setup.

use core::ffi::c_void;
use kernel::prelude::*;

extern "C" {
    fn rust_helper_set_cfg80211_ops_tdls_mgmt(
        fn_ptr: Option<
            extern "C" fn(
                *mut c_void,
                *mut c_void,
                *const u8,
                c_int,
                u8,
                u8,
                u16,
                u32,
                bool,
                *const u8,
                usize,
            ) -> c_int,
        >,
    );

    fn rust_helper_set_cfg80211_ops_tdls_oper(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *const u8, c_int) -> c_int>,
    );

    fn rust_helper_cfg80211_tdls_oper_request(
        ndev: *mut c_void,
        peer: *const u8,
        oper: c_int,
        reason_code: u16,
        gfp: c_int,
    );
}

const NL80211_TDLS_DISCOVERY_REQ: c_int = 0;
const NL80211_TDLS_SETUP: c_int = 1;
const NL80211_TDLS_TEARDOWN: c_int = 2;
const NL80211_TDLS_ENABLE_LINK: c_int = 3;
const NL80211_TDLS_DISABLE_LINK: c_int = 4;

extern "C" fn tdls_mgmt_callback(
    _wiphy: *mut c_void,
    _ndev: *mut c_void,
    peer: *const u8,
    _link_id: c_int,
    action_code: u8,
    _dialog_token: u8,
    _status_code: u16,
    _peer_capability: u32,
    _initiator: bool,
    _buf: *const u8,
    _len: usize,
) -> c_int {
    pr_debug!(
        "r92su: tdls_mgmt: peer={:?}, action_code={}\n",
        peer,
        action_code
    );

    if peer.is_null() {
        return -1;
    }

    match action_code {
        0 => pr_debug!("r92su: TDLS discovery request\n"),
        1 => pr_debug!("r92su: TDLS setup request\n"),
        2 => pr_debug!("r92su: TDLS setup response\n"),
        3 => pr_debug!("r92su: TDLS teardown\n"),
        _ => pr_debug!("r92su: TDLS unknown action {}\n", action_code),
    }

    0
}

extern "C" fn tdls_oper_callback(
    _wiphy: *mut c_void,
    ndev: *mut c_void,
    peer: *const u8,
    oper: c_int,
) -> c_int {
    pr_debug!("r92su: tdls_oper: peer={:?}, oper={}\n", peer, oper);

    if peer.is_null() {
        return -1;
    }

    match oper {
        NL80211_TDLS_DISCOVERY_REQ => {
            pr_debug!("r92su: TDLS discovery request from userspace\n");
            0
        }
        NL80211_TDLS_SETUP => {
            pr_debug!("r92su: TDLS setup request from userspace\n");
            unsafe {
                rust_helper_cfg80211_tdls_oper_request(ndev, peer, NL80211_TDLS_SETUP, 0, 0);
            }
            0
        }
        NL80211_TDLS_TEARDOWN => {
            pr_debug!("r92su: TDLS teardown request from userspace\n");
            unsafe {
                rust_helper_cfg80211_tdls_oper_request(ndev, peer, NL80211_TDLS_TEARDOWN, 0, 0);
            }
            0
        }
        NL80211_TDLS_ENABLE_LINK => {
            pr_debug!("r92su: TDLS enable link\n");
            0
        }
        NL80211_TDLS_DISABLE_LINK => {
            pr_debug!("r92su: TDLS disable link\n");
            0
        }
        _ => {
            pr_warn!("r92su: tdls_oper: unknown operation {}\n", oper);
            -1
        }
    }
}

pub fn init() {
    unsafe {
        rust_helper_set_cfg80211_ops_tdls_mgmt(Some(tdls_mgmt_callback));
        rust_helper_set_cfg80211_ops_tdls_oper(Some(tdls_oper_callback));
    }
    pr_debug!("r92su: tdls cfg80211 operations initialized\n");
}
