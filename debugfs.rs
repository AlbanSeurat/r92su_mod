// SPDX-License-Identifier: GPL-2.0
//! Debugfs support for RTL8192SU driver.
//!
//! Exposes debugfs files under `/sys/kernel/debug/rtl8192su/` for viewing
//! device state and debugging information.

use kernel::prelude::*;

use crate::cfg80211;
use crate::r92u::R92suDevice; //

// ---------------------------------------------------------------------------
// Debugfs callbacks
//
// These are called from the C debugfs read handlers to get data from the
// Rust device structure. The dev_ptr is a *mut R92suDevice.
// ---------------------------------------------------------------------------

extern "C" fn get_tx_pending_urbs(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.tx_queue
        .urbs
        .iter()
        .filter(|u| u.status == crate::r92u::UrbStatus::Pending)
        .count() as i32
}

extern "C" fn get_chip_rev(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.chip_rev as i32
}

extern "C" fn get_rf_type(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.rf_type as i32
}

extern "C" fn get_eeprom_type(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.eeprom_type as i32
}

extern "C" fn get_h2c_seq(dev_ptr: *mut core::ffi::c_void) -> u8 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.h2c_seq
}

extern "C" fn get_c2h_seq(dev_ptr: *mut core::ffi::c_void) -> u8 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.c2h_seq
}

extern "C" fn get_cpwm(dev_ptr: *mut core::ffi::c_void) -> u8 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.cpwm
}

extern "C" fn get_rpwm(_dev_ptr: *mut core::ffi::c_void) -> u8 {
    // RPWM is written by the driver, not stored in device state currently
    0
}

extern "C" fn get_rx_queue_len(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.pending_rx.len() as i32
}

// ---------------------------------------------------------------------------
// Debugfs registration
// ---------------------------------------------------------------------------

/// Register debugfs entries for the device.
///
/// Mirrors `r92su_register_debugfs()` from `debugfs.c`.
pub fn register_debugfs(dev: &mut R92suDevice, wiphy: *mut core::ffi::c_void) {
    // Register callbacks first
    // SAFETY: The dev pointer (KBox<R92suDevice>) is stable for the lifetime
    // of the module, and the callbacks only read from the device.
    let dev_ptr = dev as *mut R92suDevice as *mut core::ffi::c_void;
    unsafe {
        cfg80211::rust_helper_debugfs_set_callbacks(
            dev_ptr,
            Some(get_tx_pending_urbs),
            Some(get_chip_rev),
            Some(get_rf_type),
            Some(get_eeprom_type),
            Some(get_h2c_seq),
            Some(get_c2h_seq),
            Some(get_cpwm),
            Some(get_rpwm),
            Some(get_rx_queue_len),
        );
    }

    // Create the debugfs directory and files
    // SAFETY: wiphy is a valid pointer from the device probe, dev_ptr is the device.
    let dentry = unsafe { cfg80211::rust_helper_debugfs_create(dev_ptr, wiphy) };

    dev.debugfs_dentry = dentry;
    dev.debugfs_registered = true;

    if dentry.is_null() {
        pr_warn!("r92su: failed to create debugfs entries\n");
    } else {
        pr_debug!("r92su: debugfs entries created\n");
    }
}

/// Unregister debugfs entries for the device.
///
/// Mirrors `r92su_unregister_debugfs()` from `debugfs.c`.
pub fn unregister_debugfs(dev: &mut R92suDevice) {
    let dentry = dev.debugfs_dentry;
    if !dentry.is_null() {
        // SAFETY: dentry was returned by rust_helper_debugfs_create and is valid.
        unsafe {
            cfg80211::rust_helper_debugfs_remove(dentry);
        }
        dev.debugfs_dentry = core::ptr::null_mut();
        dev.debugfs_registered = false;
        pr_debug!("r92su: debugfs entries removed\n");
    }
}
