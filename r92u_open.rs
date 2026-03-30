// SPDX-License-Identifier: GPL-2.0
//! r92u_open - RTL8192SU device open and firmware upload logic.

use core::ffi::c_void;
use kernel::prelude::*;

use crate::cmd;
use crate::fw;
use crate::r92u::{hw_early_mac_setup, hw_late_mac_setup, init_mac, R92suDevice, Result, State}; //
use crate::rx; //

extern "C" {
    fn rust_helper_set_ndo_open(fn_ptr: Option<extern "C" fn(*mut c_void) -> i32>);

    fn rust_helper_set_rx_fn(
        fn_ptr: Option<extern "C" fn(*mut c_void, *const u8, usize)>,
        dev_ptr: *mut c_void,
    );

    fn rust_helper_submit_rx_urbs(
        udev: *mut kernel::bindings::usb_device,
        endpoint: u8,
        n_urbs: i32,
    ) -> i32;
}

/// USB bulk-in completion callback — called from the C RX URB completion
/// handler in `rust_helpers.c:r92su_bulk_in_complete`.
///
/// Invoked in softirq (USB completion) context; must not sleep.
extern "C" fn rx_complete_callback(dev_ptr: *mut c_void, data: *const u8, len: usize) {
    if dev_ptr.is_null() || data.is_null() || len == 0 {
        return;
    }
    // SAFETY: dev_ptr was stored via rust_helper_set_rx_fn in r92su_open and
    // is valid for the lifetime of the USB interface.  data/len come from the
    // URB transfer buffer, which is valid for `len` bytes.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };
    let buf = unsafe { core::slice::from_raw_parts(data, len) };
    rx::r92su_rx(dev, buf);
}

extern "C" fn ndo_open_callback(dev_ptr: *mut c_void) -> i32 {
    if dev_ptr.is_null() {
        pr_err!("r92su: ndo_open with null device pointer\n");
        return -19; // -ENODEV
    }
    // SAFETY: dev_ptr was written into the wiphy private area during device
    // allocation and is valid for the lifetime of the USB interface.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };
    let firmware = dev.firmware;
    if firmware.is_empty() {
        pr_err!("r92su: ndo_open: firmware not stored\n");
        return -19; // -ENODEV
    }
    match r92su_open(dev, firmware) {
        Ok(()) => 0,
        Err(e) => {
            pr_err!("r92su: ndo_open failed: {:?}\n", e);
            -5 // -EIO
        }
    }
}

/// Register the ndo_open callback with the C netdev ops.
///
/// Must be called once during probe, before the net_device is registered.
pub fn ndo_open_init() {
    // SAFETY: ndo_open_callback is a valid extern "C" function pointer.
    unsafe {
        rust_helper_set_ndo_open(Some(ndo_open_callback));
    }
    pr_info!("r92su: ndo_open callback registered\n");
}

// ── r92su_open ────────────────────────────────────────────────────────────────
//
// Mirrors the C kernel function `r92su_open()` from main.c. This is called
// when the network device is opened (ndo_open). It performs:
//   1. Check device is stopped
//   2. Early MAC hardware setup
//   3. Upload firmware
//   4. Initialize command subsystem
//   5. Late MAC hardware setup
//   6. Initialize MAC
//   7. Set device state
//   8. Queue service work
// ---------------------------------------------------------------------------

pub fn r92su_open(dev: &mut R92suDevice, firmware: &[u8]) -> Result<()> {
    if !dev.is_stopped() {
        pr_err!("r92su_open: device is not stopped\n");
        return Err(crate::r92u::R92suError::Io("device not stopped"));
    }

    hw_early_mac_setup(dev).map_err(|e| {
        pr_err!("r92su_open: hw_early_mac_setup failed: {}\n", e);
        e
    })?;
    pr_info!("r92su_open: early MAC setup complete\n");

    fw::upload_firmware(
        dev,
        firmware,
        dev.rf_type as u8,
        dev.chip_rev as u8,
        dev.disable_ht,
    )
    .map_err(|e| {
        pr_err!("r92su_open: firmware upload failed: {}\n", e);
        e
    })?;
    pr_info!("r92su_open: firmware uploaded ({} bytes)\n", firmware.len());

    cmd::cmd_init(dev);
    pr_info!("r92su_open: command subsystem initialized\n");

    hw_late_mac_setup(dev).map_err(|e| {
        pr_err!("r92su_open: hw_late_mac_setup failed: {}\n", e);
        e
    })?;
    pr_info!("r92su_open: late MAC setup complete\n");

    init_mac(dev).map_err(|e| {
        pr_err!("r92su_open: init_mac failed: {}\n", e);
        e
    })?;
    pr_info!("r92su_open: MAC initialized\n");

    dev.set_state(State::Open);
    pr_info!("r92su_open: device opened successfully\n");

    // Register the RX callback and submit bulk-in URBs so the driver can
    // receive C2H firmware events (Survey, SurveyDone, etc.).
    // SAFETY: dev is valid for the USB interface lifetime; bulk_in was
    // discovered during endpoint enumeration in r92su_usb_init.
    let dev_ptr = dev as *mut R92suDevice as *mut c_void;
    unsafe {
        rust_helper_set_rx_fn(Some(rx_complete_callback), dev_ptr);
    }
    if let Some(ep) = dev.bulk_in {
        // SAFETY: dev.udev is valid (set during probe, lives until disconnect).
        let ret = unsafe {
            rust_helper_submit_rx_urbs(dev.udev, ep.address, 8)
        };
        if ret < 0 {
            pr_err!("r92su_open: failed to submit RX URBs (err={})\n", ret);
        } else {
            pr_info!("r92su_open: 8 RX URBs submitted on ep={:#04x}\n", ep.address);
        }
    } else {
        pr_err!("r92su_open: no bulk-in endpoint; RX URBs not submitted\n");
    }

    Ok(())
}
