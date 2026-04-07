// SPDX-License-Identifier: GPL-2.0
//! r92u_open - RTL8192SU device open and firmware upload logic.

use core::ffi::c_void;
use kernel::prelude::*;

use crate::cmd;
use crate::cmd::r92su_set_power;
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

    fn rust_helper_set_tx_complete_fn(
        fn_ptr: Option<extern "C" fn(*mut c_void)>,
        dev_ptr: *mut c_void,
    );

    fn rust_helper_submit_one_tx_urb(
        udev: *mut kernel::bindings::usb_device,
        endpoint: u8,
        data: *const u8,
        len: usize,
    ) -> i32;

    fn rust_helper_kill_tx_urbs();

    fn rust_helper_set_ndo_start_xmit(
        fn_ptr: Option<extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
    );

    fn rust_helper_set_ndo_stop(fn_ptr: Option<extern "C" fn(*mut c_void) -> i32>);

    fn rust_helper_kill_rx_urbs();

    fn rust_helper_netif_tx_wake_all_queues(ndev: *mut core::ffi::c_void);

    fn rust_helper_netif_carrier_off(ndev: *mut core::ffi::c_void);

    fn rust_helper_netif_tx_stop_all_queues(ndev: *mut core::ffi::c_void);
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

extern "C" fn tx_complete_callback(dev_ptr: *mut c_void) {
    if dev_ptr.is_null() {
        return;
    }
    // SAFETY: dev_ptr was stored via rust_helper_set_tx_complete_fn in r92su_open
    // and is valid for the lifetime of the USB interface.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };

    dev.tx_pending_urbs
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
    pr_debug!(
        "r92su: TX complete, pending={}\n",
        dev.tx_pending_urbs
            .load(core::sync::atomic::Ordering::Acquire)
    );

    if !dev.netdev_ptr.is_null() && dev.is_open() {
        unsafe { rust_helper_netif_tx_wake_all_queues(dev.netdev_ptr) };
    }
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
    pr_debug!("r92su: ndo_open callback registered\n");
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
    pr_debug!("r92su_open: early MAC setup complete\n");

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
    pr_debug!("r92su_open: firmware uploaded ({} bytes)\n", firmware.len());

    cmd::cmd_init(dev);
    pr_debug!("r92su_open: command subsystem initialized\n");

    hw_late_mac_setup(dev).map_err(|e| {
        pr_err!("r92su_open: hw_late_mac_setup failed: {}\n", e);
        e
    })?;
    pr_debug!("r92su_open: late MAC setup complete\n");

    init_mac(dev).map_err(|e| {
        pr_err!("r92su_open: init_mac failed: {}\n", e);
        e
    })?;
    pr_debug!("r92su_open: MAC initialized\n");

    dev.set_state(State::Open);
    pr_debug!("r92su_open: device opened successfully\n");

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
        let ret = unsafe { rust_helper_submit_rx_urbs(dev.udev, ep.address, 8) };
        if ret < 0 {
            pr_err!("r92su_open: failed to submit RX URBs (err={})\n", ret);
        } else {
            pr_debug!(
                "r92su_open: 8 RX URBs submitted on ep={:#04x}\n",
                ep.address
            );
        }
    } else {
        pr_err!("r92su_open: no bulk-in endpoint; RX URBs not submitted\n");
    }

    // Register the TX completion callback for async URB-based transmission.
    // SAFETY: dev is valid for the USB interface lifetime.
    unsafe {
        rust_helper_set_tx_complete_fn(Some(tx_complete_callback), dev_ptr);
    }

    Ok(())
}

// ── ndo_start_xmit / ndo_stop ─────────────────────────────────────────────────

/// Called from C `r92su_ndo_start_xmit_dispatch` with raw Ethernet frame bytes.
///
/// Invoked in softirq (TX queue) context; must not sleep.
extern "C" fn start_xmit_callback(dev_ptr: *mut c_void, data: *const u8, len: usize) -> i32 {
    if dev_ptr.is_null() || data.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: dev_ptr was stored during device allocation; data/len come from the skb.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };
    let eth = unsafe { core::slice::from_raw_parts(data, len) };
    match crate::tx::tx_from_ethernet(dev, eth) {
        Ok(()) => 0,
        Err(_) => -5, // -EIO
    }
}

/// Called from C `r92su_ndo_stop_impl` when the interface is brought down.
extern "C" fn ndo_stop_callback(dev_ptr: *mut c_void) -> i32 {
    if dev_ptr.is_null() {
        return -19; // -ENODEV
    }
    // SAFETY: dev_ptr is valid for the USB interface lifetime.
    let dev = unsafe { &mut *(dev_ptr as *mut R92suDevice) };

    if dev.state == State::Connected {
        let _ = cmd::h2c_disconnect(dev);
    }

    // Turn off the radio and put firmware into power-down state.
    // SAFETY: r92su_set_power writes to hardware via USB control transfer.
    if let Err(e) = r92su_set_power(dev, false) {
        pr_warn!("r92su: failed to set power off: {:?}\n", e);
    }

    // Kill all active RX URBs so the bulk-in pipe is drained.
    // SAFETY: safe to call even if no URBs are active.
    unsafe { rust_helper_kill_rx_urbs() };

    // Kill all pending TX URBs.
    // SAFETY: safe to call even if no URBs are active.
    unsafe { rust_helper_kill_tx_urbs() };

    dev.set_state(State::Stop);
    pr_debug!("r92su: interface stopped\n");
    0
}

/// Register the TX and stop callbacks with the C netdev_ops.
///
/// Must be called once during probe, before the net_device is registered.
pub fn ndo_xmit_stop_init() {
    // SAFETY: start_xmit_callback and ndo_stop_callback are valid extern "C" fns.
    unsafe {
        rust_helper_set_ndo_start_xmit(Some(start_xmit_callback));
        rust_helper_set_ndo_stop(Some(ndo_stop_callback));
    }
    pr_debug!("r92su: ndo_start_xmit and ndo_stop callbacks registered\n");
}
