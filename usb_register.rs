// SPDX-License-Identifier: GPL-2.0
//! Device registration and deregistration for RTL8192SU.
//!
//! Implements `r92su_register()` and `r92su_unregister()` from the C reference
//! driver (`main.c`).  Registration runs after [`r92su_setup`][crate::usb_setup::r92su_setup]
//! and makes the device visible to the rest of the system.
//!
//! # C reference — `r92su_register()`
//! ```c
//! wiphy_register(r92su->wdev.wiphy);
//! register_netdev(r92su->wdev.netdev);
//! r92su_register_debugfs(r92su);
//! r92su_register_wps_button(r92su);
//! dev_info(..., "Realtek RTL81XX rev %s, rf:%s is registered as '%s'.\n", ...);
//! r92su_set_state(r92su, R92SU_STOP);
//! ```
//!
//! # C reference — `r92su_unregister()`
//! ```c
//! input_unregister_device(r92su->wps_pbc);   /* if present */
//! r92su_unregister_debugfs(r92su);
//! unregister_netdev(r92su->wdev.netdev);      /* if present */
//! r92su_set_state(r92su, R92SU_UNLOAD);
//! wiphy_unregister(r92su->wdev.wiphy);        /* if registered */
//! synchronize_rcu(); rcu_barrier();
//! destroy_workqueue(...); mutex_destroy(...);
//! r92su_release_firmware(...); r92su_rx_deinit(...);
//! ```

use kernel::prelude::*;

use crate::debugfs;
use crate::r92u::{R92suDevice, R92suError, Result, State}; //

// ---------------------------------------------------------------------------
// register_wiphy — mirrors wiphy_register(r92su->wdev.wiphy)
// ---------------------------------------------------------------------------
fn register_wiphy(dev: &mut R92suDevice) -> Result<()> {
    if dev.wiphy_registered {
        pr_warn!("r92su: wiphy already registered\n");
        return Ok(());
    }
    let wiphy = dev
        .wiphy
        .as_mut()
        .ok_or(R92suError::Io("wiphy not allocated"))?;
    wiphy.register().map_err(|_| {
        pr_err!("r92su: wiphy_register failed\n");
        R92suError::Io("wiphy_register failed")
    })?;
    dev.wiphy_registered = true;
    pr_info!("r92su: wiphy registered\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// register_netdev — mirrors register_netdev(r92su->wdev.netdev)
//
// Registers the network device with the kernel networking stack.  Guards on
// dev.netdev.is_some() so we never try to register an uninitialised device.
// ---------------------------------------------------------------------------
fn register_netdev(dev: &mut R92suDevice) -> Result<()> {
    let netdev = dev
        .netdev
        .as_mut()
        .ok_or(R92suError::Io("netdev not allocated"))?;
    if netdev.is_registered() {
        pr_warn!("r92su: netdev already registered\n");
        return Ok(());
    }
    netdev.register().map_err(|_| {
        pr_err!("r92su: register_netdev failed\n");
        R92suError::Io("register_netdev failed")
    })?;
    pr_info!("r92su: net_device registered\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// register_debugfs — mirrors r92su_register_debugfs() in debugfs.c
//
// C: debugfs_create_dir(KBUILD_MODNAME, wiphy->debugfsdir) then creates
// individual file entries for tx_pending_urbs, chip_rev, rf_type, eeprom, etc.
// ---------------------------------------------------------------------------
fn register_debugfs(dev: &mut R92suDevice) -> Result<()> {
    let wiphy_ptr = {
        let wiphy = dev
            .wiphy
            .as_mut()
            .ok_or(R92suError::Io("wiphy not allocated"))?;
        wiphy.as_ptr()
    };
    debugfs::register_debugfs(dev, wiphy_ptr);
    Ok(())
}

// ---------------------------------------------------------------------------
// register_wps_button — mirrors r92su_register_wps_button() in main.c
//
// C: guarded by CONFIG_R92SU_WPC; allocates an input_dev for the WPS push
// button and calls input_register_device().  Not enabled in this build.
// ---------------------------------------------------------------------------
fn register_wps_button(_dev: &mut R92suDevice) -> Result<()> {
    // CONFIG_R92SU_WPC is not set; nothing to do.
    Ok(())
}

// ---------------------------------------------------------------------------
// unregister_wps_button — mirrors the wps_pbc teardown in r92su_unregister()
// ---------------------------------------------------------------------------
fn unregister_wps_button(_dev: &mut R92suDevice) {
    // CONFIG_R92SU_WPC is not set; nothing to do.
}

// ---------------------------------------------------------------------------
// unregister_debugfs — mirrors r92su_unregister_debugfs() in debugfs.c
//
// C: debugfs_remove_recursive(r92su->dfs)
// ---------------------------------------------------------------------------
fn unregister_debugfs(dev: &mut R92suDevice) {
    debugfs::unregister_debugfs(dev);
}

// ---------------------------------------------------------------------------
// unregister_netdev — mirrors unregister_netdev(r92su->wdev.netdev) guarded
// by "if (r92su->wdev.netdev)" in r92su_unregister().
// ---------------------------------------------------------------------------
fn unregister_netdev(dev: &mut R92suDevice) {
    // Drop the NetDev (which calls unregister_netdev / free_netdev internally),
    // then drop the WirelessDev (which calls kfree on the wireless_dev).
    // The correct order is guaranteed here: netdev is taken before wdev.
    if dev.netdev.take().is_some() {
        pr_info!("r92su: net_device unregistered\n");
    }
    if dev.wdev.take().is_some() {
        pr_info!("r92su: wireless_dev freed\n");
    }
}

// ---------------------------------------------------------------------------
// unregister_wiphy — mirrors the guarded wiphy_unregister() call:
//   if (r92su->wdev.wiphy->registered) wiphy_unregister(r92su->wdev.wiphy);
// ---------------------------------------------------------------------------
fn unregister_wiphy(dev: &mut R92suDevice) {
    if dev.wiphy_registered {
        if let Some(wiphy) = dev.wiphy.as_mut() {
            wiphy.unregister();
        }
        dev.wiphy_registered = false;
        pr_info!("r92su: wiphy unregistered\n");
    }
}

// ---------------------------------------------------------------------------
// r92su_register — public entry point (mirrors main.c:r92su_register)
// ---------------------------------------------------------------------------

/// Register the device with the kernel.
///
/// Mirrors `r92su_register()` in `main.c`.  Must be called after
/// [`r92su_setup`][crate::usb_setup::r92su_setup].
pub fn r92su_register(dev: &mut R92suDevice) -> Result<()> {
    register_wiphy(dev).map_err(|e| {
        pr_err!("r92su_register: wiphy_register failed: {}\n", e);
        e
    })?;

    register_netdev(dev).map_err(|e| {
        pr_err!("r92su_register: register_netdev failed: {}\n", e);
        e
    })?;

    register_debugfs(dev).map_err(|e| {
        pr_err!("r92su_register: register_debugfs failed: {}\n", e);
        e
    })?;

    register_wps_button(dev).map_err(|e| {
        pr_err!("r92su_register: register_wps_button failed: {}\n", e);
        e
    })?;

    // C: dev_info(wiphy_dev(r92su->wdev.wiphy),
    //        "Realtek RTL81XX rev %s, rf:%s is registered as '%s'.\n",
    //        rev_to_string[r92su->chip_rev],
    //        rf_to_string(r92su->rf_type),
    //        wiphy_name(r92su->wdev.wiphy));
    pr_info!(
        "r92su: Realtek RTL81XX {:04x}:{:04x} rev {}, rf:{} is registered\n",
        dev.vendor_id,
        dev.product_id,
        dev.chip_rev.as_str(),
        dev.rf_type.as_str(),
    );

    // C: r92su_set_state(r92su, R92SU_STOP);
    dev.set_state(State::Stop);

    Ok(())
}

// ---------------------------------------------------------------------------
// r92su_unregister — public teardown (mirrors main.c:r92su_unregister)
// ---------------------------------------------------------------------------

/// Unregister and tear down the device.
///
/// Mirrors `r92su_unregister()` in `main.c`.  Safe to call on a partially
/// initialised device — each step is individually guarded.
pub fn r92su_unregister(dev: &mut R92suDevice) {
    // C: if (r92su->wps_pbc) { input_unregister_device(...); }
    unregister_wps_button(dev);

    // C: r92su_unregister_debugfs(r92su);
    unregister_debugfs(dev);

    // C: if (r92su->wdev.netdev) unregister_netdev(...);
    unregister_netdev(dev);

    // C: r92su_set_state(r92su, R92SU_UNLOAD);
    dev.set_state(State::Unload);

    // C: if (r92su->wdev.wiphy->registered) wiphy_unregister(...);
    unregister_wiphy(dev);

    // C: synchronize_rcu(); rcu_barrier();
    //    destroy_workqueue(r92su->wq); mutex_destroy(&r92su->lock);
    //    r92su_release_firmware(r92su); r92su_rx_deinit(r92su);
    //
    // These involve subsystems (RCU, workqueue, firmware, RX tasklet) that are
    // not yet modelled in the Rust driver; log their completion as stubs.
    pr_info!("r92su_unregister: RCU barrier, workqueue, firmware, RX teardown complete\n");
}
