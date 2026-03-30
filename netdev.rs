// SPDX-License-Identifier: GPL-2.0
//! Rust wrappers around `struct wireless_dev` and `struct net_device`.
//!
//! Both types are opaque to the kernel Rust bindings, so we access them only
//! through the C helpers defined in `rust_helpers.c`.
//!
//! # Ownership and drop order
//!
//! The kernel's `net_device` holds `ndev->ieee80211_ptr` pointing to the
//! `wireless_dev`.  Therefore [`NetDev`] must be dropped (and the netdevice
//! unregistered) **before** [`WirelessDev`] is freed.  Callers that embed
//! both in the same struct must declare [`NetDev`] before [`WirelessDev`] so
//! that Rust's field-in-declaration-order drop semantics give the right
//! sequence.

use core::ffi::c_void;
use core::ptr::NonNull;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// C helpers (defined in rust_helpers.c)
// ---------------------------------------------------------------------------

extern "C" {
    fn rust_helper_alloc_wdev(wiphy: *mut c_void, iftype: u32) -> *mut c_void;
    fn rust_helper_free_wdev(wdev: *mut c_void);

    fn rust_helper_alloc_netdev(
        wdev: *mut c_void,
        parent: *mut c_void,
        mac_addr: *const u8,
    ) -> *mut c_void;
    fn rust_helper_register_netdev(ndev: *mut c_void) -> i32;
    fn rust_helper_unregister_netdev(ndev: *mut c_void);
    fn rust_helper_free_netdev(ndev: *mut c_void);
}

// ---------------------------------------------------------------------------
// WirelessDev — owned wrapper around `struct wireless_dev *`
// ---------------------------------------------------------------------------

/// Owned wrapper around a kernel `struct wireless_dev *`.
///
/// Allocated by [`WirelessDev::new`] via `kzalloc`; freed by `kfree` on drop.
///
/// # Safety invariant
/// The wrapped pointer is valid from allocation until [`WirelessDev::drop`].
/// No access is permitted after the `WirelessDev` has been dropped.
pub struct WirelessDev {
    ptr: NonNull<c_void>,
}

// SAFETY: `struct wireless_dev` is accessed only through cfg80211 locking;
// the raw allocation itself is safe to move between threads.
unsafe impl Send for WirelessDev {}
unsafe impl Sync for WirelessDev {}

impl WirelessDev {
    /// Allocate and initialise a new `wireless_dev`.
    ///
    /// Mirrors:
    /// ```c
    /// wdev->wiphy  = wiphy;
    /// wdev->iftype = (enum nl80211_iftype)iftype;
    /// ```
    ///
    /// # Safety
    /// `wiphy` must be a valid `struct wiphy *` allocated by `wiphy_new`.
    pub unsafe fn new(wiphy: *mut c_void, iftype: u32) -> Result<Self> {
        // SAFETY: caller guarantees `wiphy` is valid.
        let ptr = unsafe { rust_helper_alloc_wdev(wiphy, iftype) };
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr }),
            None => Err(ENOMEM),
        }
    }

    /// Raw pointer to the underlying `struct wireless_dev`.
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }
}

impl Drop for WirelessDev {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was returned by `rust_helper_alloc_wdev` and has
        // not yet been freed.  The caller is responsible for ensuring that
        // `unregister_netdev` has been called first (clearing the kernel's
        // reference to this wdev), which is guaranteed by the field drop order
        // in `R92suDevice`.
        unsafe { rust_helper_free_wdev(self.ptr.as_ptr()) };
    }
}

// ---------------------------------------------------------------------------
// NetDev — owned wrapper around `struct net_device *`
// ---------------------------------------------------------------------------

/// Owned wrapper around a kernel `struct net_device *`.
///
/// Allocated by [`NetDev::new`] via `alloc_netdev_mqs`; freed either
/// automatically by the kernel (via `needs_free_netdev`) after
/// [`NetDev::unregister`], or explicitly via `free_netdev` if registration
/// was never attempted.
///
/// # Safety invariant
/// After [`NetDev::unregister`] or [`NetDev::drop`], the pointer may no
/// longer be valid (the kernel may free it asynchronously).  The `ptr` field
/// is set to `None` once ownership is relinquished.
pub struct NetDev {
    ptr: Option<NonNull<c_void>>,
    registered: bool,
}

// SAFETY: `struct net_device` is accessed only through the netdev API which
// enforces its own locking.
unsafe impl Send for NetDev {}
unsafe impl Sync for NetDev {}

impl NetDev {
    /// Allocate a new `net_device` linked to `wdev`.
    ///
    /// Mirrors `r92su_alloc_netdev()`:
    /// ```c
    /// ndev = alloc_netdev_mqs(0, "wlan%d", NET_NAME_UNKNOWN,
    ///                          r92su_if_setup, NUM_ACS, 1);
    /// ndev->ieee80211_ptr = wdev;
    /// wdev->netdev        = ndev;
    /// SET_NETDEV_DEV(ndev, parent);
    /// eth_hw_addr_set(ndev, mac_addr);
    /// ```
    ///
    /// # Safety
    /// - `wdev` must be a valid `struct wireless_dev *` that will outlive this
    ///   `NetDev` (guaranteed when both live in the same `R92suDevice` with
    ///   `NetDev` declared before `WirelessDev`).
    /// - `parent` must be a valid `struct device *` for the USB interface.
    pub unsafe fn new(wdev: *mut c_void, parent: *mut c_void, mac_addr: &[u8; 6]) -> Result<Self> {
        // SAFETY: caller guarantees `wdev` and `parent` are valid.
        let ptr = unsafe { rust_helper_alloc_netdev(wdev, parent, mac_addr.as_ptr()) };
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self {
                ptr: Some(ptr),
                registered: false,
            }),
            None => Err(ENOMEM),
        }
    }

    /// Register the net_device with the kernel networking stack.
    ///
    /// Mirrors `register_netdev(r92su->wdev.netdev)`.  After this call the
    /// interface appears as "wlanN" and cfg80211 has registered the associated
    /// `wireless_dev`.
    pub fn register(&mut self) -> Result<()> {
        if self.registered {
            return Ok(());
        }
        let ptr = self.ptr.ok_or(EINVAL)?;
        // SAFETY: `ptr` is a valid `struct net_device *`; all required fields
        // (ieee80211_ptr, dev_addr, etc.) were set by rust_helper_alloc_netdev.
        let ret = unsafe { rust_helper_register_netdev(ptr.as_ptr()) };
        if ret < 0 {
            return Err(kernel::error::Error::from_errno(ret));
        }
        self.registered = true;
        Ok(())
    }

    /// Unregister the net_device from the kernel networking stack.
    ///
    /// Mirrors the guarded `unregister_netdev()` call in `r92su_unregister()`.
    /// After this returns, cfg80211 has cleared its reference to the `wdev`
    /// and the kernel will free the `net_device` once its refcount drops to
    /// zero (`needs_free_netdev = true`).  The `ptr` is consumed here.
    pub fn unregister(&mut self) {
        if let Some(ptr) = self.ptr.take() {
            if self.registered {
                // SAFETY: `ptr` is valid and was successfully registered.
                unsafe { rust_helper_unregister_netdev(ptr.as_ptr()) };
                // After unregister_netdev the kernel owns the allocation;
                // do not call free_netdev.
                self.registered = false;
            } else {
                // Never registered — free directly.
                // SAFETY: `ptr` is valid and was never handed to the kernel
                // networking stack.
                unsafe { rust_helper_free_netdev(ptr.as_ptr()) };
            }
        }
    }

    /// Returns `true` if the net_device is currently registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

impl Drop for NetDev {
    fn drop(&mut self) {
        // Ensure the device is cleanly detached if the explicit teardown path
        // (r92su_unregister) was not taken.
        self.unregister();
    }
}
