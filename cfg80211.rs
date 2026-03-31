// SPDX-License-Identifier: GPL-2.0
//! Safe Rust wrapper around the kernel's cfg80211 / wiphy subsystem.
//!
//! Only the subset of the API used by `r92su_alloc` is exposed here.
//! All types from `<net/cfg80211.h>` that are not in the pre-generated
//! `kernel::bindings` are accessed through the C helpers in `rust_helpers.c`.

use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Signal type (mirrors enum cfg80211_signal_type)
// ---------------------------------------------------------------------------

/// Signal-strength reporting convention advertised to cfg80211
/// (`wiphy->signal_type`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SignalType {
    None = 0,
    Mbm = 1,
    Unspec = 2,
}

// ---------------------------------------------------------------------------
// extern "C" — C helpers and exported kernel functions
// ---------------------------------------------------------------------------

extern "C" {
    /// `rust_helper_wiphy_new` — wrapper around the inline `wiphy_new()`.
    fn rust_helper_wiphy_new(ops: *const c_void, sizeof_priv: c_int) -> *mut c_void;

    /// `wiphy_register` — exported by cfg80211, registers the wiphy with the
    /// wireless subsystem and makes it visible to userspace (`iw phy`).
    fn wiphy_register(wiphy: *mut c_void) -> c_int;

    /// `wiphy_unregister` — exported by cfg80211, removes the wiphy from the
    /// wireless subsystem. Must be called before `wiphy_free`.
    fn wiphy_unregister(wiphy: *mut c_void);

    /// `wiphy_free` — exported by cfg80211, frees a wiphy allocated with
    /// `wiphy_new`.
    fn wiphy_free(wiphy: *mut c_void);

    /// `rust_helper_wiphy_priv` — wrapper around the inline `wiphy_priv()`.
    fn rust_helper_wiphy_priv(wiphy: *mut c_void) -> *mut c_void;

    /// `rust_helper_set_wiphy_dev` — wrapper around the inline
    /// `set_wiphy_dev()`.
    fn rust_helper_set_wiphy_dev(wiphy: *mut c_void, dev: *mut c_void);

    fn rust_helper_wiphy_set_interface_modes(wiphy: *mut c_void, modes: u16);
    fn rust_helper_wiphy_set_max_scan_ssids(wiphy: *mut c_void, val: u8);
    fn rust_helper_wiphy_set_max_scan_ie_len(wiphy: *mut c_void, val: u16);
    fn rust_helper_wiphy_set_signal_type(wiphy: *mut c_void, t: c_int);
    fn rust_helper_wiphy_set_cipher_suites(wiphy: *mut c_void, suites: *const u32, n: c_int);

    /// `rust_helper_sizeof_band_2ghz` — returns
    /// `sizeof(struct ieee80211_supported_band)`.
    ///
    /// Used to size the wiphy private area so the per-device band struct can
    /// be stored there (mirrors the C driver embedding `band_2GHZ` inside
    /// `struct r92su` in the wiphy private area).
    fn rust_helper_sizeof_band_2ghz() -> c_int;

    /// `rust_helper_wiphy_set_band_2ghz` — initialise the 2.4 GHz band in
    /// the wiphy private area and assign `wiphy->bands[NL80211_BAND_2GHZ]`.
    ///
    /// Must be called after `wiphy_new()` with
    /// `sizeof_priv >= sizeof(struct ieee80211_supported_band)`.
    fn rust_helper_wiphy_set_band_2ghz(
        wiphy: *mut c_void,
        ht_supported: bool,
        rx_mask_1: u8,
        rx_highest: u16,
    );

    /// The module-level `cfg80211_ops` defined in `rust_helpers.c`.
    /// All function pointers are NULL (operation not supported) until the
    /// corresponding Rust handlers are wired up.
    static r92su_cfg80211_ops: c_void;

    /// `rust_helper_set_cfg80211_ops_scan` — set the .scan callback.
    fn rust_helper_set_cfg80211_ops_scan(
        scan_fn: Option<extern "C" fn(wiphy: *mut c_void, request: *mut c_void) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_abort_scan` — set the .abort_scan callback.
    fn rust_helper_set_cfg80211_ops_abort_scan(
        abort_fn: Option<extern "C" fn(wiphy: *mut c_void, request: *mut c_void) -> c_int>,
    );

    /// `rust_helper_cfg80211_scan_done` — notify cfg80211 that scan is complete.
    fn rust_helper_cfg80211_scan_done(request: *mut c_void, aborted: bool);

    /// `rust_helper_cfg80211_inform_bss_data` — inform cfg80211 of a discovered BSS.
    fn rust_helper_cfg80211_inform_bss_data(
        wiphy: *mut c_void,
        channel: *mut c_void,
        bssid: *const u8,
        tsf: u64,
        capability: u16,
        beacon_interval: u16,
        ie: *const u8,
        ielen: usize,
        gfp: c_int,
    ) -> *mut c_void;

    /// `rust_helper_cfg80211_put_bss` — release BSS reference.
    fn rust_helper_cfg80211_put_bss(bss: *mut c_void);

    /// `rust_helper_ieee80211_channel_to_frequency` — convert channel to frequency.
    fn rust_helper_ieee80211_channel_to_frequency(chan: c_int, band: c_int) -> c_int;

    /// `rust_helper_wiphy_get_channel` — get ieee80211_channel by channel number.
    fn rust_helper_wiphy_get_channel(wiphy: *mut c_void, ch_num: u8) -> *mut c_void;

    /// `rust_helper_set_cfg80211_ops_get_station` — set the .get_station callback.
    fn rust_helper_set_cfg80211_ops_get_station(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *const u8, *mut c_void) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_dump_station` — set the .dump_station callback.
    fn rust_helper_set_cfg80211_ops_dump_station(
        fn_ptr: Option<
            extern "C" fn(*mut c_void, *mut c_void, c_int, *mut u8, *mut c_void) -> c_int,
        >,
    );

    /// `rust_helper_set_cfg80211_ops_change_virtual_intf` — set the .change_virtual_intf callback.
    fn rust_helper_set_cfg80211_ops_change_virtual_intf(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, c_int, *mut c_void) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_join_ibss` — set the .join_ibss callback.
    fn rust_helper_set_cfg80211_ops_join_ibss(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_leave_ibss` — set the .leave_ibss callback.
    fn rust_helper_set_cfg80211_ops_leave_ibss(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_set_wiphy_params` — set the .set_wiphy_params callback.
    fn rust_helper_set_cfg80211_ops_set_wiphy_params(
        fn_ptr: Option<extern "C" fn(*mut c_void, c_int, u32) -> c_int>,
    );

    /// `rust_helper_set_cfg80211_ops_set_monitor_channel` — set the .set_monitor_channel callback.
    fn rust_helper_set_cfg80211_ops_set_monitor_channel(
        fn_ptr: Option<extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int>,
    );

    /// `rust_helper_debugfs_create` — create debugfs entries for the device.
    pub fn rust_helper_debugfs_create(dev: *mut c_void, wiphy: *mut c_void) -> *mut c_void;

    /// `rust_helper_debugfs_remove` — remove debugfs entries.
    pub fn rust_helper_debugfs_remove(dfs: *mut c_void);

    /// `rust_helper_debug_ring_add` — add a register read to the debug ring.
    pub fn rust_helper_debug_ring_add(ring: *mut c_void, reg: u32, value: u32, mem_type: c_int);

    /// `rust_helper_debugfs_set_callbacks` — register Rust callbacks for debugfs reads.
    pub fn rust_helper_debugfs_set_callbacks(
        dev_ptr: *mut c_void,
        get_tx_pending_urbs: Option<extern "C" fn(*mut c_void) -> c_int>,
        get_chip_rev: Option<extern "C" fn(*mut c_void) -> c_int>,
        get_rf_type: Option<extern "C" fn(*mut c_void) -> c_int>,
        get_eeprom_type: Option<extern "C" fn(*mut c_void) -> c_int>,
        get_h2c_seq: Option<extern "C" fn(*mut c_void) -> u8>,
        get_c2h_seq: Option<extern "C" fn(*mut c_void) -> u8>,
        get_cpwm: Option<extern "C" fn(*mut c_void) -> u8>,
        get_rpwm: Option<extern "C" fn(*mut c_void) -> u8>,
        get_rx_queue_len: Option<extern "C" fn(*mut c_void) -> c_int>,
    );
}

// ---------------------------------------------------------------------------
// band_2ghz_storage_size — private-data size needed for band storage
// ---------------------------------------------------------------------------

/// Returns `sizeof(struct ieee80211_supported_band)`.
///
/// Pass this as `sizeof_priv` to [`Wiphy::new`] so that
/// [`Wiphy::set_band_2ghz`] can store the per-device band descriptor in the
/// wiphy's private-data area (the same layout the C driver uses by embedding
/// `band_2GHZ` inside `struct r92su`).
pub fn band_2ghz_storage_size() -> usize {
    // SAFETY: pure C helper with no side effects, always returns a positive
    // constant (sizeof(struct ieee80211_supported_band)).
    unsafe { rust_helper_sizeof_band_2ghz() as usize }
}

// ---------------------------------------------------------------------------
// Wiphy — owned wrapper around `struct wiphy *`
// ---------------------------------------------------------------------------

/// Owned wrapper around a `struct wiphy *` allocated by `wiphy_new`.
///
/// Calls `wiphy_unregister` (if registered) then `wiphy_free` when dropped.
pub struct Wiphy {
    ptr: NonNull<c_void>,
    registered: bool,
}

// SAFETY: `struct wiphy` is accessed only through the cfg80211 API, which
// enforces its own locking.  The pointer is valid for the lifetime of `Wiphy`.
unsafe impl Send for Wiphy {}
unsafe impl Sync for Wiphy {}

impl Wiphy {
    /// Allocate a new wiphy with `sizeof_priv` bytes of driver-private storage.
    ///
    /// Mirrors:
    /// ```c
    /// wiphy = wiphy_new(&r92su_cfg80211_ops, sizeof_priv);
    /// if (!wiphy) return -ENOMEM;
    /// ```
    pub fn new(sizeof_priv: usize) -> Result<Self> {
        // SAFETY: `r92su_cfg80211_ops` is a valid static `cfg80211_ops`
        // defined in `rust_helpers.c`.  `sizeof_priv` fits in `c_int`.
        let ptr = unsafe {
            rust_helper_wiphy_new(
                core::ptr::addr_of!(r92su_cfg80211_ops),
                sizeof_priv as c_int,
            )
        };
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self {
                ptr,
                registered: false,
            }),
            None => Err(ENOMEM),
        }
    }

    /// Raw pointer to the underlying `struct wiphy`.
    pub fn as_ptr(&self) -> *mut c_void {
        self.ptr.as_ptr()
    }

    /// Create a Wiphy from a raw pointer (for callbacks).
    ///
    /// # Safety
    /// The pointer must be a valid `struct wiphy *`.
    pub unsafe fn from_ptr(ptr: *mut c_void) -> Self {
        Self {
            ptr: NonNull::new(ptr).expect("invalid wiphy pointer"),
            registered: false,
        }
    }

    /// Associate the wiphy with a kernel `struct device`.
    ///
    /// Mirrors `set_wiphy_dev(wiphy, dev)`.
    ///
    /// # Safety
    /// `dev` must be a valid pointer to a live `struct device`.
    pub unsafe fn set_device(&self, dev: *mut c_void) {
        // SAFETY: caller guarantees `dev` is valid; `self.ptr` is valid by
        // construction.
        unsafe { rust_helper_set_wiphy_dev(self.ptr.as_ptr(), dev) };
    }

    /// Set `wiphy->interface_modes` (bitmask of `BIT(NL80211_IFTYPE_*)`).
    pub fn set_interface_modes(&self, modes: u16) {
        // SAFETY: `self.ptr` is valid for the lifetime of `Wiphy`.
        unsafe { rust_helper_wiphy_set_interface_modes(self.ptr.as_ptr(), modes) };
    }

    /// Set `wiphy->max_scan_ssids`.
    pub fn set_max_scan_ssids(&self, val: u8) {
        // SAFETY: `self.ptr` is valid for the lifetime of `Wiphy`.
        unsafe { rust_helper_wiphy_set_max_scan_ssids(self.ptr.as_ptr(), val) };
    }

    /// Set `wiphy->max_scan_ie_len`.
    pub fn set_max_scan_ie_len(&self, val: u16) {
        // SAFETY: `self.ptr` is valid for the lifetime of `Wiphy`.
        unsafe { rust_helper_wiphy_set_max_scan_ie_len(self.ptr.as_ptr(), val) };
    }

    /// Set `wiphy->signal_type`.
    pub fn set_signal_type(&self, t: SignalType) {
        // SAFETY: `self.ptr` is valid for the lifetime of `Wiphy`.
        unsafe { rust_helper_wiphy_set_signal_type(self.ptr.as_ptr(), t as c_int) };
    }

    /// Set `wiphy->cipher_suites` and `wiphy->n_cipher_suites`.
    ///
    /// # Safety
    /// `suites` must remain valid and immutable for as long as the wiphy is
    /// registered.  Using a `'static` slice (e.g. a module-level constant)
    /// satisfies this requirement.
    pub unsafe fn set_cipher_suites(&self, suites: &'static [u32]) {
        // SAFETY: `suites` is `'static` per the caller's contract; `self.ptr`
        // is valid for the lifetime of `Wiphy`.
        unsafe {
            rust_helper_wiphy_set_cipher_suites(
                self.ptr.as_ptr(),
                suites.as_ptr(),
                suites.len() as c_int,
            )
        };
    }

    /// Initialise the 2.4 GHz band in the wiphy private area and assign
    /// `wiphy->bands[NL80211_BAND_2GHZ]`.
    ///
    /// Mirrors `r92su_init_band()` from `main.c`.  Must be called before
    /// [`register`][Self::register].  The wiphy must have been allocated with
    /// `sizeof_priv >= band_2ghz_storage_size()` (i.e. via
    /// `Wiphy::new(band_2ghz_storage_size())`).
    pub fn set_band_2ghz(&self, ht_supported: bool, rx_mask_1: u8, rx_highest: u16) {
        // SAFETY: `self.ptr` is a valid `struct wiphy *` allocated by
        // `wiphy_new` with `sizeof_priv >= sizeof(struct
        // ieee80211_supported_band)`.  The C helper writes only into the wiphy
        // private area and into `wiphy->bands[NL80211_BAND_2GHZ]`; both are
        // valid for the lifetime of the wiphy.
        unsafe {
            rust_helper_wiphy_set_band_2ghz(self.ptr.as_ptr(), ht_supported, rx_mask_1, rx_highest)
        };
    }

    /// Register the wiphy with cfg80211, making it visible to userspace.
    ///
    /// Mirrors `wiphy_register(r92su->wdev.wiphy)`.  Returns an error if the
    /// kernel call fails or if the wiphy is already registered.
    pub fn register(&mut self) -> Result<()> {
        if self.registered {
            return Ok(());
        }
        // SAFETY: `self.ptr` is a valid `struct wiphy *` allocated by
        // `wiphy_new`.  All required fields (interface_modes, signal_type,
        // cipher_suites, etc.) must have been set before calling this.
        let ret = unsafe { wiphy_register(self.ptr.as_ptr()) };
        if ret < 0 {
            return Err(kernel::error::Error::from_errno(ret));
        }
        self.registered = true;
        Ok(())
    }

    /// Unregister the wiphy from cfg80211.
    ///
    /// Mirrors the guarded `wiphy_unregister()` call in `r92su_unregister()`.
    /// Safe to call more than once — subsequent calls are no-ops.
    pub fn unregister(&mut self) {
        if self.registered {
            // SAFETY: `self.ptr` is valid and `wiphy_register` completed
            // successfully (tracked by `self.registered`).
            unsafe { wiphy_unregister(self.ptr.as_ptr()) };
            self.registered = false;
        }
    }
}

impl Drop for Wiphy {
    fn drop(&mut self) {
        // Unregister first if the explicit teardown path was not taken.
        self.unregister();
        // SAFETY: `self.ptr` was returned by `wiphy_new` and has not been
        // freed — `Wiphy` is the unique owner of this allocation.
        unsafe { wiphy_free(self.ptr.as_ptr()) };
    }
}

pub fn wiphy_priv(wiphy: *mut c_void) -> *mut c_void {
    // SAFETY: wiphy is valid, this just calls the C helper.
    unsafe { rust_helper_wiphy_priv(wiphy) }
}
