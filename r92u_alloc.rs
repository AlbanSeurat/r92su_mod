// SPDX-License-Identifier: GPL-2.0
//! Allocation and cfg80211 / wiphy initialisation for RTL8192SU.
//!
//! Mirrors `r92su_alloc()` from `r92su/main.c`.

use kernel::prelude::*;

use crate::cfg80211::{band_2ghz_storage_size, wiphy_priv, SignalType, Wiphy};
use crate::r92u::{R92suDevice, State};

// ---------------------------------------------------------------------------
// NL80211 interface-type constants (from uapi/linux/nl80211.h)
// ---------------------------------------------------------------------------

/// NL80211_IFTYPE_ADHOC
pub const NL80211_IFTYPE_ADHOC: u32 = 1;
/// NL80211_IFTYPE_STATION
pub const NL80211_IFTYPE_STATION: u32 = 2;
/// NL80211_IFTYPE_MONITOR
pub const NL80211_IFTYPE_MONITOR: u32 = 6;
/// NL80211_IFTYPE_P2P_CLIENT
pub const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
/// NL80211_IFTYPE_P2P_GO
pub const NL80211_IFTYPE_P2P_GO: u32 = 7;

/// NUM_NL80211_IFTYPES - number of interface types
pub const NUM_NL80211_IFTYPES: usize = 9;

// ---------------------------------------------------------------------------
// WLAN cipher suite OUIs (from linux/ieee80211.h / WLAN_CIPHER_SUITE_*)
// ---------------------------------------------------------------------------

/// Cipher suites advertised to cfg80211 (mirrors `r92su_chiper_suites[]`).
///
/// `'static` lifetime is required by `Wiphy::set_cipher_suites` so that the
/// pointer remains valid for the entire lifetime of the registered wiphy.
pub static CIPHER_SUITES: [u32; 4] = [
    0x000F_AC01, // WLAN_CIPHER_SUITE_WEP40
    0x000F_AC05, // WLAN_CIPHER_SUITE_WEP104
    0x000F_AC02, // WLAN_CIPHER_SUITE_TKIP
    0x000F_AC04, // WLAN_CIPHER_SUITE_CCMP
];

/// Management frame subtypes supported for rx (mirrors `ieee80211_txrx_stypes`).
///
/// Used to enable mgmt frame registration in cfg80211 (required for wpa_supplicant
/// action frame support). Indexed by NL80211_IFTYPE_*.
///
/// Each entry is a struct with tx and rx bitmasks. The bitmasks use
/// (IEEE80211_STYPE_XXX >> 4) as the bit index.
#[repr(C)]
pub struct Ieee80211TxrxStypes {
    pub tx: u16,
    pub rx: u16,
}

/// Default mgmt frame stypes - allows ACTION frames for station mode (needed for
/// wpa_supplicant P2P/mesh operations) and probe requests.
pub static DEFAULT_MGMT_STYPES: [Ieee80211TxrxStypes; NUM_NL80211_IFTYPES] = [
    // IFTYPE_UNSPECIFIED (0)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // NL80211_IFTYPE_ADHOC (1)
    Ieee80211TxrxStypes {
        tx: 0xffff,
        rx: 0x2000, // BIT(IEEE80211_STYPE_ACTION >> 4) = BIT(13)
    },
    // NL80211_IFTYPE_STATION (2) - needed for wpa_supplicant
    Ieee80211TxrxStypes {
        tx: 0xffff,
        rx: 0x2000 | 0x0010, // ACTION (BIT(13)) + PROBE_REQ (BIT(4))
    },
    // IFTYPE_AP (3)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // IFTYPE_AP_VLAN (4)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // IFTYPE_WDS (5)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // NL80211_IFTYPE_MONITOR (6)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // NL80211_IFTYPE_P2P_GO (7)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
    // NL80211_IFTYPE_P2P_CLIENT (8)
    Ieee80211TxrxStypes { tx: 0, rx: 0 },
];

// ---------------------------------------------------------------------------
// r92su_alloc
// ---------------------------------------------------------------------------

/// Allocate and initialise a new [`R92suDevice`], including the real
/// `struct wiphy` managed through [`Wiphy`].
///
/// Mirrors `r92su_alloc(struct device *main_dev)` from `r92su/main.c`:
///
/// ```c
/// wiphy = wiphy_new(&r92su_cfg80211_ops, sizeof(struct r92su));
/// if (!wiphy) return ERR_PTR(-ENOMEM);
/// r92su = wiphy_priv(wiphy);
/// r92su->wdev.wiphy = wiphy;
/// mutex_init(&r92su->lock);
/// spin_lock_init(&r92su->rx_path);
/// if (modparam_noht) r92su->disable_ht = true;
/// INIT_LIST_HEAD(&r92su->sta_list);
/// spin_lock_init(&r92su->sta_lock);
/// set_wiphy_dev(r92su->wdev.wiphy, main_dev);
/// r92su->wdev.iftype = NL80211_IFTYPE_STATION;
/// wiphy->interface_modes = BIT(STATION)|BIT(ADHOC)|BIT(MONITOR);
/// wiphy->max_scan_ssids  = 1;
/// wiphy->max_scan_ie_len = 256;
/// wiphy->signal_type     = CFG80211_SIGNAL_TYPE_UNSPEC;
/// wiphy->cipher_suites   = r92su_chiper_suites;
/// init_completion(&r92su->scan_done);
/// r92su_hw_init(r92su);   /* INIT_DELAYED_WORK for service_work */
/// r92su->wq = create_singlethread_workqueue(R92SU_DRVNAME);
/// ```
///
/// # Parameters
/// - `vendor_id`  — USB idVendor from the device descriptor.
/// - `product_id` — USB idProduct from the device descriptor.
/// - `disable_ht` — mirrors the `noht` module parameter.
///
/// # Errors
/// Returns `ENOMEM` when `wiphy_new` fails (mirrors `ERR_PTR(-ENOMEM)`).
pub fn r92su_alloc(vendor_id: u16, product_id: u16, disable_ht: bool) -> Result<KBox<R92suDevice>> {
    // wiphy_new(&r92su_cfg80211_ops, sizeof(struct ieee80211_supported_band))
    //
    // The C driver embeds `struct r92su` (which contains `band_2GHZ`) in the
    // wiphy private area.  In this Rust port the rest of the device state
    // lives in `R92suDevice`, but we still need the wiphy private area to
    // hold the `struct ieee80211_supported_band` so that
    // `wiphy->bands[NL80211_BAND_2GHZ]` points to a valid allocation whose
    // lifetime is tied to the wiphy.
    let wiphy = Wiphy::new(band_2ghz_storage_size())?;

    // if (modparam_noht) r92su->disable_ht = true;
    // r92su->wdev.iftype = NL80211_IFTYPE_STATION;
    // (set on R92suDevice below)

    // wiphy->interface_modes = BIT(STATION) | BIT(ADHOC) | BIT(MONITOR);
    wiphy.set_interface_modes(
        ((1u32 << NL80211_IFTYPE_STATION)
            | (1u32 << NL80211_IFTYPE_ADHOC)
            | (1u32 << NL80211_IFTYPE_MONITOR)) as u16,
    );

    // wiphy->max_scan_ssids = 1;
    wiphy.set_max_scan_ssids(1);

    // wiphy->max_scan_ie_len = 256;
    wiphy.set_max_scan_ie_len(256);

    // wiphy->signal_type = CFG80211_SIGNAL_TYPE_UNSPEC;
    wiphy.set_signal_type(SignalType::Unspec);

    // wiphy->cipher_suites = r92su_chiper_suites;
    // wiphy->n_cipher_suites = ARRAY_SIZE(r92su_chiper_suites);
    //
    // SAFETY: `CIPHER_SUITES` is a `'static` array; its address remains
    // valid for the entire lifetime of the wiphy.
    unsafe { wiphy.set_cipher_suites(&CIPHER_SUITES) };

    // wiphy->mgmt_stypes = r92su_default_mgmt_stypes;
    //
    // SAFETY: `DEFAULT_MGMT_STYPES` is a `'static` array; its address remains
    // valid for the entire lifetime of the wiphy.
    unsafe { wiphy.set_mgmt_stypes(DEFAULT_MGMT_STYPES.as_ptr() as *const core::ffi::c_void) };

    // set_wiphy_dev() is called later in usb_probe once the USB device
    // pointer is available (mirrors the C flow where main_dev is passed in
    // as the first argument).

    // Build the Rust device state on the heap so its address is stable.
    let mut dev =
        KBox::new(R92suDevice::new(vendor_id, product_id), GFP_KERNEL).map_err(|_| ENOMEM)?;

    // Attach the wiphy — `dev` now owns it and will call `wiphy_free` on drop.
    dev.wiphy = Some(wiphy);

    // Store the stable heap address in the wiphy private area so that
    // cfg80211 callbacks can recover the device pointer via wiphy_priv().
    // The private area layout is: [*mut R92suDevice][ieee80211_supported_band].
    // SAFETY: wiphy was just allocated above; the private area is sized to
    // hold sizeof(void*) + sizeof(ieee80211_supported_band) bytes.  We write
    // only to the first sizeof(void*) bytes (the device pointer slot).
    let dev_ptr: *mut R92suDevice = &mut *dev as *mut R92suDevice;
    if let Some(w) = dev.wiphy.as_ref() {
        unsafe {
            let slot = wiphy_priv(w.as_ptr()) as *mut *mut R92suDevice;
            slot.write(dev_ptr);
        }
    }

    // if (modparam_noht) r92su->disable_ht = true;
    dev.disable_ht = disable_ht;

    // r92su->wdev.iftype = NL80211_IFTYPE_STATION;
    dev.iftype = NL80211_IFTYPE_STATION;

    // Mirror the derived fields that were stored on R92suDevice as a cache of
    // what was written to the wiphy.
    dev.interface_modes =
        (1 << NL80211_IFTYPE_STATION) | (1 << NL80211_IFTYPE_ADHOC) | (1 << NL80211_IFTYPE_MONITOR);
    dev.max_scan_ssids = 1;
    dev.max_scan_ie_len = 256;

    // init_completion(&r92su->scan_done): not yet signalled.
    dev.scan_done = false;

    // r92su_hw_init(): INIT_DELAYED_WORK(&r92su->service_work, …)
    dev.service_work_scheduled = false;

    pr_debug!(
        "r92su_alloc: device {:04x}:{:04x} allocated (disable_ht={})\n",
        vendor_id,
        product_id,
        disable_ht
    );

    // Device is allocated but not yet open.
    dev.set_state(State::Unload);

    Ok(dev) //
}
