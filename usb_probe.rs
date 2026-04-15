// SPDX-License-Identifier: GPL-2.0
//! USB probe path for RTL8192SU.
//!
//! Bridges the kernel USB framework (`usb::Interface<Core>`) to the
//! device-initialisation logic in [`crate::r92u`].

use core::ffi::c_void;
use kernel::{bindings, device::Core, prelude::*, usb};

use crate::cfg80211_misc;
use crate::connect;
use crate::keys;
use crate::mgmt_frame;
use crate::power_mgmt;
use crate::r92u::{r92su_usb_init, EndpointDirection, EndpointType, R92suDevice, UsbEndpoint};
use crate::r92u_alloc::r92su_alloc;
use crate::r92u_open;
use crate::scan;

use crate::station_info;
use crate::tdls;
use crate::usb_register::r92su_register;
use crate::usb_setup::r92su_setup;

const USB_DIR_IN: u8 = 0x80;
const USB_ENDPOINT_XFER_BULK: u8 = 0x02;
const USB_ENDPOINT_XFER_INT: u8 = 0x03;
const USB_ENDPOINT_XFER_ISO: u8 = 0x01;

/// Probe the RTL8192SU USB interface.
///
/// Mirrors the probe path from the C driver:
///   1. [`r92su_alloc`] — allocate and configure the wiphy / device state
///   2. Retrieve vendor/product IDs via `interface_to_usbdev()`
///   3. Walk `cur_altsetting->endpoint[]` to collect all endpoints
///   4. [`r92su_usb_init`] — endpoint discovery, URB allocation, hw registers
pub fn r92su_usb_probe(
    intf: &usb::Interface<Core>,
    firmware: &'static [u8],
    disable_ht: bool,
) -> Result<KBox<R92suDevice>> {
    // SAFETY: `intf` is a valid `usb::Interface<Core>` provided by the USB
    // driver framework. `Interface<Core>` is `#[repr(transparent)]` over
    // `Opaque<bindings::usb_interface>`, which is layout-compatible with
    // `bindings::usb_interface` through the `repr(transparent)` chain:
    // `Opaque<T>` → `UnsafeCell<MaybeUninit<T>>` → `T`.
    // We only read fields that the USB core guarantees are stable during probe:
    // `cur_altsetting`, its `endpoint[]` array, and `dev` (the interface device).
    let (vendor_id, product_id, endpoints, intf_dev, udev) = unsafe {
        let raw_intf = intf as *const usb::Interface<Core> as *mut bindings::usb_interface;

        // interface_to_usbdev(intf) — walks the kobject parent chain to struct usb_device.
        let udev = bindings::interface_to_usbdev(raw_intf);
        let vendor_id = (*udev).descriptor.idVendor;
        let product_id = (*udev).descriptor.idProduct;

        // &intf->dev — the struct device for SET_NETDEV_DEV / set_wiphy_dev.
        let intf_dev = core::ptr::addr_of_mut!((*raw_intf).dev) as *mut c_void;

        // intf->cur_altsetting — active alternate setting chosen during enumeration.
        let iface_desc = (*raw_intf).cur_altsetting;
        let num_endpoints = (*iface_desc).desc.bNumEndpoints as usize;
        let ep_array = (*iface_desc).endpoint;

        let mut eps: KVec<UsbEndpoint> =
            KVec::with_capacity(num_endpoints, GFP_KERNEL).map_err(|_| ENOMEM)?;

        // C: for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
        //        ep = &iface_desc->endpoint[i].desc; ... }
        for i in 0..num_endpoints {
            let desc = &(*ep_array.add(i)).desc;
            let addr = desc.bEndpointAddress;
            let direction = if addr & USB_DIR_IN != 0 {
                EndpointDirection::In
            } else {
                EndpointDirection::Out
            };
            let ep_type = match desc.bmAttributes & 0x03 {
                USB_ENDPOINT_XFER_BULK => EndpointType::Bulk,
                USB_ENDPOINT_XFER_INT => EndpointType::Interrupt,
                USB_ENDPOINT_XFER_ISO => EndpointType::Isochronous,
                _ => EndpointType::Control,
            };
            eps.push(
                UsbEndpoint {
                    address: addr,
                    direction,
                    ep_type,
                    max_packet_size: desc.wMaxPacketSize,
                },
                GFP_KERNEL,
            )
            .map_err(|_| ENOMEM)?;
        }

        (vendor_id, product_id, eps, intf_dev, udev)
    };

    // r92su_alloc(): allocate the device state and configure wiphy parameters.
    let mut dev = r92su_alloc(vendor_id, product_id, disable_ht).map_err(|e| {
        pr_err!("r92su: alloc failed\n");
        e
    })?;

    // Store the USB device pointer so that r92su_setup() can perform real
    // register I/O (EFUSE reads, chip version) via USB vendor control transfers.
    // SAFETY: `udev` is the USB device owning the interface; it is kept alive
    // by the USB core for the entire lifetime of the interface (probe → disconnect).
    dev.udev = udev;
    dev.firmware = firmware;

    // C: set_wiphy_dev(r92su->wdev.wiphy, main_dev)
    // Associates the wiphy with the USB interface device so that
    // wiphy_dev() returns the correct struct device *.
    if let Some(wiphy) = dev.wiphy.as_ref() {
        // SAFETY: `intf_dev` is `&intf->dev`, valid for the lifetime of the
        // USB interface.  `wiphy` is valid by construction.
        unsafe { wiphy.set_device(intf_dev) };
    }

    r92su_usb_init(&mut dev, &endpoints, firmware).map_err(|e| {
        pr_err!("r92su: usb_init failed: {}\n", e);
        EINVAL
    })?;

    // ── r92su_setup: rx/cmd init, chip version, EEPROM, band, netdev ─────────
    r92su_setup(&mut dev, intf_dev).map_err(|e| {
        pr_err!("r92su: setup failed: {}\n", e);
        EINVAL
    })?;

    // ── r92su_register: wiphy, netdev, debugfs registration ──────────────────
    r92su_register(&mut dev).map_err(|e| {
        pr_err!("r92su: register failed: {}\n", e);
        EINVAL
    })?;

    // Register ndo_open callback so firmware is uploaded on interface up.
    r92u_open::ndo_open_init();

    // Register ndo_start_xmit and ndo_stop callbacks.
    r92u_open::ndo_xmit_stop_init();

    // Initialise scan subsystem and register callbacks.
    scan::init();

    // Initialise connect/disconnect subsystem and register callbacks.
    connect::init();

    // Initialise key management and register add/del/set_default_key callbacks.
    keys::init();

    // Initialise station info operations for get_station/dump_station.
    station_info::init();

    // Initialise misc cfg80211 operations.
    cfg80211_misc::init();

    // Initialise mgmt_frame_register callback.
    mgmt_frame::init();

    // Initialise TDLS callbacks.
    tdls::init();

    // Initialise power management callback.
    power_mgmt::init();

    Ok(dev)
}
