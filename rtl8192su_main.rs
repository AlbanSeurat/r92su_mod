// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (C) 2026 Alban Seurat

//! RTL8192SU WLAN Driver - Rust cfg80211 FullMAC driver
//!
//! This module provides a USB-based WLAN driver using the cfg80211 subsystem.

mod anchor;
pub mod cfg80211;
mod cfg80211_misc;
mod cmd;
mod connect;
mod debugfs;
mod event;
mod fw;
mod keys;
mod netdev;
mod r92u;
mod r92u_alloc;
mod r92u_open;
mod rx;
mod scan;
mod sta;
mod station_info;
mod tx;
mod usb_probe;
mod usb_register;
mod usb_setup;

use kernel::{device::Core, prelude::*, usb};
use r92u::R92suDevice;
use usb_probe::r92su_usb_probe;

const DRIVER_VERSION: &str = "0.1.0";

pub struct DeviceInfo {
    pub vid: u16,
    pub pid: u16,
    pub disable_ht: bool,
}

kernel::usb_device_table!(
    USB_TABLE,
    MODULE_USB_TABLE,
    DeviceInfo,
    [
        // RTL8188SU devices
        (
            usb::DeviceId::from_id(0x0BDA, 0x8171),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8171,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x8173),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8173,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x8712),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8712,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x8713),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8713,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0xC047),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0xC047,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0xC512),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0xC512,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07B8, 0x8188),
            DeviceInfo {
                vid: 0x07B8,
                pid: 0x8188,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x083A, 0xC512),
            DeviceInfo {
                vid: 0x083A,
                pid: 0xC512,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x1B75, 0x8171),
            DeviceInfo {
                vid: 0x1B75,
                pid: 0x8171,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0B05, 0x1786),
            DeviceInfo {
                vid: 0x0B05,
                pid: 0x1786,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0B05, 0x1791),
            DeviceInfo {
                vid: 0x0B05,
                pid: 0x1791,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x050D, 0x945A),
            DeviceInfo {
                vid: 0x050D,
                pid: 0x945A,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x050D, 0x11F1),
            DeviceInfo {
                vid: 0x050D,
                pid: 0x11F1,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07AA, 0x0047),
            DeviceInfo {
                vid: 0x07AA,
                pid: 0x0047,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x2001, 0x3306),
            DeviceInfo {
                vid: 0x2001,
                pid: 0x3306,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07D1, 0x3306),
            DeviceInfo {
                vid: 0x07D1,
                pid: 0x3306,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x7392, 0x7611),
            DeviceInfo {
                vid: 0x7392,
                pid: 0x7611,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x1740, 0x9603),
            DeviceInfo {
                vid: 0x1740,
                pid: 0x9603,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0E66, 0x0016),
            DeviceInfo {
                vid: 0x0E66,
                pid: 0x0016,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x06F8, 0xE034),
            DeviceInfo {
                vid: 0x06F8,
                pid: 0xE034,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x06F8, 0xE032),
            DeviceInfo {
                vid: 0x06F8,
                pid: 0xE032,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0789, 0x0167),
            DeviceInfo {
                vid: 0x0789,
                pid: 0x0167,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x2019, 0xAB28),
            DeviceInfo {
                vid: 0x2019,
                pid: 0xAB28,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x2019, 0xED16),
            DeviceInfo {
                vid: 0x2019,
                pid: 0xED16,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0057),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0057,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0045),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0045,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0059),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0059,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x004B),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x004B,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x005B),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x005B,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x005D),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x005D,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0063),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0063,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x177F, 0x0154),
            DeviceInfo {
                vid: 0x177F,
                pid: 0x0154,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x5077),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x5077,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x1690, 0x0752),
            DeviceInfo {
                vid: 0x1690,
                pid: 0x0752,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x20F4, 0x646B),
            DeviceInfo {
                vid: 0x20F4,
                pid: 0x646B,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x25D4, 0x4CA1),
            DeviceInfo {
                vid: 0x25D4,
                pid: 0x4CA1,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x25D4, 0x4CAB),
            DeviceInfo {
                vid: 0x25D4,
                pid: 0x4CAB,
                disable_ht: false
            }
        ),
        // RTL8191SU devices
        (
            usb::DeviceId::from_id(0x0BDA, 0x8175),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8175,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x8172),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8172,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0BDA, 0x8192),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8192,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x1B75, 0x8172),
            DeviceInfo {
                vid: 0x1B75,
                pid: 0x8172,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0EB0, 0x9061),
            DeviceInfo {
                vid: 0x0EB0,
                pid: 0x9061,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3323),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3323,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3311),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3311,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3342),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3342,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3333),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3333,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3334),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3334,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3335),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3335,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3336),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3336,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3309),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3309,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x050D, 0x815F),
            DeviceInfo {
                vid: 0x050D,
                pid: 0x815F,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07D1, 0x3302),
            DeviceInfo {
                vid: 0x07D1,
                pid: 0x3302,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07D1, 0x3300),
            DeviceInfo {
                vid: 0x07D1,
                pid: 0x3300,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07D1, 0x3303),
            DeviceInfo {
                vid: 0x07D1,
                pid: 0x3303,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x7392, 0x7612),
            DeviceInfo {
                vid: 0x7392,
                pid: 0x7612,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x1740, 0x9605),
            DeviceInfo {
                vid: 0x1740,
                pid: 0x9605,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x06F8, 0xE031),
            DeviceInfo {
                vid: 0x06F8,
                pid: 0xE031,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0E66, 0x0015),
            DeviceInfo {
                vid: 0x0E66,
                pid: 0x0015,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3306),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3306,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x2019, 0xED18),
            DeviceInfo {
                vid: 0x2019,
                pid: 0xED18,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x2019, 0x4901),
            DeviceInfo {
                vid: 0x2019,
                pid: 0x4901,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0058),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0058,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0049),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0049,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x004C),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x004C,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0064),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0064,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x14B2, 0x3300),
            DeviceInfo {
                vid: 0x14B2,
                pid: 0x3300,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x14B2, 0x3301),
            DeviceInfo {
                vid: 0x14B2,
                pid: 0x3301,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x14B2, 0x3302),
            DeviceInfo {
                vid: 0x14B2,
                pid: 0x3302,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0CDE, 0x0030),
            DeviceInfo {
                vid: 0x0CDE,
                pid: 0x0030,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x04F2, 0xAFF2),
            DeviceInfo {
                vid: 0x04F2,
                pid: 0xAFF2,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x04F2, 0xAFF5),
            DeviceInfo {
                vid: 0x04F2,
                pid: 0xAFF5,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x04F2, 0xAFF6),
            DeviceInfo {
                vid: 0x04F2,
                pid: 0xAFF6,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3339),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3339,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3340),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3340,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3341),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3341,
                disable_ht: true
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3310),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3310,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x13D3, 0x3325),
            DeviceInfo {
                vid: 0x13D3,
                pid: 0x3325,
                disable_ht: false
            }
        ),
        // RTL8192SU devices
        (
            usb::DeviceId::from_id(0x0BDA, 0x8174),
            DeviceInfo {
                vid: 0x0BDA,
                pid: 0x8174,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x050D, 0x845A),
            DeviceInfo {
                vid: 0x050D,
                pid: 0x845A,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x07AA, 0x0051),
            DeviceInfo {
                vid: 0x07AA,
                pid: 0x0051,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x7392, 0x7622),
            DeviceInfo {
                vid: 0x7392,
                pid: 0x7622,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0409, 0x02B6),
            DeviceInfo {
                vid: 0x0409,
                pid: 0x02B6,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x0061),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x0061,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0DF6, 0x006C),
            DeviceInfo {
                vid: 0x0DF6,
                pid: 0x006C,
                disable_ht: false
            }
        ),
        // Unknown devices
        (
            usb::DeviceId::from_id(0x0009, 0x21E7),
            DeviceInfo {
                vid: 0x0009,
                pid: 0x21E7,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x0E0B, 0x9063),
            DeviceInfo {
                vid: 0x0E0B,
                pid: 0x9063,
                disable_ht: false
            }
        ),
        (
            usb::DeviceId::from_id(0x5A57, 0x0291),
            DeviceInfo {
                vid: 0x5A57,
                pid: 0x0291,
                disable_ht: false
            }
        ),
    ]
);

const FIRMWARE_BLOB: &[u8] = include_bytes!("firmware/rtl8712u.bin");

struct Rtl8192SuDriver {
    _r92su: KBox<R92suDevice>,
}

impl usb::Driver for Rtl8192SuDriver {
    type IdInfo = DeviceInfo;

    const ID_TABLE: usb::IdTable<Self::IdInfo> = &USB_TABLE;

    fn probe(
        intf: &usb::Interface<Core>,
        _id: &usb::DeviceId,
        info: &Self::IdInfo,
    ) -> impl PinInit<Self, Error> {
        let dev: &kernel::device::Device<Core> = intf.as_ref();

        dev_info!(dev, "RTL8192SU Rust FullMAC driver\n");
        dev_info!(dev, "Driver version: {}\n", DRIVER_VERSION);
        dev_info!(dev, "Probing device {:04x}:{:04x}\n", info.vid, info.pid);

        let r92su = r92su_usb_probe(intf, FIRMWARE_BLOB, info.disable_ht)?;

        Ok(Self { _r92su: r92su })
    }

    fn disconnect(intf: &usb::Interface<Core>, _data: Pin<&Self>) {
        let dev: &kernel::device::Device<Core> = intf.as_ref();
        dev_info!(dev, "RTL8192SU driver: device disconnected\n");
    }
}

kernel::module_usb_driver! {
    type: Rtl8192SuDriver,
    name: "rtl8192su",
    authors: ["Alban Seurat <alban.seurat@me.com>"],
    description: "Rust RTL8192SU FullMAC WLAN Driver",
    license: "GPL v2",
}
