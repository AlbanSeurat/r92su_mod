// SPDX-License-Identifier: GPL-2.0
//! USB device setup for RTL8192SU.
//!
//! Implements `r92su_setup()` from the C reference driver (`main.c`), which
//! runs after `r92su_usb_init()` and before `r92su_register()`.  The function
//! orchestrates five sub-steps:
//!
//! 1. [`rx_init`]            — initialise the RX subsystem
//! 2. [`cmd_init`]           — initialise the command subsystem
//! 3. [`read_adapter_info`]  — read chip revision and EEPROM (MAC address)
//! 4. [`init_band`]          — configure the 2.4 GHz band capabilities
//! 5. [`alloc_netdev`]       — allocate the network device
//!
//! Finally the permanent MAC address is propagated from the EEPROM data into
//! the device's `mac_addr` field, mirroring the two `memcpy` calls at the end
//! of the C function.

use core::ffi::c_void;
use kernel::{bindings, prelude::*}; //

use crate::netdev::{NetDev, WirelessDev};
use crate::r92u::{
    cmd_init, //
    hw_read32,
    hw_read8,
    hw_write8, //
    mdelay,    //
    Band2GHz,
    ChipRev,
    EepromType,
    R92suDevice,
    R92suError,
    Result,
    RfType,
    EEPROM_SIZE,
    ETH_ALEN,
};

// Number of 2.4 GHz channels (matches r92su_channeltable in main.c: ch 1–14).
const N_CHANNELS_2GHZ: usize = 14;

// Number of 2.4 GHz bitrates (matches r92su_ratetable in main.c: 12 entries).
const N_BITRATES_2GHZ: usize = 12;

// MCS rx_highest for 2-stream configurations (300 Mbps, matches C driver).
const MCS_RX_HIGHEST_2STREAM: u16 = 300;

// REG_PMC_FSM — power-management FSM register.
// Full address: RTL8712_SYSCFG_ + 0x0004 = 0x10250004.
// USB address (low 16 bits after implicit u32→u16 truncation in C driver): 0x0004.
const REG_PMC_FSM: u16 = 0x0004;

// PCM_FSM_VER: bits [19:15] of the 32-bit REG_PMC_FSM value.
// Mask = 0x000f8000 per reg.h (#define PCM_FSM_VER 0x0000f8000).
const PCM_FSM_VER_SHIFT: u32 = 15;
const PCM_FSM_VER_MASK: u32 = 0x000f_8000;

// EFUSE / EEPROM register USB addresses (RTL8712_SYSCFG_ offsets, low 16 bits).
// REG_EEPROM_CMD = RTL8712_SYSCFG_ + 0x000A → 0x000A
const REG_EEPROM_CMD: u16 = 0x000A;
// REG_EFUSE_CTRL = RTL8712_SYSCFG_ + 0x0030 → 0x0030 (four byte-wide sub-registers)
const REG_EFUSE_CTRL_0: u16 = 0x0030; // data byte (read result)
const REG_EFUSE_CTRL_1: u16 = 0x0031; // address low byte
const REG_EFUSE_CTRL_2: u16 = 0x0032; // address high bits [1:0]
const REG_EFUSE_CTRL_3: u16 = 0x0033; // control / status (0x72 = trigger read; bit7 = ready)
                                      // REG_EFUSE_TEST = RTL8712_SYSCFG_ + 0x0034 → 0x0034; we only need byte +3 = 0x0037
const REG_EFUSE_TEST_3: u16 = 0x0037; // bit7: LDOE25 enable
                                      // REG_EFUSE_CLK_CTRL = RTL8712_SYSCFG_ + 0x02F8 → 0x02F8
const REG_EFUSE_CLK_CTRL: u16 = 0x02F8;

// EEPROM_CMD register flags.
const EEPROM_CMD_93C46: u8 = 1 << 4; // BIT(4): device is 93C46 SPI EEPROM
const EEPROM_CMD_AUTOLOAD_OK: u8 = 1 << 5; // BIT(5): hardware autoload succeeded

// RTL8190_EEPROM_ID — expected signature at EEPROM offset 0 (little-endian).
const RTL8190_EEPROM_ID: u16 = 0x8129;

// Physical EFUSE size in bytes (R92SU_EFUSE_REAL_SIZE in eeprom.h).
const EFUSE_REAL_SIZE: u16 = 512;

// ---------------------------------------------------------------------------
// rx_init — mirrors r92su_rx_init() in rx.c
//
// C:
//   skb_queue_head_init(&r92su->rx_queue);
//   tasklet_init(&r92su->rx_tasklet, r92su_rx_tasklet, (unsigned long) r92su);
//
// The Rust RxQueue is already zero-initialised inside R92suDevice::new(), so
// no allocation is required here.
// ---------------------------------------------------------------------------
fn rx_init(_dev: &mut R92suDevice) {
    pr_debug!("r92su_rx_init: RX subsystem initialized\n");
}

// ---------------------------------------------------------------------------
// read_chip_version — mirrors r92su_hw_read_chip_version() in hw.c
//
// C:
//   rev = GET_VAL(PCM_FSM_VER, r92su_read32(r92su, REG_PMC_FSM));
//   if (rev != R92SU_C_CUT) { rev = (rev >> 1) + 1; ... }
//   r92su->chip_rev = rev;
//
// PCM_FSM_VER occupies bits [19:15] of the 32-bit PMC_FSM register.
// ---------------------------------------------------------------------------
fn read_chip_version(dev: &mut R92suDevice) -> Result<()> {
    // SAFETY: dev.udev was populated during probe and is valid until disconnect.
    let raw = unsafe { hw_read32(dev.udev, REG_PMC_FSM) };
    let mut rev = (raw & PCM_FSM_VER_MASK) >> PCM_FSM_VER_SHIFT;

    if rev != ChipRev::CCut as u32 {
        rev = (rev >> 1) + 1;
        if rev > ChipRev::CCut as u32 {
            // C driver defaults to B_CUT here; treat as an error per the comment
            // in hw.c ("I'm not sure what the math above is all about").
            pr_warn!("r92su: unexpected chip revision field {:#x}\n", rev);
            return Err(R92suError::Io("unexpected chip revision"));
        }
    }

    dev.chip_rev = match rev {
        0 => ChipRev::Fpga,
        1 => ChipRev::ACut,
        2 => ChipRev::BCut,
        3 => ChipRev::CCut,
        _ => return Err(R92suError::Io("unknown chip revision")),
    };

    pr_debug!("r92su: chip revision: {:?}\n", dev.chip_rev);
    Ok(())
}

// ---------------------------------------------------------------------------
// EFUSE low-level helpers — mirrors eeprom.c in the C reference driver
// ---------------------------------------------------------------------------

// Enable LDOE25 macro block and set EFUSE clock to 40 MHz for access.
// Mirrors r92su_efuse_initialize().
//
// # Safety
//
// `udev` must be valid.
unsafe fn efuse_initialize(udev: *mut bindings::usb_device) {
    // Enable LDOE25 Macro Block (BIT(7) of REG_EFUSE_TEST+3).
    // SAFETY: caller guarantees `udev` is valid.
    let tmp = unsafe { hw_read8(udev, REG_EFUSE_TEST_3) };
    unsafe { hw_write8(udev, REG_EFUSE_TEST_3, tmp | 0x80) };

    // Set EFuse Clock for 40 MHz write action.
    unsafe { hw_write8(udev, REG_EFUSE_CLK_CTRL, 0x03) };

    // Arm EFUSE_CTRL+3 for read mode.
    unsafe { hw_write8(udev, REG_EFUSE_CTRL_3, 0x72) };
}

// Disable LDOE25 macro block and restore EFUSE clock to 500 kHz.
// Mirrors r92su_efuse_shutdown().
//
// # Safety
//
// `udev` must be valid.
unsafe fn efuse_shutdown(udev: *mut bindings::usb_device) {
    // Disable LDOE25 Macro Block.
    // SAFETY: caller guarantees `udev` is valid.
    let tmp = unsafe { hw_read8(udev, REG_EFUSE_TEST_3) };
    unsafe { hw_write8(udev, REG_EFUSE_TEST_3, tmp & !0x80) };

    // Change EFuse Clock back to 500 kHz.
    unsafe { hw_write8(udev, REG_EFUSE_CLK_CTRL, 0x02) };
}

// Read one byte from the EFUSE physical address space.
// EFUSE must already be initialised with efuse_initialize().
// Mirrors __r92su_efuse_read().
//
// Returns 0xff on retry exhaustion (matches the C driver).
//
// # Safety
//
// `udev` must be valid and EFUSE must be initialised.
unsafe fn efuse_read_byte(udev: *mut bindings::usb_device, address: u16) -> u8 {
    const RETRIES: u32 = 10;

    // Set address low byte.
    // SAFETY: caller guarantees preconditions.
    unsafe { hw_write8(udev, REG_EFUSE_CTRL_1, (address & 0xff) as u8) };

    // Set address high bits [1:0], preserving reserved bits in the register.
    let mut tmp = unsafe { hw_read8(udev, REG_EFUSE_CTRL_2) };
    tmp &= !(0x01 | 0x02);
    tmp |= ((address >> 8) & 0x3) as u8;
    unsafe { hw_write8(udev, REG_EFUSE_CTRL_2, tmp) };

    // Trigger a read (0x72 = read command; bit7 will be set by hw when ready).
    unsafe { hw_write8(udev, REG_EFUSE_CTRL_3, 0x72) };

    // Poll for completion: bit7 of EFUSE_CTRL+3 goes high when data is ready.
    let mut i = 0u32;
    loop {
        i += 1;
        tmp = unsafe { hw_read8(udev, REG_EFUSE_CTRL_3) };
        if tmp & 0x80 != 0 || i >= RETRIES {
            break;
        }
    }

    if i >= RETRIES {
        pr_warn!("r92su: EFUSE read timeout at address {:#06x}\n", address);
        return 0xff;
    }

    // Read result from EFUSE_CTRL+0.
    unsafe { hw_read8(udev, REG_EFUSE_CTRL_0) }
}

// Reconstruct the flat 128-byte EEPROM image from the sparse EFUSE blocks.
// Mirrors r92su_fetch_eeprom_data().
//
// The EFUSE is a sparse 512-byte store.  Each entry begins with a descriptor
// byte: high nibble = 8-byte-block index in the EEPROM image; low nibble =
// bitmap of 2-byte pairs to skip (0 = valid, 1 = bad/skip).
//
// # Safety
//
// `udev` must be valid.
unsafe fn fetch_eeprom_data(
    udev: *mut bindings::usb_device,
    eeprom_type: &mut EepromType,
    raw: &mut [u8; EEPROM_SIZE],
) -> Result<()> {
    const BLOCK_SIZE: usize = 8;
    const FETCH_SIZE: usize = 2;

    // SAFETY: caller guarantees `udev` is valid.
    let eprom = unsafe { hw_read8(udev, REG_EEPROM_CMD) };

    *eeprom_type = if eprom & EEPROM_CMD_93C46 != 0 {
        EepromType::Eeprom93C46
    } else {
        EepromType::BootEfuse
    };

    if eprom & EEPROM_CMD_AUTOLOAD_OK == 0 {
        pr_err!(
            "r92su: EEPROM autoload not complete (EEPROM_CMD={:#04x})\n",
            eprom
        );
        return Err(R92suError::Io("EEPROM autoload failed"));
    }

    // SAFETY: caller guarantees `udev` is valid.
    unsafe { efuse_initialize(udev) };

    // Start with all bytes 0xff — unwritten EFUSE cells read as 0xff.
    raw.fill(0xff);

    let mut off: u16 = 0;
    'outer: while off < EFUSE_REAL_SIZE {
        // SAFETY: caller guarantees `udev` is valid and EFUSE is initialised.
        let desc = unsafe { efuse_read_byte(udev, off) };
        off += 1;

        // 0xff marks the end of the EFUSE content.
        if desc == 0xff {
            break;
        }

        let pos = (desc >> 4) as usize; // 8-byte block index in the EEPROM image
        let mut map = desc & 0x0f; // pair-skip bitmap: bit0 = first pair, etc.

        let base = pos * BLOCK_SIZE;
        for i in (0..BLOCK_SIZE).step_by(FETCH_SIZE) {
            if map & 0x01 == 0 {
                // Bit clear = valid pair: read two bytes into the EEPROM image.
                raw[base + i] = unsafe { efuse_read_byte(udev, off) };
                off += 1;
                if off >= EFUSE_REAL_SIZE {
                    break 'outer;
                }
                raw[base + i + 1] = unsafe { efuse_read_byte(udev, off) };
                off += 1;
                if off >= EFUSE_REAL_SIZE {
                    break 'outer;
                }
            }
            map >>= 1;
        }
    }

    // SAFETY: caller guarantees `udev` is valid.
    unsafe { efuse_shutdown(udev) };
    Ok(())
}

// Validate EEPROM signature and derive rf_type from board_type.
// Mirrors r92su_parse_eeprom().
fn parse_eeprom(dev: &mut R92suDevice) -> Result<()> {
    let id = dev.eeprom.id();
    if id != RTL8190_EEPROM_ID {
        pr_err!(
            "r92su: EEPROM signature mismatch (expected {:#06x}, got {:#06x})\n",
            RTL8190_EEPROM_ID,
            id
        );
        return Err(R92suError::Io("EEPROM signature mismatch"));
    }

    dev.rf_type = match dev.eeprom.board_type() {
        0 => RfType::T1R1,
        1 => RfType::T1R2,
        2 => RfType::T2R2,
        other => {
            pr_err!("r92su: unknown board_type {}\n", other);
            return Err(R92suError::Io("unknown board type"));
        }
    };

    pr_debug!("r92su: rf_type: {:?}\n", dev.rf_type);
    Ok(())
}

// ---------------------------------------------------------------------------
// read_eeprom — mirrors r92su_eeprom_read() in eeprom.c
//
// C:
//   r92su_fetch_eeprom_data(r92su);   // reads SPI flash / EFUSE
//   r92su_parse_eeprom(r92su);        // extracts mac_addr and other fields
// ---------------------------------------------------------------------------
fn read_eeprom(dev: &mut R92suDevice) -> Result<()> {
    // SAFETY: dev.udev was populated during probe from interface_to_usbdev()
    // and remains valid until r92su_disconnect(); r92su_setup() is called from
    // the probe path before the device is registered.
    unsafe { fetch_eeprom_data(dev.udev, &mut dev.eeprom_type, &mut dev.eeprom.raw) }?;

    parse_eeprom(dev)?;

    // Populate dev.mac_addr from the EEPROM image so alloc_netdev() can use it.
    dev.mac_addr = dev.eeprom.mac_addr();

    let mac = dev.mac_addr;
    pr_debug!(
        "r92su: EEPROM MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// read_adapter_info — mirrors r92su_read_adapter_info() in main.c
//
// C:
//   err = r92su_hw_read_chip_version(r92su);
//   err = r92su_eeprom_read(r92su);
// ---------------------------------------------------------------------------
fn read_adapter_info(dev: &mut R92suDevice) -> Result<()> {
    read_chip_version(dev)?;

    // Initialize eFuse hardware for B and C cut chips before reading.
    // This mirrors the sequence in r92su_usb_init_b_and_c_cut() that writes
    // 0xb0 -> 0x30 to REG_EFUSE_TEST+3. This must happen before eFuse access.
    match dev.chip_rev {
        ChipRev::BCut | ChipRev::CCut => {
            const REG_EFUSE_TEST_3: u16 = 0x0037;
            unsafe {
                hw_write8(dev.udev, REG_EFUSE_TEST_3, 0xb0);
            }
            mdelay(20);
            unsafe {
                hw_write8(dev.udev, REG_EFUSE_TEST_3, 0x30);
            }
        }
        _ => {}
    }

    read_eeprom(dev)
}

// ---------------------------------------------------------------------------
// init_band — mirrors r92su_init_band() in main.c
//
// C:
//   band->channels  = dup(r92su_channeltable);  /* 14 channels */
//   band->bitrates  = dup(r92su_ratetable);      /* 12 rates    */
//   memcpy(&band->ht_cap, &r92su_ht_info, ...);
//   band->ht_cap.ht_supported = !r92su->disable_ht;
//   switch (r92su->rf_type) {
//       case R92SU_1T2R / R92SU_2T2R:
//           band->ht_cap.mcs.rx_mask[1] = 0xff;
//           band->ht_cap.mcs.rx_highest = cpu_to_le16(300);
//   }
//   wiphy->bands[NL80211_BAND_2GHZ] = &r92su->band_2GHZ;
// ---------------------------------------------------------------------------
fn init_band(dev: &mut R92suDevice) -> Result<()> {
    let band = Band2GHz {
        n_channels: N_CHANNELS_2GHZ,
        n_bitrates: N_BITRATES_2GHZ,
        ht_supported: !dev.disable_ht,
        // rx_mask[1] and rx_highest are updated below for 2-stream configs.
        rx_mask_1: 0x00,
        rx_highest: 150,
    };
    dev.band_2ghz = band;

    match dev.rf_type {
        RfType::T1R1 => {
            // Single-stream: the default caps from Band2GHz::new() are correct.
        }
        RfType::T1R2 | RfType::T2R2 => {
            dev.band_2ghz.rx_mask_1 = 0xff;
            dev.band_2ghz.rx_highest = MCS_RX_HIGHEST_2STREAM;
        }
    }

    // C: wiphy->bands[NL80211_BAND_2GHZ] = &r92su->band_2GHZ;
    //
    // Write the per-device HT parameters into the wiphy private area and
    // assign wiphy->bands[NL80211_BAND_2GHZ].  This must happen before
    // wiphy_register() or the kernel will WARN_ON(!have_band).
    let wiphy = dev
        .wiphy
        .as_ref()
        .ok_or(R92suError::Io("wiphy not allocated"))?;
    wiphy.set_band_2ghz(
        dev.band_2ghz.ht_supported,
        dev.band_2ghz.rx_mask_1,
        dev.band_2ghz.rx_highest,
    );

    pr_debug!(
        "r92su: 2.4 GHz band: {} channels, {} rates, HT={}\n",
        dev.band_2ghz.n_channels,
        dev.band_2ghz.n_bitrates,
        dev.band_2ghz.ht_supported,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// alloc_netdev — mirrors r92su_alloc_netdev() in main.c
//
// C:
//   ndev = alloc_netdev_mqs(0, "wlan%d", NET_NAME_UNKNOWN,
//                           r92su_if_setup, NUM_ACS, 1);
//   ndev->ml_priv = r92su;
//   r92su->wdev.netdev = ndev;
//   ndev->ieee80211_ptr = &r92su->wdev;
//   SET_NETDEV_DEV(ndev, wiphy_dev(r92su->wdev.wiphy));
//
// The Rust port allocates wireless_dev separately (it is not embedded in a
// wiphy private area as in the C driver) and links netdev → wdev via
// ndev->ieee80211_ptr.
// ---------------------------------------------------------------------------
fn alloc_netdev(dev: &mut R92suDevice, parent_dev: *mut c_void) -> Result<()> {
    let wiphy_ptr = dev
        .wiphy
        .as_ref()
        .ok_or(R92suError::Io("wiphy not allocated"))?
        .as_ptr();

    // Allocate the wireless_dev — mirrors wdev embedded in struct r92su.
    //
    // SAFETY: `wiphy_ptr` is valid; owned by `dev.wiphy` which outlives `wdev`.
    let wdev = unsafe { WirelessDev::new(wiphy_ptr, dev.iftype) }.map_err(|_| {
        pr_err!("r92su: failed to allocate wireless_dev\n");
        R92suError::Io("wireless_dev alloc failed")
    })?;

    // Allocate the net_device, linking it to the wdev just created.
    //
    // SAFETY:
    // - `wdev.as_ptr()` is valid; `wdev` is owned by this frame and will be
    //   moved into `dev.wdev` below, ensuring it outlives `netdev`.
    // - `parent_dev` is `&intf->dev`, valid for the USB interface lifetime.
    // - `dev.mac_addr` was populated by `read_eeprom` earlier in `r92su_setup`.
    let mac: &[u8; ETH_ALEN] = &dev.mac_addr;
    let netdev = unsafe { NetDev::new(wdev.as_ptr(), parent_dev, mac) }.map_err(|_| {
        pr_err!("r92su: failed to allocate net_device\n");
        R92suError::Io("net_device alloc failed")
    })?;

    dev.wdev = Some(wdev);
    dev.netdev = Some(netdev);
    pr_debug!("r92su: wireless_dev and net_device allocated\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// r92su_setup — public entry point (mirrors main.c:r92su_setup)
//
// C:
//   r92su_rx_init(r92su);
//   r92su_cmd_init(r92su);
//   err = r92su_read_adapter_info(r92su);  if (err) goto err_out;
//   err = r92su_init_band(r92su);          if (err) goto err_out;
//   err = r92su_alloc_netdev(r92su);       if (err) goto err_out;
//   memcpy(wiphy->perm_addr, r92su->eeprom.mac_addr, ETH_ALEN);
//   memcpy(r92su->wdev.netdev->dev_addr,
//          r92su->wdev.wiphy->perm_addr, ETH_ALEN);
// ---------------------------------------------------------------------------

/// Perform post-USB-init device setup.
///
/// Mirrors `r92su_setup()` in `main.c`. Must be called after
/// [`r92su_usb_init`][crate::r92u::r92su_usb_init] and before device
/// registration.
///
/// `parent_dev` is `&intf->dev` of the USB interface; it is passed through
/// to `alloc_netdev` for `SET_NETDEV_DEV`.
pub fn r92su_setup(dev: &mut R92suDevice, parent_dev: *mut c_void) -> Result<()> {
    rx_init(dev);
    cmd_init(dev);

    read_adapter_info(dev).map_err(|e| {
        pr_err!("r92su_setup: read_adapter_info failed: {}\n", e);
        e
    })?;

    init_band(dev).map_err(|e| {
        pr_err!("r92su_setup: init_band failed: {}\n", e);
        e
    })?;

    alloc_netdev(dev, parent_dev).map_err(|e| {
        pr_err!("r92su_setup: alloc_netdev failed: {}\n", e);
        e
    })?;

    // C: memcpy(wiphy->perm_addr, r92su->eeprom.mac_addr, ETH_ALEN);
    //    memcpy(r92su->wdev.netdev->dev_addr, r92su->wdev.wiphy->perm_addr, ETH_ALEN);
    //
    // In the Rust model both perm_addr and netdev dev_addr are unified in
    // dev.mac_addr; already set by read_eeprom(), but mirror the C assignment.
    dev.mac_addr = dev.eeprom.mac_addr();

    pr_debug!(
        "r92su_setup: complete (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})\n",
        dev.mac_addr[0],
        dev.mac_addr[1],
        dev.mac_addr[2],
        dev.mac_addr[3],
        dev.mac_addr[4],
        dev.mac_addr[5],
    );

    Ok(())
}
