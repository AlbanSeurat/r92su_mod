// SPDX-License-Identifier: GPL-2.0
//! Debugfs support for RTL8192SU driver.
//!
//! Exposes debugfs files under `/sys/kernel/debug/rtl8192su/` for viewing
//! device state and debugging information.

use kernel::prelude::*;

use crate::cfg80211;
use crate::r92u::{DebugMemType, R92suDevice}; //

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

extern "C" fn get_rpwm(dev_ptr: *mut core::ffi::c_void) -> u8 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.rpwm
}

extern "C" fn get_rx_queue_len(dev_ptr: *mut core::ffi::c_void) -> i32 {
    if dev_ptr.is_null() {
        return 0;
    }
    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    dev.pending_rx.len() as i32
}

// ---------------------------------------------------------------------------
// Helper functions for formatting debugfs output
// ---------------------------------------------------------------------------

fn write_str(out: &mut [u8], pos: &mut usize, s: &str) {
    let remaining = out.len().saturating_sub(*pos);
    let copy_len = s.len().min(remaining);
    if copy_len > 0 {
        out[*pos..*pos + copy_len].copy_from_slice(s.as_bytes());
        *pos += copy_len;
    }
}

fn write_hex_u8(out: &mut [u8], pos: &mut usize, val: u8) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    if *pos + 2 <= out.len() {
        out[*pos] = HEX_CHARS[((val >> 4) & 0xf) as usize];
        out[*pos + 1] = HEX_CHARS[((val >> 0) & 0xf) as usize];
        *pos += 2;
    }
}

fn write_dec_usize(out: &mut [u8], pos: &mut usize, val: usize) {
    let mut buf = [0u8; 20];
    let mut idx = 0;

    if val == 0 {
        buf[0] = b'0';
        idx = 1;
    } else {
        let mut n = val;
        while n > 0 {
            buf[19 - idx] = b'0' + (n % 10) as u8;
            n /= 10;
            idx += 1;
        }
    }

    let s = core::str::from_utf8(&buf[20 - idx..20]).unwrap_or("0");
    write_str(out, pos, s);
}

// ---------------------------------------------------------------------------
// Complex debugfs read callbacks
// ---------------------------------------------------------------------------

/// Format the station table into the provided buffer.
/// Returns the number of bytes written.
extern "C" fn debugfs_sta_table(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    if dev_ptr.is_null() || buf.is_null() || buf_size == 0 {
        return 0;
    }

    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    let mut out = unsafe { core::slice::from_raw_parts_mut(buf, buf_size) };
    let mut pos = 0usize;

    for i in 0..32 {
        write_str(&mut out, &mut pos, "mac_id:");
        write_dec_usize(&mut out, &mut pos, i);
        write_str(&mut out, &mut pos, " ");

        let sta = dev.sta_by_macid(i);
        if sta.is_none() {
            write_str(&mut out, &mut pos, " - empty -\n");
            continue;
        }

        let sta = sta.unwrap();
        write_str(&mut out, &mut pos, "mac_addr:");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[0]);
        write_str(&mut out, &mut pos, ":");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[1]);
        write_str(&mut out, &mut pos, ":");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[2]);
        write_str(&mut out, &mut pos, ":");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[3]);
        write_str(&mut out, &mut pos, ":");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[4]);
        write_str(&mut out, &mut pos, ":");
        write_hex_u8(&mut out, &mut pos, sta.mac_addr[5]);
        write_str(&mut out, &mut pos, " aid:");
        write_dec_usize(&mut out, &mut pos, sta.aid);
        write_str(&mut out, &mut pos, " id2:");
        write_dec_usize(&mut out, &mut pos, sta.mac_id);
        write_str(&mut out, &mut pos, " enc:");
        write_str(&mut out, &mut pos, if sta.enc_sta { "1" } else { "0" });
        write_str(&mut out, &mut pos, " qos:");
        write_str(&mut out, &mut pos, if sta.qos_sta { "1" } else { "0" });
        write_str(&mut out, &mut pos, " ht:");
        write_str(&mut out, &mut pos, if sta.ht_sta { "1" } else { "0" });
        write_str(&mut out, &mut pos, "\n");

        if let Some(ref key) = sta.sta_key {
            write_str(&mut out, &mut pos, "key: type:");
            write_dec_usize(&mut out, &mut pos, key.algo as usize);
            write_str(&mut out, &mut pos, " key_len:");
            write_dec_usize(&mut out, &mut pos, key.key_len);
            write_str(&mut out, &mut pos, " idx:");
            write_dec_usize(&mut out, &mut pos, key.index);
            write_str(&mut out, &mut pos, "\n");
        }
    }

    pos
}

/// Format the connected BSS info into the provided buffer.
/// Returns the number of bytes written.
extern "C" fn debugfs_connected_bss(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    if dev_ptr.is_null() || buf.is_null() || buf_size == 0 {
        return 0;
    }

    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    let mut out = unsafe { core::slice::from_raw_parts_mut(buf, buf_size) };
    let mut pos = 0usize;

    if dev.bssid == [0u8; 6] {
        return 0;
    }

    write_str(&mut out, &mut pos, "BSSID:");
    write_hex_u8(&mut out, &mut pos, dev.bssid[0]);
    write_str(&mut out, &mut pos, ":");
    write_hex_u8(&mut out, &mut pos, dev.bssid[1]);
    write_str(&mut out, &mut pos, ":");
    write_hex_u8(&mut out, &mut pos, dev.bssid[2]);
    write_str(&mut out, &mut pos, ":");
    write_hex_u8(&mut out, &mut pos, dev.bssid[3]);
    write_str(&mut out, &mut pos, ":");
    write_hex_u8(&mut out, &mut pos, dev.bssid[4]);
    write_str(&mut out, &mut pos, ":");
    write_hex_u8(&mut out, &mut pos, dev.bssid[5]);
    write_str(&mut out, &mut pos, " channel:");
    write_dec_usize(&mut out, &mut pos, dev.channel as usize);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "def_multi_key_idx:");
    write_dec_usize(&mut out, &mut pos, dev.def_multi_key_idx as usize);
    write_str(&mut out, &mut pos, " def_uni_key_idx:");
    write_dec_usize(&mut out, &mut pos, dev.def_uni_key_idx as usize);
    write_str(&mut out, &mut pos, "\n");

    for (i, key_opt) in dev.group_keys.iter().enumerate() {
        if let Some(ref key) = key_opt {
            write_str(&mut out, &mut pos, "key: type:");
            write_dec_usize(&mut out, &mut pos, key.algo as usize);
            write_str(&mut out, &mut pos, " key_len:");
            write_dec_usize(&mut out, &mut pos, key.key_len);
            write_str(&mut out, &mut pos, " idx:");
            write_dec_usize(&mut out, &mut pos, i);
            write_str(&mut out, &mut pos, "\n");
        }
    }

    pos
}

/// Format the EEPROM data into the provided buffer.
/// Returns the number of bytes written.
extern "C" fn debugfs_eeprom(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    if dev_ptr.is_null() || buf.is_null() || buf_size == 0 {
        return 0;
    }

    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    let eeprom = &dev.eeprom;
    let mut out = unsafe { core::slice::from_raw_parts_mut(buf, buf_size) };
    let mut pos = 0usize;

    write_str(&mut out, &mut pos, "id:           ");
    let id_val = eeprom.id();
    write_hex_u8(&mut out, &mut pos, (id_val >> 8) as u8);
    write_hex_u8(&mut out, &mut pos, (id_val & 0xff) as u8);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "mac_addr:     ");
    let mac = eeprom.mac_addr();
    for (i, b) in mac.iter().enumerate() {
        write_hex_u8(&mut out, &mut pos, *b);
        if i < 5 {
            write_str(&mut out, &mut pos, ":");
        }
    }
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "version:      ");
    write_hex_u8(&mut out, &mut pos, eeprom.raw[80]);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "channel plan: ");
    write_hex_u8(&mut out, &mut pos, eeprom.raw[81]);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "custom_id:    ");
    write_hex_u8(&mut out, &mut pos, eeprom.raw[82]);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "sub_custom_id:");
    write_hex_u8(&mut out, &mut pos, eeprom.raw[83]);
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "board_type:   ");
    write_hex_u8(&mut out, &mut pos, eeprom.board_type());
    write_str(&mut out, &mut pos, "\n");

    write_str(&mut out, &mut pos, "eeprom_type:  ");
    let et_str = match dev.eeprom_type {
        crate::r92u::EepromType::Eeprom93C46 => "Eeprom93C46",
        crate::r92u::EepromType::BootEfuse => "BootEfuse",
    };
    write_str(&mut out, &mut pos, et_str);
    write_str(&mut out, &mut pos, "\n");

    pos
}

/// Copy raw EEPROM bytes to the provided buffer.
/// Returns the number of bytes copied.
extern "C" fn debugfs_eeprom_raw(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    if dev_ptr.is_null() || buf.is_null() {
        return 0;
    }

    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    let eeprom = &dev.eeprom;
    let copy_len = eeprom.raw.len().min(buf_size);

    unsafe {
        core::ptr::copy_nonoverlapping(eeprom.raw.as_ptr(), buf, copy_len);
    }
    copy_len
}

const MEM_TYPE_STR: [&str; 3] = ["byte", "word", " int"];

/// Format the debug ring (hardware I/O reads) into the provided buffer.
/// Returns the number of bytes written.
extern "C" fn debugfs_hw_ioread(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    if dev_ptr.is_null() || buf.is_null() || buf_size == 0 {
        return 0;
    }

    let dev = unsafe { &*dev_ptr.cast::<R92suDevice>() };
    let mut out = unsafe { core::slice::from_raw_parts_mut(buf, buf_size) };
    let mut pos = 0usize;

    write_str(
        &mut out,
        &mut pos,
        "                      33222222 22221111 11111100 00000000\n",
    );
    write_str(
        &mut out,
        &mut pos,
        "                      10987654 32109876 54321098 76543210\n",
    );

    let mut ring_len = dev.debug.ring_len;
    let mut ring_head = dev.debug.ring_head;

    while ring_len > 0 {
        let rbe = &dev.debug.ring[ring_head];
        let mem_str = MEM_TYPE_STR[rbe.mem_type as usize % 3];

        write_str(&mut out, &mut pos, "0x");
        for shift in [12, 8, 4, 0] {
            write_hex_u8(&mut out, &mut pos, ((rbe.reg >> shift) & 0xff) as u8);
        }
        write_str(&mut out, &mut pos, " = 0x");
        for shift in [28, 24, 20, 16, 12, 8, 4, 0] {
            write_hex_u8(&mut out, &mut pos, ((rbe.value >> shift) & 0xff) as u8);
        }
        write_str(&mut out, &mut pos, " [");
        write_str(&mut out, &mut pos, mem_str);
        write_str(&mut out, &mut pos, "]");

        for i in (0..32).rev() {
            if pos < out.len() {
                let bit = if (rbe.value & (1 << i)) != 0 {
                    b'X'
                } else {
                    b' '
                };
                out[pos] = bit;
                pos += 1;
                if i % 8 == 0 && i > 0 && pos < out.len() {
                    out[pos] = b' ';
                    pos += 1;
                }
            }
        }
        write_str(&mut out, &mut pos, "\n");

        ring_head = (ring_head + 1) % 64;
        ring_len -= 1;
    }

    pos
}

/// Write to a hardware register and add the result to the debug ring.
/// Input format: "0xADDR" (reads 1 byte), "0xADDR SIZE" (reads SIZE bytes)
/// Returns 0 on success, negative error code on failure.
extern "C" fn debugfs_hw_iowrite(
    dev_ptr: *mut core::ffi::c_void,
    buf: *const u8,
    buf_len: usize,
) -> i32 {
    if dev_ptr.is_null() || buf.is_null() || buf_len == 0 {
        return -1;
    }

    let dev = unsafe { &mut *dev_ptr.cast::<R92suDevice>() };

    let input = unsafe { core::slice::from_raw_parts(buf, buf_len) };
    let input_str = match core::str::from_utf8(input) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    let mut parts = input_str.split_whitespace();
    let reg_str = match parts.next() {
        Some(s) => s,
        None => return -1,
    };

    let reg = match parse_hex(reg_str) {
        Some(r) => r,
        None => return -1,
    };
    let size_str = parts.next();
    let size = match size_str.and_then(|s| s.parse::<usize>().ok()) {
        Some(s) if s > 0 && s <= 4 => s,
        _ => 1,
    };

    let mem_type = match size {
        1 => DebugMemType::Mem8,
        2 => DebugMemType::Mem16,
        4 => DebugMemType::Mem32,
        _ => DebugMemType::Mem8,
    };

    let read_val = match size {
        1 => {
            let v = unsafe { crate::r92u::hw_read8(dev.udev, reg as u16) };
            v as u32
        }
        2 => {
            let v = unsafe { crate::r92u::hw_read16(dev.udev, reg as u16) };
            v as u32
        }
        4 => unsafe { crate::r92u::hw_read32(dev.udev, reg as u16) },
        _ => 0,
    };

    dev.debug.add_read(reg, read_val, mem_type);

    0
}

fn parse_hex(s: &str) -> Option<u32> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}

// ---------------------------------------------------------------------------
// FFI exports for debugfs read handlers
// ---------------------------------------------------------------------------

#[no_mangle]
extern "C" fn r92su_debugfs_sta_table(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    debugfs_sta_table(dev_ptr, buf, buf_size)
}

#[no_mangle]
extern "C" fn r92su_debugfs_connected_bss(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    debugfs_connected_bss(dev_ptr, buf, buf_size)
}

#[no_mangle]
extern "C" fn r92su_debugfs_eeprom(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    debugfs_eeprom(dev_ptr, buf, buf_size)
}

#[no_mangle]
extern "C" fn r92su_debugfs_eeprom_raw(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    debugfs_eeprom_raw(dev_ptr, buf, buf_size)
}

#[no_mangle]
extern "C" fn r92su_debugfs_hw_ioread(
    dev_ptr: *mut core::ffi::c_void,
    buf: *mut u8,
    buf_size: usize,
) -> usize {
    debugfs_hw_ioread(dev_ptr, buf, buf_size)
}

#[no_mangle]
extern "C" fn r92su_debugfs_hw_iowrite(
    dev_ptr: *mut core::ffi::c_void,
    buf: *const u8,
    buf_len: usize,
) -> i32 {
    debugfs_hw_iowrite(dev_ptr, buf, buf_len)
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
        pr_info!("r92su: debugfs entries created\n");
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
        pr_info!("r92su: debugfs entries removed\n");
    }
}
