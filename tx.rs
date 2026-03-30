// SPDX-License-Identifier: GPL-2.0
//! tx - RTL8192SU transmit path.
//!
//! Mirrors `r92su/tx.c` from the C reference driver.  Builds the 32-byte TX
//! hardware descriptor, prepends it to the 802.11 frame, and submits the
//! resulting buffer via the USB bulk-out endpoint.
//!
//! # Frame layout sent to hardware
//!
//! ```text
//! ┌──────────────────┬─────────────────────────────────────┐
//! │  TX_DESC (32 B)  │  802.11 frame (variable)            │
//! └──────────────────┴─────────────────────────────────────┘
//! ```
//!
//! # Entry points
//!
//! - [`r92su_tx`] — transmit a raw 802.11 frame (called from `ndo_start_xmit`
//!   once that hook is wired into `rust_helpers.c`).
//! - [`r92su_tx_monitor`] — inject a frame received via a monitor-mode
//!   interface (strips the radiotap header first).

use kernel::prelude::*;

use crate::cmd::EncAlg; //
use crate::r92u::{usb_tx_cmd, R92suDevice, Result, State}; //

// ── Constants ─────────────────────────────────────────────────────────────────

/// Size of the hardware TX descriptor in bytes (`tx_hdr` = `__le32[8]`).
pub const TX_DESC_SIZE: usize = 32;

/// Minimum radiotap header size (2-byte presence bitmap + 2-byte len).
const RADIOTAP_HDR_MIN: usize = 8;

/// Frame Check Sequence length appended by hardware.
const FCS_LEN: usize = 4;

// Queue selector constants (QSLT_* from def.h).
const QSLT_BK: u32 = 0x01;
const QSLT_BE: u32 = 0x03;
const QSLT_VI: u32 = 0x05;
const QSLT_VO: u32 = 0x07;
const QSLT_MGNT: u32 = 0x12;

/// 1M fallback rate used for management / low-rate frames (bit 15 = MCS index 0).
const RATE_1M_USER: u32 = 0x001f_8000;

// SEC_TYPE values for SET_TX_DESC_SEC_TYPE.
const SEC_NONE: u32 = 0;
const SEC_WEP: u32 = 1;
const SEC_TKIP: u32 = 2;
const SEC_CCMP: u32 = 3;

// ── TX descriptor bit-field helper ───────────────────────────────────────────

/// Set a field within a little-endian 32-bit word at byte offset `dw_off * 4`.
#[inline]
fn set_bits_le(desc: &mut [u8; TX_DESC_SIZE], dw_off: usize, shift: u32, len: u32, val: u32) {
    let base = dw_off * 4;
    let mut word = u32::from_le_bytes([desc[base], desc[base + 1], desc[base + 2], desc[base + 3]]);
    let mask = ((1u32 << len).wrapping_sub(1)) << shift;
    word = (word & !mask) | ((val << shift) & mask);
    let bytes = word.to_le_bytes();
    desc[base] = bytes[0];
    desc[base + 1] = bytes[1];
    desc[base + 2] = bytes[2];
    desc[base + 3] = bytes[3];
}

// ── Per-frame TX metadata ────────────────────────────────────────────────────

/// Per-frame TX context threaded through the pipeline.
///
/// Mirrors `struct r92su_tx_info` stored in `skb->cb` in the C driver.
struct TxMeta {
    /// Index into `dev.sta_list` for the destination; `usize::MAX` if none.
    sta_idx: usize,
    /// Encryption algorithm for this frame (`None` = unencrypted).
    enc_alg: Option<EncAlg>,
    /// Key index (0–3) for the selected key.
    key_idx: usize,
    /// True if SW must encrypt (HW has no uploaded key).
    needs_encrypt: bool,
    /// 64-bit packet number (IV value) for the selected key.
    pn: u64,
    /// True if the frame should be transmitted at 1 Mbit/s.
    low_rate: bool,
    /// True if the station is HT-capable and A-MPDU is possible.
    ht_possible: bool,
    /// True if A-MPDU aggregation is active for this TID.
    ampdu: bool,
    /// QoS TID (0–15).
    tid: u8,
    /// True if the WEP/TKIP/CCMP protect bit was set on the frame.
    has_protect: bool,
    /// Multicast / broadcast destination.
    is_bmc: bool,
    /// 802.1D priority (0–7) derived from the QoS TID.
    priority: u8,
    /// Queue selector (QSLT_*) for the hardware queue.
    queue_sel: u32,
}

impl TxMeta {
    fn new() -> Self {
        Self {
            sta_idx: usize::MAX,
            enc_alg: None,
            key_idx: 0,
            needs_encrypt: false,
            pn: 0,
            low_rate: false,
            ht_possible: false,
            ampdu: false,
            tid: 0,
            has_protect: false,
            is_bmc: false,
            priority: 0,
            queue_sel: QSLT_BE,
        }
    }
}

// ── 802.11 frame control helpers ──────────────────────────────────────────────

fn fc_type(fc: u16) -> u16 {
    (fc >> 2) & 0x3
}

fn is_data(fc: u16) -> bool {
    fc_type(fc) == 2
}

fn is_mgmt(fc: u16) -> bool {
    fc_type(fc) == 0
}

fn is_data_qos(fc: u16) -> bool {
    fc_type(fc) == 2 && ((fc >> 7) & 1) != 0
}

fn has_protected(fc: u16) -> bool {
    (fc & (1 << 14)) != 0
}

/// 802.11 header length for the given `frame_control` word.
fn ieee80211_hdrlen(fc: u16) -> usize {
    let ftype = fc_type(fc);
    let fsub = (fc >> 4) & 0xf;
    match ftype {
        0 => 24,
        1 => match fsub {
            0xA => 20,
            0xB | 0xC => 16,
            0xD => 10,
            _ => 24,
        },
        2 => {
            let to_ds = (fc >> 8) & 1;
            let from_ds = (fc >> 9) & 1;
            24 + if to_ds == 1 && from_ds == 1 { 6 } else { 0 }
                + if is_data_qos(fc) { 2 } else { 0 }
        }
        _ => 24,
    }
}

/// Return a 6-byte slice from `frame` starting at `off`, or `[0u8; 6]`.
fn get_addr(frame: &[u8], off: usize) -> [u8; 6] {
    if frame.len() >= off + 6 {
        let mut a = [0u8; 6];
        a.copy_from_slice(&frame[off..off + 6]);
        a
    } else {
        [0u8; 6]
    }
}

/// IEEE 802.3 multicast/broadcast address check.
fn is_multicast(addr: &[u8; 6]) -> bool {
    (addr[0] & 1) != 0
}

/// Return the Destination Address (DA) of the 802.11 frame.
///
/// - ToDS=0 → DA = addr1
/// - ToDS=1 → DA = addr3
fn frame_da(frame: &[u8]) -> [u8; 6] {
    if frame.len() < 4 {
        return [0u8; 6];
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let to_ds = (fc >> 8) & 1;
    if to_ds == 0 {
        get_addr(frame, 4) // addr1
    } else {
        get_addr(frame, 16) // addr3
    }
}

/// Map a QoS TID (0–7) to an IEEE 802.11 AC index (0=BK,1=BE,2=VI,3=VO).
fn tid_to_ac(tid: u8) -> usize {
    // ieee802_1d_to_ac mapping
    const MAP: [usize; 8] = [1, 0, 0, 1, 2, 2, 3, 3];
    MAP[(tid & 0x7) as usize]
}

/// Map an AC index to the hardware queue selector.
fn ac_to_qslt(ac: usize) -> u32 {
    match ac {
        0 => QSLT_BK,
        1 => QSLT_BE,
        2 => QSLT_VI,
        3 => QSLT_VO,
        _ => QSLT_BE,
    }
}

// ── IV insertion ──────────────────────────────────────────────────────────────

/// IV lengths per cipher.
fn iv_len(alg: EncAlg) -> usize {
    match alg {
        EncAlg::Wep40 | EncAlg::Wep104 => 4,
        EncAlg::Tkip | EncAlg::TkipWtmic => 8,
        EncAlg::AesCcmp => 8,
        EncAlg::None => 0,
    }
}

/// Prepend a cipher IV to the frame buffer, shifting the 802.11 header.
///
/// On entry `frame` is the raw 802.11 frame (starting at FC).  Returns a new
/// `KVec<u8>` with the IV inserted after the MAC header, or the original frame
/// if no key is selected.
fn tx_add_iv(
    frame: KVec<u8>,
    meta: &mut TxMeta,
    dev: &mut R92suDevice,
) -> core::result::Result<KVec<u8>, ()> {
    let alg = match meta.enc_alg {
        Some(a) => a,
        None => return Ok(frame),
    };
    let ivl = iv_len(alg);
    if ivl == 0 {
        return Ok(frame);
    }

    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let hdrlen = ieee80211_hdrlen(fc);
    let total = frame.len() + ivl;

    let mut out: KVec<u8> = KVec::new();
    out.extend_from_slice(&frame[..hdrlen], GFP_ATOMIC)
        .map_err(|_| ())?;

    // Write IV bytes.
    let iv_start = out.len();
    for _ in 0..ivl {
        out.push(0u8, GFP_ATOMIC).map_err(|_| ())?;
    }

    out.extend_from_slice(&frame[hdrlen..], GFP_ATOMIC)
        .map_err(|_| ())?;

    let iv = &mut out.as_mut_slice()[iv_start..iv_start + ivl];

    // Retrieve key material from the station.
    // Read immutable fields (key_idx, key_len) before taking the mutable
    // borrow needed to advance the per-key TX sequence counter.
    let (pn, key_idx) = if meta.sta_idx != usize::MAX {
        let sta = &mut dev.sta_list[meta.sta_idx];
        if let Some(key) = &mut sta.sta_key {
            // Snapshot immutable key fields before the mutable borrow.
            let kidx = key.index;
            let klen = key.key_len;
            match alg {
                EncAlg::Wep40 | EncAlg::Wep104 => {
                    if let crate::sta::KeyData::Wep40 { tx_seq, .. }
                    | crate::sta::KeyData::Wep104 { tx_seq, .. } = &mut key.data
                    {
                        let seq = *tx_seq;
                        // Filter weak WEP IV.
                        let b = ((seq >> 16) & 0xff) as u8;
                        let effective =
                            if (seq & 0xff00) == 0xff00 && b >= 3 && b < (3 + klen as u8) {
                                seq + 0x0100
                            } else {
                                seq
                            };
                        iv[0] = ((effective >> 16) & 0xff) as u8;
                        iv[1] = ((effective >> 8) & 0xff) as u8;
                        iv[2] = (effective & 0xff) as u8;
                        iv[3] = (kidx as u8) << 6;
                        *tx_seq = effective.wrapping_add(1);
                        (effective as u64, kidx)
                    } else {
                        (0, 0)
                    }
                }
                EncAlg::Tkip | EncAlg::TkipWtmic => {
                    if let crate::sta::KeyData::Tkip { tx_seq, .. } = &mut key.data {
                        let seq = *tx_seq;
                        iv[0] = ((seq >> 8) & 0xff) as u8;
                        iv[1] = (((seq >> 8) | 0x20) & 0x7f) as u8;
                        iv[2] = (seq & 0xff) as u8;
                        iv[3] = ((kidx as u8) << 6) | (1 << 5); // ExtIV
                        iv[4] = ((seq >> 16) & 0xff) as u8;
                        iv[5] = ((seq >> 24) & 0xff) as u8;
                        iv[6] = ((seq >> 32) & 0xff) as u8;
                        iv[7] = ((seq >> 40) & 0xff) as u8;
                        *tx_seq = seq.wrapping_add(1);
                        (seq, kidx)
                    } else {
                        (0, 0)
                    }
                }
                EncAlg::AesCcmp => {
                    if let crate::sta::KeyData::Ccmp { tx_seq, .. } = &mut key.data {
                        let seq = *tx_seq;
                        iv[0] = (seq & 0xff) as u8;
                        iv[1] = ((seq >> 8) & 0xff) as u8;
                        iv[2] = 0;
                        iv[3] = ((kidx as u8) << 6) | (1 << 5); // ExtIV
                        iv[4] = ((seq >> 16) & 0xff) as u8;
                        iv[5] = ((seq >> 24) & 0xff) as u8;
                        iv[6] = ((seq >> 32) & 0xff) as u8;
                        iv[7] = ((seq >> 40) & 0xff) as u8;
                        *tx_seq = seq.wrapping_add(1);
                        (seq, kidx)
                    } else {
                        (0, 0)
                    }
                }
                EncAlg::None => (0, 0),
            }
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    meta.pn = pn;
    meta.key_idx = key_idx;
    let _ = total; // suppress unused warning; out.len() == total
    Ok(out)
}

// ── TX descriptor builder ────────────────────────────────────────────────────

/// Build the 32-byte TX descriptor for a data/management frame.
///
/// Mirrors `r92su_tx_fill_desc()` from `tx.c`.
fn build_tx_desc(desc: &mut [u8; TX_DESC_SIZE], pkt_size: usize, meta: &TxMeta, mac_id: usize) {
    // DW0: pkt_size[15:0] | offset[23:16] | last_seg[26] | first_seg[27] | own[31]
    set_bits_le(desc, 0, 0, 16, pkt_size as u32);
    set_bits_le(desc, 0, 16, 8, TX_DESC_SIZE as u32);
    set_bits_le(desc, 0, 26, 1, 1); // last_seg
    set_bits_le(desc, 0, 27, 1, 1); // first_seg
    set_bits_le(desc, 0, 31, 1, 1); // own

    // DW1: macid[4:0] | queue_sel[12:8] | non_qos[16] | key_id[18:17] | sec_type[23:22]
    set_bits_le(desc, 1, 0, 5, mac_id as u32);
    set_bits_le(desc, 1, 8, 5, meta.queue_sel);
    set_bits_le(
        desc,
        1,
        16,
        1,
        if is_data_qos_from_meta(meta) { 0 } else { 1 },
    );
    if let Some(alg) = meta.enc_alg {
        let sec = match alg {
            EncAlg::Wep40 | EncAlg::Wep104 => SEC_WEP,
            EncAlg::Tkip | EncAlg::TkipWtmic => SEC_TKIP,
            EncAlg::AesCcmp => SEC_CCMP,
            EncAlg::None => SEC_NONE,
        };
        set_bits_le(desc, 1, 17, 2, meta.key_idx as u32); // key_id
        set_bits_le(desc, 1, 22, 2, sec); // sec_type
    }

    // DW2: bmc[7]
    set_bits_le(desc, 2, 7, 1, meta.is_bmc as u32);

    // DW3: priority[27:16] — firmware uses this to advance the HW seq counter.
    set_bits_le(desc, 3, 16, 12, meta.priority as u32);

    // DW4: user_rate[31]
    if meta.low_rate {
        set_bits_le(desc, 4, 31, 1, 1);
    }

    // DW5: user_tx_rate[30:0] — 1M if low_rate.
    if meta.low_rate {
        set_bits_le(desc, 5, 0, 31, RATE_1M_USER);
    }
}

/// Helper: check if QoS data from meta (approximated by non-zero tid or ampdu).
fn is_data_qos_from_meta(meta: &TxMeta) -> bool {
    meta.tid > 0 || meta.ampdu
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Locate the destination station in the station table and fill metadata.
fn tx_find_sta(dev: &R92suDevice, frame: &[u8], meta: &mut TxMeta) -> bool {
    let da = frame_da(frame);
    meta.is_bmc = is_multicast(&da);

    for (i, sta) in dev.sta_list.iter().enumerate() {
        if sta.mac_addr == da {
            meta.sta_idx = i;
            meta.ht_possible = sta.ht_sta;
            return true;
        }
    }
    // Fallback to station 0 (the AP / BSSID station).
    if !dev.sta_list.is_empty() {
        meta.sta_idx = 0;
        meta.ht_possible = dev.sta_list[0].ht_sta;
    }
    true
}

/// Select the encryption key for the frame.
fn tx_select_key(dev: &R92suDevice, frame: &[u8], meta: &mut TxMeta) -> bool {
    if meta.sta_idx == usize::MAX {
        return true;
    }
    let sta = &dev.sta_list[meta.sta_idx];
    if !sta.enc_sta {
        return true;
    }
    if let Some(key) = &sta.sta_key {
        meta.enc_alg = Some(key.algo);
        meta.key_idx = key.index;
        meta.needs_encrypt = !key.uploaded;
        // Set the Protected bit in the frame control word (caller must do this
        // if modifying the frame; here we just record the intent).
        meta.has_protect = true;
    }
    true
}

/// Derive QoS priority and queue selector from the frame.
fn tx_set_priority(frame: &[u8], meta: &mut TxMeta) {
    let fc = if frame.len() >= 2 {
        u16::from_le_bytes([frame[0], frame[1]])
    } else {
        return;
    };
    if is_data_qos(fc) {
        let hdrlen = ieee80211_hdrlen(fc);
        let tid = if frame.len() > hdrlen {
            frame[hdrlen] & 0x0f
        } else {
            0
        };
        meta.tid = tid;
        meta.priority = tid & 0x7;
        let ac = tid_to_ac(tid);
        meta.queue_sel = ac_to_qslt(ac);
    } else if is_mgmt(fc) {
        meta.queue_sel = QSLT_MGNT;
        meta.low_rate = true;
    } else {
        meta.queue_sel = QSLT_BE;
    }
}

/// Apply the low-rate hint: force 1 Mbit/s for PAE/ARP/DHCP frames.
///
/// Mirrors `r92su_tx_rate_control_hint()`.  We inspect the first 2 bytes of
/// the payload (after the 802.11 + LLC header) for the EtherType.
fn tx_low_rate_hint(frame: &[u8], meta: &mut TxMeta) {
    let fc = if frame.len() >= 2 {
        u16::from_le_bytes([frame[0], frame[1]])
    } else {
        return;
    };
    if !is_data(fc) {
        return;
    }
    let hdrlen = ieee80211_hdrlen(fc);
    // LLC snap header is 8 bytes; EtherType at offset hdrlen + 6.
    let et_off = hdrlen + 6;
    if frame.len() < et_off + 2 {
        return;
    }
    let ethertype = u16::from_be_bytes([frame[et_off], frame[et_off + 1]]);
    match ethertype {
        0x888e /* ETH_P_PAE */ | 0x0806 /* ETH_P_ARP */ => {
            meta.low_rate = true;
            meta.ht_possible = false;
        }
        0x0800 /* ETH_P_IP */ => {
            // Detect DHCP (UDP src=68/dst=67 or src=67/dst=68).
            let ip_off = hdrlen + 8; // after LLC-SNAP
            if frame.len() >= ip_off + 10 && frame[ip_off + 9] == 17 /* IPPROTO_UDP */ {
                let ihl = (frame[ip_off] & 0x0f) as usize * 4;
                let udp_off = ip_off + ihl;
                if frame.len() >= udp_off + 4 {
                    let src = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
                    let dst = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
                    if (src == 68 && dst == 67) || (src == 67 && dst == 68) {
                        meta.low_rate = true;
                        meta.ht_possible = false;
                    }
                }
            }
        }
        _ => {}
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Transmit a raw 802.11 frame.
///
/// `frame` must be a complete 802.11 MPDU (no FCS).  `mac_id` is the
/// firmware station index for the destination (use 5 for management frames
/// or when no station is known).
///
/// Mirrors `r92su_tx()` from `tx.c`.
///
/// # Wiring note
///
/// This function is to be called from `ndo_start_xmit` once that hook is
/// connected in `rust_helpers.c`.  The caller is responsible for converting
/// the Ethernet frame to 802.11 (via `ieee80211_data_from_8023`) before
/// passing it here.  Until SKB / `ieee80211_data_from_8023` Rust bindings
/// are available the full `ndo_start_xmit` pipeline is stubbed.
pub fn r92su_tx(dev: &mut R92suDevice, frame: &[u8], mac_id: usize) -> Result<()> {
    if !dev.is_open() {
        return Err(crate::r92u::R92suError::Io("device not open"));
    }
    if frame.len() < 4 {
        return Err(crate::r92u::R92suError::Io("frame too short"));
    }

    let mut meta = TxMeta::new();

    // ── Classify the frame ────────────────────────────────────────────────────
    tx_set_priority(frame, &mut meta);
    tx_find_sta(dev, frame, &mut meta);
    tx_select_key(dev, frame, &mut meta);
    tx_low_rate_hint(frame, &mut meta);

    // Override mac_id from metadata if found, else use caller's hint.
    let effective_mac_id = if meta.sta_idx != usize::MAX {
        dev.sta_list[meta.sta_idx].mac_id
    } else {
        mac_id
    };

    // ── Set Protected bit if we have a key ────────────────────────────────────
    let mut frame_buf: KVec<u8> = KVec::new();
    frame_buf
        .extend_from_slice(frame, GFP_KERNEL)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

    if meta.has_protect && frame_buf.len() >= 2 {
        frame_buf[1] |= 1 << 6; // set Protected bit in byte 1 of FC
    }

    // ── IV insertion ──────────────────────────────────────────────────────────
    let frame_buf = tx_add_iv(frame_buf, &mut meta, dev)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

    // ── Build the full USB packet: [TX_DESC | frame] ──────────────────────────
    let pkt_size = frame_buf.len(); // bytes after the descriptor
    let total = TX_DESC_SIZE + pkt_size;

    let mut pkt: KVec<u8> = KVec::from_elem(0u8, total, GFP_KERNEL)
        .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

    // Build descriptor into first 32 bytes.
    let mut desc_arr = [0u8; TX_DESC_SIZE];
    build_tx_desc(&mut desc_arr, pkt_size, &meta, effective_mac_id);
    pkt[..TX_DESC_SIZE].copy_from_slice(&desc_arr);
    pkt[TX_DESC_SIZE..].copy_from_slice(&frame_buf);

    // ── Submit via USB bulk-out ───────────────────────────────────────────────
    usb_tx_cmd(dev, &pkt)?;

    dev.tx_packets += 1;
    dev.tx_bytes += pkt_size as u64;

    pr_info!(
        "r92su tx: {} bytes queued (mac_id={})\n",
        pkt_size,
        effective_mac_id
    );
    Ok(())
}

/// Transmit a frame injected via a monitor-mode interface.
///
/// Strips the radiotap header (if present) and forwards to [`r92su_tx`].
///
/// Mirrors `r92su_tx_monitor()` from `tx.c`.
pub fn r92su_tx_monitor(dev: &mut R92suDevice, frame: &[u8]) -> Result<()> {
    if !dev.is_open() {
        return Err(crate::r92u::R92suError::Io("device not open"));
    }

    // Radiotap header: bytes 2–3 carry the total header length (LE u16).
    if frame.len() < RADIOTAP_HDR_MIN {
        pr_warn!("r92su tx_monitor: frame too short for radiotap header\n");
        return Err(crate::r92u::R92suError::Io("radiotap header too short"));
    }

    let rthdr_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
    if rthdr_len < RADIOTAP_HDR_MIN || rthdr_len > frame.len() {
        pr_warn!("r92su tx_monitor: invalid radiotap length {}\n", rthdr_len);
        return Err(crate::r92u::R92suError::Io("invalid radiotap length"));
    }

    // Strip the radiotap header; everything that follows is the 802.11 frame.
    let i3e = &frame[rthdr_len..];
    if i3e.len() < 10 {
        pr_warn!("r92su tx_monitor: frame after radiotap too short\n");
        return Err(crate::r92u::R92suError::Io("802.11 frame too short"));
    }

    // Use lowest-rate injection (5 = firmware management MACID).
    r92su_tx(dev, i3e, 5)
}
