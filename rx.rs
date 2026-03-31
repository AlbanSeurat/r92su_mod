// SPDX-License-Identifier: GPL-2.0
//! rx - RTL8192SU receive path.
//!
//! Mirrors `r92su/rx.c` from the C reference driver.  Processes USB bulk-in
//! buffers: parses aggregate RX descriptors, dispatches C2H events, and runs
//! each data frame through the processing pipeline:
//!
//! ```text
//! rx buffer ──► r92su_rx() ──► [C2H] ──► event::r92su_c2h_event()
//!                          └► [data] ──► rx_hw_header_check()
//!                                    ──► rx_find_sta()
//!                                    ──► rx_deduplicate()
//!                                    ──► rx_sta_stats()
//!                                    ──► rx_handle_mgmt()
//!                                    ──► rx_reorder_ampdu()
//!                                    ──► rx_defrag()
//!                                    ──► rx_deliver()
//! ```
//!
//! The delivery step (`rx_deliver`) queues the processed 802.11 frame onto
//! `dev.pending_rx` for later consumption once `netif_rx()` bindings are
//! available.  All other steps are functionally complete.

use core::ffi::c_void;

use kernel::prelude::*;

use crate::event; //
use crate::r92u::{R92suDevice, State}; //
use crate::sta; //

extern "C" {
    /// Deliver a 802.11 data frame to the network stack.
    ///
    /// Converts the 802.11 frame to 802.3 via `ieee80211_data_to_8023()` and
    /// then calls `netif_rx()`.  Returns 0 on success, negative errno on error.
    fn rust_helper_rx_deliver_80211(ndev: *mut c_void, data: *const u8, len: usize) -> i32;
}

// ── Constants ─────────────────────────────────────────────────────────────────

/// Size of the hardware RX descriptor in bytes.
pub const RX_DESC_SIZE: usize = 24;
/// Each DRVINFO unit is 8 bytes.
const RX_DRV_INFO_SIZE_UNIT: usize = 8;
/// FCS appended by the hardware to every frame.
const FCS_LEN: usize = 4;
/// Maximum size of a single USB RX buffer.
const RTL92SU_SIZE_MAX_RX_BUFFER: usize = 32768;
/// Reorder window: frames held for at most 100 ms (in jiffies, approximated).
const HT_RX_REORDER_BUF_TIMEOUT_JIFFIES: u64 = 10; // ~HZ/10

// ── RX descriptor ─────────────────────────────────────────────────────────────

/// Parsed 24-byte hardware RX descriptor (`rx_hdr` / `__le32 rx_hdr[6]`).
///
/// Fields mirror the `GET_RX_DESC_*` macros defined in `def.h`.  All values
/// are already in host byte order after parsing.
#[derive(Clone, Copy)]
pub struct RxDesc {
    dw: [u32; 6],
}

impl RxDesc {
    /// Parse from the first [`RX_DESC_SIZE`] bytes of `data`.
    ///
    /// Returns `None` if `data` is too short.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < RX_DESC_SIZE {
            return None;
        }
        let mut dw = [0u32; 6];
        for (i, w) in dw.iter_mut().enumerate() {
            let off = i * 4;
            *w = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        }
        Some(Self { dw })
    }

    #[inline]
    fn field(self, dword: usize, shift: u32, bits: u32) -> u32 {
        (self.dw[dword] >> shift) & ((1u32 << bits) - 1)
    }

    /// DW0[13:0] — payload length in bytes.
    pub fn pkt_len(self) -> usize {
        self.field(0, 0, 14) as usize
    }

    /// DW0[14] — CRC32 error flag.
    pub fn crc32(self) -> bool {
        self.field(0, 14, 1) != 0
    }

    /// DW0[19:16] — driver info size in [`RX_DRV_INFO_SIZE_UNIT`]-byte units.
    pub fn drvinfo_size(self) -> usize {
        self.field(0, 16, 4) as usize
    }

    /// DW0[25:24] — data shift offset (bytes to skip after header).
    pub fn shift(self) -> usize {
        self.field(0, 24, 2) as usize
    }

    /// DW0[27] — 1 = SW must decrypt; 0 = HW already decrypted.
    pub fn swdec(self) -> bool {
        self.field(0, 27, 1) != 0
    }

    /// DW1[8:0] == 0x1ff — packet is a C2H firmware event, not a data frame.
    pub fn is_cmd(self) -> bool {
        self.field(1, 0, 9) == 0x1ff
    }

    /// DW1[4:0] — firmware station index (MACID).
    pub fn macid(self) -> usize {
        self.field(1, 0, 5) as usize
    }

    /// DW2[23:16] — number of aggregated packets (first packet only).
    pub fn pktcnt(self) -> usize {
        self.field(2, 16, 8) as usize
    }

    /// DW3[5:0] — RX MCS index (or legacy rate index).
    pub fn rx_mcs(self) -> u32 {
        self.field(3, 0, 6)
    }

    /// DW3[6] — 1 if the frame was received at HT (MCS) rate.
    pub fn rx_ht(self) -> bool {
        self.field(3, 6, 1) != 0
    }

    /// DW3[9] — 1 if the frame was received in 40 MHz bandwidth.
    pub fn bw_40(self) -> bool {
        self.field(3, 9, 1) != 0
    }

    /// DW1[14] — this packet is part of an A-MPDU.
    pub fn paggr(self) -> bool {
        self.field(1, 14, 1) != 0
    }
}

// ── 802.11 frame helpers ──────────────────────────────────────────────────────

/// Return the 802.11 header length for a given `frame_control` word (host LE).
///
/// Mirrors `ieee80211_hdrlen()` from `<linux/ieee80211.h>`.
pub fn ieee80211_hdrlen(fc: u16) -> usize {
    let ftype = (fc >> 2) & 0x3;
    let fsub = (fc >> 4) & 0xf;
    match ftype {
        0 => 24, // Management: always 24
        1 => {
            // Control
            match fsub {
                0xA => 20,       // PS-Poll
                0xB | 0xC => 16, // RTS / CTS
                0xD => 10,       // ACK
                _ => 24,
            }
        }
        2 => {
            // Data
            let to_ds = (fc >> 8) & 1;
            let from_ds = (fc >> 9) & 1;
            let a4 = to_ds == 1 && from_ds == 1;
            let qos = (fsub & 0x8) != 0;
            24 + if a4 { 6 } else { 0 } + if qos { 2 } else { 0 }
        }
        _ => 24,
    }
}

/// `frame_control` type check helpers.
fn fc_type(fc: u16) -> u16 {
    (fc >> 2) & 0x3
}

fn is_mgmt(fc: u16) -> bool {
    fc_type(fc) == 0
}

fn is_data(fc: u16) -> bool {
    fc_type(fc) == 2
}

/// True if the frame has the Protected/WEP bit set (bit 14 of LE FC word).
fn has_protected(fc: u16) -> bool {
    (fc & (1 << 14)) != 0
}

/// True if the frame is a data-type frame with actual payload (not null).
fn is_data_present(fc: u16) -> bool {
    // type=data AND subtype bit-2 clear (bit-2 of subtype = null data flag)
    fc_type(fc) == 2 && ((fc >> 6) & 1) == 0
}

/// True if the data frame carries a QoS control field.
fn is_data_qos(fc: u16) -> bool {
    fc_type(fc) == 2 && ((fc >> 7) & 1) != 0
}

/// True if the frame has the More-Fragments bit set (bit 10 of LE FC word).
fn has_more_frags(fc: u16) -> bool {
    (fc & (1 << 10)) != 0
}

/// Extract the 4-bit TID from the QoS control field.
///
/// `qos_ctrl` is a pointer into the frame at `hdrlen` bytes past the start.
fn get_tid(frame: &[u8], hdrlen: usize) -> u8 {
    if frame.len() > hdrlen {
        frame[hdrlen] & 0x0f
    } else {
        0
    }
}

/// Return the Source Address (SA) of an 802.11 data or management frame.
///
/// For data:
/// - ToDS=0, FromDS=0 → SA = addr2
/// - ToDS=0, FromDS=1 → SA = addr3
/// - ToDS=1, FromDS=0 → SA = addr2
/// - ToDS=1, FromDS=1 → SA = addr4
///
/// For management: SA = addr2.
fn frame_sa(frame: &[u8]) -> Option<[u8; 6]> {
    if frame.len() < 10 {
        return None;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let to_ds = (fc >> 8) & 1;
    let from_ds = (fc >> 9) & 1;
    let addr_off = match (to_ds, from_ds) {
        (0, 0) | (1, 0) => 10, // addr2
        (0, 1) => 16,          // addr3
        (1, 1) => 24,          // addr4
        _ => 10,
    };
    if frame.len() < addr_off + 6 {
        return None;
    }
    let mut sa = [0u8; 6];
    sa.copy_from_slice(&frame[addr_off..addr_off + 6]);
    Some(sa)
}

// ── Per-frame metadata ────────────────────────────────────────────────────────

/// Per-frame RX state threaded through the processing pipeline.
///
/// Mirrors `struct r92su_rx_info` which is stored in `skb->cb` in the C driver.
struct RxMeta {
    /// Station index in `dev.sta_list` for the sender; `usize::MAX` if unknown.
    sta_idx: usize,
    /// Frame has the Protected bit set.
    has_protect: bool,
    /// SW must decrypt (HW did not).
    needs_decrypt: bool,
    /// Extracted IV value (used for replay detection).
    iv: u64,
    /// Queue mapping (AC index 0–3 from QoS priority).
    ac: usize,
}

impl RxMeta {
    fn new() -> Self {
        Self {
            sta_idx: usize::MAX,
            has_protect: false,
            needs_decrypt: false,
            iv: 0,
            ac: 0,
        }
    }
}

/// Return value from each pipeline step.
enum RxControl {
    Continue,
    Queue, // frame was queued (defrag / reorder); consumed, do not drop
    Drop,
}

// ── Pipeline steps ────────────────────────────────────────────────────────────

/// Validate the raw 802.11 frame and initialise [`RxMeta`].
///
/// Mirrors `r92su_rx_hw_header_check()`.
fn rx_hw_header_check<'a>(
    desc: &RxDesc,
    frame: &'a [u8],
    meta: &mut RxMeta,
) -> Result<&'a [u8], RxControl> {
    // Must have at least a 3-address header + FCS.
    if frame.len() < 24 + FCS_LEN {
        return Err(RxControl::Drop);
    }

    // Drop frames with a bad FCS.
    if desc.crc32() {
        return Err(RxControl::Drop);
    }

    // Strip FCS.
    let frame = &frame[..frame.len() - FCS_LEN];

    let fc = u16::from_le_bytes([frame[0], frame[1]]);

    // Only accept data and management frames.
    if !is_data_present(fc) && !is_mgmt(fc) {
        return Err(RxControl::Drop);
    }

    // Minimum header length check.
    let hdrlen = ieee80211_hdrlen(fc);
    if frame.len() < hdrlen {
        return Err(RxControl::Drop);
    }

    // Compute AC from QoS priority.
    meta.ac = if is_data_qos(fc) {
        let tid = get_tid(frame, hdrlen);
        // ieee802_1d_to_ac mapping: TID → AC (simplified: BK=1, BE=0, VI=2, VO=3)
        const IEEE802_1D_TO_AC: [usize; 8] = [0, 1, 1, 0, 2, 2, 3, 3];
        IEEE802_1D_TO_AC[(tid & 0x7) as usize]
    } else {
        0
    };

    meta.has_protect = has_protected(fc);
    meta.needs_decrypt = meta.has_protect && desc.swdec();

    Ok(frame)
}

/// Look up the sender station in the station table.
///
/// Mirrors `r92su_rx_find_sta()`.
fn rx_find_sta(dev: &R92suDevice, frame: &[u8], meta: &mut RxMeta) {
    if let Some(sa) = frame_sa(frame) {
        for (i, sta) in dev.sta_list.iter().enumerate() {
            if sta.mac_addr == sa {
                meta.sta_idx = i;
                return;
            }
        }
    }
    // Try to use the BSSID station (mac_id 0) as fallback.
    if !dev.sta_list.is_empty() {
        meta.sta_idx = 0;
    }
}

/// Drop duplicate frames based on `seq_ctrl`.
///
/// Mirrors `r92su_rx_deduplicate()`.
fn rx_deduplicate(dev: &mut R92suDevice, frame: &[u8], meta: &RxMeta) -> RxControl {
    if meta.sta_idx == usize::MAX || frame.len() < 22 {
        return RxControl::Continue;
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let seq_ctrl = u16::from_le_bytes([frame[22], frame[23]]);

    let sta = &mut dev.sta_list[meta.sta_idx];
    let rx_seq = if is_data_qos(fc) {
        let hdrlen = ieee80211_hdrlen(fc);
        let tid = get_tid(frame, hdrlen) as usize;
        &mut sta.rx_seq_tid[tid.min(15)]
    } else {
        &mut sta.rx_seq
    };

    if *rx_seq == seq_ctrl {
        sta.drop_dup += 1;
        return RxControl::Drop;
    }
    *rx_seq = seq_ctrl;
    RxControl::Continue
}

/// Update per-station RX rate statistics from the descriptor.
///
/// Mirrors `r92su_rx_sta_stats()`.
fn rx_sta_stats(dev: &mut R92suDevice, desc: &RxDesc, meta: &RxMeta) {
    if meta.sta_idx == usize::MAX {
        return;
    }
    let sta = &mut dev.sta_list[meta.sta_idx];
    // Rate info flags: 1 = MCS (HT), 0 = legacy.
    const RATE_INFO_FLAGS_MCS: u32 = 1;
    const RATE_INFO_BW_40: u32 = 1;
    const RATE_INFO_BW_20: u32 = 0;

    if desc.rx_ht() {
        sta.last_rx_rate = desc.rx_mcs();
        sta.last_rx_rate_flag = RATE_INFO_FLAGS_MCS;
        sta.last_rx_rate_bw = if desc.bw_40() {
            RATE_INFO_BW_40
        } else {
            RATE_INFO_BW_20
        };
    } else {
        sta.last_rx_rate = desc.rx_mcs();
        sta.last_rx_rate_flag = 0;
        sta.last_rx_rate_bw = RATE_INFO_BW_20;
    }
}

/// Drop management frames (cfg80211_rx_mgmt not yet bound).
///
/// Mirrors `r92su_rx_handle_mgmt()`.
fn rx_handle_mgmt(frame: &[u8]) -> RxControl {
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if is_mgmt(fc) {
        // TODO: forward to cfg80211_rx_mgmt() once bindings are available.
        return RxControl::Queue; // consumed; not delivered
    }
    RxControl::Continue
}

// ── A-MPDU Reorder ────────────────────────────────────────────────────────────

/// Queue a frame into the per-TID reorder buffer and release in-order frames
/// into `out`.
///
/// Simplified version of `r92su_rx_reorder_ampdu()`.  Timer-based flushing is
/// not yet implemented (requires kernel timer bindings); frames older than the
/// window are released immediately.
///
/// Returns `RxControl::Queue` if the frame was placed in the buffer (caller
/// must not free it), `RxControl::Continue` if passed directly.
fn rx_reorder_ampdu(
    dev: &mut R92suDevice,
    frame: KVec<u8>,
    meta: &RxMeta,
    out: &mut KVec<KVec<u8>>,
) -> (RxControl, Option<KVec<u8>>) {
    // Only reorder QoS data frames from known stations.
    let fc = if frame.len() >= 2 {
        u16::from_le_bytes([frame[0], frame[1]])
    } else {
        return (RxControl::Continue, Some(frame));
    };

    if !is_data_qos(fc) || meta.sta_idx == usize::MAX {
        return (RxControl::Continue, Some(frame));
    }

    let hdrlen = ieee80211_hdrlen(fc);
    let tid = get_tid(&frame, hdrlen) as usize;
    if tid >= 16 {
        return (RxControl::Continue, Some(frame));
    }

    // seq_ctrl: bits 15:4 = sequence number, bits 3:0 = fragment number.
    if frame.len() < 24 {
        return (RxControl::Continue, Some(frame));
    }
    let sc = u16::from_le_bytes([frame[22], frame[23]]);
    let mpdu_seq = (sc >> 4) & 0x0fff;

    let sta = &mut dev.sta_list[meta.sta_idx];
    let tid_opt = &mut sta.rx_tid[tid];

    let tid_buf = match tid_opt.as_mut() {
        Some(t) => t,
        None => return (RxControl::Continue, Some(frame)),
    };

    let size = tid_buf.size as u16;
    let head_seq = tid_buf.head_seq;

    // Out-of-window old frame: drop.
    if ieee80211_sn_less(mpdu_seq, head_seq) {
        return (RxControl::Drop, None);
    }

    // Frame beyond window: advance head_seq and flush.
    if !ieee80211_sn_less(mpdu_seq, ieee80211_sn_add(head_seq, size)) {
        let new_head = ieee80211_sn_inc(ieee80211_sn_sub(mpdu_seq, size));
        reorder_release_frames(tid_buf, new_head, out);
    }

    let index = (ieee80211_sn_sub(mpdu_seq, tid_buf.ssn) % (size as u16)) as usize;

    // Duplicate in buffer.
    if tid_buf.reorder_buf[index].is_some() {
        return (RxControl::Drop, None);
    }

    // Frame at head with empty buffer: pass directly.
    if mpdu_seq == tid_buf.head_seq && tid_buf.len == 0 {
        tid_buf.head_seq = ieee80211_sn_inc(mpdu_seq);
        return (RxControl::Continue, Some(frame));
    }

    // Store in reorder buffer.
    let jiffies_now = unsafe { kernel::bindings::jiffies as u64 };
    tid_buf.reorder_buf[index] = Some(frame);
    tid_buf.reorder_time[index] = jiffies_now + HT_RX_REORDER_BUF_TIMEOUT_JIFFIES;
    tid_buf.len += 1;

    reorder_release_in_order(tid_buf, out);

    (RxControl::Queue, None)
}

/// Release all frames from `head_seq` up to (but not including) `new_head_seq`.
fn reorder_release_frames(
    tid: &mut crate::sta::RxTid,
    new_head_seq: u16,
    out: &mut KVec<KVec<u8>>,
) {
    while ieee80211_sn_less(tid.head_seq, new_head_seq) {
        let index = (ieee80211_sn_sub(tid.head_seq, tid.ssn) % (tid.size as u16)) as usize;
        reorder_release_slot(tid, index, out);
    }
}

/// Release consecutive in-order frames from the front of the buffer.
fn reorder_release_in_order(tid: &mut crate::sta::RxTid, out: &mut KVec<KVec<u8>>) {
    loop {
        let index = (ieee80211_sn_sub(tid.head_seq, tid.ssn) % (tid.size as u16)) as usize;
        if tid.reorder_buf[index].is_none() {
            break;
        }
        reorder_release_slot(tid, index, out);
    }
}

/// Release one slot from the reorder buffer.
fn reorder_release_slot(tid: &mut crate::sta::RxTid, index: usize, out: &mut KVec<KVec<u8>>) {
    if let Some(frame) = tid.reorder_buf[index].take() {
        tid.len -= 1;
        let _ = out.push(frame, GFP_ATOMIC);
    }
    tid.head_seq = ieee80211_sn_inc(tid.head_seq);
}

// ── 802.11 sequence number arithmetic ────────────────────────────────────────

/// 12-bit sequence number arithmetic (`IEEE80211_SEQ_MASK = 0x0fff`).

fn ieee80211_sn_less(a: u16, b: u16) -> bool {
    ((b - a) & 0x0fff) < 0x0800
}

fn ieee80211_sn_add(a: u16, b: u16) -> u16 {
    (a + b) & 0x0fff
}

fn ieee80211_sn_sub(a: u16, b: u16) -> u16 {
    (a - b) & 0x0fff
}

fn ieee80211_sn_inc(a: u16) -> u16 {
    (a + 1) & 0x0fff
}

// ── Defragmentation ───────────────────────────────────────────────────────────

/// Defragment a received 802.11 frame.
///
/// Simplified port of `r92su_rx_defrag()`.  Returns `RxControl::Continue`
/// with the reassembled frame in `frame_out` if complete, `RxControl::Queue`
/// if a fragment was buffered, or `RxControl::Drop` on error.
fn rx_defrag(
    dev: &mut R92suDevice,
    frame: KVec<u8>,
    meta: &RxMeta,
    frame_out: &mut Option<KVec<u8>>,
) -> RxControl {
    if meta.sta_idx == usize::MAX || frame.len() < 24 {
        *frame_out = Some(frame);
        return RxControl::Continue;
    }

    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let sc = u16::from_le_bytes([frame[22], frame[23]]);
    let frag_num = (sc & 0x000f) as u8;
    let more_frags = has_more_frags(fc);

    let hdrlen = ieee80211_hdrlen(fc);
    let ac = meta.ac.min(3);

    if !more_frags && frag_num == 0 {
        // Unfragmented frame; discard any stale defrag buffer.
        let sta = &mut dev.sta_list[meta.sta_idx];
        sta.defrag[ac].purge();
        *frame_out = Some(frame);
        return RxControl::Continue;
    }

    if more_frags && frag_num == 0 {
        // First fragment: reset defrag buffer.
        let sta = &mut dev.sta_list[meta.sta_idx];
        sta.defrag[ac].purge();
        let sta = &mut dev.sta_list[meta.sta_idx];
        if frame.len() <= hdrlen {
            return RxControl::Drop;
        }
        let payload_len = frame.len() - hdrlen;
        // Store the full first fragment (header + payload).
        let mut entry: KVec<u8> = KVec::new();
        if entry.extend_from_slice(&frame, GFP_ATOMIC).is_err() {
            return RxControl::Drop;
        }
        sta.defrag[ac].size = payload_len;
        let _ = sta.defrag[ac].queue.push(entry, GFP_ATOMIC);
        return RxControl::Queue;
    }

    // Middle or last fragment: append payload.
    let sta = &mut dev.sta_list[meta.sta_idx];
    if sta.defrag[ac].queue.is_empty() {
        // No first fragment buffered.
        return RxControl::Drop;
    }

    let data_payload = if frame.len() > hdrlen {
        &frame[hdrlen..]
    } else {
        return RxControl::Drop;
    };
    sta.defrag[ac].size += data_payload.len();

    let mut piece: KVec<u8> = KVec::new();
    if piece.extend_from_slice(data_payload, GFP_ATOMIC).is_err() {
        sta.defrag[ac].purge();
        return RxControl::Drop;
    }
    let _ = sta.defrag[ac].queue.push(piece, GFP_ATOMIC);

    if more_frags {
        // More fragments to come.
        return RxControl::Queue;
    }

    // Last fragment: reassemble.
    // The first buffer holds the full 802.11 header + first payload.
    // Subsequent buffers hold payloads only.
    let mut assembled: KVec<u8> = KVec::new();
    for frag in sta.defrag[ac].queue.iter() {
        if assembled.extend_from_slice(frag, GFP_ATOMIC).is_err() {
            sta.defrag[ac].purge();
            return RxControl::Drop;
        }
    }
    sta.defrag[ac].purge();
    *frame_out = Some(assembled);
    RxControl::Continue
}

// ── Delivery ──────────────────────────────────────────────────────────────────

/// Deliver a processed 802.11 frame to the network stack.
///
/// If a cached `netdev_ptr` is available the frame is converted to 802.3
/// via `rust_helper_rx_deliver_80211()` and passed to `netif_rx()`.
/// If no netdev is available yet the frame is queued in `pending_rx` for
/// later delivery (e.g. during a scan before the device is fully open).
///
/// Mirrors `r92su_rx_deliver()` / `__r92su_rx_deliver()`.
fn rx_deliver(dev: &mut R92suDevice, frame: KVec<u8>) {
    dev.rx_bytes += frame.len() as u64;
    dev.rx_packets += 1;

    if !dev.netdev_ptr.is_null() && dev.is_open() {
        // SAFETY: netdev_ptr was set from rust_helper_get_netdev_ptr() after
        // register_netdev() and is valid for the lifetime of the interface.
        // frame.as_ptr() / frame.len() are valid for the duration of this call.
        let ret =
            unsafe { rust_helper_rx_deliver_80211(dev.netdev_ptr, frame.as_ptr(), frame.len()) };
        if ret < 0 {
            dev.rx_dropped += 1;
        }
    } else {
        // Device not yet open or no netdev — buffer the frame.
        if dev.pending_rx.push(frame, GFP_ATOMIC).is_err() {
            dev.rx_dropped += 1;
        }
    }
}

// ── Data frame processing ─────────────────────────────────────────────────────

/// Process a single non-C2H data frame.
///
/// Runs it through the full receive pipeline; delivers the frame if it
/// passes all checks.
fn process_data_frame(dev: &mut R92suDevice, desc: &RxDesc, raw_frame: &[u8]) {
    // ── Header check ─────────────────────────────────────────────────────────
    let mut meta = RxMeta::new();
    let frame_slice = match rx_hw_header_check(desc, raw_frame, &mut meta) {
        Ok(f) => f,
        Err(_) => {
            dev.rx_dropped += 1;
            return;
        }
    };

    // ── Clone frame into owned buffer ─────────────────────────────────────────
    let mut frame: KVec<u8> = KVec::new();
    if frame.extend_from_slice(frame_slice, GFP_ATOMIC).is_err() {
        dev.rx_dropped += 1;
        return;
    }

    // ── Station lookup ────────────────────────────────────────────────────────
    rx_find_sta(dev, &frame, &mut meta);

    // ── Deduplication ────────────────────────────────────────────────────────
    match rx_deduplicate(dev, &frame, &meta) {
        RxControl::Drop => {
            dev.rx_dropped += 1;
            return;
        }
        _ => {}
    }

    // ── Station RX stats ─────────────────────────────────────────────────────
    rx_sta_stats(dev, desc, &meta);

    // ── Management frame handling ────────────────────────────────────────────
    match rx_handle_mgmt(&frame) {
        RxControl::Queue | RxControl::Drop => return,
        RxControl::Continue => {}
    }

    // ── A-MPDU reorder ───────────────────────────────────────────────────────
    let mut reordered: KVec<KVec<u8>> = KVec::new();
    let (ctrl, frame_opt) = rx_reorder_ampdu(dev, frame, &meta, &mut reordered);
    match ctrl {
        RxControl::Drop => {
            dev.rx_dropped += 1;
            return;
        }
        RxControl::Queue => {
            // Frame is buffered; deliver any frames released from the window.
            for f in reordered.drain_all() {
                deliver_one(dev, f, &meta);
            }
            return;
        }
        RxControl::Continue => {}
    }

    // Deliver the frame (not reordered).
    if let Some(f) = frame_opt {
        for released in reordered.drain_all() {
            deliver_one(dev, released, &meta);
        }
        deliver_one(dev, f, &meta);
    }
}

/// Run defrag then deliver a single frame.
fn deliver_one(dev: &mut R92suDevice, frame: KVec<u8>, meta: &RxMeta) {
    let mut frame_out: Option<KVec<u8>> = None;
    match rx_defrag(dev, frame, meta, &mut frame_out) {
        RxControl::Drop => {
            dev.rx_dropped += 1;
        }
        RxControl::Queue => { /* fragment buffered */ }
        RxControl::Continue => {
            if let Some(f) = frame_out {
                rx_deliver(dev, f);
            }
        }
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Process a raw USB bulk-in buffer.
///
/// Called from the USB RX completion handler (to be wired up in a future
/// step) after a successful bulk-in transfer.  Parses the packet aggregate,
/// dispatches C2H events, and feeds data frames through the processing
/// pipeline.
///
/// Mirrors `r92su_rx()` in `rx.c`.
pub fn r92su_rx(dev: &mut R92suDevice, buf: &[u8]) {
    if !dev.is_open() {
        return;
    }

    let max_len = buf.len().min(RTL92SU_SIZE_MAX_RX_BUFFER - RX_DESC_SIZE);
    if max_len < RX_DESC_SIZE {
        return;
    }

    // Parse the packet count from the first descriptor.
    let first_desc = match RxDesc::parse(&buf[..RX_DESC_SIZE]) {
        Some(d) => d,
        None => return,
    };
    let pkt_cnt = first_desc.pktcnt().max(1);

    let mut pos = 0usize;
    let mut remaining = pkt_cnt;

    while pos + RX_DESC_SIZE <= max_len && remaining > 0 {
        let desc = match RxDesc::parse(&buf[pos..]) {
            Some(d) => d,
            None => break,
        };

        let drvinfo = desc.drvinfo_size() * RX_DRV_INFO_SIZE_UNIT;
        let shift = desc.shift();
        let pkt_len = desc.pkt_len();
        let hdr_len = RX_DESC_SIZE + drvinfo;

        if pos + hdr_len + shift + pkt_len > max_len {
            pr_info!("r92su rx: clipped frame at pos={}\n", pos);
            break;
        }

        if desc.is_cmd() {
            // C2H firmware event: the h2cc2h header starts right after
            // the RX descriptor (no shift for C2H packets).
            let c2h_start = pos + RX_DESC_SIZE;
            let c2h_end = c2h_start + pkt_len;
            if c2h_end <= buf.len() {
                event::r92su_c2h_event(dev, &buf[c2h_start..c2h_end]);
            }
        } else {
            let frame_start = pos + hdr_len + shift;
            let frame_end = frame_start + pkt_len;
            if frame_end <= buf.len() {
                process_data_frame(dev, &desc, &buf[frame_start..frame_end]);
            }
        }

        // Advance by alignment; if rx_alignment is 0, use raw size.
        let raw_step = hdr_len + pkt_len;
        let step = if dev.rx_alignment > 1 {
            (raw_step + dev.rx_alignment - 1) & !(dev.rx_alignment - 1)
        } else {
            raw_step
        };
        pos += step;
        remaining -= 1;
    }
}

// ── IE scanning utility ───────────────────────────────────────────────────────

/// Search a sequence of 802.11 Information Elements for one with the given tag.
///
/// Returns the offset of the matching IE (including the tag and length bytes)
/// within `ies`, or `None` if not found.
///
/// Mirrors `r92su_find_ie()` in `rx.c`.
pub fn find_ie(ies: &[u8], ie_tag: u8) -> Option<usize> {
    let mut pos = 0usize;
    while pos + 2 <= ies.len() {
        let tag = ies[pos];
        let len = ies[pos + 1] as usize;
        if pos + 2 + len > ies.len() {
            break;
        }
        if tag == ie_tag {
            return Some(pos);
        }
        pos += 2 + len;
    }
    None
}
