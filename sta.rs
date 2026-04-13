// SPDX-License-Identifier: GPL-2.0
//! Station and key management for RTL8192SU.
//!
//! Mirrors `sta.c` / `sta.h` from the C reference driver.
//!
//! # Station table
//!
//! The RTL8712 firmware uses a 5-bit MACID field in the TX/RX descriptors,
//! giving a hardware station table of up to 32 entries.  A linear list is
//! used here because 32 entries makes a hash table wasteful.
//!
//! # RX TID reordering
//!
//! Each station can hold up to [`IEEE80211_NUM_TIDS`] (16) per-TID reorder
//! buffers, each containing a 64-slot window.  Entries are allocated lazily
//! when a BlockAck session is established (`sta_alloc_tid`) and freed when
//! the session ends.
//!
//! # Encryption keys
//!
//! The driver supports WEP-40, WEP-104, TKIP and CCMP.  Key material is
//! stored in [`R92suKey`]; crypto handles for software fallback are NOT
//! allocated here — they are added in the RX/TX crypto path (Part 3).

use kernel::prelude::*; //

use crate::cmd::EncAlg; //
use crate::r92u::{R92suDevice, Result, ETH_ALEN}; //

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Maximum number of firmware-managed stations (5-bit MACID → 32 entries).
pub const MAX_STA: usize = 32;

/// Number of 802.11 TIDs (0–15).
pub const IEEE80211_NUM_TIDS: usize = 16;

/// Number of Access Categories used for defragmentation queues.
pub const NUM_ACS: usize = 4;

/// WLAN cipher suite identifiers (RSN / IEEE 802.11-2020 Table 12-8).
pub const WLAN_CIPHER_SUITE_WEP40: u32 = 0x000F_AC01;
pub const WLAN_CIPHER_SUITE_TKIP: u32 = 0x000F_AC02;
pub const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000F_AC04;
pub const WLAN_CIPHER_SUITE_WEP104: u32 = 0x000F_AC05;

/// Key length in bytes for CCMP (AES-CCM).
pub const WLAN_KEY_LEN_CCMP: usize = 16;

/// Key length in bytes for TKIP (encryption key + two MIC keys).
pub const WLAN_KEY_LEN_TKIP: usize = 32;

/// Key length in bytes for WEP-40.
pub const WLAN_KEY_LEN_WEP40: usize = 5;

/// Key length in bytes for WEP-104.
pub const WLAN_KEY_LEN_WEP104: usize = 13;

// ---------------------------------------------------------------------------
// Key material storage
// ---------------------------------------------------------------------------

/// Per-algorithm key material.
///
/// Mirrors the anonymous union inside `struct r92su_key` in `sta.h`.
/// Crypto transform handles (`struct crypto_aead *`, `struct crypto_cipher *`)
/// are intentionally omitted here — they will be wired in when the software
/// crypto path is implemented in the RX/TX layer.
pub enum KeyData {
    Wep40 {
        /// WEP IV counter for the next TX frame (24-bit).
        tx_seq: u32,
        /// Expected next RX IV (24-bit).
        rx_seq: u32,
        key: [u8; WLAN_KEY_LEN_WEP40],
    },
    Wep104 {
        tx_seq: u32,
        rx_seq: u32,
        key: [u8; WLAN_KEY_LEN_WEP104],
    },
    Tkip {
        /// 48-bit TX PN counter.
        tx_seq: u64,
        /// 48-bit RX PN counter.
        rx_seq: u64,
        /// 16-byte encryption key (TK1) followed by 8-byte TX MIC key and
        /// 8-byte RX MIC key (= WLAN_KEY_LEN_TKIP = 32 bytes total).
        key: [u8; WLAN_KEY_LEN_TKIP],
    },
    Ccmp {
        /// 48-bit TX PN counter.
        tx_seq: u64,
        /// 48-bit RX PN counter (checked per-MSDU).
        rx_seq: u64,
        key: [u8; WLAN_KEY_LEN_CCMP],
    },
}

// ---------------------------------------------------------------------------
// Encryption key entry
// ---------------------------------------------------------------------------

/// Encryption key held by the driver for a station or as a group key.
///
/// Mirrors `struct r92su_key` from `sta.h`.
pub struct R92suKey {
    /// MAC address this key is bound to (all-zeros for group keys).
    pub mac_addr: [u8; ETH_ALEN],
    /// Firmware algorithm selector — used when sending `H2C_SETKEY_CMD`.
    pub algo: EncAlg,
    /// Length in bytes of the key material sent to the firmware.
    pub key_len: usize,
    /// True once the key has been uploaded to firmware.
    pub uploaded: bool,
    /// True for a pairwise (unicast) key; false for a group key.
    pub pairwise: bool,
    /// cfg80211 key index (0–3).
    pub index: usize,
    /// Key material and sequence number state.
    pub data: KeyData,
}

// ---------------------------------------------------------------------------
// RX TID reorder buffer
// ---------------------------------------------------------------------------

/// Per-TID A-MPDU reorder state for one station.
///
/// Mirrors `struct r92su_rx_tid` from `sta.h`.
///
/// The 64-slot `reorder_buf` holds out-of-order MSDUs keyed by their
/// sequence number modulo 64.  `head_seq` is the next expected sequence
/// number; entries older than `head_seq + size` are flushed.
///
/// The C driver uses a `struct timer_list` to flush stale entries after
/// 1 second.  In this Rust implementation the timer deadline is tracked in
/// `flush_at_jiffies`; the RX path (Part 3) checks this field and flushes
/// the window when it expires.
pub struct RxTid {
    /// TID index (0–15).
    pub tid: u8,
    /// Starting sequence number of the BA window.
    pub ssn: u16,
    /// Next expected sequence number (advances as the window fills).
    pub head_seq: u16,
    /// Number of occupied slots in `reorder_buf`.
    pub len: u16,
    /// Window size (set to 32 on alloc; may be updated by ADDBA).
    pub size: u16,
    /// Count of frames dropped due to reorder-buffer overflow.
    pub dropped: u16,
    /// Buffered MSDUs indexed by `seq_num % 64`.
    pub reorder_buf: [Option<KVec<u8>>; 64],
    /// Jiffies when slot `i` was buffered (for timeout tracking).
    pub reorder_time: [u64; 64],
    /// Jiffies deadline after which the oldest buffered entry must be
    /// flushed even if the window cannot advance normally.
    pub flush_at_jiffies: u64,
}

impl RxTid {
    fn new(tid: u8, ssn: u16) -> Self {
        Self {
            tid,
            ssn,
            head_seq: ssn >> 4, // mirrors `new_tid->head_seq = ssn >> 4` in sta.c
            len: 0,
            size: 32,
            dropped: 0,
            reorder_buf: core::array::from_fn(|_| None),
            reorder_time: [0u64; 64],
            flush_at_jiffies: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Defragmentation entry
// ---------------------------------------------------------------------------

/// Per-AC fragment reassembly buffer for one station.
///
/// Mirrors `struct r92su_defrag_entry` from `sta.h`.  Each access category
/// keeps a queue of raw MSDU fragments that are assembled into a complete
/// MSDU once the last fragment (More Frag bit clear) is received.
pub struct DefragEntry {
    /// Queue of received fragments (each as a raw frame buffer).
    pub queue: KVec<KVec<u8>>,
    /// Total reassembled byte count so far.
    pub size: usize,
}

impl DefragEntry {
    fn new() -> Self {
        Self {
            queue: KVec::new(),
            size: 0,
        }
    }

    /// Discard all buffered fragments for this AC.
    pub fn purge(&mut self) {
        self.queue = KVec::new();
        self.size = 0;
    }
}

// ---------------------------------------------------------------------------
// Station entry
// ---------------------------------------------------------------------------

/// One entry in the driver's station table.
///
/// Mirrors `struct r92su_sta` from `sta.h`.
pub struct R92suSta {
    // ── Identity ─────────────────────────────────────────────────────────────
    /// Hardware MAC address (6 bytes).
    pub mac_addr: [u8; ETH_ALEN],
    /// 5-bit firmware station index (0–31).
    pub mac_id: usize,
    /// Association ID (AID) assigned by the AP.
    pub aid: usize,
    // ── Capability flags ─────────────────────────────────────────────────────
    /// Station supports QoS / WMM.
    pub qos_sta: bool,
    /// Station is HT-capable (802.11n).
    pub ht_sta: bool,
    /// Station requires encryption.
    pub enc_sta: bool,
    // ── Statistics ───────────────────────────────────────────────────────────
    /// Unix timestamp (seconds) when the station last associated.
    pub last_connected: i64,
    /// Last measured RSSI (dBm).
    pub signal: i32,
    /// Numeric rate of the last received frame (legacy Mbps × 10 or MCS index).
    pub last_rx_rate: u32,
    /// `RATE_INFO_FLAGS_*` bitmask for `last_rx_rate`.
    pub last_rx_rate_flag: u32,
    /// `RATE_INFO_BW_*` value for `last_rx_rate`.
    pub last_rx_rate_bw: u32,
    // ── Sequence number tracking (deduplication) ──────────────────────────────
    /// Last received non-QoS sequence number (little-endian).
    pub rx_seq: u16,
    /// Last received sequence number per TID (little-endian).
    pub rx_seq_tid: [u16; IEEE80211_NUM_TIDS],
    /// Non-QoS TX sequence counter.
    pub tx_seq: u32,
    /// Per-TID TX sequence counters.
    pub tx_seq_tid: [u32; IEEE80211_NUM_TIDS],
    /// Count of duplicate frames dropped.
    pub drop_dup: u64,
    // ── Per-TID A-MPDU reorder state ─────────────────────────────────────────
    /// Reorder buffer allocated when a BlockAck session is established.
    pub rx_tid: [Option<KBox<RxTid>>; IEEE80211_NUM_TIDS],
    // ── Defragmentation ──────────────────────────────────────────────────────
    /// Per-AC fragment reassembly queues.
    pub defrag: [DefragEntry; NUM_ACS],
    // ── Unicast key ──────────────────────────────────────────────────────────
    /// Pairwise encryption key installed for this station.
    pub sta_key: Option<KBox<R92suKey>>,
}

impl R92suSta {
    fn new(mac_addr: &[u8; ETH_ALEN], mac_id: usize, aid: usize) -> Self {
        let mut this = Self {
            mac_addr: *mac_addr,
            mac_id,
            aid,
            qos_sta: false,
            ht_sta: false,
            enc_sta: false,
            last_connected: 0,
            signal: 0,
            last_rx_rate: 0,
            last_rx_rate_flag: 0,
            last_rx_rate_bw: 0,
            rx_seq: 0,
            rx_seq_tid: [0u16; IEEE80211_NUM_TIDS],
            tx_seq: 0,
            tx_seq_tid: [0u32; IEEE80211_NUM_TIDS],
            drop_dup: 0,
            rx_tid: core::array::from_fn(|_| None),
            defrag: core::array::from_fn(|_| DefragEntry::new()),
            sta_key: None,
        };
        // Record wall-clock time of association using kernel jiffies as a
        // seconds approximation.  Mirrors `ktime_get_ts(&uptime);
        // sta->last_connected = uptime.tv_sec;` in sta.c.
        //
        // SAFETY: jiffies is a kernel global, always valid after init.
        this.last_connected = unsafe { kernel::bindings::jiffies as i64 };
        this
    }
}

// ---------------------------------------------------------------------------
// impl R92suDevice — station management methods
// ---------------------------------------------------------------------------

impl R92suDevice {
    /// Allocate a new station entry and add it to the station table.
    ///
    /// If a station with the same `mac_id` already exists it is removed
    /// first (mirrors `r92su_sta_del(r92su, mac_id)` in sta.c).
    ///
    /// Returns `Err` if the station table is full or memory allocation fails.
    ///
    /// Mirrors `r92su_sta_alloc()` from `sta.c`.
    pub fn sta_alloc(
        &mut self,
        mac_addr: &[u8; ETH_ALEN],
        mac_id: usize,
        aid: usize,
    ) -> Result<()> {
        if self.sta_num >= MAX_STA {
            return Err(crate::r92u::R92suError::Io("station table full"));
        }

        // Remove any existing entry with the same hardware slot.
        self.sta_del(mac_id);

        let sta = R92suSta::new(mac_addr, mac_id, aid);

        self.sta_list
            .push(sta, GFP_KERNEL)
            .map_err(|_| crate::r92u::R92suError::UrbAllocFailed)?;

        self.sta_num += 1;
        self.sta_generation = self.sta_generation.wrapping_add(1);

        pr_info!(
            "r92su: sta_alloc mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} \
             mac_id={} aid={} total={}\n",
            mac_addr[0],
            mac_addr[1],
            mac_addr[2],
            mac_addr[3],
            mac_addr[4],
            mac_addr[5],
            mac_id,
            aid,
            self.sta_num,
        );

        Ok(())
    }

    /// Remove the station with hardware slot `mac_id` from the table.
    ///
    /// All associated per-TID reorder buffers, defrag queues and the
    /// pairwise key are freed.  If no station with `mac_id` exists, the call
    /// is a no-op.
    ///
    /// Mirrors `r92su_sta_del()` from `sta.c`.
    pub fn sta_del(&mut self, mac_id: usize) {
        if let Some(pos) = self.sta_list.iter().position(|s| s.mac_id == mac_id) {
            // Explicitly free resource-holding fields before removing the slot
            // so that the unsafe set_len below does not leak heap allocations.
            {
                let sta = &mut self.sta_list[pos];
                for tid in &mut sta.rx_tid {
                    *tid = None;
                }
                for entry in &mut sta.defrag {
                    entry.purge();
                }
                sta.sta_key = None;
            }

            // Manual swap-remove: swap the element-to-delete with the tail,
            // then truncate the list by one.  kernel::alloc's Vec<T, A> does
            // not expose `swap_remove`, so we replicate it here.
            //
            // SAFETY:
            // - `pos` and `len - 1` are valid, distinct indices (or equal)
            //   within the allocated buffer; we have unique mutable access.
            // - After the swap, `sta_list[len - 1]` is the station we already
            //   cleaned up: all heap-owning fields are None/empty.  The
            //   `truncate` call runs `drop_in_place` on that slot; because all
            //   interesting fields are already None/empty, the generated Drop
            //   for the remaining scalar fields is a trivial no-op.
            let len = self.sta_list.len();
            unsafe {
                if pos < len - 1 {
                    core::ptr::swap(
                        self.sta_list.as_mut_ptr().add(pos),
                        self.sta_list.as_mut_ptr().add(len - 1),
                    );
                }
            }
            // truncate(len - 1) properly runs drop_in_place on sta_list[len-1]
            // (the cleaned-up entry) and adjusts the Vec length.
            self.sta_list.truncate(len - 1);

            self.sta_num = self.sta_num.saturating_sub(1);
            self.sta_generation = self.sta_generation.wrapping_add(1);
            pr_info!("r92su: sta_del mac_id={}\n", mac_id);
        }
    }

    /// Free every station in the table.
    ///
    /// Called during device stop / disconnect to release all state.
    pub fn sta_free_all(&mut self) {
        // Free all resource-holding fields first so that the subsequent
        // swap-in of an empty Vec (via mem::replace) does not need to run
        // destructors that are already handled.
        for sta in &mut self.sta_list {
            for tid in &mut sta.rx_tid {
                *tid = None;
            }
            for entry in &mut sta.defrag {
                entry.purge();
            }
            sta.sta_key = None;
        }
        // truncate(0) runs drop_in_place on each element.  Since all
        // heap-owning fields are already None/empty the generated destructors
        // are trivial no-ops that only touch scalar fields.
        self.sta_list.truncate(0);
        self.sta_num = 0;
        self.sta_generation = self.sta_generation.wrapping_add(1);
    }

    /// Look up a station by its MAC address (immutable).
    ///
    /// Mirrors `r92su_sta_get()` from `sta.c`.
    pub fn sta_by_mac(&self, mac_addr: &[u8; ETH_ALEN]) -> Option<&R92suSta> {
        self.sta_list.iter().find(|s| s.mac_addr == *mac_addr)
    }

    /// Look up a station by its MAC address (mutable).
    pub fn sta_by_mac_mut(&mut self, mac_addr: &[u8; ETH_ALEN]) -> Option<&mut R92suSta> {
        self.sta_list.iter_mut().find(|s| s.mac_addr == *mac_addr)
    }

    /// Look up a station by its firmware MACID (immutable).
    ///
    /// Mirrors `r92su_sta_get_by_macid()` from `sta.c`.
    pub fn sta_by_macid(&self, mac_id: usize) -> Option<&R92suSta> {
        self.sta_list.iter().find(|s| s.mac_id == mac_id)
    }

    /// Look up a station by its firmware MACID (mutable).
    pub fn sta_by_macid_mut(&mut self, mac_id: usize) -> Option<&mut R92suSta> {
        self.sta_list.iter_mut().find(|s| s.mac_id == mac_id)
    }

    /// Return the station at list index `idx` (immutable).
    ///
    /// Mirrors `r92su_sta_get_by_idx()` from `sta.c`.
    pub fn sta_by_idx(&self, idx: usize) -> Option<&R92suSta> {
        self.sta_list.get(idx)
    }
}

// ---------------------------------------------------------------------------
// Per-TID reorder buffer management
// ---------------------------------------------------------------------------

/// Allocate (or replace) the RX TID reorder state for a station.
///
/// If a reorder buffer already exists for `tid` it is freed before the new
/// one is installed, matching the RCU replacement semantics in `sta.c`.
///
/// `ssn` is the BlockAck starting sequence number (raw 12-bit, the driver
/// uses `ssn >> 4` as `head_seq` following the C reference).
///
/// Mirrors `r92su_sta_alloc_tid()` from `sta.c`.
pub fn sta_alloc_tid(sta: &mut R92suSta, tid: u8, ssn: u16) {
    let idx = tid as usize;
    if idx >= IEEE80211_NUM_TIDS {
        return;
    }

    let new_tid = match KBox::new(RxTid::new(tid, ssn), GFP_KERNEL) {
        Ok(t) => t,
        Err(_) => {
            pr_warn!("r92su: sta_alloc_tid: OOM for tid={}\n", tid);
            sta.rx_tid[idx] = None;
            return;
        }
    };

    sta.rx_tid[idx] = Some(new_tid);
    pr_info!("r92su: sta_alloc_tid tid={} ssn={:#06x}\n", tid, ssn);
}

/// Free the RX TID reorder state for a station, flushing any buffered frames.
///
/// Mirrors the `r92su_free_tid()` / `r92su_free_tid_rcu()` path in `sta.c`.
pub fn sta_free_tid(sta: &mut R92suSta, tid: u8) {
    let idx = tid as usize;
    if idx < IEEE80211_NUM_TIDS {
        sta.rx_tid[idx] = None;
    }
}

// ---------------------------------------------------------------------------
// Key allocation / deallocation
// ---------------------------------------------------------------------------

/// Allocate an encryption key from a cfg80211 cipher suite identifier.
///
/// Mirrors `r92su_key_alloc()` from `sta.c`.  Crypto transform handles
/// are NOT allocated here (deferred to the SW crypto path in Part 3).
///
/// `cipher` is a `WLAN_CIPHER_SUITE_*` constant.
/// `idx` is the cfg80211 key index (0–3).
/// `mac_addr` is the peer address (pass `[0u8; 6]` for group keys).
/// `pairwise` distinguishes pairwise (unicast) from group keys.
/// `keydata` is the raw key bytes from cfg80211.
pub fn key_alloc(
    cipher: u32,
    idx: u8,
    mac_addr: &[u8; ETH_ALEN],
    pairwise: bool,
    keydata: &[u8],
) -> Result<KBox<R92suKey>> {
    let (algo, key_len, data) = match cipher {
        WLAN_CIPHER_SUITE_WEP40 => {
            if keydata.len() < WLAN_KEY_LEN_WEP40 {
                return Err(crate::r92u::R92suError::Io("WEP40 key too short"));
            }
            let mut k = [0u8; WLAN_KEY_LEN_WEP40];
            k.copy_from_slice(&keydata[..WLAN_KEY_LEN_WEP40]);
            (
                EncAlg::Wep40,
                WLAN_KEY_LEN_WEP40,
                KeyData::Wep40 {
                    tx_seq: 0,
                    rx_seq: 0,
                    key: k,
                },
            )
        }

        WLAN_CIPHER_SUITE_WEP104 => {
            if keydata.len() < WLAN_KEY_LEN_WEP104 {
                return Err(crate::r92u::R92suError::Io("WEP104 key too short"));
            }
            let mut k = [0u8; WLAN_KEY_LEN_WEP104];
            k.copy_from_slice(&keydata[..WLAN_KEY_LEN_WEP104]);
            (
                EncAlg::Wep104,
                WLAN_KEY_LEN_WEP104,
                KeyData::Wep104 {
                    tx_seq: 0,
                    rx_seq: 0,
                    key: k,
                },
            )
        }

        WLAN_CIPHER_SUITE_TKIP => {
            if keydata.len() < WLAN_KEY_LEN_TKIP {
                return Err(crate::r92u::R92suError::Io("TKIP key too short"));
            }
            let mut k = [0u8; WLAN_KEY_LEN_TKIP];
            k.copy_from_slice(&keydata[..WLAN_KEY_LEN_TKIP]);
            // TKIP sequence counters start at 1 following the C reference.
            (
                EncAlg::Tkip,
                WLAN_KEY_LEN_TKIP,
                KeyData::Tkip {
                    tx_seq: 1,
                    rx_seq: 1,
                    key: k,
                },
            )
        }

        WLAN_CIPHER_SUITE_CCMP => {
            if keydata.len() < WLAN_KEY_LEN_CCMP {
                return Err(crate::r92u::R92suError::Io("CCMP key too short"));
            }
            let mut k = [0u8; WLAN_KEY_LEN_CCMP];
            k.copy_from_slice(&keydata[..WLAN_KEY_LEN_CCMP]);
            (
                EncAlg::AesCcmp,
                WLAN_KEY_LEN_CCMP,
                KeyData::Ccmp {
                    tx_seq: 0,
                    rx_seq: 0,
                    key: k,
                },
            )
        }

        _ => return Err(crate::r92u::R92suError::Io("unsupported cipher suite")),
    };

    let key = R92suKey {
        mac_addr: *mac_addr,
        algo,
        key_len,
        uploaded: false,
        pairwise,
        index: idx as usize,
        data,
    };

    KBox::new(key, GFP_KERNEL).map_err(|_| crate::r92u::R92suError::UrbAllocFailed)
}

/// Drop an encryption key.
///
/// Mirrors `r92su_key_free()` from `sta.c`.  Key material is zeroed by the
/// allocator on deallocation in debug kernels; for production use the caller
/// should zero the key bytes before calling this function if required by
/// the security policy.
pub fn key_free(key: KBox<R92suKey>) {
    drop(key);
}
