# Plan: RTL8192SU Rust Driver — Gap Analysis & Implementation Plan

## Context

This Rust port of the RTL8192SU USB WiFi driver is a significantly advanced partial port. The core USB infrastructure, device initialization, cfg80211 callback plumbing, and packet processing pipelines are largely in place. However, several critical subsystems are incomplete or stub-only when compared against the C reference at `/home/alkpone/driver/r92su/r92su/`. This plan identifies all gaps and outlines what to implement.

---

## Gap Analysis: C Reference vs. Rust Port

### 1. Firmware Upload — INCOMPLETE (`fw.rs`)
**C reference**: `fw.c` (331 lines) — full upload of IMEM/SRAM regions via USB control transfers, CPU start sequence, polling for CPU-OK status.
**Rust status**: Header parsing and validation exists. Actual USB transfer (region extraction, chunked upload, CPU enable) is stubbed out.
**What's missing**:
- IMEM region extraction from firmware blob
- Chunked USB bulk/control writes to upload firmware pages
- CPU enable register write after upload
- Poll loop waiting for CPU-OK bit in firmware status register

### 2. Hardware Initialization — INCOMPLETE (`hw.c` equivalent)
**C reference**: `hw.c` (552 lines) — system clock config, chip-revision-specific USB init (B/C-cut paths differ), MAC early/late setup, RX filter configuration, RSSI mapping.
**Rust status**: No `hw.rs` file exists. MAC init is called from `r92u_open.rs` but the actual register sequences are absent.
**What's missing**:
- `r92su_halset_sysclk()` — system clock setup
- `r92su_usb_init_b_and_c_cut()` — chip-revision-specific USB init
- MAC early setup (power domain, clocks)
- MAC late setup (MAC address programming into hardware)
- RX filter register configuration (BSSID/multicast filter modes)
- RSSI-to-dBm mapping function

### 3. H2C Commands — INCOMPLETE (`cmd.rs`)
**C reference**: `cmd.c` (293 lines) with these commands:
**Rust status**: Has `h2c_connect`, `h2c_disconnect`, `h2c_scan`, `h2c_set_auth`, `h2c_set_key`, `h2c_set_sta_key`, minimal `h2c_set_ra`.
**Missing commands**:
- `h2c_set_mac_addr()` — programs MAC address into firmware
- `h2c_set_opmode()` — sets STA/ADHOC/AP operation mode
- `h2c_set_channel()` — explicit channel switch command
- `h2c_start_ba()` — initiates block ack aggregation session
- `h2c_set_power_mode()` — power save mode (ACTIVE, MIN, MAX, DTIM, VOIP, UAPSD)

### 4. C2H Events — INCOMPLETE (`event.rs`)
**C reference**: `event.c` (238 lines) with 26 event types.
**Rust status**: Has `C2H_SURVEY_EVENT`, `C2H_JOIN_BSS_EVENT`, `C2H_DISCONNECT_EVENT`, `C2H_TX_REPORT`, `C2H_CPWM`.
**Missing events**:
- `C2H_ADD_STA_EVENT` — station joined BSS; must allocate station entry, notify cfg80211
- `C2H_DEL_STA_EVENT` — station left; must free resources, notify cfg80211
- `C2H_ADD_BA_EVENT` — block ack negotiation complete; must update TID state
- `C2H_WPS_PBC_EVENT` — WPS button pressed; notify userspace via cfg80211_report_wowlan_wakeup or similar

### 5. RX Frame Delivery — INCOMPLETE (`rx.rs`)
**C reference**: Frames delivered to `ieee80211_rx_irqsafe()` / `netif_receive_skb()`.
**Rust status**: Frames are queued in `pending_rx` vector but never actually passed to the network stack — `netif_rx()` binding is missing.
**What's missing**:
- Call to `netif_rx()` (or equivalent `rust_helper_netif_rx()`) for each received data frame
- Proper 802.3/802.11 frame conversion if needed before delivery

### 6. TX Completion — INCOMPLETE (`r92u_open.rs`, `tx.rs`)
**C reference**: `tx.c` `r92su_tx_cb()` frees the SKB, decrements pending counter, handles errors.
**Rust status**: `tx_complete_callback()` logs but does not update `tx_pending_urbs`, does not free buffer, no error handling.
**What's missing**:
- Decrement `tx_pending_urbs` atomic on each completion
- Handle USB errors (ENODEV → mark device dead)
- Requeue or free TX buffer

### 7. Power Management — STUB (`pwr.c` equivalent)
**C reference**: `pwr.c` — `r92su_set_power()` writes power registers, used during open/stop.
**Rust status**: `C2H_CPWM` event tracked. No actual power register writes.
**What's missing**:
- Power enable/disable register sequence (used in `ndo_open` before MAC init)
- RPWM register writes for sleep/wake transitions

### 8. Station Events in cfg80211 — INCOMPLETE
**C reference**: On `C2H_ADD_STA_EVENT`, calls `cfg80211_new_sta()`; on `C2H_DEL_STA_EVENT`, calls `cfg80211_del_sta()`.
**Rust status**: No `cfg80211_new_sta` / `cfg80211_del_sta` wrappers exist.
**What's missing**:
- `rust_helper_cfg80211_new_sta()` in `rust_helpers.c`
- `rust_helper_cfg80211_del_sta()` in `rust_helpers.c`
- Rust wrappers in `cfg80211.rs`
- Call sites in `event.rs`

### 9. Block Ack / AMPDU Setup — INCOMPLETE
**C reference**: `C2H_ADD_BA_EVENT` triggers `r92su_h2c_start_ba()` to confirm block ack.
**Rust status**: TID reorder buffers allocated in `sta.rs` but no H2C `start_ba` command and no BA event handler.
**What's missing**:
- `h2c_start_ba()` in `cmd.rs`
- `c2h_add_ba_event()` handler in `event.rs`
- TID state update on BA confirmation

### 10. Debugfs Register Access — INCOMPLETE (`debugfs.rs`)
**C reference**: `debugfs.c` (512 lines) — R/W access to any register via files in `/sys/kernel/debug/r92su/`, ring buffer of recent I/O.
**Rust status**: Read-only counters exposed; no register read/write interface.
**What's missing**:
- Debugfs files for direct 8/16/32-bit register reads/writes
- Proper ring buffer implementation for I/O tracing

### 11. Software Crypto — NOT PRESENT
**C reference**: `wep.c`, `tkip.c`, `michael.c`, `aes_ccm.c` (~600 lines total) — software implementations for when hardware offload is unavailable.
**Rust status**: Key material is stored and uploaded to firmware. No software crypto.
**Assessment**: Since this is a FullMAC firmware-offload driver, firmware handles all crypto. Software crypto in the C driver appears to be a legacy artifact not strictly required. **Low priority / skip**.

---

## Implementation Priority

### Phase 1 — Make it boot and pass data (Critical path)
1. **Firmware upload** (`fw.rs`) — device can't operate without firmware
2. **Hardware init sequence** (new `hw.rs`) — MAC won't work without register setup
3. **H2C: `h2c_set_mac_addr`, `h2c_set_opmode`, `h2c_set_channel`** (`cmd.rs`)
4. **RX frame delivery** (`rx.rs`) — add `rust_helper_netif_rx()` and call it
5. **TX completion** (`r92u_open.rs`, `tx.rs`) — properly handle URB done callbacks

### Phase 2 — Full feature parity
6. **C2H: `C2H_ADD_STA_EVENT`, `C2H_DEL_STA_EVENT`** (`event.rs`, `cfg80211.rs`, `rust_helpers.c`)
7. **C2H: `C2H_ADD_BA_EVENT`** + `h2c_start_ba()` (`event.rs`, `cmd.rs`)
8. **Power management** — `r92su_set_power()` register sequence at open/stop
9. **H2C: `h2c_set_power_mode()`** — power save negotiation

### Phase 3 — Nice to have
10. **Debugfs register R/W** (`debugfs.rs`, `rust_helpers.c`)
11. **C2H: `C2H_WPS_PBC_EVENT`** — WPS button notification
12. **IBSS/Ad Hoc complete** (`cfg80211_misc.rs`) — full join/leave logic
13. **RSSI mapping** — proper dBm conversion in `hw.rs`

---

## Critical Files to Modify

| File | Changes Needed |
|------|---------------|
| `fw.rs` | Implement actual firmware upload protocol (IMEM region extraction, USB transfer, CPU start) |
| `cmd.rs` | Add `h2c_set_mac_addr`, `h2c_set_opmode`, `h2c_set_channel`, `h2c_start_ba`, `h2c_set_power_mode` |
| `event.rs` | Add `C2H_ADD_STA_EVENT`, `C2H_DEL_STA_EVENT`, `C2H_ADD_BA_EVENT`, `C2H_WPS_PBC_EVENT` handlers |
| `rx.rs` | Add actual `netif_rx()` call for data frame delivery |
| `r92u_open.rs` | Fix `tx_complete_callback` to decrement counter and handle errors |
| `rust_helpers.c` | Add `rust_helper_netif_rx`, `rust_helper_cfg80211_new_sta`, `rust_helper_cfg80211_del_sta` |
| `cfg80211.rs` | Add wrappers for `cfg80211_new_sta`, `cfg80211_del_sta` |
| **`hw.rs`** (new) | Hardware init: clock setup, chip-revision-specific USB init, MAC early/late setup, RX filter |

## Reference Functions to Port

| Rust Target | C Reference | File |
|------------|-------------|------|
| `fw::r92su_fw_upload()` | `r92su_upload_mem()`, `r92su_fw_startup_cpu()` | `fw.c:200-331` |
| `hw::r92su_halset_sysclk()` | `r92su_halset_sysclk()` | `hw.c:30-80` |
| `hw::r92su_usb_mac_init()` | `r92su_set_mac_address()`, `r92su_init_mac()` | `hw.c:250-450` |
| `cmd::h2c_set_mac_addr()` | `r92su_h2c_set_mac_addr()` | `cmd.c:55-70` |
| `cmd::h2c_set_opmode()` | `r92su_h2c_set_opmode()` | `cmd.c:72-90` |
| `cmd::h2c_set_channel()` | `r92su_h2c_set_channel()` | `cmd.c:92-115` |
| `cmd::h2c_start_ba()` | `r92su_h2c_start_ba()` | `cmd.c:250-270` |
| `event::c2h_add_sta()` | `r92su_event_add_sta()` | `event.c:90-140` |
| `event::c2h_del_sta()` | `r92su_event_del_sta()` | `event.c:142-180` |
| `event::c2h_add_ba()` | `r92su_event_add_ba()` | `event.c:182-220` |

## Verification

After implementing Phase 1:
```bash
# Build the module
make LLVM=1 -C /home/alkpone/driver/linux-rust M=$(pwd) modules

# Load the module (as root on target system)
insmod rtl8192su.ko

# Verify device appears
ip link show

# Trigger scan
iw dev wlan0 scan

# Check dmesg for firmware upload confirmation and H2C/C2H command logs
dmesg | grep rtl8192su
```

After Phase 2:
```bash
# Connect to AP
wpa_supplicant -i wlan0 -c /etc/wpa_supplicant.conf

# Verify station info
iw dev wlan0 station dump

# Check debugfs
ls /sys/kernel/debug/rtl8192su/
```
