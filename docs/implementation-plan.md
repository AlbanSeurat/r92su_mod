# Plan: RTL8192SU Rust Driver — Missing Pieces vs C Reference

## Context

The C reference driver (`/home/alkpone/driver/r92su/r92su/`) is a complete, production-quality RTL8192SU WiFi driver. The Rust port (`/home/alkpone/driver/r92su_mod/`) has implemented the USB probe/disconnect path, EEPROM, firmware upload, TX/RX descriptor parsing, H2C/C2H command structures, scan, and station storage. However, several subsystems needed for actual network operation are missing or stubbed.

The goal is to implement everything required to bring the driver to functional parity: opening a network interface, connecting to an AP, sending/receiving data, and managing encryption keys.

---

## Gap Analysis (Rust vs C)

### P1 — Required for basic operation

| Missing | C reference location | Rust current state |
|---|---|---|
| `init_mac` completes | `main.c:1365` | Stubbed — H2C commands commented out |
| Frame delivery to network stack (`netif_rx`) | `rx.c` | `pending_rx` queue exists, `netif_rx` not bound |
| `ndo_start_xmit` registration | `main.c:1600` | TX descriptor builder exists; no `ndo_start_xmit` hook |
| `ndo_stop` (device close) | `main.c:1514` | Not implemented |
| cfg80211 `.connect` op | `main.c:483` | Not implemented |
| cfg80211 `.disconnect` op | `main.c:626` | Not implemented |
| `c2h_join_bss_event` handling → `cfg80211_connect_result` | `main.c:731` | Event struct defined; no connect flow |
| Workqueue for scan done / connect / disconnect | `main.c:1488, 1717–1718` | Direct calls only; no deferred work |

### P2 — Required for WPA/WPA2

| Missing | C reference location | Rust current state |
|---|---|---|
| cfg80211 `.add_key` op | `main.c:944` | Not implemented |
| cfg80211 `.del_key` op | `main.c:967` | Not implemented |
| cfg80211 `.set_default_key` op | `main.c:1054` | Not implemented |
| `r92su_h2c_set_key` / `r92su_h2c_set_sta_key` H2C wrappers | `cmd.c` | Payload structs defined in `cmd.rs`; no send wrappers |

### P3 — Completeness

| Missing | C reference location | Rust current state |
|---|---|---|
| cfg80211 `.get_station` / `.dump_station` | `main.c:137, 164` | Not registered |
| cfg80211 `.change_virtual_intf` | `main.c:866` | Not registered |
| cfg80211 `.join_ibss` / `.leave_ibss` | `main.c:1220, 1307` | Not registered |
| cfg80211 `.set_wiphy_params` | `main.c:1088` | Not registered |
| cfg80211 `.set_monitor_channel` | `main.c:915` | Not registered |
| AMPDU reorder buffer flush timer | `rx.c` (`r92su_reorder_tid_timer`) | Buffer present; no timer |
| Software encryption — WEP/TKIP/AES-CCMP | `wep.c, tkip.c, aes_ccm.c, michael.c` | Key storage only; no crypto transforms |
| Monitor mode TX (`ndo_start_xmit` monitor path) | `tx.c` (`r92su_tx_monitor`) | Not implemented |
| Power management (RPWM/CPWM) | `pwr.c` | H2C command struct only |
| `ndo_set_rx_mode` / RX filter | `main.c:1357` | Commented reference in `init_mac` |

### P4 — Debug/tracing

| Missing | C reference location |
|---|---|
| Debugfs register ring buffer | `debugfs.c, debug.c` |
| Tracepoints for H2C/C2H and register I/O | `trace.c` |

---

## Implementation Plan

### Phase 1 — Basic network operation ✅ DONE

**1a. Complete `init_mac` (`r92u.rs`)** ✅
- H2C wrappers `h2c_set_opmode`, `h2c_set_mac_addr`, `h2c_set_channel` added to `cmd.rs`
- `init_mac` calls them in order, mirroring `r92su_init_mac` in `main.c:1365`
- `r92su_hw_mac_set_rx_filter` register writes implemented (RXFLTMAP0/1/2)
- `r92su_fw_iocmd(0xf4000700)` call for 40MHz/STBC enable added

**1b. Wire `netif_rx` in RX path (`rx.rs`)** ✅
- `rust_helper_rx_deliver_80211` C helper converts 802.11→802.3 and calls `netif_rx()`
- Called from `rx_deliver()` when `netdev_ptr` is set (Open/Connected state)
- Fallback to `pending_rx` queue when device not yet registered

**1c. Register `ndo_start_xmit` (`rust_helpers.c` + `r92u_open.rs`)** ✅
- `rust_helper_set_ndo_start_xmit()` C helper added
- `start_xmit_callback` extern fn bridges to `tx::r92su_tx()` in `tx.rs`
- Registered in `usb_probe.rs` alongside `ndo_open`

**1d. Implement `ndo_stop` (`r92u_open.rs`)** ✅
- `rust_helper_set_ndo_stop()` C helper added
- `ndo_stop_callback` cancels anchored URBs, sends `h2c_disconnect` if Connected
- Transitions state to `State::Stop`

**1e. Implement cfg80211 `.connect` and `.disconnect` ops (`connect.rs`)** ✅
- `connect_callback`: extracts params → finds BSS in scan cache → sends `H2C_JOINBSS_CMD`
- `disconnect_callback`: sends `h2c_disconnect`, notifies cfg80211 via `cfg80211_disconnected`
- `c2h_join_bss_event` in `event.rs` stores result and schedules `join_result_process`
- `join_result_process` calls `cfg80211_connect_result` from process context

**1f. Deferred work for connect result** ✅
- `rust_helper_schedule_join_result` + static `struct work_struct` in `rust_helpers.c`
- `schedule_join_result()` called from softirq event path; `join_result_process` runs in workqueue

### Phase 2 — Key management ✅ DONE

**2a. H2C key command wrappers (`cmd.rs`)** ✅
- `h2c_set_key(dev, algo, key_id, group_key, keydata)` — sends `H2cKey` payload for group keys
- `h2c_set_sta_key(dev, algo, mac_addr, keydata)` — sends `H2cStaKey` for pairwise keys

**2b. cfg80211 `.add_key`, `.del_key`, `.set_default_key` ops (`keys.rs`)**
- Add group key storage (`group_keys: [Option<KBox<R92suKey>>; 4]`) to `R92suDevice`
- Add `def_multi_key_idx` / `def_uni_key_idx` fields to `R92suDevice`
- Add C helpers: `rust_helper_set_cfg80211_ops_set_default_key`, `rust_helper_key_params_get`
- `add_key_callback`: calls `sta::key_alloc`, stores in `sta.sta_key` (pairwise) or `dev.group_keys[idx]` (group); sends H2C command to firmware; mirrors `r92su_internal_add_key` (`main.c:349`)
- `del_key_callback`: sends empty-key H2C to clear firmware slot; drops stored `R92suKey`
- `set_default_key_callback`: updates `def_uni_key_idx` / `def_multi_key_idx` in `R92suDevice`
- `keys::init()` registered from `usb_probe.rs`

### Phase 3 — Additional cfg80211 ops ✅ DONE

**3a. `.get_station` / `.dump_station`** ✅
- Added `station_info.rs` with `get_station_callback` and `dump_station_callback`
- Fill `station_info` from `R92suSta` fields (RSSI, TX/RX rates)
- C helper `rust_helper_station_info_set` in `rust_helpers.c`

**3b. `.change_virtual_intf`** ✅
- Added `cfg80211_misc.rs` with `change_virtual_intf_callback`
- Update `dev.iftype`; send `h2c_set_opmode` if device is Open/Connected

**3c. `.join_ibss` / `.leave_ibss`** ✅
- Implemented `join_ibss_callback` and `leave_ibss_callback` in `cfg80211_misc.rs`
- Uses `h2c_set_opmode` / `h2c_disconnect`

**3d. `.set_wiphy_params`** ✅
- Added `set_wiphy_params_callback` in `cfg80211_misc.rs`
- Handles RTS threshold changes

**3e. `.set_monitor_channel`** ✅
- Added `set_monitor_channel_callback` in `cfg80211_misc.rs`
- Notifies firmware of monitor mode

**3f. AMPDU reorder timer** (not implemented)
- Requires kernel timer infrastructure; deferred

**3g. Software encryption** (not implemented)
- Only needed for `nohwcrypt=1` or hardware failure; firmware handles crypto by default

### Phase 4 — Debug/tracing ✅ DONE

**4a. Debugfs implementation (`debugfs.rs` + `rust_helpers.c`)** ✅
- `debugfs.rs` module with Rust callbacks for reading device state (chip_rev, rf_type, etc.)
- `rust_helper_debugfs_set_callbacks` in C to register Rust callbacks
- `rust_helper_debugfs_create` / `rust_helper_debugfs_remove` for directory management
- Debugfs files created: tx_pending_urbs, chip_rev, rf_type, eeprom_type, h2c_seq, c2h_seq, cpwm, rpwm, rx_queue_len
- Stub implementations for: hw_ioread, hw_iowrite, sta_table, connected_bss, eeprom, eeprom_raw

**4b. Tracepoints** (not implemented)
- Requires kernel TRACE_EVENT macro infrastructure; deferred as not critical for basic operation

---

## Critical Files to Modify

| File | Changes |
|---|---|
| `r92u.rs` | Complete `init_mac`, add `ndo_stop`, hw_mac_set_rx_filter |
| `cmd.rs` | Add `h2c_set_key`, `h2c_set_sta_key`, `h2c_set_opmode`, `h2c_set_mac_addr`, `h2c_set_channel` send wrappers |
| `rx.rs` | Wire `netif_rx` in `rx_deliver()` |
| `r92u_open.rs` | Add `ndo_start_xmit` and `ndo_stop` registration |
| `cfg80211.rs` | Add helper externs for connect/disconnect/add_key/del_key/set_default_key/get_station ops |
| `scan.rs` / new `connect.rs` | Implement connect/disconnect cfg80211 callbacks and `c2h_join_bss_event` response |
| `event.rs` | Complete `c2h_join_bss_event` handler → `cfg80211_connect_result` |
| `sta.rs` | Add `sta_set_sinfo`, AMPDU timer |
| `rust_helpers.c` | Add C helpers for all new callbacks and bindings |

## C Reference Functions to Mirror (in priority order)

1. `r92su_init_mac` — `main.c:1365`
2. `r92su_start_xmit` — `main.c:1577`
3. `r92su_stop` — `main.c:1514`
4. `r92su_connect` / `r92su_internal_connect` — `main.c:483, 466`
5. `r92su_disconnect` — `main.c:626`
6. `r92su_bss_connect_work` — `main.c:731`
7. `r92su_internal_add_key` — `main.c:349`
8. `r92su_add_key` / `r92su_del_key` / `r92su_set_default_key` — `main.c:944, 967, 1054`
9. `r92su_get_station` / `r92su_sta_set_sinfo` — `main.c:137`, `sta.c`
10. `r92su_join_ibss` — `main.c:1220`

## Verification

1. **Build**: `make LLVM=1 -C /home/alkpone/driver/linux-rust M=$(pwd) modules` — must compile cleanly
2. **Format**: `make LLVM=1 rustfmtcheck` — no diff
3. **Load**: `insmod r92su_mod.ko` on a machine with the USB adapter — device should appear as `wlan0`
4. **Interface up**: `ip link set wlan0 up` — should trigger `ndo_open` → firmware upload → `State::Open`
5. **Scan**: `iw wlan0 scan` — should trigger `cfg80211_scan` → `h2c_survey` → `SurveyDone` event → BSS list
6. **Connect**: `wpa_supplicant` or `iw wlan0 connect <ssid>` → `State::Connected`
7. **Data**: `ping` through the interface — exercises TX/RX data path + `netif_rx`
