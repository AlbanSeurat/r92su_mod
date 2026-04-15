# r92su_mod

A Linux kernel module for RTL8192SU/RTL8188SU/RTL8191SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

This driver is based on the [rtl8192su](https://github.com/AlbanSeurat/rtl8192su) C implementation and translates the original C code into idiomatic Rust. A companion C file (`rust_helpers.c`) provides FFI bridge functions for kernel subsystems not yet exposed by the Rust kernel bindings.

**Status:** Beta -- Working and testing

## Features

- cfg80211 FullMAC driver for RTL8192SU/RTL8188SU/RTL8191SU USB WiFi adapters
- Support for 802.11b/g/n (up to 300Mbps)
- WPA/WPA2 personal authentication
- Station mode (client) support
- Hardware encryption offload (WEP/TKIP/CCMP)
- Power management (set_power_mgmt) for wpa_supplicant power save
- TX/RX data paths via USB bulk URBs
- Debugfs interface for diagnostics (registers, stats, EEPROM, station table)
- Management frame transmission (mgmt_tx)
- TDLS (Tunneled Direct-Link Setup) support
- IBSS (ad-hoc) mode stubs

## Hardware Requirements

- Linux kernel 6.x or later with Rust support enabled (`CONFIG_RUST=y`)
- RTL8192SU, RTL8188SU, or RTL8191SU based USB WiFi adapter
- Rust toolchain (nightly)
- LLVM/Clang
- Kernel source tree matching your running kernel

## Quick Start

```bash
# Build the module
make

# Load the module
sudo insmod rtl8192su.ko

# Check if device is recognized
iw dev

# Unload the module
sudo rmmod rtl8192su
```

## Building

```bash
make
```

Or explicitly:

```bash
make LLVM=1 -C /path/to/linux-rust M=$(pwd) modules
```

## Cleaning

```bash
make clean
```

## Code Formatting

```bash
# Format code
make LLVM=1 rustfmt

# Check formatting
make LLVM=1 rustfmtcheck
```

## Supported Devices

### RTL8188SU / RTL8191SU Devices

| Vendor ID | Product ID | Vendor        | Chipset     | HT Disabled |
|-----------|------------|---------------|-------------|-------------|
| 0x0BDA    | 0x8171     | Realtek       | RTL8191SU   | No          |
| 0x0BDA    | 0x8173     | Realtek       | RTL8188SU   | No          |
| 0x0BDA    | 0x8712     | Realtek       | RTL8188SU   | No          |
| 0x0BDA    | 0x8713     | Realtek       | RTL8188SU   | No          |
| 0x0BDA    | 0xC047     | Realtek       | RTL8188SU   | No          |
| 0x0BDA    | 0xC512     | Realtek       | RTL8188SU   | No          |
| 0x07B8    | 0x8188     | Abocom        | RTL8188SU   | No          |
| 0x083A    | 0xC512     | -             | RTL8188SU   | No          |
| 0x1B75    | 0x8171     | -             | RTL8188SU   | No          |
| 0x0B05    | 0x1786     | ASUS          | RTL8188SU   | No          |
| 0x0B05    | 0x1791     | ASUS          | RTL8188SU   | Yes         |
| 0x050D    | 0x945A     | Belkin        | RTL8188SU   | No          |
| 0x050D    | 0x11F1     | Belkin        | RTL8188SU   | No          |
| 0x07AA    | 0x0047     | ATKK          | RTL8188SU   | No          |
| 0x2001    | 0x3306     | D-Link        | RTL8188SU   | No          |
| 0x07D1    | 0x3306     | D-Link        | RTL8188SU   | Yes         |
| 0x7392    | 0x7611     | Edimax        | RTL8188SU   | No          |
| 0x1740    | 0x9603     | -             | RTL8188SU   | No          |
| 0x0E66    | 0x0016     | -             | RTL8188SU   | No          |
| 0x06F8    | 0xE034     | Guillemot     | RTL8188SU   | No          |
| 0x06F8    | 0xE032     | Guillemot     | RTL8188SU   | No          |
| 0x0789    | 0x0167     | -             | RTL8188SU   | No          |
| 0x2019    | 0xAB28     | -             | RTL8188SU   | No          |
| 0x2019    | 0xED16     | -             | RTL8188SU   | No          |
| 0x0DF6    | 0x0057     | Sitecom       | RTL8188SU   | No          |
| 0x0DF6    | 0x0045     | Sitecom       | RTL8188SU   | No          |
| 0x0DF6    | 0x0059     | Sitecom       | RTL8188SU   | Yes         |
| 0x0DF6    | 0x004B     | Sitecom       | RTL8188SU   | No          |
| 0x0DF6    | 0x005B     | Sitecom       | RTL8188SU   | No          |
| 0x0DF6    | 0x005D     | Sitecom       | RTL8188SU   | No          |
| 0x0DF6    | 0x0063     | Sitecom       | RTL8188SU   | No          |
| 0x177F    | 0x0154     | -             | RTL8188SU   | No          |
| 0x0BDA    | 0x5077     | Realtek       | RTL8188SU   | No          |
| 0x1690    | 0x0752     | -             | RTL8188SU   | No          |
| 0x20F4    | 0x646B     | -             | RTL8188SU   | No          |
| 0x25D4    | 0x4CA1     | -             | RTL8188SU   | No          |
| 0x25D4    | 0x4CAB     | -             | RTL8188SU   | No          |

### RTL8191SU Devices

| Vendor ID | Product ID | Vendor        | HT Disabled |
|-----------|------------|---------------|-------------|
| 0x0BDA    | 0x8175     | Realtek       | No          |
| 0x0BDA    | 0x8172     | Realtek       | No          |
| 0x0BDA    | 0x8192     | Realtek       | No          |
| 0x1B75    | 0x8172     | -             | No          |
| 0x0EB0    | 0x9061     | -             | No          |
| 0x13D3    | 0x3323     | -             | No          |
| 0x13D3    | 0x3311     | -             | Yes         |
| 0x13D3    | 0x3342     | -             | No          |
| 0x13D3    | 0x3333     | -             | No          |
| 0x13D3    | 0x3334     | -             | No          |
| 0x13D3    | 0x3335     | -             | Yes         |
| 0x13D3    | 0x3336     | -             | Yes         |
| 0x13D3    | 0x3309     | -             | No          |
| 0x050D    | 0x815F     | Belkin        | No          |
| 0x07D1    | 0x3302     | D-Link        | No          |
| 0x07D1    | 0x3300     | D-Link        | No          |
| 0x07D1    | 0x3303     | D-Link        | No          |
| 0x7392    | 0x7612     | Edimax        | No          |
| 0x1740    | 0x9605     | -             | No          |
| 0x06F8    | 0xE031     | Guillemot     | No          |
| 0x0E66    | 0x0015     | -             | No          |
| 0x13D3    | 0x3306     | -             | No          |
| 0x2019    | 0xED18     | -             | No          |
| 0x2019    | 0x4901     | -             | No          |
| 0x0DF6    | 0x0058     | Sitecom       | No          |
| 0x0DF6    | 0x0049     | Sitecom       | No          |
| 0x0DF6    | 0x004C     | Sitecom       | No          |
| 0x0DF6    | 0x0064     | Sitecom       | No          |
| 0x14B2    | 0x3300     | -             | No          |
| 0x14B2    | 0x3301     | -             | No          |
| 0x14B2    | 0x3302     | -             | No          |
| 0x0CDE    | 0x0030     | -             | No          |
| 0x04F2    | 0xAFF2     | -             | No          |
| 0x04F2    | 0xAFF5     | -             | No          |
| 0x04F2    | 0xAFF6     | -             | No          |
| 0x13D3    | 0x3339     | -             | No          |
| 0x13D3    | 0x3340     | -             | Yes         |
| 0x13D3    | 0x3341     | -             | Yes         |
| 0x13D3    | 0x3310     | -             | No          |
| 0x13D3    | 0x3325     | -             | No          |

### RTL8192SU Devices

| Vendor ID | Product ID | Vendor        | HT Disabled |
|-----------|------------|---------------|-------------|
| 0x0BDA    | 0x8174     | Realtek       | No          |
| 0x050D    | 0x845A     | Belkin        | No          |
| 0x07AA    | 0x0051     | ATKK          | No          |
| 0x7392    | 0x7622     | Edimax        | No          |
| 0x0409    | 0x02B6     | NEC           | No          |
| 0x0DF6    | 0x0061     | Sitecom       | No          |
| 0x0DF6    | 0x006C     | Sitecom       | No          |

### Other Devices

| Vendor ID | Product ID | Vendor        | Chipset     | HT Disabled |
|-----------|------------|---------------|-------------|-------------|
| 0x0009    | 0x21E7     | Unknown       | Unknown     | No          |
| 0x0E0B    | 0x9063     | Hawking       | Unknown     | No          |
| 0x5A57    | 0x0291     | Seagate       | Unknown     | No          |

## Project Structure

```
r92su_mod/
├── rtl8192su_main.rs    # Main module, USB registration, device table
├── usb_probe.rs          # USB device probe/attach logic
├── usb_register.rs       # Device registration with subsystems
├── usb_setup.rs          # USB endpoint configuration
├── netdev.rs             # Network device operations
├── cfg80211.rs           # cfg80211 subsystem integration
├── cfg80211_misc.rs      # cfg80211 helper functions
├── r92u.rs               # Hardware-specific operations, R92suDevice struct
├── r92u_open.rs          # Device open/close logic
├── r92u_alloc.rs          # Memory allocation helpers
├── tx.rs                  # Transmit path
├── rx.rs                  # Receive path
├── cmd.rs                 # Firmware command interface (H2C/C2H)
├── connect.rs             # Connection management
├── scan.rs                # Scanning operations
├── fw.rs                  # Firmware loading
├── event.rs               # Event handling from hardware
├── keys.rs                # Cryptographic key management
├── mgmt_frame.rs          # Management frame handling
├── sta.rs                 # Station handling
├── station_info.rs        # Station statistics
├── tdls.rs                # TDLS (Tunneled Direct-Link Setup)
├── power_mgmt.rs          # Power management (set_power_mgmt)
├── packet_formatter.rs    # Packet logging formatter for debugging
├── anchor.rs              # USB URB anchoring
├── debugfs.rs             # Debug filesystem interface
├── rust_helpers.c         # C FFI bridge for kernel subsystems
├── firmware/              # Firmware binaries
│   └── rtl8712u.bin
└── Makefile               # Build configuration
```

## Reference Implementation

The original C implementation is available at [rtl8192su](https://github.com/AlbanSeurat/rtl8192su). This Rust driver follows the same architecture and behavior as the C version.

## Development

See [CLAUDE.md](CLAUDE.md) for development guidelines, code style, and implementation patterns.

## License

GPL v2