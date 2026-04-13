# r92su_mod

A Linux kernel module for RTL8192SU/RTL8188SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

This driver is based on the [rtl8192su](https://github.com/AlbanSeurat/rtl8192su) C implementation and translates the original C code into idiomatic Rust.

**Status:** Alpha - Work in progress

## Features

- cfg80211 FullMAC driver for RTL8192SU/RTL8188SU USB WiFi adapters
- Support for 802.11b/g/n (up to 300Mbps)
- WPA/WPA2 personal authentication
- Station mode (client) support
- Hardware encryption offload
- Debugfs interface for diagnostics

## Hardware Requirements

- Linux kernel 6.x or later with Rust support enabled (`CONFIG_RUST=y`)
- RTL8192SU or RTL8188SU based USB WiFi adapter
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

| Vendor ID | Product ID | Vendor   | Chipset    | HT Support |
|-----------|------------|----------|------------|------------|
| 0x0BDA    | 0x8171     | Realtek  | RTL8191SU  | Yes        |
| 0x0BDA    | 0x8173     | Realtek  | RTL8192SU  | Yes        |
| 0x0BDA    | 0x8174     | Realtek  | RTL8192SU  | Yes        |
| 0x0BDA    | 0x8712     | Realtek  | RTL8192SU  | Yes        |
| 0x0BDA    | 0x8713     | Realtek  | RTL8192SU  | Yes        |
| 0x0BDA    | 0xC047     | Realtek  | RTL8192SU  | Yes        |
| 0x0BDA    | 0xC512     | Realtek  | RTL8192SU  | Yes        |
| 0x07B8     | 0x8188     | Abocom   | RTL8188SU  | Yes        |
| 0x050D     | 0x845A     | Belkin   | RTL8192SU  | Yes        |
| 0x07AA     | 0x0051     | ATKK     | RTL8192SU  | Yes        |
| 0x7392     | 0x7622     | Edimax   | RTL8192SU  | Yes        |
| 0x0409     | 0x02B6     | NEC      | RTL8192SU  | Yes        |
| 0x0DF6     | 0x0061     | Sitecom  | RTL8192SU  | Yes        |
| 0x0DF6     | 0x006C     | Sitecom  | RTL8192SU  | Yes        |
| 0x0009     | 0x21E7     | Unknown  | RTL8192SU  | Yes        |
| 0x0E0B     | 0x9063     | Hawking  | RTL8192SU  | Yes        |
| 0x5A57     | 0x0291     | Seagate  | RTL8192SU  | Yes        |

## Project Structure

```
r92su_mod/
├── rtl8192su_main.rs    # Main module, USB registration, device table
├── usb_*.rs             # USB-specific code (probe, setup, register)
├── netdev.rs            # Network device operations
├── cfg80211.rs          # cfg80211 subsystem integration
├── cfg80211_misc.rs     # cfg80211 helper functions
├── r92u.rs              # Hardware-specific operations
├── r92u_*.rs            # Hardware initialization, opening, allocation
├── tx.rs / rx.rs        # Transmit and receive paths
├── cmd.rs               # Firmware command interface
├── connect.rs           # Connection management
├── scan.rs              # Scanning functionality
├── fw.rs                # Firmware loading
├── event.rs             # Event handling
├── keys.rs              # Cryptographic key management
├── mgmt_frame.rs        # Management frame handling
├── sta.rs               # Station handling
├── station_info.rs      # Station statistics
├── tdls.rs              # TDLS (Tunneled Direct-Link Setup)
├── anchor.rs            # Buffer anchoring for USB URBs
├── debugfs.rs           # Debug filesystem interface
└── firmware/            # Firmware binaries
```

## Reference Implementation

The original C implementation is available at [rtl8192su](https://github.com/AlbanSeurat/rtl8192su). This Rust driver follows the same architecture and behavior as the C version.

## Development

See [CLAUDE.md](CLAUDE.md) for development guidelines, code style, and implementation patterns.

## License

GPL v2
