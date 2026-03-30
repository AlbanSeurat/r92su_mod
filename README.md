# r92su_mod

A Linux kernel module for RTL8192SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

This driver is based on the [rtl8192su](https://github.com/AlbanSeurat/rtl8192su) C implementation.

## Requirements

- Linux kernel with Rust support
- Rust toolchain (nightly)
- LLVM/Clang
- The kernel source tree

## Building

```bash
make
```

or explicitly:

```bash
make LLVM=1 -C /path/to/linux-rust M=$(pwd) modules
```

## Cleaning

```bash
make clean
```

## Loading the Module

After building, load the module with:

```bash
insmod rtl8192su.ko
```

## Supported Devices

This driver supports USB devices with the following IDs:

| Vendor ID | Product ID | Vendor |
|-----------|------------|--------|
| 0x0BDA | 0x8174 | Realtek |
| 0x050D | 0x845A | Belkin |
| 0x07AA | 0x0051 | ATKK |
| 0x7392 | 0x7622 | Edimax |
| 0x0409 | 0x02B6 | NEC |
| 0x0DF6 | 0x0061 | Sitecom |
| 0x0DF6 | 0x006C | Sitecom |
| 0x0009 | 0x21E7 | Unknown |
| 0x0E0B | 0x9063 | Hawking |
| 0x5A57 | 0x0291 | Seagate |

## License

GPL v2
