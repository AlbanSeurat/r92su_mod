# AGENTS.md - RTL8192SU Rust Kernel Module

## Project Overview

This is a Linux kernel module for RTL8192SU/RTL8188SU/RTL8191SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

The driver is organized into modules that mirror the original C implementation structure for easier porting and maintenance. C FFI bridge functions in `rust_helpers.c` provide access to kernel subsystems (cfg80211, netdev, USB, debugfs) not yet exposed by the Rust kernel bindings.

## Reference Implementation

The code is based on the C implementation at https://github.com/AlbanSeurat/rtl8192su (located in the `r92su` directory). When writing new code:

1. First understand the behavior from the C reference
2. Study the data structures and hardware interaction patterns
3. Translate C constructs into idiomatic Rust/kernel-Rust equivalents
4. Maintain functional equivalence with the C code

## Build Commands

### Build the module
```bash
make
```
or explicitly:
```bash
make LLVM=1 -C /home/alkpone/driver/linux-rust M=$(pwd) modules
```

### Clean build artifacts
```bash
make clean
```

### Check formatting (rustfmt)
```bash
# Format code
make LLVM=1 rustfmt

# Check formatting (print diff)
make LLVM=1 rustfmtcheck
```

### Rust Analyzer support
```bash
make rust-analyzer
```

### Testing
This project does not currently have KUnit tests. To add tests, follow the kernel's testing documentation at `/home/alkpone/driver/linux-rust/Documentation/rust/testing.rst`.

To run KUnit tests generally:
```bash
./tools/testing/kunit/kunit.py run --make_options LLVM=1 --arch x86_64 --kconfig_add CONFIG_RUST=y
```

## Code Style Guidelines

### General
- Code must be formatted with `rustfmt` (default settings)
- Follow the Linux kernel Rust coding guidelines: `/home/alkpone/driver/linux-rust/Documentation/rust/coding-guidelines.rst`

### Imports
- Use vertical layout for imports with trailing `//` comments to preserve formatting
```rust
use kernel::{
    device::Core,
    prelude::*,
    usb, //
};
```

### Comments
- Use Markdown-style comments (`//`) for implementation details
- Use doc comments (`///` or `//!`) for public API documentation
- Comments should be capitalized and end with a period
- Precede every `unsafe` block with a `// SAFETY:` comment explaining soundness

### Naming Conventions
- Follow standard Rust naming conventions
- When wrapping C concepts, use names close to the C side but with Rust casing
- Types wrapping C enums should be Rust enums with `#[repr(u32)]`
- Private modules use snake_case: `r92u_open.rs`
- Public APIs use Rust conventions

### Error Handling
- Use the kernel's `Result` type from the prelude (`kernel::prelude::Result`)
- Prefer fallible approaches over panicking
- Use `Error` type from kernel prelude for errors
- Always handle or propagate errors from functions with `Result` return types; never ignore them with `_` or leave them unchecked

### Lints
- Prefer `#[expect(lint)]` over `#[allow(lint)]` when the lint is expected to be fulfilled
- Use `#[allow(lint)]` for conditional compilation cases or macro expansions

## Kernel-Specific Patterns

### Module Structure
The main module (`rtl8192su_main.rs`) contains:
- Module-level documentation
- USB device table definition
- `usb::Driver` trait implementation
- Module registration macro

```rust
// SPDX-License-Identifier: GPL-2.0
// SPDX-FileCopyrightText: Copyright (C) 2026 <Name>

//! Module description.

use kernel::{device::Core, prelude::*, usb};

kernel::usb_device_table!(
    USB_TABLE,
    MODULE_USB_TABLE,
    DeviceInfo,
    [
        // Device entries
    ]
);

impl usb::Driver for MyDriver {
    type IdInfo = DeviceInfo;
    const ID_TABLE: usb::IdTable<Self::IdInfo> = &USB_TABLE;

    fn probe(...) -> impl PinInit<Self, Error> { ... }
    fn disconnect(...) { ... }
}

kernel::module_usb_driver! {
    type: MyDriver,
    name: "mymodule",
    authors: ["Name <email>"],
    description: "Description",
    license: "GPL v2",
}
```

### Null Pointers
```rust
use core::ptr::null;
use core::ptr::null_mut;
```

### Atomic Types
```rust
use core::sync::atomic::{AtomicU32, Ordering};

pub tx_pending_urbs: AtomicU32::new(0),

// Usage with explicit ordering
count.fetch_add(1, Ordering::Relaxed);
```

### Enums with C Equivalents
```rust
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum State {
    Dead = 0,
    Active = 1,
    // ...
}
```

### Unsafe Traits
```rust
unsafe impl kernel::sync::aref::AlwaysRefCounted for MyStruct {
    fn inc_ref(&self) {}
    unsafe fn dec_ref(_obj: core::ptr::NonNull<Self>) {}
}
```

### PinInit for Complex Structures
When structures need to be pinned in memory (e.g., for DMA or self-references):
```rust
fn probe(...) -> impl PinInit<Self, Error> {
    pin_init! {
        MyStruct {
            field1: some_value,
            field2: another_value,
            // ...
        }
    }
}
```

### C FFI Bridge (rust_helpers.c)
The `rust_helpers.c` file provides C bridge functions for kernel subsystems that cannot be accessed from Rust directly (inline functions, opaque structs, macro-based APIs). The pattern is:
- C functions are named `rust_helper_*` and exported with `EXPORT_SYMBOL_GPL`
- Rust code declares them as `extern "C"` functions and calls them
- Callback registration uses function pointer setters (e.g., `rust_helper_set_cfg80211_ops_scan`)

Key areas covered by the bridge:
- **cfg80211**: wiphy allocation, ops registration, scan/connect/disconnect/key callbacks, station info
- **net_device**: alloc, register, unregister, TX/RX path bridges
- **USB**: pipe macros, bulk URB submission, RX/TX URB pool management
- **debugfs**: directory/file creation, ring buffer, callback registration
- **Work queues**: deferred join-result processing, scan timeout scheduling

## File Organization

### Core Modules
| File | Purpose |
|------|---------|
| `rtl8192su_main.rs` | Main entry point, USB registration, device table |
| `usb_probe.rs` | USB device probe/attach logic |
| `usb_register.rs` | Device registration with subsystems |
| `usb_setup.rs` | USB endpoint configuration |
| `netdev.rs` | Network device operations |

### cfg80211 Integration
| File | Purpose |
|------|---------|
| `cfg80211.rs` | Main cfg80211 ops implementation |
| `cfg80211_misc.rs` | Helper functions for cfg80211 |
| `connect.rs` | Connection management |
| `scan.rs` | Scanning operations |

### Hardware Abstraction (r92u)
| File | Purpose |
|------|---------|
| `r92u.rs` | Hardware-specific operations, R92suDevice struct |
| `r92u_open.rs` | Device open/close logic |
| `r92u_alloc.rs` | Memory allocation helpers |

### Data Paths
| File | Purpose |
|------|---------|
| `tx.rs` | Transmit path |
| `rx.rs` | Receive path |

### Supporting Modules
| File | Purpose |
|------|---------|
| `cmd.rs` | Firmware command interface (H2C/C2H) |
| `fw.rs` | Firmware loading |
| `event.rs` | Event handling from hardware |
| `keys.rs` | Cryptographic key management |
| `mgmt_frame.rs` | Management frame handling |
| `sta.rs` | Station handling |
| `station_info.rs` | Station statistics |
| `tdls.rs` | TDLS support |
| `power_mgmt.rs` | Power management (set_power_mgmt cfg80211 callback) |
| `packet_formatter.rs` | Packet logging formatter for debugging |
| `anchor.rs` | USB URB anchoring |
| `debugfs.rs` | Debug filesystem interface |

### C FFI Bridge
| File | Purpose |
|------|---------|
| `rust_helpers.c` | C bridge functions for cfg80211, netdev, USB, debugfs, work queues |

### Firmware
| Path | Purpose |
|------|---------|
| `firmware/rtl8712u.bin` | RTL8712U firmware binary (embedded via `include_bytes!`) |

## Porting Strategy

When adding features from the C reference:

1. **Identify the C code** - Find the relevant functions in the C implementation
2. **Understand the flow** - Follow the call chain to understand context
3. **Check rust_helpers.c** - See if a C bridge function already exists or needs to be added for the kernel API in question
4. **Create Rust module** - Add to existing module or create new file
5. **Define types** - Translate C structs to Rust structs, use `#[repr(C)]` if needed
6. **Implement logic** - Translate functions, handling error propagation
7. **Test incrementally** - Build and test after each logical unit

When adding a new kernel API that is not yet in the Rust bindings:
1. Add a `rust_helper_*` function in `rust_helpers.c` with `EXPORT_SYMBOL_GPL`
2. Declare it as `extern "C"` in the appropriate Rust module
3. Call it from Rust code
4. Add the object file to the Makefile if needed

## Testing in Rust Kernel Modules

- Use `#[kunit_tests(suite_name)]` attribute for unit tests
- Use doctests (`/// ```rust ... ````) for documentation examples
- Assert with standard `assert!` and `assert_eq!` macros (mapped to KUnit)

## Debugging Tips

### Debugfs Interface
The driver provides debugfs entries under `/sys/kernel/debug/ieee80211/phyN/rtl8192su/`:
- `tx_pending_urbs` - Count of pending TX URBs
- `hw_ioread` - Read hardware registers (ring buffer)
- `hw_iowrite` - Write hardware registers
- `chip_rev` - Chip revision information
- `eeprom_type` - EEPROM type
- `rf_type` - RF type (1T1R, 1T2R, 2T2R)
- `h2c_seq` / `c2h_seq` - Host-to-chip / chip-to-host sequence numbers
- `cpwm` / `rpwm` - Power management state
- `rx_queue_len` - RX queue length
- `sta_table` - Station table dump
- `connected_bss` - Connected BSS information
- `eeprom` / `eeprom_raw` - EEPROM contents

### Useful Commands
```bash
# Check module loaded
lsmod | grep rtl8192su

# View kernel messages
dmesg | grep -E "(r92su|rtl8192)"

# Check debugfs
ls -la /sys/kernel/debug/ieee80211/phy0/rtl8192su/

# Monitor interface
iw dev wlan0 monitor

# Connect to network
iw dev wlan0 connect <SSID>
```

## Architecture Notes

### Device Structure
The `R92suDevice` struct (defined in `r92u.rs`) is the central data structure. It holds all device state including:
- USB interface reference
- Wiphy/netdev/wireless_dev pointers
- Firmware blob
- TX/RX state
- Station table
- Scan state
- Configuration (HT capability, chip info, etc.)

### Callback Registration Pattern
Because cfg80211 ops and netdev ops are C structs with function pointers, the driver uses a registration pattern:
1. C defines static structs with `NULL` function pointers (`r92su_cfg80211_ops`, `r92su_netdev_ops`)
2. Rust registers its handlers via `rust_helper_set_cfg80211_ops_*` and `rust_helper_set_ndo_*` functions during probe
3. The C callbacks recover the `R92suDevice` pointer via `wiphy_priv()` and dispatch to Rust

### RX Path
1. RX URBs are submitted during probe via `rust_helper_submit_rx_urbs()`
2. The C completion handler calls back into Rust via `rust_helper_set_rx_fn()`
3. Rust processes C2H events and 802.11 frames
4. Data frames are converted from 802.11 to Ethernet and delivered via `rust_helper_rx_deliver_80211()`

### TX Path
1. `ndo_start_xmit` dispatches to Rust via `rust_helper_set_ndo_start_xmit()`
2. Rust converts Ethernet frames to 802.11 and submits via `rust_helper_submit_one_tx_urb()`
3. TX URB completion notifies Rust via `rust_helper_set_tx_complete_fn()`

## Claude Specific

When exiting plan mode to begin implementation, ALWAYS save the implementation plan first as a markdown file in `docs/`.