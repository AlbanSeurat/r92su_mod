# AGENTS.md - RTL8192SU Rust Kernel Module

## Project Overview

This is a Linux kernel module for RTL8192SU/RTL8188SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

The driver is organized into modules that mirror the original C implementation structure for easier porting and maintenance.

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
| `r92u.rs` | Hardware-specific operations |
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
| `cmd.rs` | Firmware command interface |
| `fw.rs` | Firmware loading |
| `event.rs` | Event handling from hardware |
| `keys.rs` | Cryptographic key management |
| `mgmt_frame.rs` | Management frame handling |
| `sta.rs` | Station handling |
| `station_info.rs` | Station statistics |
| `tdls.rs` | TDLS support |
| `anchor.rs` | USB URB anchoring |
| `debugfs.rs` | Debug filesystem interface |

## Porting Strategy

When adding features from the C reference:

1. **Identify the C code** - Find the relevant functions in the C implementation
2. **Understand the flow** - Follow the call chain to understand context
3. **Create Rust module** - Add to existing module or create new file
4. **Define types** - Translate C structs to Rust structs, use `#[repr(C)]` if needed
5. **Implement logic** - Translate functions, handling error propagation
6. **Test incrementally** - Build and test after each logical unit

## Testing in Rust Kernel Modules

- Use `#[kunit_tests(suite_name)]` attribute for unit tests
- Use doctests (`/// ```rust ... ````) for documentation examples
- Assert with standard `assert!` and `assert_eq!` macros (mapped to KUnit)

## Debugging Tips

### Debugfs Interface
The driver provides debugfs entries at `/sys/kernel/debug/r92su/`:
- `registers` - Read hardware registers
- `stats` - Driver statistics
- `txqueues` - TX queue state

### Useful Commands
```bash
# Check module loaded
lsmod | grep rtl8192su

# View kernel messages
dmesg | grep -E "(r92su|rtl8192)"

# Check debugfs
ls -la /sys/kernel/debug/r92su/

# Monitor interface
iw dev wlan0 monitor
```

## Claude Specific

When exiting plan mode to begin implementation, ALWAYS save the implementation plan first as a markdown file in `docs/`.
