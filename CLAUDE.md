# AGENTS.md - RTL8192SU Rust Kernel Module

## Project Overview

This is a Linux kernel module for RTL8192SU WLAN adapters, written in Rust using the Linux kernel's Rust infrastructure (Rust for Linux). It is a cfg80211 FullMAC USB driver.

## Reference Implementation

This code is inspired by the C implementation at https://github.com/AlbanSeurat/rtl8192su (located in the `r92su` directory). When writing new code for this driver, use that repository as a reference for the expected behavior, data structures, and hardware interaction patterns. Translate C constructs into idiomatic Rust/kernel-Rust equivalents.

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
- Example:
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

### Error Handling
- Use the kernel's `Result` type from the prelude (`kernel::prelude::Result`)
- Prefer fallible approaches over panicking
- Use `Error` type from kernel prelude for errors
- Always handle or propagate errors from functions with `Result` return types; never ignore them with `_` or leave them unchecked

### Lints
- Prefer `#[expect(lint)]` over `#[allow(lint)]` when the lint is expected to be fulfilled
- Use `#[allow(lint)]` for conditional compilation cases or macro expansions

### Kernel-Specific Patterns

#### Module structure
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

#### Null pointers
Use `core::ptr::null()` or `core::ptr::null_mut()` for raw pointers.

#### Atomic types
```rust
use core::sync::atomic::AtomicU32;
pub tx_pending_urbs: AtomicU32::new(0),
```

#### Enums with C equivalents
```rust
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum State {
    Dead = 0,
    // ...
}
```

#### Unsafe traits
```rust
unsafe impl kernel::sync::aref::AlwaysRefCounted for MyStruct {
    fn inc_ref(&self) {}
    unsafe fn dec_ref(_obj: core::ptr::NonNull<Self>) {}
}
```

### File Organization
- Main driver code in `rtl8192su.rs`
- Device-specific structures in separate modules (e.g., `r92.rs`)
- License header required on every file (SPDX identifiers)

### Testing in Rust kernel modules
- Use `#[kunit_tests(suite_name)]` attribute for unit tests
- Use doctests (`/// ```rust ... ```) for documentation examples
- Assert with standard `assert!` and `assert_eq!` macros (mapped to KUnit)
