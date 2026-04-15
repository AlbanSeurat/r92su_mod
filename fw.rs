// SPDX-License-Identifier: GPL-2.0
//! Firmware loading and upload for RTL8192SU.
//!
//! Mirrors the firmware handling from `r92su/fw.c`.

use kernel::prelude::*;

use crate::r92u::{hw_read8, hw_write8, R92suDevice, Result};

use crate::r92u::R92suError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RTL8192_MAX_FIRMWARE_CODE_SIZE: usize = 64 * 1024;
const RTL8192_MAX_RAW_FIRMWARE_CODE_SIZE: usize = 200000;
const RT_8192S_FIRMWARE_HDR_SIZE: usize = 80;

const R8712SU_FW_SIGNATURE: u16 = 0x8712;
const R8192SU_FW_SIGNATURE: u16 = 0x8192;

// ---------------------------------------------------------------------------
// Firmware header structures
// ---------------------------------------------------------------------------

/// Firmware DMEM private area (mirrors `struct fw_priv` from fw.h).
#[repr(C, packed)]
#[derive(Debug, Default)]
pub struct FwPriv {
    pub signature_0: u8,
    pub signature_1: u8,
    pub hci_sel: u8,
    pub chip_version: u8,
    pub customer_id_0: u8,
    pub customer_id_1: u8,
    pub rf_config: u8,
    pub usb_ep_num: u8,
    pub regulatory_class_0: u8,
    pub regulatory_class_1: u8,
    pub regulatory_class_2: u8,
    pub regulatory_class_3: u8,
    pub rfintfs: u8,
    pub def_nettype: u8,
    pub turbo_mode: u8,
    pub low_power_mode: u8,
    pub lbk_mode: u8,
    pub mp_mode: u8,
    pub vcs_type: u8,
    pub vcs_mode: u8,
    pub rsvd022: u8,
    pub rsvd023: u8,
    pub rsvd024: u8,
    pub rsvd025: u8,
    pub qos_en: u8,
    pub bw_40mhz_en: u8,
    pub amsdu2ampdu_en: u8,
    pub ampdu_en: u8,
    pub rate_control_offload: u8,
    pub aggregation_offload: u8,
    pub rsvd030: u8,
    pub rsvd031: u8,
    pub beacon_offload: u8,
    pub mlme_offload: u8,
    pub hwpc_offload: u8,
    pub tcp_checksum_offload: u8,
    pub tcp_offload: u8,
    pub ps_control_offload: u8,
    pub wwlan_offload: u8,
    pub rsvd040: u8,
    pub tcp_tx_frame_len_l: u8,
    pub tcp_tx_frame_len_h: u8,
    pub tcp_rx_frame_len_l: u8,
    pub tcp_rx_frame_len_h: u8,
    pub rsvd050: u8,
    pub rsvd051: u8,
    pub rsvd052: u8,
    pub rsvd053: u8,
}

/// Firmware header (mirrors `struct fw_hdr` from fw.h).
#[repr(C, packed)]
pub struct FwHdr {
    pub signature: u16,
    pub version: u16,
    pub dmem_size: u32,
    pub img_imem_size: u32,
    pub img_sram_size: u32,
    pub fw_priv_size: u32,
    pub efuse_addr: u16,
    pub h2ccmd_resp_addr: u16,
    pub svn_evision: u32,
    pub release_time: u32,
    pub fwpriv: FwPriv,
}

// ---------------------------------------------------------------------------
// Parsed firmware info
// ---------------------------------------------------------------------------

/// Parsed firmware information.
pub struct FirmwareInfo {
    /// Reference to the firmware data (needed for the lifetime).
    firmware: &'static [u8],
    /// Offset where IMEM data starts.
    imem_offset: usize,
    /// Size of IMEM data.
    imem_size: usize,
    /// Offset where SRAM data starts.
    sram_offset: usize,
    /// Size of SRAM data.
    sram_size: usize,
    /// Firmware version.
    pub fw_version: u16,
}

impl FirmwareInfo {
    /// Parse and validate firmware blob.
    ///
    /// Returns error if the firmware is invalid or too large.
    pub fn parse(firmware: &[u8]) -> Result<FirmwareInfo> {
        if firmware.len() > RTL8192_MAX_RAW_FIRMWARE_CODE_SIZE {
            return Err(R92suError::FirmwareUploadFailed("firmware is too big"));
        }

        if firmware.len() < RT_8192S_FIRMWARE_HDR_SIZE {
            return Err(R92suError::FirmwareUploadFailed(
                "firmware too small for header",
            ));
        }

        // SAFETY: We read the header fields directly from the firmware buffer.
        let signature = unsafe {
            let ptr = firmware.as_ptr() as *const u16;
            u16::from_le(ptr.read_unaligned())
        };

        if signature != R8712SU_FW_SIGNATURE && signature != R8192SU_FW_SIGNATURE {
            return Err(R92suError::FirmwareUploadFailed(
                "invalid firmware signature",
            ));
        }

        // SAFETY: Read version at offset 2.
        let fw_version = unsafe {
            let ptr = firmware.as_ptr().add(2) as *const u16;
            u16::from_le(ptr.read_unaligned())
        };
        pr_debug!("r92su: firmware version: 0x{:04x}\n", fw_version);

        // SAFETY: Read imem_size at offset 8.
        let imem_size = unsafe {
            let ptr = firmware.as_ptr().add(8) as *const u32;
            u32::from_le(ptr.read_unaligned()) as usize
        };

        // SAFETY: Read sram_size at offset 12.
        let sram_size = unsafe {
            let ptr = firmware.as_ptr().add(12) as *const u32;
            u32::from_le(ptr.read_unaligned()) as usize
        };

        if imem_size == 0 || imem_size >= RTL8192_MAX_FIRMWARE_CODE_SIZE {
            return Err(R92suError::FirmwareUploadFailed(
                "firmware IMEM size out of range",
            ));
        }

        if sram_size == 0 || sram_size >= RTL8192_MAX_FIRMWARE_CODE_SIZE {
            return Err(R92suError::FirmwareUploadFailed(
                "firmware SRAM size out of range",
            ));
        }

        // IMEM starts after the header (80 bytes)
        let imem_offset = RT_8192S_FIRMWARE_HDR_SIZE;
        let sram_offset = imem_offset + imem_size;

        if sram_offset + sram_size > firmware.len() {
            return Err(R92suError::FirmwareUploadFailed(
                "firmware too small for IMEM/SRAM",
            ));
        }

        // Convert firmware to 'static lifetime for storage.
        // This is safe because the firmware data lives for the duration of the
        // driver (it's embedded in the kernel module).
        let firmware_static: &'static [u8] =
            unsafe { core::slice::from_raw_parts(firmware.as_ptr(), firmware.len()) };

        Ok(FirmwareInfo {
            firmware: firmware_static,
            imem_offset,
            imem_size,
            sram_offset,
            sram_size,
            fw_version,
        })
    }

    /// Get the IMEM data.
    pub fn imem(&self) -> &[u8] {
        &self.firmware[self.imem_offset..self.imem_offset + self.imem_size]
    }

    /// Get the SRAM data.
    pub fn sram(&self) -> &[u8] {
        &self.firmware[self.sram_offset..self.sram_offset + self.sram_size]
    }

    /// Prepare the fw_priv structure for DMEM upload.
    pub fn prepare_fw_priv(&self, rf_type: u8, chip_rev: u8, disable_ht: bool) -> FwPriv {
        let mut dmem = FwPriv::default();

        // HCI type: USB (0x12)
        dmem.hci_sel = 0x12;
        dmem.chip_version = chip_rev;
        dmem.rf_config = rf_type;

        // QoS enabled
        dmem.qos_en = 1;

        // HT settings
        dmem.bw_40mhz_en = if disable_ht { 0 } else { 1 };
        dmem.ampdu_en = if disable_ht { 0 } else { 1 };
        dmem.aggregation_offload = if disable_ht { 0 } else { 1 };

        // Firmware offloads
        dmem.rate_control_offload = 1;
        dmem.mlme_offload = 1;

        // VCS settings
        dmem.vcs_type = 2; // auto
        dmem.vcs_mode = 1; // RTS/CTS

        // Send two probe requests during scanning
        dmem.rsvd024 = 1;

        dmem
    }
}

// ---------------------------------------------------------------------------
// Register definitions for firmware upload
// ---------------------------------------------------------------------------

const REG_TCR: u16 = 0x0044;
const REG_SYS_CLKR: u16 = 0x0008;
const REG_SYS_FUNC_EN: u16 = 0x0002;

const REG_EEPROM_CMD: u16 = 0x000A;

// TCR bits
const IMEM_CODE_DONE: u8 = 0x01;
const IMEM_CHK_RPT: u8 = 0x02;
const EMEM_CODE_DONE: u8 = 0x04;
const EMEM_CHK_RPT: u8 = 0x08;
const DMEM_CODE_DONE: u8 = 0x10;
const IMEM_RDY: u8 = 0x20;
const FWRDY: u8 = 0x80;

// SYS_CLKR bits
const SYS_CPU_CLKSEL: u8 = 0x04;

// SYS_FUNC_EN bits
const FEN_CPUEN: u16 = 0x0400;

// EEPROM_CMD bits
const EEPROM_CMD_93C46: u8 = 0x10;

// ---------------------------------------------------------------------------
// Firmware upload functions
// ---------------------------------------------------------------------------

const TX_DESC_SIZE: usize = 32;
const BLOCK_SIZE: usize = 2048;

/// Upload firmware to device.
///
/// This performs the full sequence:
/// 1. Upload IMEM (instruction memory)
/// 2. Upload SRAM (static RAM)
/// 3. Upload DMEM (data memory / fw_priv)
pub fn upload_firmware(
    dev: &mut R92suDevice,
    firmware: &[u8],
    rf_type: u8,
    chip_rev: u8,
    disable_ht: bool,
) -> Result<()> {
    let fw_info = FirmwareInfo::parse(firmware)?;

    // Step 1: Upload IMEM
    upload_imem(dev, fw_info.imem())?;

    // Step 2: Upload SRAM
    upload_sram(dev, fw_info.sram())?;

    // Step 3: Upload DMEM (fw_priv)
    let fw_priv = fw_info.prepare_fw_priv(rf_type, chip_rev, disable_ht);
    upload_dmem(dev, &fw_priv)?;

    dev.fw_loaded = true;
    pr_debug!("r92su: firmware upload complete\n");
    Ok(())
}

/// Upload IMEM (instruction memory) segment.
fn upload_imem(dev: &mut R92suDevice, imem: &[u8]) -> Result<()> {
    pr_debug!("r92su: uploading IMEM ({} bytes)\n", imem.len());

    let chunks = imem.chunks(BLOCK_SIZE);
    let total_chunks = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last = i == total_chunks - 1;
        submit_firmware_block(dev, chunk, is_last)?;
    }

    // Wait for IMEM code to complete
    wait_for_firmware(dev, IMEM_CODE_DONE, IMEM_CHK_RPT, "IMEM")?;

    pr_debug!("r92su: IMEM upload complete\n");
    Ok(())
}

/// Upload SRAM (static RAM) segment and enable CPU.
fn upload_sram(dev: &mut R92suDevice, sram: &[u8]) -> Result<()> {
    pr_debug!("r92su: uploading SRAM ({} bytes)\n", sram.len());

    let chunks = sram.chunks(BLOCK_SIZE);
    let total_chunks = chunks.len();

    for (i, chunk) in chunks.enumerate() {
        let is_last = i == total_chunks - 1;
        submit_firmware_block(dev, chunk, is_last)?;
    }

    // Wait for SRAM code to complete
    wait_for_firmware(dev, EMEM_CODE_DONE, EMEM_CHK_RPT, "SRAM")?;

    // Enable CPU
    enable_cpu(dev)?;

    pr_debug!("r92su: SRAM upload complete\n");
    Ok(())
}

/// Upload DMEM (data memory) - the fw_priv structure.
fn upload_dmem(dev: &mut R92suDevice, fw_priv: &FwPriv) -> Result<()> {
    pr_debug!("r92su: uploading DMEM\n");

    let dmem_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            fw_priv as *const FwPriv as *const u8,
            core::mem::size_of::<FwPriv>(),
        )
    };

    // DMEM is always a single block
    submit_firmware_block(dev, dmem_bytes, true)?;

    // Wait for DMEM code to complete
    wait_for_firmware(dev, DMEM_CODE_DONE, DMEM_CODE_DONE, "DMEM")?;

    // Wait for firmware boot ready
    let tries = 30;
    let mut delay = 100;

    for _ in 0..tries {
        let status = unsafe { hw_read8(dev.udev, REG_TCR) };
        if status & FWRDY != 0 {
            pr_debug!("r92su: firmware boot ready\n");
            return Ok(());
        }
        // Check for EEPROM boot (slower)
        let eeprom = unsafe { hw_read8(dev.udev, REG_EEPROM_CMD) };
        if eeprom & EEPROM_CMD_93C46 != 0 {
            delay = 200; // Slower boot from EEPROM
        }
        crate::r92u::mdelay(delay);
    }

    Err(R92suError::FirmwareUploadFailed("firmware boot timeout"))
}

/// Submit a single firmware block via bulk-out.
fn submit_firmware_block(dev: &mut R92suDevice, data: &[u8], is_last: bool) -> Result<()> {
    // Build TX descriptor header
    let mut tx_desc = [0u8; TX_DESC_SIZE];

    // Dword 0: packet size (lower 16 bits)
    let pkt_size = data.len() as u32;
    tx_desc[0] = pkt_size as u8;
    tx_desc[1] = (pkt_size >> 8) as u8;

    // Set LINIP (last block) on last block
    if is_last {
        tx_desc[3] |= 0x10; // LINIP bit position
    }

    // Build full frame: TX descriptor + data
    let mut frame = KVec::with_capacity(TX_DESC_SIZE + data.len(), GFP_KERNEL)
        .map_err(|_| R92suError::FirmwareUploadFailed("out of memory"))?;
    frame
        .extend_from_slice(&tx_desc, GFP_KERNEL)
        .map_err(|_| R92suError::FirmwareUploadFailed("out of memory"))?;
    frame
        .extend_from_slice(data, GFP_KERNEL)
        .map_err(|_| R92suError::FirmwareUploadFailed("out of memory"))?;

    // Submit via synchronous bulk-out (usb_bulk_msg).
    crate::r92u::fw_bulk_write(dev, &frame)?;

    Ok(())
}

/// Wait for firmware operation to complete by polling TCR register.
fn wait_for_firmware(
    dev: &mut R92suDevice,
    done_flag: u8,
    done2_flag: u8,
    name: &str,
) -> Result<()> {
    let tries = 100;
    let delay = 20;

    for _ in 0..tries {
        let status = unsafe { hw_read8(dev.udev, REG_TCR) };
        if status & done_flag != 0 && (status & done2_flag != 0 || done_flag == done2_flag) {
            return Ok(());
        }
        crate::r92u::mdelay(delay);
    }

    let status = unsafe { hw_read8(dev.udev, REG_TCR) };
    pr_err!(
        "r92su: firmware {} upload failed, status=0x{:02x}\n",
        name,
        status
    );
    Err(R92suError::FirmwareUploadFailed("firmware upload failed"))
}

/// Enable the CPU after SRAM upload.
fn enable_cpu(dev: &mut R92suDevice) -> Result<()> {
    // Select CPU clock
    let clk = unsafe { hw_read8(dev.udev, REG_SYS_CLKR) };
    unsafe { hw_write8(dev.udev, REG_SYS_CLKR, clk | SYS_CPU_CLKSEL) };

    // Enable CPU
    let func = unsafe { crate::r92u::hw_read16(dev.udev, REG_SYS_FUNC_EN) };
    unsafe { crate::r92u::hw_write16(dev.udev, REG_SYS_FUNC_EN, func | FEN_CPUEN) };

    // Wait for IMEM ready
    let tries = 1000;
    for _ in 0..tries {
        let status = unsafe { hw_read8(dev.udev, REG_TCR) };
        if status & IMEM_RDY != 0 {
            return Ok(());
        }
        crate::r92u::udelay(20);
    }

    Err(R92suError::FirmwareUploadFailed("CPU enable timeout"))
}
