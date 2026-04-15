// SPDX-License-Identifier: GPL-2.0
//! Packet logging formatter for debugging.
//!
//! This module provides simple packet formatting for logging purposes.

pub struct PacketFormatter;

impl PacketFormatter {
    pub fn format_packet(data: &[u8]) -> PacketString<'_> {
        PacketString { data }
    }
}

pub fn format_80211_frame(data: &[u8]) -> impl kernel::fmt::Display + '_ {
    Ieee80211String { data }
}

pub fn hex_dump(data: &[u8]) -> impl kernel::fmt::Display + '_ {
    HexDump::new(data)
}

pub struct PacketString<'a> {
    data: &'a [u8],
}

impl<'a> kernel::fmt::Display for PacketString<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.data.len() < 14 {
            return write!(f, "ether[{} bytes]", self.data.len());
        }

        let dst_mac = &self.data[0..6];
        let src_mac = &self.data[6..12];
        let ether_type = u16::from_be_bytes([self.data[12], self.data[13]]);

        write!(f, "ether {} > {}, ", MacAddr(dst_mac), MacAddr(src_mac))?;

        match ether_type {
            0x0800 => write_ip(f, &self.data[14..]),
            0x86DD => write_ipv6(f, &self.data[14..]),
            0x0806 => write!(f, "ARP"),
            _ => write!(f, "ethertype={:04X}", ether_type),
        }
    }
}

pub struct MacAddr<'a>(&'a [u8]);

impl<'a> core::fmt::Display for MacAddr<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.len() >= 6 {
            write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
            )
        } else {
            write!(f, "??:??:??:??:??:??")
        }
    }
}

fn write_ip(f: &mut core::fmt::Formatter<'_>, payload: &[u8]) -> core::fmt::Result {
    if payload.len() < 20 {
        return write!(f, "IPv4[truncated]");
    }

    let ihl = (payload[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let protocol = payload[9];
    let src = [payload[12], payload[13], payload[14], payload[15]];
    let dst = [payload[16], payload[17], payload[18], payload[19]];

    if payload.len() < ihl {
        return write!(f, "IPv4[truncated]");
    }

    let trans_payload = &payload[ihl..];

    match protocol {
        6 => write_tcp(f, src, dst, trans_payload, total_len),
        17 => write_udp(f, src, dst, trans_payload, total_len),
        1 => write!(
            f,
            "IPv4 {} > {}, ICMP, len={}",
            Ipv4Addr(&src),
            Ipv4Addr(&dst),
            total_len
        ),
        _ => write!(
            f,
            "IPv4 {} > {}, proto={}, len={}",
            Ipv4Addr(&src),
            Ipv4Addr(&dst),
            protocol,
            total_len
        ),
    }
}

fn write_ipv6(f: &mut core::fmt::Formatter<'_>, payload: &[u8]) -> core::fmt::Result {
    if payload.len() < 40 {
        return write!(f, "IPv6[truncated]");
    }

    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let next_header = payload[6];
    let src = &payload[8..24];
    let dst = &payload[24..40];

    let trans_payload = &payload[40..];

    match next_header {
        6 => write_tcp_ipv6(f, src, dst, trans_payload, payload_len),
        17 => write_udp_ipv6(f, src, dst, trans_payload, payload_len),
        58 => write!(
            f,
            "IPv6 {} > {}, ICMPv6, plen={}",
            Ipv6Addr(src),
            Ipv6Addr(dst),
            payload_len
        ),
        _ => write!(
            f,
            "IPv6 {} > {}, nh={}, plen={}",
            Ipv6Addr(src),
            Ipv6Addr(dst),
            next_header,
            payload_len
        ),
    }
}

fn write_tcp(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    payload: &[u8],
    total_len: usize,
) -> kernel::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "IPv4 {} > {}, TCP[truncated], len={}",
            Ipv4Addr(&src_ip),
            Ipv4Addr(&dst_ip),
            total_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "IPv4 {}:{} > {}:{}, TCP, len={}",
        Ipv4Addr(&src_ip),
        src_port,
        Ipv4Addr(&dst_ip),
        dst_port,
        total_len
    )
}

fn write_udp(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    payload: &[u8],
    total_len: usize,
) -> kernel::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "IPv4 {} > {}, UDP[truncated], len={}",
            Ipv4Addr(&src_ip),
            Ipv4Addr(&dst_ip),
            total_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "IPv4 {}:{} > {}:{}, UDP, len={}",
        Ipv4Addr(&src_ip),
        src_port,
        Ipv4Addr(&dst_ip),
        dst_port,
        total_len
    )
}

fn write_tcp_ipv6(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: &[u8],
    dst_ip: &[u8],
    payload: &[u8],
    plen: usize,
) -> kernel::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "IPv6 {} > {}, TCP[truncated], plen={}",
            Ipv6Addr(src_ip),
            Ipv6Addr(dst_ip),
            plen
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "IPv6 {}:{} > {}:{}, TCP, plen={}",
        Ipv6Addr(src_ip),
        src_port,
        Ipv6Addr(dst_ip),
        dst_port,
        plen
    )
}

fn write_udp_ipv6(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: &[u8],
    dst_ip: &[u8],
    payload: &[u8],
    plen: usize,
) -> kernel::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "IPv6 {} > {}, UDP[truncated], plen={}",
            Ipv6Addr(src_ip),
            Ipv6Addr(dst_ip),
            plen
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "IPv6 {}:{} > {}:{}, UDP, plen={}",
        Ipv6Addr(src_ip),
        src_port,
        Ipv6Addr(dst_ip),
        dst_port,
        plen
    )
}

pub struct Ipv4Addr<'a>(&'a [u8; 4]);

impl<'a> core::fmt::Display for Ipv4Addr<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

pub struct Ipv6Addr<'a>(&'a [u8]);

impl<'a> core::fmt::Display for Ipv6Addr<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0.len() < 16 {
            return write!(f, "::<ipv6 truncated>::");
        }
        write!(
            f,
            "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]",
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]]),
            u16::from_be_bytes([self.0[8], self.0[9]]),
            u16::from_be_bytes([self.0[10], self.0[11]]),
            u16::from_be_bytes([self.0[12], self.0[13]]),
            u16::from_be_bytes([self.0[14], self.0[15]]),
        )
    }
}

pub struct HexDump<'a> {
    data: &'a [u8],
    max_bytes: usize,
}

impl<'a> HexDump<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            max_bytes: 256,
        }
    }

    pub fn limited(data: &'a [u8], max_bytes: usize) -> Self {
        Self { data, max_bytes }
    }
}

impl<'a> kernel::fmt::Display for HexDump<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let display_data = if self.data.len() > self.max_bytes {
            &self.data[..self.max_bytes]
        } else {
            self.data
        };

        for (i, &byte) in display_data.iter().enumerate() {
            if i % 16 == 0 && i != 0 {
                write!(f, "\n")?;
            }
            if i % 16 == 0 {
                write!(f, "{:04x}: ", i)?;
            }
            write!(f, "{:02x} ", byte)?;
        }

        if self.data.len() > self.max_bytes {
            write!(f, "\n... {} more bytes", self.data.len() - self.max_bytes)?;
        }

        Ok(())
    }
}

pub struct Ieee80211String<'a> {
    data: &'a [u8],
}

impl<'a> kernel::fmt::Display for Ieee80211String<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.data.len() < 24 {
            return write!(f, "802.11[{} bytes]", self.data.len());
        }

        let fc = u16::from_le_bytes([self.data[0], self.data[1]]);
        let (to_ds, from_ds) = ((fc >> 8) & 1, (fc >> 9) & 1);
        let ftype = (fc >> 2) & 0x3;
        let subtype = (fc >> 4) & 0xf;

        let ft = match ftype {
            0 => "MGMT",
            1 => "CTRL",
            2 => "DATA",
            _ => "unk",
        };

        match (ftype, subtype) {
            (0, 0x00) => write!(f, "802.11 {}: Assoc Req", ft),
            (0, 0x01) => write!(f, "802.11 {}: Assoc Resp", ft),
            (0, 0x04) => write!(f, "802.11 {}: Probe Request", ft),
            (0, 0x05) => write!(f, "802.11 {}: Probe Response", ft),
            (0, 0x08) => write!(f, "802.11 {}: Beacon", ft),
            (0, 0x0B) => write!(f, "802.11 {}: Auth", ft),
            (0, 0x0C) => write!(f, "802.11 {}: Deauth", ft),
            (0, 0x0D) => write!(f, "802.11 {}: Action", ft),
            (2, _) => {
                let (src, dst) = match (to_ds, from_ds) {
                    (0, 0) => (&self.data[10..16], &self.data[4..10]),
                    (0, 1) => (&self.data[16..22], &self.data[4..10]),
                    (1, 0) => (&self.data[10..16], &self.data[16..22]),
                    _ => (&self.data[10..16], &self.data[16..22]),
                };

                let hdrlen = ieee80211_hdrlen(fc);
                let protected = (fc & (1 << 14)) != 0;
                let ccmp_hdr_len: usize = if protected { 8 } else { 0 };
                let llc_start = hdrlen + ccmp_hdr_len;

                if self.data.len() >= llc_start + 8 {
                    let ethertype =
                        u16::from_be_bytes([self.data[llc_start + 6], self.data[llc_start + 7]]);
                    let eth_payload = &self.data[llc_start + 8..];

                    write!(f, "802.11 DATA: ")?;
                    write!(f, "ether {} > {}, ", MacAddr(dst), MacAddr(src))?;

                    match ethertype {
                        0x0800 => {
                            write!(f, "IPv4 ")?;
                            write_ip_eth(f, eth_payload)?;
                            Ok(())
                        }
                        0x86DD => {
                            write!(f, "IPv6 ")?;
                            write_ipv6_eth(f, eth_payload)?;
                            Ok(())
                        }
                        0x0806 => {
                            write!(f, "ARP")?;
                            Ok(())
                        }
                        _ => {
                            write!(f, "ethertype={:04X}", ethertype)?;
                            Ok(())
                        }
                    }
                } else {
                    write!(
                        f,
                        "802.11 {} > {} (DS={}{})",
                        MacAddr(src),
                        MacAddr(dst),
                        to_ds,
                        from_ds
                    )?;
                    if self.data.len() > 24 {
                        let frame_len = self.data.len() - 24;
                        write!(f, ", {} data bytes", frame_len)?;
                    }
                    Ok(())
                }
            }
            _ => {
                let (src, dst) = match (to_ds, from_ds) {
                    (0, 0) => (&self.data[10..16], &self.data[4..10]),
                    (0, 1) => (&self.data[16..22], &self.data[4..10]),
                    (1, 0) => (&self.data[10..16], &self.data[16..22]),
                    _ => (&self.data[10..16], &self.data[16..22]),
                };

                write!(
                    f,
                    "802.11 {} > {} (DS={}{})",
                    MacAddr(src),
                    MacAddr(dst),
                    to_ds,
                    from_ds
                )?;

                if self.data.len() > 24 {
                    let frame_len = self.data.len() - 24;
                    write!(f, ", {} data bytes", frame_len)?;
                }

                Ok(())
            }
        }
    }
}

fn ieee80211_hdrlen(fc: u16) -> usize {
    let ftype = (fc >> 2) & 0x3;
    let fsub = (fc >> 4) & 0xf;
    match ftype {
        0 => 24,
        1 => 24,
        2 => {
            let to_ds = (fc >> 8) & 1;
            let from_ds = (fc >> 9) & 1;
            let a4 = to_ds == 1 && from_ds == 1;
            let qos = (fsub & 0x8) != 0;
            24 + if a4 { 6 } else { 0 } + if qos { 2 } else { 0 }
        }
        _ => 24,
    }
}

fn write_ip_eth(f: &mut core::fmt::Formatter<'_>, payload: &[u8]) -> core::fmt::Result {
    if payload.len() < 20 {
        return write!(f, "IPv4[truncated]");
    }

    let ihl = (payload[0] & 0x0F) as usize * 4;
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let protocol = payload[9];
    let src = [payload[12], payload[13], payload[14], payload[15]];
    let dst = [payload[16], payload[17], payload[18], payload[19]];

    if payload.len() < ihl {
        return write!(f, "IPv4[truncated]");
    }

    let trans_payload = &payload[ihl..];

    match protocol {
        6 => write_tcp_eth(f, src, dst, trans_payload, total_len),
        17 => write_udp_eth(f, src, dst, trans_payload, total_len),
        1 => write!(
            f,
            "{} > {}, ICMP, len={}",
            Ipv4Addr(&src),
            Ipv4Addr(&dst),
            total_len
        ),
        _ => write!(
            f,
            "{} > {}, proto={}, len={}",
            Ipv4Addr(&src),
            Ipv4Addr(&dst),
            protocol,
            total_len
        ),
    }
}

fn write_ipv6_eth(f: &mut core::fmt::Formatter<'_>, payload: &[u8]) -> core::fmt::Result {
    if payload.len() < 40 {
        return write!(f, "IPv6[truncated]");
    }

    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let next_header = payload[6];
    let src = &payload[8..24];
    let dst = &payload[24..40];

    let trans_payload = &payload[40..];

    match next_header {
        6 => write_tcp_ipv6_eth(f, src, dst, trans_payload, payload_len),
        17 => write_udp_ipv6_eth(f, src, dst, trans_payload, payload_len),
        58 => write!(
            f,
            "{} > {}, ICMPv6, plen={}",
            Ipv6Addr(src),
            Ipv6Addr(dst),
            payload_len
        ),
        _ => write!(
            f,
            "{} > {}, nh={}, plen={}",
            Ipv6Addr(src),
            Ipv6Addr(dst),
            next_header,
            payload_len
        ),
    }
}

fn write_tcp_eth(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    payload: &[u8],
    total_len: usize,
) -> core::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "{} > {}, TCP[truncated], len={}",
            Ipv4Addr(&src_ip),
            Ipv4Addr(&dst_ip),
            total_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "{}:{} > {}:{}, TCP, len={}",
        Ipv4Addr(&src_ip),
        src_port,
        Ipv4Addr(&dst_ip),
        dst_port,
        total_len
    )
}

fn write_udp_eth(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    payload: &[u8],
    total_len: usize,
) -> core::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "{} > {}, UDP[truncated], len={}",
            Ipv4Addr(&src_ip),
            Ipv4Addr(&dst_ip),
            total_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "{}:{} > {}:{}, UDP, len={}",
        Ipv4Addr(&src_ip),
        src_port,
        Ipv4Addr(&dst_ip),
        dst_port,
        total_len
    )
}

fn write_tcp_ipv6_eth(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: &[u8],
    dst_ip: &[u8],
    payload: &[u8],
    payload_len: usize,
) -> core::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "{} > {}, TCP[truncated], plen={}",
            Ipv6Addr(src_ip),
            Ipv6Addr(dst_ip),
            payload_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "{}:{} > {}:{}, TCP, plen={}",
        Ipv6Addr(src_ip),
        src_port,
        Ipv6Addr(dst_ip),
        dst_port,
        payload_len
    )
}

fn write_udp_ipv6_eth(
    f: &mut core::fmt::Formatter<'_>,
    src_ip: &[u8],
    dst_ip: &[u8],
    payload: &[u8],
    payload_len: usize,
) -> core::fmt::Result {
    if payload.len() < 4 {
        return write!(
            f,
            "{} > {}, UDP[truncated], plen={}",
            Ipv6Addr(src_ip),
            Ipv6Addr(dst_ip),
            payload_len
        );
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    write!(
        f,
        "{}:{} > {}:{}, UDP, plen={}",
        Ipv6Addr(src_ip),
        src_port,
        Ipv6Addr(dst_ip),
        dst_port,
        payload_len
    )
}
