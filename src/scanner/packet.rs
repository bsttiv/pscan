//! Packet construction logic.
//!
//! This module handles the low-level details of building raw IPv4 and TCP headers
//! required for the port scan.

use std::net::Ipv4Addr;

use pnet::packet::{MutablePacket, ip::IpNextHeaderProtocols, ipv4::{MutableIpv4Packet, checksum}, tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum}};
use rand::random;

/// Constructs a raw IPv4 packet containing a TCP SYN segment.
///
/// This function manually builds the IP and TCP headers required for a
/// "stealth" SYN scan. It calculates the necessary checksums to ensure
/// validity on the network.
///
/// # Arguments
///
/// * `port` - The destination port to scan.
/// * `target` - The destination IPv4 address.
/// * `source` - The source IPv4 address (can be a decoy or real IP).
/// * `buf` - A mutable byte slice used as the backing storage for the packet.
///
/// # Returns
///
/// Returns a `MutableIpv4Packet` wrapper around the provided buffer.
///
/// # Notes
///
/// TODO: Currently uses `expect` for buffer allocation failures.
/// Future updates will implement proper error propagation.
pub(super) fn create_packet<'a>(port: u16, target: Ipv4Addr, source: Ipv4Addr, buf: &'a mut [u8]) -> MutableIpv4Packet<'a> {
    // Initialize the IPv4 packet wrapper.
    let mut ip_packet = MutableIpv4Packet::new(buf).expect("Error: Could not create IPv4 packet");

    // Configure IPv4 Header Fields
    ip_packet.set_version(4);
    ip_packet.set_destination(target);
    ip_packet.set_source(source);
    // Standard IHL (Internet Header Length) is 5 words (20 bytes).
    ip_packet.set_header_length(5);
    // Total Length = IP Header (20 bytes) + TCP Header (20 bytes) = 40 bytes.
    // We are not sending data payload, just headers.
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

    // Create the TCP packet inside the IPv4 payload area.
    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).expect("Error: Could not create TCP packet");

    // Configure TCP Header Fields
    // Set the SYN flag to initiate a connection (part 1 of the 3-way handshake).
    tcp_packet.set_flags(TcpFlags::SYN);
    // Standard window size.
    tcp_packet.set_window(64240);
    // Data Offset: 5 words (20 bytes), meaning no TCP options.
    tcp_packet.set_data_offset(5);
    tcp_packet.set_destination(port);

    // Randomize the source port to avoid collisions or simple firewall filtering.
    let random_port = random::<u16>();
    tcp_packet.set_source(random_port);

    // Set an arbitrary sequence number.
    // Note: In a production scanner, randomizing this helps avoid OS fingerprinting.
    tcp_packet.set_sequence(43274);

    // Calculate Checksums
    // The TCP checksum requires a pseudo-header containing IP info.
    tcp_packet.set_checksum(ipv4_checksum(&tcp_packet.to_immutable(), &source, &target));

    // The IP checksum is calculated over the IP header only.
    ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));

    ip_packet
}