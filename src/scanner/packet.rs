use std::net::Ipv4Addr;

use pnet::packet::{MutablePacket, ip::IpNextHeaderProtocols, ipv4::{MutableIpv4Packet, checksum}, tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum}};
use rand::random;

pub(super) fn create_packet<'a>(port:u16, target:Ipv4Addr, source:Ipv4Addr, buf:&'a mut [u8]) -> MutableIpv4Packet<'a>{
    let mut ip_packet = MutableIpv4Packet::new(buf).expect("Error: Could not create IPv4 packet");
    ip_packet.set_version(4);
    ip_packet.set_destination(target);
    ip_packet.set_source(source);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    let mut tcp_packet = MutableTcpPacket::new(ip_packet.payload_mut()).expect("Error: Could not create TCP packet");
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_destination(port);
    let random_port = random::<u16>();
    tcp_packet.set_source(random_port);
    tcp_packet.set_sequence(43274);
    tcp_packet.set_checksum(ipv4_checksum(&tcp_packet.to_immutable(), &source, &target));
    ip_packet.set_checksum(checksum(&ip_packet.to_immutable()));
    ip_packet
}