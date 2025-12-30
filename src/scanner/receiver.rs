use std::{net::{IpAddr, Ipv4Addr}, sync::mpsc::Sender};

use pnet::{packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::{TcpFlags, TcpPacket}}, transport::{TransportReceiver, ipv4_packet_iter}};

pub(super) struct ScannerReceiver{
    transport_receiver: TransportReceiver,
    tx_results: Sender<(bool, Ipv4Addr, u16)>
}

impl ScannerReceiver{
    pub(super) fn new(tr: TransportReceiver, tx_results: Sender<(bool, Ipv4Addr, u16)>) -> Self{
        ScannerReceiver { transport_receiver: tr, tx_results }
    }

    fn handle_packet(packet:Ipv4Packet, target: &Ipv4Addr) -> (bool, u16){
        if !packet.get_source().eq(target){return (false, 0)}
        if let IpNextHeaderProtocols::Tcp = packet.get_next_level_protocol(){
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()){
                let port = tcp_packet.get_source();
                return (tcp_packet.get_flags() == TcpFlags::SYN + TcpFlags::ACK, port)
            }
        }
        (false, 0)
    }

    pub(super) fn receive(&mut self, target: &Ipv4Addr){
        let mut tr_iter = ipv4_packet_iter(&mut self.transport_receiver);
        loop{
            if let Ok((packet, _)) = tr_iter.next(){
                let (is_open, port) = Self::handle_packet(packet, target);
                    self.tx_results.send((is_open, *target, port)).unwrap();
            }
        }
    }
}