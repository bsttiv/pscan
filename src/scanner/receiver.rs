use std::{net::{IpAddr, Ipv4Addr}, sync::mpsc::Sender};

use pnet::{packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::{TcpFlags, TcpPacket}}, transport::{TransportReceiver, ipv4_packet_iter}};

#[allow(dead_code)]
pub(super) struct ScannerReceiver{
    transport_receiver: TransportReceiver,
    tx_results: Sender<bool>
}

impl ScannerReceiver{
    pub(super) fn new(tr: TransportReceiver, tx_results: Sender<bool>) -> Self{
        ScannerReceiver { transport_receiver: tr, tx_results }
    }
    #[allow(dead_code)]
    fn handle_packet(packet:Ipv4Packet) -> bool{
        if let IpNextHeaderProtocols::Tcp = packet.get_next_level_protocol(){
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()){
                return tcp_packet.get_flags() == TcpFlags::SYN + TcpFlags::ACK
            }
        }
        false
    }
    #[allow(dead_code)]
    pub(super) fn receive(&mut self, target: &Ipv4Addr){
        let mut tr_iter = ipv4_packet_iter(&mut self.transport_receiver);
        loop{
            if let Ok((packet, ip)) = tr_iter.next(){
                if let IpAddr::V4(ipv4) = ip{
                    if ipv4.eq(target) {
                        self.tx_results.send(Self::handle_packet(packet)).unwrap();
                    }
                }
            }
        }
    }
}