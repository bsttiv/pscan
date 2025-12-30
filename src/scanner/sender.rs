use std::{net::Ipv4Addr, sync:: mpsc::Receiver};

use pnet::transport::TransportSender;

use crate::scanner::packet::create_packet;

#[allow(dead_code)]
pub(super) struct ScannerSender{
    transport_sender: TransportSender,
    rx_target: Receiver<(Ipv4Addr, u16)>
}

impl ScannerSender{
    pub(super) fn new(ts: TransportSender, rx_target: Receiver<(Ipv4Addr, u16)>) -> Self{
        ScannerSender { transport_sender: ts, rx_target }
    }
    #[allow(dead_code)]
    pub(super) fn send(&mut self, sources: Vec<Ipv4Addr>){
        for (ip, port) in self.rx_target.iter(){
            for source in sources.iter(){
                let mut buf = vec![0;40];
                let packet = create_packet(port, ip, *source, &mut buf);
                self.transport_sender.send_to(packet, std::net::IpAddr::V4(ip)).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}