use std::{net::Ipv4Addr, sync::{Mutex, mpsc::Receiver}};

use pnet::transport::TransportSender;

#[allow(dead_code)]
pub(super) struct ScannerSender{
    transport_sender: Mutex<TransportSender>,
    rx_target: Receiver<(Ipv4Addr, u16)>
}

impl ScannerSender{
    pub(super) fn new(ts: TransportSender, rx_target: Receiver<(Ipv4Addr, u16)>) -> Self{
        ScannerSender { transport_sender: Mutex::new(ts), rx_target }
    }
}