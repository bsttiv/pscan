use std::{net::Ipv4Addr, sync::mpsc::{Receiver, Sender}};

use pnet::datalink::NetworkInterface;

use super::cli::ScannerArgs;
use self::{receiver::ScannerReceiver, sender::ScannerSender, utils::new_transport};

mod packet;
mod sender;
mod receiver;
mod utils;

#[allow(dead_code)]
pub(super) struct Scanner{
    sender: ScannerSender,
    receiver: ScannerReceiver,
    rx_results: Receiver<bool>,
    tx_target: Sender<(Ipv4Addr, u16)>,
    interface: NetworkInterface
}

#[allow(dead_code)]
impl Scanner{
    #[allow(unused_variables)]
    pub(super) fn new(args: ScannerArgs) -> Self{
        let (tx_target, rx_target) = std::sync::mpsc::channel();
        let (tx_results, rx_results) = std::sync::mpsc::channel();
        let (ts, tr) = new_transport();
        let s = ScannerSender::new(ts, rx_target);
        let r = ScannerReceiver::new(tr, tx_results);
        Scanner { 
            sender: s,
            receiver: r,
            rx_results,
            tx_target,
            interface: args.interface
        }
    }
}