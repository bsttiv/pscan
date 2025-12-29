use std::sync::{Mutex, mpsc::Sender};

use pnet::transport::TransportReceiver;

#[allow(dead_code)]
pub(super) struct ScannerReceiver{
    transport_receiver: Mutex<TransportReceiver>,
    tx_results: Sender<bool>
}

impl ScannerReceiver{
    pub(super) fn new(tr: TransportReceiver, tx_results: Sender<bool>) -> Self{
        ScannerReceiver { transport_receiver: Mutex::new(tr), tx_results }
    }
}