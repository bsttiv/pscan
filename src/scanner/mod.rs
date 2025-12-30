use std::{net::{IpAddr, Ipv4Addr}, ops::Range, str::FromStr, sync::{Arc, Mutex, mpsc::{Receiver, Sender}}};


use super::cli::{ScannerArgs, utils::IntOrRange};
use self::{receiver::ScannerReceiver, sender::ScannerSender, utils::new_transport};

mod packet;
mod sender;
mod receiver;
mod utils;

pub(super) struct Scanner{
    sender: Arc<Mutex<ScannerSender>>,
    receiver: Arc<Mutex<ScannerReceiver>>,
    rx_results: Receiver<(bool, Ipv4Addr, u16)>,
    tx_target: Sender<(Ipv4Addr, u16)>,
    target: Ipv4Addr,
    source_ips: Vec<Ipv4Addr>,
    ports: Vec<u16>
}

impl Scanner{
    pub(super) fn new(args: ScannerArgs) -> Self{
        let (tx_target, rx_target) = std::sync::mpsc::channel();
        let (tx_results, rx_results) = std::sync::mpsc::channel::<(bool, Ipv4Addr, u16)>();
        let (ts, tr) = new_transport();
        let s = ScannerSender::new(ts, rx_target);
        let r = ScannerReceiver::new(tr, tx_results);
        let ports = match args.port{
            IntOrRange::Int(p) => vec![p],
            IntOrRange::Range(start, end) => Range{start, end:end+1}.collect()
        };
        let src = args.interface.ips.first().expect("Error: Selected interface has no IPs").ip();
        let src = match src{
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("Error: IPv6 is not supported")
        };
        let source_ips = match args.decoy{
            Some(d) => {
                let mut v:Vec<Ipv4Addr> = d.iter().map(|a|Ipv4Addr::from_str(a).unwrap()).collect();
                if !v.contains(&src){
                    v.push(src);
                }
                v
            },
            None => {vec![src]}
        };
        Scanner { 
            sender: Arc::new(Mutex::new(s)),
            receiver: Arc::new(Mutex::new(r)),
            rx_results,
            tx_target,
            target: args.target,
            source_ips,
            ports
        }
    }
    pub(crate) fn scan(self){
        std::thread::spawn(move || {
            let recv = Arc::clone(&self.receiver);
            let mut recv = recv.lock().unwrap();
            recv.receive(&self.target);
        });
        std::thread::spawn(move || {
            let send = Arc::clone(&self.sender);
            let mut send = send.lock().unwrap();
            send.send(self.source_ips);
        });
        for port in self.ports{
            self.tx_target.send((self.target, port)).unwrap();
        }
        for (result, ip, port) in self.rx_results{
            if result{
                println!("Open port: {}:{}", ip, port);
            }
        }
    }
}