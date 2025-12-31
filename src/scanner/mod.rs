//! Core scanning functionality.
//!
//! This module orchestrates the packet sending and receiving threads,
//! manages the state of the scan, and handles the synchronization between components.

use std::{net::{IpAddr, Ipv4Addr}, ops::Range, str::FromStr, sync::{Arc, Mutex, mpsc::{Receiver, Sender}}};

use super::cli::{ScannerArgs, utils::IntOrRange};
use self::{receiver::ScannerReceiver, sender::ScannerSender, utils::new_transport};

mod packet;
mod sender;
mod receiver;
mod utils;

/// The main scanner coordinator.
///
/// This struct holds the shared state and channels required to run the port scan.
/// It manages the lifecycle of the sender and receiver threads.
pub(super) struct Scanner {
    /// Thread-safe reference to the packet sender logic.
    sender: Arc<Mutex<ScannerSender>>,
    /// Thread-safe reference to the packet receiver logic.
    receiver: Arc<Mutex<ScannerReceiver>>,
    /// Channel receiver for results coming from the sniffing thread.
    rx_results: Receiver<(bool, Ipv4Addr, u16)>,
    /// Channel sender to dispatch scan tasks (IP, Port) to the sender thread.
    tx_target: Sender<(Ipv4Addr, u16)>,
    /// The target IP address to scan.
    target: Ipv4Addr,
    /// List of source IPs to use (includes the real interface IP and decoys).
    source_ips: Vec<Ipv4Addr>,
    /// The list of ports to scan.
    ports: Vec<u16>
}

impl Scanner {
    /// Creates a new `Scanner` instance from the provided arguments.
    ///
    /// Initializes the transport layer, sets up synchronization channels,
    /// and prepares the list of target ports and source IPs.
    ///
    /// # Arguments
    ///
    /// * `args` - The parsed command-line arguments containing target and config info.
    ///
    /// # Notes
    ///
    /// TODO: Current implementation uses `unwrap` and `expect` for simplicity.
    /// Robust error handling and `Result` propagation will be added in future updates.
    pub(super) fn new(args: ScannerArgs) -> Self {
        // Create channels for thread communication.
        // tx_target/rx_target: Used to send tasks (ports) to the sender thread.
        // tx_results/rx_results: Used to send found open ports back to the main thread.
        let (tx_target, rx_target) = std::sync::mpsc::channel();
        let (tx_results, rx_results) = std::sync::mpsc::channel::<(bool, Ipv4Addr, u16)>();

        // Initialize the raw socket transport layer (pnet).
        let (ts, tr) = new_transport();

        let s = ScannerSender::new(ts, rx_target);
        let r = ScannerReceiver::new(tr, tx_results);

        // Convert the CLI port argument (single int or range) into a vector of u16.
        let ports = match args.port {
            IntOrRange::Int(p) => vec![p],
            // Range is exclusive at the end, so we add +1 to include the last port.
            IntOrRange::Range(start, end) => Range { start, end: end + 1 }.collect(),
        };

        // Extract the source IPv4 address from the selected network interface.
        let src = args.interface.ips.first().expect("Error: Selected interface has no IPs").ip();
        let src = match src {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("Error: IPv6 is not supported"),
        };

        // Prepare the list of source IPs.
        // If decoys are provided, mix them with the real source IP.
        let source_ips = match args.decoy {
            Some(d) => {
                let mut v: Vec<Ipv4Addr> = d.iter().map(|a| Ipv4Addr::from_str(a).unwrap()).collect();
                // Ensure the real source IP is included in the rotation so packets actually return.
                if !v.contains(&src) {
                    v.push(src);
                }
                v
            },
            None => { vec![src] }
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

    /// Executes the port scan.
    ///
    /// This method spawns the receiver and sender threads, feeds the ports to be scanned
    /// into the pipeline, and listens for results to print to stdout.
    pub(crate) fn scan(self) {
        // Spawn the receiver thread first to ensure it's listening before packets go out.
        std::thread::spawn(move || {
            let recv = Arc::clone(&self.receiver);
            let mut recv = recv.lock().unwrap();
            recv.receive(&self.target);
        });

        // Spawn the sender thread to dispatch packets.
        std::thread::spawn(move || {
            let send = Arc::clone(&self.sender);
            let mut send = send.lock().unwrap();
            send.send(self.source_ips);
        });

        // Feed the target ports into the channel for the sender thread to consume.
        for port in self.ports {
            self.tx_target.send((self.target, port)).unwrap();
        }

        // Main thread blocks here waiting for results from the receiver thread.
        for (result, ip, port) in self.rx_results {
            if result {
                println!("Open port: {}:{}", ip, port);
            }
        }
    }
}