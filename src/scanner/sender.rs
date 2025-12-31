//! Packet dispatch logic.
//!
//! This module manages the outgoing packet stream, handling the construction
//! of buffers and the transmission of raw packets via the network interface.

use std::{net::Ipv4Addr, sync:: mpsc::Receiver};

use pnet::transport::TransportSender;

use crate::scanner::packet::create_packet;

/// Handles the transmission of raw packets.
///
/// This struct runs in a background thread and consumes tasks (IP, Port)
/// from a channel to execute the scan.
pub(super) struct ScannerSender {
    /// The underlying raw socket sender provided by `pnet`.
    transport_sender: TransportSender,
    /// Channel receiver for incoming scan tasks (Target IP, Target Port).
    rx_target: Receiver<(Ipv4Addr, u16)>
}

impl ScannerSender {
    /// Creates a new `ScannerSender`.
    pub(super) fn new(ts: TransportSender, rx_target: Receiver<(Ipv4Addr, u16)>) -> Self {
        ScannerSender { transport_sender: ts, rx_target }
    }

    /// Continuously retrieves targets from the channel and sends SYN packets.
    ///
    /// For every target port received, this function constructs and sends a packet
    /// from each of the provided source IPs. If decoys are configured, this results
    /// in multiple packets per target port.
    ///
    /// # Arguments
    ///
    /// * `sources` - A list of IPv4 addresses to use as the source IP in the packet header.
    ///
    /// # Notes
    ///
    /// TODO: Error handling for packet transmission failures (`unwrap`) will be
    /// improved in future updates.
    pub(super) fn send(&mut self, sources: Vec<Ipv4Addr>) {
        // Iterate over incoming scan tasks.
        // This iterator blocks until a new task is available or the channel is closed.
        for (ip, port) in self.rx_target.iter() {
            
            // Iterate through every source IP (Real IP + Decoys).
            for source in sources.iter() {
                // Allocate a buffer for the packet.
                // 40 bytes is sufficient for IPv4 Header (20) + TCP Header (20).
                let mut buf = vec![0; 40];

                let packet = create_packet(port, ip, *source, &mut buf);

                // Send the constructed packet to the target.
                self.transport_sender.send_to(packet, std::net::IpAddr::V4(ip)).unwrap();

                // Rate limiting:
                // Sleep for 500ms between packets to avoid network congestion,
                // reduce packet loss, and lower the chance of triggering IDS.
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}