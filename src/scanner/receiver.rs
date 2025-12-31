//! Packet reception logic.
//!
//! This module handles capturing raw packets from the network interface and
//! analyzing them to determine if a port is open based on the TCP flags.

use std::{net::Ipv4Addr, sync::mpsc::Sender};

use pnet::{packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::{TcpFlags, TcpPacket}}, transport::{TransportReceiver, ipv4_packet_iter}};

/// Handles the reception and processing of incoming network packets.
///
/// This struct runs in a background thread, listening for TCP responses
/// to the SYN packets sent by the `ScannerSender`.
pub(super) struct ScannerReceiver {
    /// The underlying raw socket receiver provided by `pnet`.
    transport_receiver: TransportReceiver,
    /// Channel to send scan results (Open/Closed status) back to the main thread.
    tx_results: Sender<(bool, Ipv4Addr, u16)>
}

impl ScannerReceiver {
    /// Creates a new `ScannerReceiver`.
    pub(super) fn new(tr: TransportReceiver, tx_results: Sender<(bool, Ipv4Addr, u16)>) -> Self {
        ScannerReceiver { transport_receiver: tr, tx_results }
    }

    /// Analyzes a raw IPv4 packet to determine if it indicates an open port.
    ///
    /// # Arguments
    ///
    /// * `packet` - The raw IPv4 packet captured from the network.
    /// * `target` - The specific IP address we are scanning (used for filtering).
    ///
    /// # Returns
    ///
    /// Returns a tuple `(bool, u16)`:
    /// * `true` if the port is open (SYN+ACK received).
    /// * `false` if the packet is irrelevant or indicates a closed port.
    /// * `u16` contains the port number (source port of the incoming packet).
    fn handle_packet(packet: Ipv4Packet, target: &Ipv4Addr) -> (bool, u16) {
        // Filter: Ignore packets that do not originate from our target IP.
        if !packet.get_source().eq(target) {
            return (false, 0);
        }

        // Filter: We are only interested in TCP packets.
        if let IpNextHeaderProtocols::Tcp = packet.get_next_level_protocol() {
            // Attempt to extract the TCP segment from the IP payload.
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                let port = tcp_packet.get_source();

                // Check for Open Port criteria:
                // If we sent a SYN, an open port replies with SYN + ACK.
                // A closed port usually replies with RST (Reset).
                return (tcp_packet.get_flags() == TcpFlags::SYN + TcpFlags::ACK, port);
            }
        }

        // Packet is not relevant or not TCP.
        (false, 0)
    }

    /// The main execution loop for the receiver thread.
    ///
    /// Captures packets from the network interface using an iterator.
    /// It loops indefinitely (until the thread is killed) processing packets
    /// and reporting results.
    pub(super) fn receive(&mut self, target: &Ipv4Addr) {
        // Create an iterator over incoming IPv4 packets.
        let mut tr_iter = ipv4_packet_iter(&mut self.transport_receiver);

        loop {
            // Block until a packet is received.
            if let Ok((packet, _)) = tr_iter.next() {
                let (is_open, port) = Self::handle_packet(packet, target);
                
                // TODO: Handle potential send errors gracefully in future updates.
                self.tx_results.send((is_open, *target, port)).unwrap();
            }
        }
    }
}