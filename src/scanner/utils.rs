//! Scanner utility functions.
//!
//! This module handles the initialization of the low-level network transport channels
//! required by the `pnet` library.

use pnet::{packet::ip::IpNextHeaderProtocols, transport::{self, TransportReceiver, TransportSender, transport_channel}};

/// Initializes the transport layer for raw socket communication.
///
/// This function creates a channel that operates at Layer 3 (Network Layer).
/// This allows the scanner to read and write raw IP packets directly,
/// specifically filtering for TCP traffic.
///
/// # Returns
///
/// Returns a tuple containing:
/// * `TransportSender`: Used to send raw packets.
/// * `TransportReceiver`: Used to read incoming packets.
///
/// # Panics
///
/// Panics if the OS refuses to open a raw socket (e.g., if run without `sudo`/Administrator privileges).
///
/// # Notes
///
/// TODO: The current implementation uses `expect` to handle initialization failures.
/// Future updates will return a `Result` to handle permission errors more gracefully.
pub(super) fn new_transport() -> (TransportSender, TransportReceiver) {
    // 4096 is the size of the read/write buffer.
    // Layer3(Tcp) tells the OS we want to handle IP packets where the next protocol is TCP.
    transport_channel(
        4096, 
        transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)
    ).expect("Error initializing the scanner: Could not create a transport on Layer 3.")
}