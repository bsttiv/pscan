use pnet::{packet::ip::IpNextHeaderProtocols, transport::{self, TransportReceiver, TransportSender, transport_channel}};

pub(super) fn new_transport() -> (TransportSender, TransportReceiver){
    transport_channel(4096, 
        transport::TransportChannelType::Layer3(
        IpNextHeaderProtocols::Tcp
    )).expect("Error initializing the scanner: Could not create a tranport on Layer 3.")
}