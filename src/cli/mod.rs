//! Command Line Interface (CLI) module.
//!
//! This module handles argument parsing using `clap` and directs the control flow
//! based on the user's input (either listing interfaces or performing a scan).

pub(crate) mod utils;

use std::{net::Ipv4Addr, str::FromStr};

use crate::scanner::Scanner;

use self::utils::{IntOrRange, valid_interface, valid_target_ip, print_interfaces};

use clap::{Parser, Args};
use pnet::datalink::NetworkInterface;

/// The main argument parser struct.
///
/// This struct defines the high-level modes of operation:
/// 1. Scanning mode (captured by `scanner_args`).
/// 2. Interface listing mode (captured by `interfaces`).
#[derive(Parser)]
#[command(name = "PScan")]
#[command(version, about)]
pub(super) struct Cli {
    /// Arguments specific to the port scanning functionality.
    ///
    /// This is flattened so flags appear directly at the top level.
    #[command(flatten)]
    pub(super) scanner_args: Option<ScannerArgs>,

    /// Flag to list available network interfaces and exit.
    ///
    /// This conflicts with `scanner_args` to ensure the user performs only one action.
    #[arg(long, conflicts_with = "scanner_args")]
    pub(super) interfaces: bool,
}

/// Configuration arguments required to perform a port scan.
///
/// These arguments are grouped to ensure that if a scan is initiated,
/// all necessary parameters (target, port, interface) are provided.
#[derive(Args)]
#[group(requires_all = &["target", "port", "interface"], multiple = true, id = "scanner_args")]
pub(super) struct ScannerArgs {
    /// The target IPv4 address to scan.
    #[arg(short, long, value_parser = valid_target_ip)]
    pub(super) target: Ipv4Addr,

    /// The port or range of ports to scan (e.g., "80" or "1-100").
    #[arg(short, long, value_parser = IntOrRange::from_str)]
    pub(super) port: IntOrRange,

    /// The network interface to use for sending packets.
    #[arg(short, long, value_parser = valid_interface)]
    pub(super) interface: NetworkInterface,

    /// Optional list of decoy IP addresses to obfuscate the source.
    #[arg(short, long)]
    pub(super) decoy: Option<Vec<String>>,
}

/// Initializes the CLI, parses arguments, and routes execution.
///
/// This function serves as the logic layer between `main.rs` and the core functionality.
/// It determines whether to simply list network interfaces or initialize the `Scanner`.
pub(super) fn init() {
    let c = Cli::parse();

    // If the user requested to list interfaces, print them and exit.
    if c.interfaces {
        print_interfaces();
        return;
    }

    // Initialize the Scanner.
    // We can safely unwrap `scanner_args` here because `clap` ensures that if
    // `interfaces` (the conflicting argument) is false, the `ScannerArgs` group
    // requirements must have been met.
    let s = Scanner::new(c.scanner_args.unwrap());
    s.scan();
}