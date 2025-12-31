//! Utility functions for CLI argument parsing and validation.
//!
//! This module contains custom parsers for port ranges, IP address validation,
//! and network interface lookup logic.

use std::{str::FromStr, net::Ipv4Addr};

use pnet::{datalink::{self, NetworkInterface}, util::MacAddr};

/// Represents the user's selection for ports to scan.
///
/// Can be either a single specific port or a range of ports.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum IntOrRange {
    /// A single port (e.g., 80).
    Int(u16),
    /// A range of ports (e.g., 1-1000).
    Range(u16, u16),
}

impl FromStr for IntOrRange {
    type Err = String;

    /// Parses a string into an `IntOrRange`.
    ///
    /// # Formats
    ///
    /// * `"80"` -> Parsed as `Int(80)`.
    /// * `"20-80"` -> Parsed as `Range(20, 80)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The format is invalid (not a number or not "start-end").
    /// * Port 0 is used.
    /// * The start of the range is greater than the end.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check if the input represents a range.
        if s.contains("-") {
            let splitted: Vec<&str> = s.split("-").collect();

            // Ensure we only have two parts: start and end.
            if splitted.len() != 2 {
                return Err("Port range must be in the START-END format".into());
            }

            // Parse the start and end values.
            let start = splitted[0].parse::<u16>().map_err(|e| {
                format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e)
            })?;
            let end = splitted[1].parse::<u16>().map_err(|e| {
                format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e)
            })?;

            // Validate logical constraints for a port range.
            if start == 0 {
                return Err("Range cannot start with port 0".into());
            }
            if start > end {
                return Err("START cannot be greater than END".into());
            }

            Ok(IntOrRange::Range(start, end))
        } else {
            // Attempt to parse as a single integer.
            let value = s.parse::<u16>().map_err(|e| {
                format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e)
            })?;

            if value == 0 {
                return Err("Port 0 cannot be scanned".into());
            }

            Ok(IntOrRange::Int(value))
        }
    }
}

/// Validates and parses the target IPv4 address.
///
/// # Arguments
///
/// * `s` - The string representation of the IP address.
///
/// # Returns
///
/// Returns the `Ipv4Addr` if valid, otherwise a descriptive error string.
pub(super) fn valid_target_ip(s: &str) -> Result<Ipv4Addr, String> {
    Ipv4Addr::from_str(s)
        .map_err(|e| format!("Error parsing the target ip: {}. Please input a correct IPv4 address.", e))
}

/// Validates the network interface name and retrieves the corresponding struct.
///
/// This function iterates through the system's available interfaces to find
/// one that matches the provided name.
///
/// # Arguments
///
/// * `s` - The name of the interface (e.g., "eth0", "wlan0").
///
/// # Returns
///
/// Returns the `NetworkInterface` struct if found, otherwise an error.
pub(super) fn valid_interface(s: &str) -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();
    interfaces
        .iter()
        .find(|i| i.name == s)
        .ok_or(format!("No such interface: {}", s))
        .cloned()
}

/// Prints a list of all available network interfaces to stdout.
///
/// Displays the interface name, MAC address (if available), and assigned IP addresses.
/// This is used when the `--interfaces` flag is passed to the CLI.
pub(super) fn print_interfaces() {
    let interfaces = datalink::interfaces();
    for interface in interfaces {
        // Format IPs as a comma-separated string.
        let ips = interface.ips.iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        // Handle cases where an interface might not have a MAC address.
        let mac = interface.mac.unwrap_or(MacAddr::zero());

        println!(
            "- Interface name: {} | Interface MAC: {:?} | Interface IPs: {}",
            interface.name, mac, ips
        );
    }
}