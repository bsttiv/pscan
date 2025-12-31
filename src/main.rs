//! Entry point for the application.
//!
//! This file registers the internal modules and initializes the
//! command-line interface execution flow.

// 'cli' handles arguments and user interaction.
mod cli;
// likely contains the core logic for port scanning/networking.
mod scanner;

use cli::init;

/// The main entry point of the binary.
///
/// This function delegates the execution logic to the CLI module
/// by calling `init()`.
fn main() {
    init();
}