pub(crate) mod utils;

use std::{net::Ipv4Addr, str::FromStr};

use crate::scanner::Scanner;

use self::utils::{IntOrRange, valid_interface, valid_target_ip, print_interfaces};

use clap::{Parser, Args};
use pnet::datalink::{NetworkInterface};



#[derive(Parser)]
#[command(name="PScan")]
#[command(version, about)]
pub(super) struct Cli{
    #[command(flatten)]
    pub(super) scanner_args: Option<ScannerArgs>,

    #[arg(long, conflicts_with="scanner_args")]
    pub(super) interfaces: bool
}

#[derive(Args)]
#[group(requires_all=&["target", "port", "interface"], multiple=true, id="scanner_args")]
pub(super) struct ScannerArgs{
    #[arg(short, long, value_parser=valid_target_ip)]
    pub(super) target: Ipv4Addr,
    #[arg(short, long, value_parser=IntOrRange::from_str)]
    pub(super) port: IntOrRange,
    #[arg(short,long, value_parser=valid_interface)]
    pub(super) interface: NetworkInterface,
    #[arg(short, long)]
    pub(super) decoy: Option<Vec<String>>
}

pub(super) fn init(){
    let c = Cli::parse();
    if c.interfaces{
        print_interfaces();
        return
    }
    let _ = Scanner::new(c.scanner_args.unwrap());
}