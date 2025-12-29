use std::{str::FromStr, net::Ipv4Addr};

use pnet::datalink::{self, NetworkInterface};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum IntOrRange{
    Int(u16),
    Range(u16, u16)
}

impl FromStr for IntOrRange{
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("-"){
            let splitted:Vec<&str> = s.split("-").collect();
            if splitted.len() != 2 {return Err("Port range must be in the START-END format".into())}
            let start = splitted[0].parse::<u16>().map_err(|e|format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e))?;
            let end = splitted[1].parse::<u16>().map_err(|e|format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e))?;
            if start == 0 {return Err("Range cannot start with port 0".into())}
            if start > end {return Err("START cannot be greater than END".into())}
            Ok(IntOrRange::Range(start, end))
        } else{
            let value = s.parse::<u16>().map_err(|e|format!("Error parsing as int: {}. Usage: --port START-END | --port INT", e))?;
            if value == 0 {return Err("Port 0 cannot be scanned".into())}
            Ok(IntOrRange::Int(value))
        }
    }
}

pub(super) fn valid_target_ip(s:&str) -> Result<Ipv4Addr, String>{
    Ipv4Addr::from_str(s).map_err(|e|format!("Error parsing the target ip: {}. Please input a correct IPv4 address.", e))
}

pub(super) fn valid_interface(s:&str) -> Result<NetworkInterface, String>{
    let interfaces = datalink::interfaces();
    interfaces.iter().find(|i|i.name==s).ok_or(format!("No such interface: {}", s)).cloned()
}