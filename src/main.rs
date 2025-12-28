use std::str::FromStr;

use clap::{Parser, Args};

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum IntOrRange{
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

#[derive(Parser)]
#[command(name="PScan")]
#[command(version, about)]
struct Cli{
    #[command(flatten)]
    scanner_args: Option<ScannerArgs>,

    #[arg(long, conflicts_with="scanner_args")]
    interfaces: bool
}

#[derive(Args)]
#[group(requires_all=&["target", "port"], multiple=true, id="scanner_args")]
struct ScannerArgs{
    #[arg(short, long)]
    target: String,
    #[arg(short, long, value_parser=IntOrRange::from_str)]
    port: IntOrRange,
    #[arg(short, long)]
    decoy: Option<Vec<String>>
}

fn main(){
    let _ = Cli::parse();

}