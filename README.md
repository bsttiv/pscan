<a href="https://crates.io/crates/pscan"><img src="https://img.shields.io/crates/v/pscan?style=for-the-badge&logo=rust&color=orange" /></a>
<a href="https://docs.rs/pscan/latest/pscan/">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=for-the-badge&logo=rust&color=blue"
      alt="docs.rs docs" />
</a>

# PScan - Port Scanner written in Rust

PScan is a Rust SYN Port Scanner. More specifically, it uses the *[SYN Port Scanning](https://en.wikipedia.org/wiki/Port_scanner#SYN_scanning)* technique to probe a server for open ports.

Pscan also includes the Decoy spoofing option (like the [Nmap](https://nmap.org) option). I am also planning to implement Banner Scanning.

# Disclaimer

I wrote this program as a personal project merely for educational purposes. For professional objectives, prefer other tools such as the well known [Nmap](https://nmap.org) or
[Armada](https://github.com/resyncgg/armada) (also written in Rust).

# Usage

First, to install pscan, run 

```shell
foo@bar:~$ cargo install pscan
```

Then, you must give CAP_NET_RAW Linux capability to pscan binary:

```shell
foo@bar:~$ sudo setcap 'cap_net_raw+ep' /path/to/pscan
```

Then, check the help flag to see all the options

```shell
foo@bar:~$ pscan -h
SYN Port Scanner written in Rust, with range and decoy scanning support.

Usage: pscan [OPTIONS] --target <TARGET> --port <PORT> --interface <INTERFACE>

Options:
  -t, --target <TARGET>
  -p, --port <PORT>
  -i, --interface <INTERFACE>
  -d, --decoy <DECOY>
      --interfaces
  -h, --help                   Print help
  -V, --version                Print version
```

Want to see the interfaces you can use for port scanning?

```shell
foo@bar:~$ pscan --interfaces
- Interface name: lo | Interface MAC: 00:00:00:00:00:00 | Interface IPs: 127.0.0.1
- ...
```
Then you can scan a target ip (example 0.0.0.0) for open ports (range 1-443) with your interface (lets say eth0) like this:

```shell
foo@bar:~$ pscan -t 0.0.0.0 -p 1-443 -i eth0
Open port: 0.0.0.0:80
```

# TODO

- Better error handling
- Maybe sending the RST request back after a SYN + ACK response
- Complete the decoy implementation
- Optimize the timeout for each request
- Make the program end (LOL)

# References
- [TCP/IP packets - inc 0x0](https://inc0x0.com/tcp-ip-packets-introduction/)
- [What is a Port Scan? - Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-a-port-scan)
- [Firewall/IDS Evasion and Spoofing - Nmap](https://nmap.org/book/man-bypass-firewalls-ids.html)
