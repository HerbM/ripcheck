#![allow(non_snake_case)]
// #![allow(unreachable_code)]
// #![feature(async_closure)]
// #![feature(rustc_private)]
#[macro_use]
extern crate lazy_static;

use regex::Regex;
use clap::{clap_app, crate_authors, crate_version, crate_description};
//use clap_generate::{generate, generators::*};
use std::net::*;
use std::env;
use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::collections::VecDeque;
use std::time::Duration;  //, Instant};
use ipnet::*;
use dnsclient::sync::*;
// use std::process::Command;
// use std::io::Command;
mod mactovendors;

//  TODO  Learn to do Git Merge etc.
/// DONE: read from file is broken??? Worked for me? Probably due to param parsing & fixed.
/// should show help for bad input -- later
/// DONE: fix alignment -- done, more testing
/// DONE: multithreaded DNS fully -- needs cleanup/simplification
/// indexing -- easy
/// fix command line parsing to make it easier - need decision
///   remove all params for targets and ports, parse for these
///   leave switches, filenames?, and DNS addresses

//  DONE  Review Panic with no range -- should be fixed, skipping RANGE if not present in ARGS
//  FIXME IPv6 basic parsing and checking
//  FIXME Find and fix error possibilities
///   Review section for combinations of command line, STDIN, and File input
/// DONE: Output CSV etc
/// DONE:  Add Port RANGES EASY:::::
/// DONE: Reverse DNS, but slow and needs testing
///   Find more host names ? With credentials?
///   Add Delay per host, per probe??
///   Add index option, to allow sorting
///   Add symbolic names for ports or protocols? Maybe groups like WinTest, LinuxTest, WebServer
///   Filtering options? Only with open ports?
///  DONE: Arp scan and
///     Add network card manufacturers???? Started, but might be hard /24 /28 /36
///     MAC Vendor list: https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4
///     Invoke-WebRequest -Uri "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf" -OutFile nicmanuf.txt

///   FQDN specific DNS server lists?
///   Configuration files?  Or syntax in input files?
///   Read CSV and structured STDIN
///   DONE: Use threads intelligently for large inputs; might need further improvement
///   Use output structure and create an output controller
///   Use struct for CheckConfig and Target, started but needs work
///   Add support for Ping, and maybe DNS, HTTP/S, email/SMTP, WinRM??? server checks etc checks
///      Maybe other protocols or even some UDP (only does TCP now)
///   Continuous monitor and interval, maybe alerts... run programs on UP status change?
///   Fix todo items below...
///     IpNet = "10.0.0.0/30".parse().unwrap();
///     valid_range regex wrong: technically IPv4-IPv6 will match
///     DONE? Fix DNS it's not timing out appropriately
///     DONE: Multi-thread DNS
/*
Why do we need a queue?
When “what” displays information about a network address, it would ideally like to display an “easier on the eyes” hostname rather than an IP address (eg. “dns.google” instead of “8.8.8.8”). To do this, it uses libc’s getnameinfo function.
http://m4rw3r.github.io/rust/std/collections/
https://locka99.gitbooks.io/a-guide-to-porting-c-to-rust/content/features_of_rust/collections.html
https://www.poor.dev/posts/what-job-queue/
*/

pub const STDIN_FILENO: i32 = 0;
static DEFAULTDNSSERVERS: [&'static str; 2] = ["103.86.99.99", "103.86.96.96"];
fn get_dnsserver() -> [&'static str; 2] { DEFAULTDNSSERVERS }
fn piped_input() -> bool { unsafe { libc::isatty(STDIN_FILENO as i32) == 0 } }

fn get_nethosts(cidr_string: &str) -> Option<IpAddrRange> {
  let net:Result<IpNet,_> = cidr_string.parse();
  match net {
    Ok(net) => Some(net.hosts().into_iter()),
    _ => None,
  }
}

lazy_static!{ static ref VALID_PORTS: Regex = Regex::new(r"^(\d{1,5}(([-,;]\d{1,5})?))$").unwrap(); }
lazy_static!{ static ref SPLIT_PORTS: Regex = Regex::new(r"[-,;]+").unwrap(); }

fn valid_port(portname: &str) -> Result<(), String> {
  for port in SPLIT_PORTS.split(portname) {
    if false { println!("port: {}", port); }
    match port.parse::<u16>().unwrap_or(0) {
      p if p != 0 => (),
      _ => return Err(String::from(format!("Port value <{}> from arg <portname> is invalid.", portname)))
    }
  }
  Ok(())
}

lazy_static!{static ref VALIDATE_IP: Regex = Regex::new(
  r"((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))"
).unwrap();}
lazy_static!{static ref VALIDATE_IP_RANGE: Regex = Regex::new(
  r"^((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))-((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))$"
).unwrap();}
lazy_static!{static ref RE: Regex = Regex::new(r"^\D").unwrap();}
lazy_static!{static ref MACADDRESS: Regex = Regex::new(r"\b(?im:(([\da-f]{2}-){5}[\da-f]{2}))\b").unwrap();}

fn valid_hostname(ipstring: &str) -> Result<(), String> {
  if RE.is_match(ipstring) {
    Ok(())
  } else {
    match std::net::IpAddr::from_str(ipstring) {
      Ok(_ip) => Ok(()),
      _ => Err(String::from(format!("Host name or address is invalid: [{}]", ipstring)))
    }
  }
}

fn parse_range(range: &str) -> Vec<String> {
  let mut v = Vec::new();
  let rs = range.split('-');
  for r in rs {
    v.push(format!("{}", r));
  }
  v
}

fn valid_range(range: &str) -> Result<(), String> {   // TODO regex wrong: technically IPv4-IPv6 will match
  match VALIDATE_IP_RANGE.is_match(range) {
    true  => Ok(()),
    false => Err("IP Range is invalid".to_string()),
  }
}

fn valid_cidr(cidr: &str) -> Result<(), String> {
  match cidr.len() > 0 {
    true  => Ok(()),
    false => Err("IP Net is invalid".to_string()),
  }
}

fn open_bufreader<P>(filename: P) -> io::Result<io::BufReader<File>>
where P: AsRef<Path>, {
  let file = File::open(filename)?;
  Ok(io::BufReader::new(file))
}

fn _ipAddr_to_u128(ipaddress: IpAddr) -> u128 {
  match ipaddress {
    IpAddr::V4(ip) => ip.octets().iter().fold(0,|acc, oct| acc << 8 + *oct as u128),
    IpAddr::V6(ip) => ip.octets().iter().fold(0,|acc, oct| acc << 8 + *oct as u128),
  }
}

fn _ipv6Addr_to_u128(ipaddress: Ipv6Addr) -> u128 {
  ipaddress.octets().iter().fold(0,|acc, oct| acc << 8 + *oct as u128)
}

fn _ipv4Addr_to_u32(ipaddress: Ipv4Addr) -> u32 {
  ipaddress.octets().iter().fold(0,|acc, oct| acc << 8 + *oct as u32)
}

#[derive(Debug)]
enum OutputType {
  Table,
  _CSV,
  _Json,
  _XML,
}

#[derive(Debug)]
struct CheckConfig<'a> {
  useDNSdirect: bool,
  timeout: Duration,
  outputType: OutputType,
  dnsserverlist: Vec<&'a str>,
  testports:  Vec<&'a str>,
  verbose:    bool,
  csvOutput:  bool,
  showheader: bool,
  reverse:    bool,
  vendor:     bool,
}

impl<'a> Default for CheckConfig<'a> {
  fn default() -> CheckConfig<'a> {
    CheckConfig {
      useDNSdirect:  false,
      timeout:       Duration::new(3, 0),
      outputType:    OutputType::Table,
      dnsserverlist: vec![],
      testports:     vec!["80", "135","445"],  //    .to_string()
      verbose:       false,
      csvOutput:     false,
      showheader:    true,
      reverse:       false,
      vendor:        false,
    }
  }
}

#[derive(Debug)]
struct Target {
  hostname    : String,
  ipaddress   : String,
  socketaddrs : std::vec::IntoIter<SocketAddr>,
  reachable   : Vec<bool>,
}

impl Default for Target {
  fn default() -> Target {
    let host: &str     = "localhost";
    let socket: String = format!("localhost:135");
    Target {
      hostname    : host.to_string(),
      ipaddress   : "127.0.0.3".to_string(),
      socketaddrs : socket.to_socket_addrs().unwrap(),
      reachable   : Vec::with_capacity(5),
    }
  }
}

fn get_timeout(wait: u64) -> Duration {
  let scale:       u64  = if wait < 100 { 1 } else { 1000 }; // must be in seconds & nanoseconds
  let seconds:     u64  = wait / scale;
  let nanoseconds: u32  = wait as u32 % scale as u32 * 1000000;
  if false { println!("sec: {} ns: {}", seconds, nanoseconds); }
  Duration::new(seconds, nanoseconds)
}

fn hostname_to_ipaddress(hostname: &str) -> std::vec::IntoIter<std::net::SocketAddr> {
  // let empty = Vec::new().into_iter();
  // (format!("{}:0", hostname)).to_socket_addrs().unwrap()  /// .or_else(empty)
  match (format!("{}:0", hostname)).to_socket_addrs() {
    Ok(sa) => sa,
    _ => "0.0.0.0:0".to_socket_addrs().unwrap(),
  }
}

fn parse_args() -> clap::ArgMatches {
  #[cfg(windows)]
  if false { println!("{:?}", std::env::args()); }
  const DEFAULTPORT: &str = "135";
  #[cfg(not(windows))]
  const DEFAULTPORT: &str = "22";
  const _LOCALHOST: &str  = "127.0.0.1";  // TODO: Fix or remove eventually, maybe static
  const WAIT:&str = "4000";
  clap_app!(ripcheck =>
    (version : crate_version!())
    (author  : crate_authors!("\n"))
    (about   : crate_description!() )                    // FIXME default_value(LOCALHOST)
    (@arg TARGETS:                                ...                                         "Query targets"                   )
    (@arg HOST:    -e -a --host  {valid_hostname} ... +takes_value                            "Query names or addresses"        )
    (@arg RANGE:      -r --range  {valid_range}   ... +takes_value                            "Query Address ranges"            )
    (@arg CIDR:   -N --net --cidr {valid_cidr}    ... +takes_value                            "Query network ranges"            )
    (@arg FILENAME:   -f --filename    --path         +takes_value                            "Read targets from file(s)"       )
    (@arg PORT:       -p --port   {valid_port}    ... +takes_value default_value(DEFAULTPORT) "Ports to test"                   )
    (@arg MAXTHREADS: -m --maxthreads                 +takes_value default_value("4000")      "Maximum thread count"            )
    (@arg DRAIN:      -d --drain                      +takes_value default_value("0")         "Drain threads to N%"             )
    (@arg TIMEOUT: -w -t --timeout     --wait         +takes_value default_value(WAIT)        "Timeout: seconds or milliseconds")
    (@arg NAMESERVER: -n --nameserver  --dns      ... +takes_value                            "Nameservers to use"              )
    (@arg ARP:        -A --arp                                                                "ARP to resolve MAC address"      )
    (@arg REVERSE:    -R --reverse                                                            "Reverse IP to name"      )
    (@arg VENDOR:     -M --vendor                                                             "Show NIC vendor"      )
    (@arg LOCALDNS:   -l --uselocalDNS --localDNS --uselocal                                  "Also try local DNS resolver"     )
    (@arg VERBOSE:    -v --verbose                                                            "Print verbose information"       )
    (@arg CSVOUT:     -s --csv --csvout                                                       "Output CSV results"              )
    (@arg NOHEADER:   -o --noheader --omit                                                    "Omit header from output"         )
  ).get_matches()
}

lazy_static!{static ref MATCHES: clap::ArgMatches = parse_args();}

fn arp_for_MAC(ipaddress: &str) -> String {
  let arpcmd = "arp.exe";
  let out = std::process::Command::new(arpcmd)
                    .args(&[ipaddress])
                    .output().expect("Couldn't run arp");
  let _out = format!("{:?}", out);
  let out = std::process::Command::new(arpcmd)
                    .args(&["-a", ipaddress])
                    .output().expect("Couldn't run arp -a");
  let out = format!("{:?}", out);
  if false { println!("arp output: {}", out) };
  let mut captures =  MACADDRESS.captures_iter(&out);
  match captures.next() {
    Some(cap) => cap[1].to_string(),
    _ => "".to_string(),
  }
}

// lazy_static!{static ref DEFAULTDNSSERVERS:Vec<&'static str> = getDefaultDNSServers();}
fn main() -> io::Result<()> {
  // let MATCHES: clap::ArgMatches = parse_args();
  let out = std::process::Command::new("netsh.exe")
                    .args(&["interface", "ipv4", "show","dns"])
                    .output().expect("Couldn't run netsh");
  let out = format!("{:?}", out);
  let separator = Regex::new(r"[^.\d]|[\r\n]+").unwrap();
  let dnsDefaultServers: Vec<_> = separator.split(&out).into_iter().filter(|s| s.len() > 6).collect();
  let arp:         bool = MATCHES.is_present("ARP" );
  let verbose:     bool = MATCHES.is_present("VERBOSE" );
  let csvOutput:   bool = MATCHES.is_present("CSVOUT"  );
  let showheader:  bool =!MATCHES.is_present("NOHEADER");
  let from_file:   bool = MATCHES.is_present("FILENAME");
  let uselocalDNS: bool = MATCHES.is_present("LOCALDNS");
  let reverse:     bool = MATCHES.is_present("REVERSE");
  let vendor:      bool = MATCHES.is_present("VENDOR");
  let MAXTHREADS: usize = match MATCHES.value_of ("MAXTHREADS").unwrap().parse::<usize>().unwrap_or(1024) {
    max if max == 0 => usize::MAX,
    max             => max,
  };
  let drain:      usize = MATCHES.value_of ("DRAIN").unwrap().parse::<usize>().unwrap_or(0);
  let timeout: Duration = get_timeout(MATCHES.value_of ("TIMEOUT").unwrap().parse::<u64>().unwrap_or(4000));
  if verbose { println!("Duration: {:?}", timeout); }
  let config = CheckConfig {
    useDNSdirect:  false,
    timeout,
    outputType:    OutputType::Table,
    dnsserverlist: dnsDefaultServers,
    testports:     vec!["80", "135","445"],
    verbose,
    showheader,
    csvOutput,
    reverse,
    vendor ,
  };
  if false {
    println!("default config: {:#?}", config);
  }
  fn get_portnumbers(portarg:&str) -> Vec<String> {   //
    let mut range = SPLIT_PORTS.splitn(portarg, 2);// {
    let start: u32 = range.next().unwrap().parse().unwrap();
    match range.next() {
      None => vec![start.to_string()],  // return single value as Vec<u16>
      Some(s) => {
        let end: u32 = s.parse::<u32>().unwrap();  // u32, no overflow on MAXPORT
        match start > end {                                           // count LO to HI
          true  => (end..(start+1)).map(|p| p.to_string()).collect(),
          false => (start..(end+1)).map(|p| p.to_string()).collect(),
        }
      },
    }
  }
  fn get_portlist(matches: &MATCHES) -> Vec<String> {   //
    matches.values_of("PORT")
           .unwrap()
           .flat_map(|portarg| get_portnumbers(&portarg))
           .collect()   // get the u16 values
  }
  let ports: Vec<String> = get_portlist(&MATCHES);
  if verbose {
    let testAddress =
    hostname_to_ipaddress("hamachi").filter(|a| a.is_ipv4());
    for ip in testAddress {
      println!("SocketAddr: {}", ip);
    }
  }
  // INFO: https://lib.rs/crates/pnet
  // todo:  Fix DNS it's not timing out appropriately, and it is single threaded now

  let nsAddress: Vec<String> = if MATCHES.is_present("NAMESERVER") {
    MATCHES.values_of("NAMESERVER").unwrap().map(|s| s.to_string()).collect()
  } else if config.dnsserverlist.len() > 0 {
    config.dnsserverlist.iter().map(|s| s.to_string()).collect()
  } else {
    get_dnsserver().iter().map(|s| s.to_string()).collect()
  };
  if verbose { for dnsServer in config.dnsserverlist { println!("{}", dnsServer); } }
  let nsSocket: Vec<SocketAddr> =
    nsAddress.iter().filter_map(|ns| format!("{}:53", ns).parse::<SocketAddr>().ok()).collect();
  let dnsServers =
    nsSocket.iter().map(|ns| dnsclient::UpstreamServer::new(*ns)).collect();
  let dnsClient: DNSClient  = DNSClient::new(dnsServers);
  let mut hosts:Vec<String> = Vec::with_capacity(128);  // OK? Seems reasonable

  // TODO --------------------------------------------------------
  if MATCHES.is_present("TARGETS") {
    hosts.extend( MATCHES.values_of("TARGETS").unwrap().map(|s| s.to_string()));
  }
  if MATCHES.is_present("HOST") {              // TODO Make sure no weirdness in the fixed section below
    hosts.extend( MATCHES.values_of("HOST").unwrap().map(|s| s.to_string()));
  }
  if verbose { println!("Line:{} {}", line!(), "MATCHES.is_present(\"RANGE\")" );}
  let mut ranges: Vec<String>   = vec![];
  if MATCHES.is_present("RANGE") {
    ranges.extend(MATCHES.values_of("RANGE").unwrap().map(|s| s.to_string()));
  }
  if verbose { println!("ranges: {:?}", ranges); }
  for r in ranges {
    let bounds: Vec<String> = parse_range(&r);
    if bounds.len() == 2 {
      let start: &String = bounds.get(0).unwrap(); // TODO: fix by adding error handling
      let end:   &String = bounds.get(1).unwrap();
      if verbose { println!("range bounds: [{:?}] [{:?}] [{:?}] [{:?}]", r, bounds, start, end); }
      let range_hosts: Vec<String> = Ipv4AddrRange::new(
        start.parse().unwrap(),  // ToDo: What happens if it doesn't Parse?
        end.parse().unwrap(),
      ).map(|ip| format!("{:?}", ip)).collect();
      hosts.extend(range_hosts);
    }
  }
  if MATCHES.is_present("CIDR") {
    for h in MATCHES.values_of("CIDR").unwrap() {
      let cidrhosts = get_nethosts(h).unwrap().map(|h| h.to_string());
      if verbose { println!("{:#?}", cidrhosts); }
      hosts.extend(cidrhosts);
    }
  }

  // TODO review next session to ensure we allow all reasonable combinations of host entry
  // if piped_input() || from_file {
    //let input: io::BufReader<_>;
    // https://doc.rust-lang.org/std/io/trait.BufRead.html

  //  WORK on threading file read
  if piped_input() {   // TODO works but only accepts host list, what if structured or CSV etc.???
    let input = io::stdin();
    let input = input.lock();
    for line in input.lines() {   // TODO: Filter on Ok() and extend???
      if let Ok(ip) = line { hosts.push(ip) }  // TODO: add warning or error handling???
    }
  }
  // NEW FILE VERSION
  /*
  let mut threads: Vec<std::thread::JoinHandle<Vec<String>> = vec![];
  if from_file {      // TODO works but only accepts host list, what if structured or CSV etc.???
    let filename = MATCHES.value_of("FILENAME").unwrap();
    threads.push(std::thread::spawn(move || {
      let hostVec: Vec<String> = Vec<String>::with_capacity(1024);
      let input = open_bufreader(filename);
      if let Ok(input) = input {
        for line in input.lines() {
          if let Ok(ip) = line { hostVec.push(ip) }
        }
      }
    }));
  }
  */
  // if (files = files(&args);
  // FilesParallel) { files_parallel(&args); }

  if from_file {      // TODO works but only accepts host list, what if structured or CSV etc.???
    let filename = MATCHES.value_of("FILENAME").unwrap();
    let input = open_bufreader(filename);
    if let Ok(input) = input {
      for line in input.lines() {
        if let Ok(ip) = line { hosts.push(ip) }
      }
    }
  }

  let hostcount = hosts.len();
  let mut targets: Box<Vec<Box<Target>>> = Box::new(Vec::with_capacity(hostcount));
  let mut hostwidth = 20;
  for host in hosts {
    let ipAddress: String  = "".to_string();
    if false  { println!("host: [{}]", host) };
    if host.len() > hostwidth { hostwidth = host.len() }
    let target = Box::new(Target{
      hostname  : format!("{}", host),
      ipaddress : format!("{}", ipAddress),
      reachable : Vec::with_capacity(ports.len()),
      ..Default::default()
    });
    targets.push(target);
  }
  // let all_fail   = vec!["false"; port_count].join("\t");   // TODO: Add SomeOpen ???? column
  if showheader || csvOutput {
    // let port_count = ports.len();
    let portsref = &ports;
    let widthfactor: usize = if csvOutput { 0 }   else { 1 };
    let separator: &str    = if csvOutput { "," } else { "" };
    let mut headers: Vec<String> = Vec::with_capacity(ports.len()+8);
    headers.push(format!("{:<width$}", "IPAddress", width=widthfactor * 16));
    headers.push(format!("{:<width$}", "Hostname",  width=widthfactor * 31));  // TODO: FIX WITH HOSTWIDTH
    if arp {
      headers.push(format!("{:<width$}", "MACaddress", width=19 * widthfactor));
      if vendor { headers.push(format!("{:<width$}", "MACvendor", width=10 * widthfactor)) };
    }
    for p in portsref {
      let portname = format!("Port{}", p);
      headers.push(format!("{:<width$}", portname, width=(portname.len()+1)*widthfactor));
    }
    // let header = headers.join(separator);
    println!("{}", headers.join(separator)); // , separator, portnames);
  }

  let maxthreads = MAXTHREADS / (ports.len() + 2);
  let maxthreads = if maxthreads <  1 {  1 } else { maxthreads };
  if verbose { println!("maxthreads: {}  from MAXTHREADS: {}", maxthreads, MAXTHREADS) };
  let mut threads: VecDeque<std::thread::JoinHandle<()>> = VecDeque::with_capacity(maxthreads);
  for target in targets.into_iter() {
    let portlist = ports.clone();
    let resolver = dnsClient.clone();
    // let config = &config;
    let t = target;
    threads.push_front(std::thread::spawn(move || {
      test_tcp_portlist(&t, &portlist, timeout,
        hostwidth, arp, csvOutput, showheader, verbose, &resolver,
        uselocalDNS, vendor, reverse)
    }));
    // println!("Does queue need draining? current:{} max:{}", threads.len(), maxthreads);
    if threads.len() > maxthreads {
      // println!("Draining queue: current:{} max:{}", threads.len(), maxthreads);
      while threads.len() > maxthreads * drain / 100 {
        threads.pop_back().take().map(|t| t.join()) ;
      }
      if verbose { println!("After draining: current:{} max:{}", threads.len(), maxthreads) };
    }
  }
  for t in threads { let _ = t.join(); };
  Ok({})
}

fn test_tcp_socket_address(address: &str, port: u16, timeout: Duration, verbose:bool) -> bool {
  let socket_name = format!("{}:{}", address, port);
  if verbose { println!("socket_name: [{}]", socket_name) };
  match &socket_name.parse() {
    Ok(socket_addr)  => TcpStream::connect_timeout(socket_addr, timeout).is_ok(),
    _ => false
  }
}

fn test_tcp_portlist(target: & Target, ports: &Vec<String>, timeout: Duration,
                      hostwidth: usize, arp:bool, csvOutput:bool, header:bool, verbose:bool,
                      dnsclient: &DNSClient, uselocalDNS: bool, vendor: bool, reverse: bool) {
  // let address: &str = &target.ipaddress;
  let name: &str = &target.hostname;
  let mut threads: Vec<std::thread::JoinHandle<bool>> = vec![];
  if verbose {
    let test = "142.250.68.164";
    let ip: std::net::IpAddr = test.parse().unwrap();
    let testname = dns_lookup::lookup_addr(&ip).unwrap();
    // https://docs.rs/dns-lookup/1.0.6/dns_lookup/
    println!("Reverse: {:#?}", testname);
  }
  let address: String  = match name.as_bytes()[0].is_ascii_digit() {
    true  => String::from(name),
    false => match dnsclient.query_a(&name) {   // TODO improve DNS & multithreading
      Ok(ipaddr) if ipaddr.len() > 0 => {    // found at least 1 ip
        let ip = ipaddr[0].to_string();
        if verbose { println!("ip: {} ipaddr.len {} {:?}", ip, ipaddr.len(), ipaddr)};
        String::from(ip)
      },
      _ if uselocalDNS => {
        let hostVec: Vec<String> = hostname_to_ipaddress(&name)
          .filter(|a| a.is_ipv4())
          .map(|ip| ip.to_string()).collect();
        match hostVec.get(0) {
          Some(ip) => ip.to_string().replace(":0", "").replace("0.0.0.0", ""),
          _  => "".to_string(),
        }
      },
      _ => "".to_string(),
    }
  };

  let reversethread: Option<std::thread::JoinHandle<String>> =
    if reverse && name.as_bytes()[0].is_ascii_digit() {
      let ip = name.parse().unwrap();
      Some(std::thread::spawn(move || -> String {
        dns_lookup::lookup_addr(&ip).unwrap()
      }))
    } else { None };
  for port in ports.iter() {
    let ip: String = address.to_string();
    let port: u16 = port.parse().unwrap();  // TODO: Works but can simplify u16 and remove this
    threads.push(std::thread::spawn(move || -> bool {
      test_tcp_socket_address(&ip, port, timeout, verbose)
    }));
  }
  let widthfactor: usize = if csvOutput { 0 }   else { 1 };
  let separator: &str    = if csvOutput { "," } else { "" };
  let mut output: Vec<String> = Vec::with_capacity(ports.len()+8);
  let results: Vec<bool> =
    threads.into_iter()
            .map(|t| t.join().unwrap_or(false))
            .collect();
  let name = match reversethread {
    Some(t) => t.join().unwrap(),
    _ => name.to_string(),
  };
  output.push(format!("{:<width$}", address, width=widthfactor * 16));
  output.push(format!("{:<width$}", name,    width=widthfactor * 31));
  if arp {
    let mac = arp_for_MAC(&address);
    output.push(format!("{:<width$}", mac, width=19 * widthfactor));
    if vendor {
      output.push(format!("{:<width$}", mactovendors::mac_to_vendor(&mac), width=10*widthfactor))
    };
  }
  let mut r = results.iter();
  for p in ports {
    let portname = format!("Port{}", p);
    let namelength = portname.len();
    let w = if header { namelength + 1 }  else { 6 };
    output.push(format!("{:<width$}", r.next().unwrap(), width= w * widthfactor));
  }
  println!("{}", output.join(separator));
}
