#![allow(non_snake_case)]
// #![allow(unreachable_code)]
// #![feature(async_closure)]
// #![feature(rustc_private)]
#[macro_use] extern crate lazy_static;

use regex::Regex;
use clap::{clap_app, crate_authors, crate_version, crate_description};
use std::net::*;
use std::env;
use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;  //, Instant};
use ipnet::Ipv4AddrRange;
use dnsclient::sync::*;
// use std::process::Command;
// use std::io::Command;

/// TODO  Learn to do Git Merge etc.

/// Working version with ranges, TODO:
///   TODO  Review Panic with no range -- should be fixed, skipping RANGE if not present in ARGS
///   FIXME IPv6 basic parsing and checking
///   FIXME Find and fix error possibilities
///   Review section for combinations of command line, STDIN, and File input
///   Output CSV etc
///   Add index option, and maybe sorting???
///   Filtering options? Only with open ports?
///   FQDN specific DNS server lists?
///   Congiguration files?  Or syntax in input files?
///   Read CSV and structured STDIN
///   Use threads intelligently for large inputs
///   Use output structure and create an output controller
///   Use struct for CheckConfig and Target
///   Add support for Ping, and maybe DNS, HTTP/S, email/SMTP, WinRM??? server checks etc checks
///      Maybe other protocols or even some UDP (only does TCP now) Arp???
///   Fix todo items below...
///     IpNet = "10.0.0.0/30".parse().unwrap();
///     valid_range regex wrong: technically IPv4-IPv6 will match
///     Fix DNS it's not timing out appropriately
///     Multi-thread DNS

/* DONE: 
config
  read the hosts
    queue hosts for conversion
  convert the hosts  -- when finished we'll know maxwidth
    queue hosts for testing
  test host
    test ports
    queue results for output
  output results     -- can't start until maxwidth is ready
finish

*/

pub const STDIN_FILENO: i32 = 0;
static DEFAULTDNSSERVERS: [&'static str; 2] = ["103.86.99.99", "103.86.96.96"];
fn get_dnsserver() -> [&'static str; 2] { DEFAULTDNSSERVERS }
fn piped_input() -> bool { unsafe { libc::isatty(STDIN_FILENO as i32) == 0 } }

/* TODO:
/// https://docs.rs/ipnet/2.3.0/ipnet/struct.Ipv4AddrRange.html 
/// https://docs.rs/ipnet/2.3.0/ipnet/enum.IpNet.html 
let net: IpNet = "10.0.0.0/30".parse().unwrap();
assert_eq!(net.hosts().collect::<Vec<IpAddr>>(), vec![
    "10.0.0.1".parse::<IpAddr>().unwrap(),
    "10.0.0.2".parse().unwrap(),
]);

let net: IpNet = "fd00::/126".parse().unwrap();
assert_eq!(net.hosts().collect::<Vec<IpAddr>>(), vec![
    "fd00::".parse::<IpAddr>().unwrap(),
    "fd00::1".parse().unwrap(),
    "fd00::2".parse().unwrap(),
    "fd00::3".parse().unwrap(),
]);

*/

fn valid_port(portname: &str) -> Result<(), String> {
  match portname.parse::<u16>().unwrap_or(0) {
    p if p != 0 => Ok(()),
    _ => Err(String::from(format!("Port <{}> is invalid.", portname)))
  }
}

lazy_static!{static ref VALIDATE_IP: Regex = Regex::new(
  r"((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))"
).unwrap();}
lazy_static!{static ref VALIDATE_IP_RANGE: Regex = Regex::new(
  r"^((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))-((\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*)|(\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*))$"
).unwrap();}

lazy_static!{static ref RE: Regex = Regex::new(r"^\D").unwrap();}
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

fn parse_args() -> clap::ArgMatches {
  #[cfg(windows)]
  println!("{:?}", std::env::args());
  const DEFAULTPORT: &str = "135";
  #[cfg(not(windows))]
  const DEFAULTPORT: &str = "22";
  const _LOCALHOST: &str  = "127.0.0.1";  // TODO: Fix or remove eventually, maybe static
  const WAIT:&str = "4000";
  clap_app!(myapp =>
    (version : crate_version!())
    (author  : crate_authors!("\n"))
    (about   : crate_description!() )                    // FIXME default_value(LOCALHOST)    
    (@arg HOST:    -a -c --host {valid_hostname} ... +takes_value                            "Computers to test" )
    (@arg PORT:       -p --port {valid_port}     ... +takes_value default_value(DEFAULTPORT) "Ports to test"     )
    (@arg TIMEOUT: -w -t --timeout    --wait         +takes_value default_value(WAIT)        "Timeout: seconds or milliseconds")
    (@arg FILENAME:   -f --filename   --path         +takes_value                            "Read targets from file(s)")
    (@arg RANGE:      -r --range {valid_range}   ... +takes_value                            "Query Address range")
    (@arg NAMESERVER: -n --nameserver --dns      ... +takes_value                            "Nameservers to use")
    (@arg LOCALDNS:   -l --localDNS --uselocalDNS --uselocal                                 "Also try local DNS resolver")
    (@arg VERBOSE:    -v --verbose                                                           "Print verbose information")
    (@arg NOHEADER:   -o --noheader --o                                                      "Omit header from output")
  ).get_matches()
}

fn open_bufreader<P>(filename: P) -> io::Result<io::BufReader<File>>
where P: AsRef<Path>, {
  let file = File::open(filename)?;
  Ok(io::BufReader::new(file))
}

// lazy_static!{
//   static ref dns4servers:  = std::process::Command::new("netsh.exe")
//                         .args(&["interface", "ipv4", "show","dns"])
//                         .output()
//                         .expect("failed to execute process");
// }

// Get DNS Server on Windows
// (netsh inter ip show dns *>&1 | sls "(configured.*|^\s+)\d+") -replace '^(.*:)?\s+([\d.]+$)','$2'
// (netsh inter ip show dns *>&1 | ? Length -gt 0).trim() -match '(\d+\.){3}\d+$' -replace '^.*:\s+'
// ???    IPv6 ????   '^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$'
// My attempt:  (netsh inter ipv6 show address *>&1) -match '(\d{0,8}:){1,7}(\d{1,7})'
// (netsh inter ipv6 show dns *>&1).trim() -match '(\d{0,8}:){1,7}(\d{1,7})' -replace '^\w.*:\s+' | Sort -uniq

// fn getDefaultDNSServers() -> Vec<&'static str> {
//   let out = std::process::Command::new("netsh.exe").args(&["interface", "ipv4", "show","dns"])
//                                   .output().expect("Couldn't run netsh");
//   let outstring = format!("{:?}", out);
//   let separator = Regex::new(r"[^.\d]|[\r\n]+").expect("Invalid regex");
//   let dnsDefaultServers: Vec<_> = separator.split(&outstring).into_iter().filter(|s| s.len() > 6).collect();
//   dnsDefaultServers
// }

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
struct CheckConfig {
  useDNSdirect: bool,
  timeout: Duration,
  outputType: OutputType,
  dnsserverlist: Vec<String>,
  testports:  Vec<String>,
  verbose:    bool,
  showheader: bool,
}

impl Default for CheckConfig {
  fn default() -> CheckConfig {
    CheckConfig {
      useDNSdirect:  false,
      timeout:       Duration::new(3, 0),
      outputType:    OutputType::Table,
      dnsserverlist: vec![],
      testports:     vec!["80".to_string(), "135".to_string(),"445".to_string()],
      verbose:       false,
      showheader:    true,
    }
  }
}

#[derive(Debug)]
struct Target {
  hostname: String,
  ipaddress: String,
  socketaddrs: std::vec::IntoIter<SocketAddr>,
  reachable: Vec<bool>,
}

impl Default for Target {
  fn default() -> Target {
    let host: &str     = "localhost";
    let socket: String = format!("{}:135", host);
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

lazy_static!{static ref MATCHES: clap::ArgMatches = parse_args();}
fn hostname_to_ipaddress(hostname: &str) -> std::vec::IntoIter<std::net::SocketAddr> {
  // let empty = Vec::new().into_iter();
  // (format!("{}:0", hostname)).to_socket_addrs().unwrap()  /// .or_else(empty)
  match (format!("{}:0", hostname)).to_socket_addrs() {
    Ok(sa) => sa,
    _ => "0.0.0.0:0".to_socket_addrs().unwrap(),
  }
}

// lazy_static!{static ref DEFAULTDNSSERVERS:Vec<&'static str> = getDefaultDNSServers();}
fn main() -> io::Result<()> {
  // let MATCHES: clap::ArgMatches = parse_args();
  let target = Target{..Default::default() };
  let config = CheckConfig{..Default::default() };
  if false {
    println!("default target: {:#?}", target);
    println!("default config: {:#?}", config);
  }  
  let out = std::process::Command::new("netsh.exe").args(&["interface", "ipv4", "show","dns"])
                                          .output().expect("Couldn't run netsh");
  let out = format!("{:?}", out);
  let separator = Regex::new(r"[^.\d]|[\r\n]+").unwrap();
  let dnsDefaultServers: Vec<_> = separator.split(&out).into_iter().filter(|s| s.len() > 6).collect();
  let verbose:     bool = MATCHES.is_present("VERBOSE" );
  let showheader:  bool =!MATCHES.is_present("NOHEADER");
  let from_file:   bool = MATCHES.is_present("FILENAME");
  let uselocalDNS: bool = MATCHES.is_present("LOCALDNS");
  let timeout: Duration = get_timeout(MATCHES.value_of ("TIMEOUT").unwrap().parse::<u64>().unwrap_or(4000));
  if verbose { println!("Duration: {:?}", timeout); }
  let ports: Vec<String> = MATCHES.values_of("PORT").unwrap().map(|s| s.to_string()).collect();
  if verbose {
    let testAddress = 
      hostname_to_ipaddress("hamachi").filter(|a| a.is_ipv4());
    for ip in testAddress {
      println!("SocketAddr: {}", ip); 
    }
  }

  // todo:  Fix DNS it's not timing out appropriately, and it is single threaded now
  
  let nsAddress: Vec<String> = if MATCHES.is_present("NAMESERVER") {
    MATCHES.values_of("NAMESERVER").unwrap().map(|s| s.to_string()).collect()
  } else if &dnsDefaultServers.len() > &0 {
      dnsDefaultServers.iter().map(|s| s.to_string()).collect()
  } else {
      get_dnsserver().iter().map(|s| s.to_string()).collect()
  };
  if verbose { for dnsServer in dnsDefaultServers { println!("{}", dnsServer); } }
  let nsSocket: Vec<SocketAddr> =
  nsAddress.iter().filter_map(|ns| format!("{}:53", ns).parse::<SocketAddr>().ok()).collect();
  let dnsServers =
    nsSocket.iter().map(|ns| dnsclient::UpstreamServer::new(*ns)).collect();
  let dnsClient: DNSClient  = dnsclient::sync::DNSClient::new(dnsServers);
  let mut hosts:Vec<String> = Vec::with_capacity(128);  // OK? Seems reasonable
  
  // TODO -------------------------------------------------------- 
  if MATCHES.is_present("HOST") {              // TODO Make sure no weirdness in the fixed section below
    hosts.extend( MATCHES.values_of("HOST").unwrap().map(|s| s.to_string()));
  }
  // WORKING: Fix range not printing
  if MATCHES.is_present("RANGE") {
    println!("Line:{} {}", line!(), "MATCHES.is_present(\"RANGE\")" );
    let ranges: Vec<String>   = MATCHES.values_of("RANGE").unwrap().map(|s| s.to_string()).collect();
    // FIXME With NO range panics: 'called `Option::unwrap()` on a `None` value', src\main.rs:330:58
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
    //hosts.extend(rangeHosts.iter());
    // println!("Line:{} {}", line!(), "1" );
    // if true || verbose { println!("rangeHosts: {:?}", rangeHosts); }
  }
  
  // -------------------------------------------------------- 
  
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

  // TODO Allow both of these once ranges are fixed
  if from_file {      // TODO works but only accepts host list, what if structured or CSV etc.??? 
    let filename = MATCHES.value_of("FILENAME").unwrap();
    let input = open_bufreader(filename);
    if let Ok(input) = input {
      for line in input.lines() {
        if let Ok(ip) = line { hosts.push(ip) }
      }
    }
  }
//  } 

  let mut hostwidth = 20;
  for h in hosts.iter() {
    if h.len() > hostwidth { hostwidth = h.len() }
  };
  let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
  let port_count = ports.len();
  let port_names = ports.join("  \t");
  let all_fail   = vec!["false"; port_count].join("\t");

  if verbose { println!("port_count: {} {}", port_count, all_fail); }
  if showheader {
    println!("{:<15} {:<width$} {}", "IPAddress", "Host", port_names, width=hostwidth);
  }
  for host in hosts {
    let ipAddress: String  = match host.as_bytes()[0].is_ascii_digit() {
      true  => String::from(&host),
      false => match dnsClient.query_a(&host) {   // TODO DNS needs improvement and multithreading
        Ok(ipaddr) if ipaddr.len() > 0 => {    // found at least 1 ip
          let ip = ipaddr[0].to_string();
          if verbose { println!("ip: {} ipaddr.len {} {:?}", ip, ipaddr.len(), ipaddr)};
          String::from(ip)
        },
        _ if uselocalDNS => {  
          let hostVec: Vec<String> = hostname_to_ipaddress(&host)
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
    /* 
    let hostVec: Vec<String> = hostname_to_ipaddress(&host)
      .filter(|a| a.is_ipv4())
      .map(|ip| ip.to_string()).collect();
    let ipAddress: String  = match hostVec.get(0) {
      Some(ip) => ip.to_string().replace(":0", "").replace("0.0.0.0", ""),
      _        => "".to_string(),  //for sa4 in sa {
    };
    */
    if false  { println!("host: [{}]", host) };
    if ipAddress == "[]" {
      println!("{:<15} {:<width$} {}", ipAddress, host, all_fail, width=hostwidth);
      continue;
    }
    let portlist = ports.clone();
    threads.push(std::thread::spawn(move || {
      test_tcp_portlist(&ipAddress, &host, &portlist, timeout, hostwidth)
    }));
  }
  for t in threads { let _ = t.join(); };
  Ok({})
}

fn test_tcp_socket_address(address: &str, port: &str, timeout: Duration) -> bool {
  let socket_name = format!("{}:{}", address, port);
  if false { println!("socket_name: [{}]", socket_name) };
  // let socket_addr = &socket_name.parse().expect("Unable to parse socket address");
  // TcpStream::connect_timeout(socket_addr, timeout).is_ok()
  match &socket_name.parse() {
    Ok(socket_addr)  => TcpStream::connect_timeout(socket_addr, timeout).is_ok(),
    _ => false
  }  
}

fn test_tcp_portlist(address: &str, name: &str, ports: &Vec<String>, 
                     timeout: Duration, hostwidth: usize) {
  let mut threads: Vec<std::thread::JoinHandle<bool>> = vec![];
  for port in ports.clone() {
    let ip: String = address.to_string();
    threads.push(std::thread::spawn(move || -> bool { test_tcp_socket_address(&ip, &port, timeout)}));
  }
  let results: Vec<bool> = 
    threads.into_iter()
           .map(|t| t.join().unwrap_or(false))
           .collect();
  let result: Vec<String> = results.into_iter().map(|r| format!("{:?}", r)).collect();         
  println!("{:<15} {:<width$} {}", address, name, result.join("\t"), width=hostwidth);
}

/* 
/// The top-level entry point for listing files without searching them. This
/// recursively steps through the file list (current directory by default) and
/// prints each path sequentially using a single thread.
fn files(args: &Args) -> Result<bool> {
  let quit_after_match = args.quit_after_match()?;
  let subject_builder = args.subject_builder();
  let mut matched = false;
  let mut path_printer = args.path_printer(args.stdout())?;
  for result in args.walker()? {
    let subject = match subject_builder.build_from_result(result) {
      Some(subject) => subject,
      None => continue,
      };
      matched = true;
      if quit_after_match {
        break;
      }
      if let Err(err) = path_printer.write_path(subject.path()) {
        if err.kind() == io::ErrorKind::BrokenPipe {
          break;               // A broken pipe means graceful termination.
          }
          // some other error prevents writing to stdout, propogate it
          return Err(err.into());
        }
      }
  Ok(matched)
}

/// The top-level entry point for listing files without searching them. This
/// recursively steps through the file list (current directory by default) and
/// prints each path sequentially using multiple threads.
fn files_parallel(args: &Args) -> Result<bool> {
  use std::sync::atomic::AtomicBool;
  use std::sync::atomic::Ordering::SeqCst;
  use std::sync::mpsc;
  use std::thread;
  
  let quit_after_match = args.quit_after_match()?;
  let subject_builder = args.subject_builder();
  let mut path_printer = args.path_printer(args.stdout())?;
  let matched = AtomicBool::new(false);
  let (tx, rx) = mpsc::channel::<Subject>();

  let print_thread = thread::spawn(move || -> io::Result<()> {
    for subject in rx.iter() {
      path_printer.write_path(subject.path())?;
    }
      Ok(())
    });
    args.walker_parallel()?.run(|| {
      let subject_builder = &subject_builder;
      let matched = &matched;
      let tx = tx.clone();
      
      Box::new(move |result| {
        let subject = match subject_builder.build_from_result(result) {
          Some(subject) => subject,
          None => return WalkState::Continue,
        };
        matched.store(true, SeqCst);
        if quit_after_match {
          WalkState::Quit
        } else {
          match tx.send(subject) {
            Ok(_) => WalkState::Continue,
            Err(_) => WalkState::Quit,
              }
            }
          })
        });
        drop(tx);
        if let Err(err) = print_thread.join().unwrap() {
          // A broken pipe means graceful termination, so fall through.
      // Otherwise, something bad happened while writing to stdout, so bubble
      // it up.
      if err.kind() != io::ErrorKind::BrokenPipe {
        return Err(err.into());
      }
    }
  Ok(matched.load(SeqCst))
}
*/
