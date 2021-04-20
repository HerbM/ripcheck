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
use std::time::Duration;  //, Instant};
use ipnet::*;
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
///   Add Port RANGES EASY:::::
///   Reverse DNS??
///   Find more host names ? With credentials?
///   Add Delay per host, per probe??
///   Add index option, and maybe sorting???
///   Add symbolic names for ports or protocols? Maybe groups like WinTest, LinuxTest, WebServer
///   Filtering options? Only with open ports?
///   Arp scan and network card manufacturers????
///     MAC Vendor list: https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4
///   FQDN specific DNS server lists?
///   Congiguration files?  Or syntax in input files?
///   Read CSV and structured STDIN
///   Use threads intelligently for large inputs
///   Use output structure and create an output controller
///   Use struct for CheckConfig and Target
///   Add support for Ping, and maybe DNS, HTTP/S, email/SMTP, WinRM??? server checks etc checks
///      Maybe other protocols or even some UDP (only does TCP now) Arp???
///   Continuous monitor and interval, maybe alerts... run programs on UP status change?
///   Fix todo items below...
///     IpNet = "10.0.0.0/30".parse().unwrap();
///     valid_range regex wrong: technically IPv4-IPv6 will match
///     Fix DNS it's not timing out appropriately
///     Multi-thread DNS
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

/* TODO:
/// https://docs.rs/ipnet/2.3.0/ipnet/struct.Ipv4AddrRange.html
/// https://docs.rs/ipnet/2.3.0/ipnet/enum.IpNet.html
let net: IpNet = "10.0.0.0/30".parse().unwrap();  # Asserts in notes_main
let net: IpNet = "fd00::/126".parse().unwrap();
*/
fn get_nethosts(cidr_string: &str) -> Option<IpAddrRange> {
  let net:Result<IpNet,_> = cidr_string.parse();
  match net {
    Ok(net) => Some(net.hosts().into_iter()),
    _ => None,
  }
}

lazy_static!{static ref VALID_PORTS: Regex = Regex::new(
  r"^(\d{1,5}(([-,;]\d{1,5})?))$"
).unwrap();}
lazy_static!{static ref SPLIT_PORTS: Regex = Regex::new(
  r"[-,;]+"
).unwrap();}

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
  showheader: bool,
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
    (@arg TARGETS:                                ...                                          "Query targets")
    (@arg HOST:    -e -a --host  {valid_hostname} ... +takes_value                             "Query names or addresses" )
    (@arg RANGE:      -r --range {valid_range}    ... +takes_value                             "Query Addresse ranges"   )
    (@arg CIDR:    --net --cidr  {valid_cidr}     ... +takes_value                             "Query network ranges"   )
    (@arg FILENAME:   -f --filename    --path         +takes_value                             "Read targets from file(s)")
    (@arg PORT:       -p --port  {valid_port}     ... +takes_value default_value(DEFAULTPORT)  "Ports to test"            )
    (@arg TIMEOUT: -w -t --timeout     --wait         +takes_value default_value(WAIT)         "Timeout: seconds or milliseconds")
    (@arg NAMESERVER: -n --nameserver  --dns      ... +takes_value                             "Nameservers to use")
    (@arg LOCALDNS:   -l --uselocalDNS --localDNS --uselocal                                   "Also try local DNS resolver")
    (@arg VERBOSE:    -v --verbose                                                             "Print verbose information")
    (@arg NOHEADER:   -o --noheader --omit                                                     "Omit header from output")
  ).get_matches()
}

lazy_static!{static ref MATCHES: clap::ArgMatches = parse_args();}

// lazy_static!{static ref DEFAULTDNSSERVERS:Vec<&'static str> = getDefaultDNSServers();}
fn main() -> io::Result<()> {
  // let MATCHES: clap::ArgMatches = parse_args();
  let out = std::process::Command::new("netsh.exe")
                    .args(&["interface", "ipv4", "show","dns"])
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
  let target = Target{..Default::default() };
  let config = CheckConfig {
    useDNSdirect:  false,
    timeout:       timeout,
    outputType:    OutputType::Table,
    dnsserverlist: dnsDefaultServers,
    testports:     vec!["80", "135","445"],
    verbose:       verbose,
    showheader:    showheader,
  };
  if true {
    println!("default target: {:#?}", target);
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
  let dnsClient: DNSClient  = dnsclient::sync::DNSClient::new(dnsServers);
  let mut hosts:Vec<String> = Vec::with_capacity(128);  // OK? Seems reasonable

  // TODO --------------------------------------------------------
  if MATCHES.is_present("TARGETS") {
    hosts.extend( MATCHES.values_of("TARGETS").unwrap().map(|s| s.to_string()));
  }

  if MATCHES.is_present("HOST") {              // TODO Make sure no weirdness in the fixed section below
    hosts.extend( MATCHES.values_of("HOST").unwrap().map(|s| s.to_string()));
  }
  // WORKING: Fix range not printing
  if verbose { println!("Line:{} {}", line!(), "MATCHES.is_present(\"RANGE\")" );}
  let mut ranges: Vec<String>   = vec![];
  if MATCHES.is_present("RANGE") {
    ranges.extend(MATCHES.values_of("RANGE").unwrap().map(|s| s.to_string()));
  }
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
  if MATCHES.is_present("CIDR") {
    for h in MATCHES.values_of("CIDR").unwrap() {
      let cidrhosts = get_nethosts(h).unwrap().map(|h| h.to_string());
      if verbose { println!("{:#?}", cidrhosts); }
      hosts.extend(cidrhosts);
    }
  }
  if MATCHES.is_present("RANGE") {
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
  let port_names = ports.join(" \tPort");
  // let all_fail   = vec!["false"; port_count].join("\t"); // TODO: Add SomeOpen ???? column

  if verbose { println!("port_count: {}", port_count); }
  if showheader {
    println!("{:<15} {:<width$} Port{}", "IPAddress", "Host", port_names, width=hostwidth);
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
    if false  { println!("host: [{}]", host) };
    if ipAddress == "[]" {
      println!("{:<15} {:<width$}", ipAddress, host, width=hostwidth);
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

fn test_tcp_socket_address(address: &str, port: u16, timeout: Duration) -> bool {
  let socket_name = format!("{}:{}", address, port);
  if false { println!("socket_name: [{}]", socket_name) };
  match &socket_name.parse() {
    Ok(socket_addr)  => TcpStream::connect_timeout(socket_addr, timeout).is_ok(),
    _ => false
  }
}

fn test_tcp_portlist(address: &str, name: &str, ports: &Vec<String>,
                     timeout: Duration, hostwidth: usize) {
  let mut threads: Vec<std::thread::JoinHandle<bool>> = vec![];
  for port in ports.iter() {
    let ip: String = address.to_string();
    let port: u16 = port.parse().unwrap();  // TODO: Works but can simplify u16 and remove this
    threads.push(std::thread::spawn(move || -> bool { test_tcp_socket_address(&ip, port, timeout)}));
  }
  let results: Vec<bool> =
    threads.into_iter()
           .map(|t| t.join().unwrap_or(false))
           .collect();
  let result: Vec<String> = results.into_iter().map(|r| format!("{:?}", r)).collect();
  println!("{:<15} {:<width$} {}", address, name, result.join("\t"), width=hostwidth);
}

