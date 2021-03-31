#![allow(non_snake_case)]
#![allow(unreachable_code)]
#![feature(async_closure)]
#![feature(rustc_private)]
#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate tokio;
extern crate rand;
//extern crate dnsclient;
//use dnsclient;
use regex::Regex;
use clap::{clap_app, crate_authors, crate_version, crate_description};
use std::net::*;
//use std::time::Duration;
use std::env;
use std::io::{self, BufRead};
use std::fs::File;

use std::path::Path;
use std::str::FromStr;
use std::thread;
use std::time::Duration;  //, Instant};
use tokio::runtime;
use tokio::runtime::Runtime;
use tokio::time::*;
use futures::future::*;
use rand::*;

// use std::process::Command;
// use std::io::Command;
// use std::io::prelude::*;

pub const STDIN_FILENO: i32 = 0;
// static DEFAULTDNSSERVERS: Vec<&'static str> = vec!["103.86.99.99", "103.86.96.96"];
static DEFAULTDNSSERVERS: [&str; 2] = ["103.86.99.99", "103.86.96.96"];
// static DEFAULTDNSSERVERS: std::vec::Vec<&'static str> = ["103.86.99.99", "103.86.96.96"];
// static DEFAULTDNSSERVERS: std::vec::Vec<&'static str> = std::vec::Vec.new(["103.86.99.99", "103.86.96.96"]);
//static DEFAULTDNSSERVERS: [&str; 2] = ["103.86.99.99", "103.86.96.96"];
// fn get_dnsserver() -> [&str; 2] { DEFAULTDNSSERVERS }

fn piped_input() -> bool { unsafe { libc::isatty(STDIN_FILENO as i32) == 0 } }

fn valid_port(portname: &str) -> Result<(), String> {
  match portname.parse::<u16>().unwrap_or(0) {
    p if p != 0 => Ok(()),
    _ => Err(String::from(format!("Port <{}> is invalid.", portname)))
  }
}

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
  let rs:Vec<&str> = range.split('-').collect();
  for r in rs {
    v.push(format!("{}", r));
  }
  v
}

fn parse_args() -> clap::ArgMatches {
  #[cfg(windows)]
  const DEFAULTPORT: &str = "135";
  #[cfg(not(windows))]
  const DEFAULTPORT: &str = "22";
  const LOCALHOST: &str  = "127.0.0.1";
  const WAIT:&str = "4000";
  clap_app!(myapp =>
    (version : crate_version!())
    (author  : crate_authors!("\n"))
    (about   : crate_description!() )
    (@arg HOST:    -a -c --host {valid_hostname} ... +takes_value default_value(LOCALHOST)   "Computers to test" )
    (@arg PORT:       -p --port {valid_port}     ... +takes_value default_value(DEFAULTPORT) "Ports to test"     )
    (@arg TIMEOUT: -w -t --timeout    --wait         +takes_value default_value(WAIT)        "Timeout: seconds or milliseconds")
    (@arg FILENAME:   -f --filename   --path         +takes_value                            "Sets the input file to use")
    (@arg RANGE:      -r --range                 ... +takes_value                            "Sets input files to use")
    (@arg NAMESERVER: -n --nameserver --dns      ... +takes_value                            "Sets nameservers to use")
    (@arg VERBOSE:    -v --verbose                                                           "Print verbose information")
    (@arg NOHEADER:      --noheader                                                          "Omit header from output")
  ).get_matches()
}

fn open_bufreader<P>(filename: P) -> io::Result<io::BufReader<File>>
where P: AsRef<Path>, {
  let file = File::open(filename)?;
  Ok(io::BufReader::new(file))
}


struct _Config {
  wait:       u64,
  verbose:    bool,
  showheader: bool,
  nsAddress:  Vec<String>,
  ports:      Vec<String>,
}

/*
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



lazy_static!{static ref MATCHES: clap::ArgMatches = parse_args();}
lazy_static!{static ref RUNTIME: Runtime = runtime::Builder::new()
  .threaded_scheduler()
  .core_threads(4)
  .enable_all()
  .build()
  .unwrap();
}

async fn __test_tcp_portlist(host: &String, name: &String, portlist: &Vec<String>, wait: Duration, hostwidth: usize) {
  let mut threads: Vec<std::thread::JoinHandle<bool>> = vec![];
  for p in portlist.clone() {
    let h = host.clone();
    // task = Duration::from_millis(0)).then(async move |_| {
      // let task = delay_for(
      //   Duration::from_millis(delay)).then(async move |_| {
      //     println!("Delay {} ms done! thread name: {}", delay, thread::current().name().unwrap());
      //     Ok(true) as Result<bool, std::io::Error>
      //   }
      // );

    threads.push(std::thread::spawn(move || -> bool {
      test_tcp_socket_address(&h, &p, wait)
    }));
  }
  let length = threads.len();
  let mut results: Vec<String> = Vec::with_capacity(length); // vec![; length];
  for t in threads {
    let result = format!("{}", t.join().unwrap_or(false));
    results.push(result);
  }
  println!("{:<15} {:<width$} {}", host, name, results.join("\t"), width=hostwidth);
  // RUNTIME.shutdown_background();
}

// async fn test_tcp_portlist(host: &str) {
// async fn test_tcp_portlist(host: &String, portlist: &Vec<String>, wait: Duration, hostwidth: usize) {
    // println!("Testing {}", host);
// }
async fn test_tcp_portlist(host: &str) {
  println!("Testing {}", host);
}

// async fn _test_tcp_portlist(host: &String, name: &String, portlist: &Vec<String>, wait: Duration, hostwidth: usize) {
//   let mut tasks = vec![];  // Vec<std::thread::JoinHandle<bool>>
//   for p in portlist.clone() {
//     let h = host.clone();
//     let task = async move |_| -> bool {
//       test_tcp_socket_address(&h, &p, wait)
//     };
//     tasks.push(rt.spawn(task));
//   }
//   let length = threads.len();
//   let mut results: Vec<String> = Vec::with_capacity(length); // vec![; length];
//   for t in tasks {
//     let result = format!("{}", t.join().unwrap_or(false));
//     results.push(result);
//   }
//   println!("{:<15} {:<width$} {}", host, name, results.join("\t"), width=hostwidth);
// }

// techempower.com benchmarks      cargo add cargo whatfeatures
async fn _t() {
  let mut tasks = vec![];
  for _ in 0..100 {
    let delay = rand::thread_rng().gen_range(1000, 2000);
    let task = delay_for(
      Duration::from_millis(delay)).then(async move |_| {
        println!("Delay {} ms done! thread name: {}", delay, thread::current().name().unwrap());
        Ok(true) as Result<bool, std::io::Error>
      }
    );
    tasks.push(RUNTIME.spawn(task));
  }
  let mut success = true;
  for task in tasks {
    success = success & task.await.unwrap().unwrap_or(false);
  }
  println!("Result: {}", success);
}

// lazy_static!{static ref DEFAULTDNSSERVERS:Vec<&'static str> = getDefaultDNSServers();}
#[tokio::main]
async fn main() {  // -> io::Result<()> {
  // t().await;
  println!("returned from calling t()");
  //rt.shutdown_background();
  let cmd = std::process::Command::new("netsh.exe").args(&["interface", "ipv4", "show","dns"])
                                                   .output().expect("Couldn't run netsh");
  let out = format!("{:?}", cmd);
  let separator = Regex::new(r"[^.\d]|[\r\n]+").unwrap();
  let dnsDefaultServers: Vec<&str> = separator.split(&out)
                                              .into_iter()
                                              .filter(|s| s.len() > 6).collect();

  let verbose:    bool  = MATCHES.is_present("VERBOSE");
  let showheader: bool =!MATCHES.is_present("NOHEADER");
  let from_file:  bool = MATCHES.is_present("FILENAME");
  let mut wait:   u64  = MATCHES.value_of  ("TIMEOUT").unwrap().parse::<u64>().unwrap_or(4000);
  if wait < 100 { wait *= 1000; }   // must be in seconds & nanoseconds
  let seconds:    u64  = wait / 1000;
  let nanoseconds:u32  = wait as u32 % 1000 * 1_000_000;
  // lazy_static!{static ref timeout: Duration = Duration::new(seconds, nanoseconds); }
  let timeout = Duration::new(seconds, nanoseconds);
  // let ports: Vec<String>     = MATCHES.values_of("PORT").unwrap().map(|s| s.to_string()).collect();
  let ports: Vec<&str>     = MATCHES.values_of("PORT").unwrap().collect();
  let nsAddress: Vec<&'static str> = if MATCHES.is_present("NAMESERVER") {
    MATCHES.values_of("NAMESERVER").unwrap().collect()
  } else if &dnsDefaultServers.len() > &0 {
    dnsDefaultServers
  } else {
    vec!["103.86.99.99", "103.86.96.96"]
  };
  // let nsAddress: Vec<String> = if MATCHES.is_present("NAMESERVER") {
  //   MATCHES.values_of("NAMESERVER").unwrap().map(|s| s.to_string()).collect()
  // } else if &dnsDefaultServers.len() > &0 {
  //     dnsDefaultServers.iter().map(|s| s.to_string()).collect()
  // } else {
  //     get_dnsserver().iter().map(|s| s.to_string()).collect()
  // };
  if verbose { for dnsServer in dnsDefaultServers { println!("{}", dnsServer); } }
  let nsSocket: Vec<SocketAddr> =
  nsAddress.iter().filter_map(|ns| format!("{}:53", ns).parse::<SocketAddr>().ok()).collect();
  let dnsServers =
    nsSocket.iter().map(|ns| dnsclient::UpstreamServer::new(*ns)).collect();
  let dnsClient  = dnsclient::sync::DNSClient::new(dnsServers);
  let mut hosts:Vec<String>  = Vec::with_capacity(128);
  let _range: Vec<String>    = parse_range(MATCHES.value_of("RANGE").unwrap_or("---"));

  if piped_input() || from_file {
    //let input: io::BufReader<_>;
    // https://doc.rust-lang.org/std/io/trait.BufRead.html
    if piped_input() {
      let input = io::stdin();
      let input = input.lock();
      for line in input.lines() {
        if let Ok(ip) = line { hosts.push(ip) }
      }
    }
    if from_file {
      let filename = MATCHES.value_of("FILENAME").unwrap();
      let input = open_bufreader(filename);
      if let Ok(input) = input {
        for line in input.lines() {
          if let Ok(ip) = line { hosts.push(ip) }
        }
      }
    }
  } else {
    hosts = MATCHES.values_of("HOST").unwrap().map(|s| s.to_string()).collect();
  }
  let mut hostwidth = 20;
  for h in hosts.iter() {
    if h.len() > hostwidth { hostwidth = h.len() }
  };
  // let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
  let mut tasks    = vec![];
  let port_count = ports.len();
  let port_names = ports.join("  \t");
  let all_fail   = vec!["false"; port_count].join("\t");

  if verbose { println!("port_count: {} {}", port_count, all_fail); }
  if showheader {
    println!("{:<15} {:<width$} {}", "IPAddress", "Host", port_names, width=hostwidth);
    //repetitive_print!("IPAddress", "Host", port_names, (hostwidth=20));
  }
  for host in hosts {
    let ipAddress  = match host.as_bytes()[0].is_ascii_digit() {
      true  => String::from(&host),
      false => match dnsClient.query_a(&host) {
        Ok(ipaddr) if ipaddr.len() > 0 => {    // found at least 1 ip
          let ip = ipaddr[0].to_string();
          if verbose { println!("ip: {} ipaddr.len {} {:?}", ip, ipaddr.len(), ipaddr)};
          String::from(ip)
        },
        _ => String::from("[]"),                                // set marker for empty/failed IP resolution
      }
    };

    if ipAddress == "[]" {
      println!("{:<15} {:<width$} {}", host, host, all_fail, width=hostwidth);
      continue;
    }
    let portlist = ports.clone();
    // threads.push(std::thread::spawn(move || {
    //   test_tcp_portlist(&ipAddress, &host, &portlist, timeout, hostwidth)
    // }));
    // let task = async move {
    //   test_tcp_portlist(&ipAddress, &host, &portlist, timeout, hostwidth);
    // };
    // tasks.push(RUNTIME.spawn(task));
    // tasks.push(test_tcp_portlist(&host, &portlist, timeout, hostwidth));
    tasks.push(test_tcp_portlist(&host));
  }
  futures::future::join_all(tasks).await;
  // for task in tasks {
  //   task.await.unwrap();
  // }
  // RUNTIME.shutdown_background();
  //RUNTIME.run();
  // Ok(())
}

fn test_tcp_socket_address(address: &str, port: &str, timeout: Duration) -> bool {
  let socket_name = format!("{}:{}", address, port);
  let socket_addr = &socket_name.parse().expect("Unable to parse socket address");
  TcpStream::connect_timeout(socket_addr, timeout).is_ok()
}

fn _test_tcp_portlist(host: &String, name: &String, portlist: &Vec<String>, wait: Duration, hostwidth: usize) {
  let mut threads: Vec<std::thread::JoinHandle<bool>> = vec![];
  for p in portlist.clone() {
    let h = host.clone();
    threads.push(std::thread::spawn(move || -> bool {
      test_tcp_socket_address(&h, &p, wait)
    }));
  }
  let length = threads.len();
  let mut results: Vec<String> = Vec::with_capacity(length); // vec![; length];
  for t in threads {
    let result = format!("{}", t.join().unwrap_or(false));
    results.push(result);
  }
  println!("{:<15} {:<width$} {}", host, name, results.join("\t"), width=hostwidth);
}
