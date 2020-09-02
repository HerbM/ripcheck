#![allow(non_snake_case)]
#![feature(rustc_private)]
#[macro_use] extern crate lazy_static;
extern crate libc;
//extern crate dnsclient;
//use dnsclient;
use std::net::{TcpStream,SocketAddr};
use std::time::Duration;
use std::env;
// use std::io::prelude::*;
use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use regex::Regex;
use clap::{clap_app, crate_authors, crate_version, crate_description};
// use tokio::runtime;
// use tokio::net::{TcpListener, TcpStream};
//use tokio::prelude::*;
//use tokio::task;
// use futures::future::*;
// std::time::(Duration, Instant);
// std::thread;
//

pub const STDIN_FILENO: i32 = 0;

/*
macro_rules! repetitive_print {
  ($($arg:tt),*) => { println!("{:<15} {:<hostwidth$} {}", $($arg),*) }
}
//repetitive_print!("world");
*/

fn piped_input() -> bool { unsafe { libc::isatty(STDIN_FILENO as i32) == 0 } }


fn get_dnsserver() -> &'static str { "103.86.99.99" }

// fn valid_port(v: &std::ffi::OsStr) -> Result<(), &std::ffi::OsStr> {
  //   let port = v.to_os_string().into_string().unwrap().parse::<u16>().expect("Invalid port");
//   match port {
//     p if p > 0 && p <= std::u16::MAX => Ok(()),
//     _ => Err(std::ffi::OsString::from("Port was out of range."))
//   }
// }
fn valid_port(portname: &str) -> Result<(), String> {
  match portname.parse::<u16>().unwrap_or(0) {
    p if p > 0 => Ok(()),
    _ => Err(String::from(format!("Port <{}> is invalid.", portname)))
  }
}

fn valid_hostname(ipstring: &str) -> Result<(), String> {
  lazy_static! {
    static ref RE: Regex = Regex::new(r"^\D").unwrap();
  }
  // println!("Checking for valid_hostname: {}", ipstring);
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
  const WAIT:&str = "WAIT";
  // const LO:u64 = 1;
  // let hi:u64 = u64::from(std::u16::MAX);
  clap_app!(myapp =>
    (version : crate_version!())
    (author  : crate_authors!("\n"))
    (about   : crate_description!() )
    (@arg HOST:    -a -c --host {valid_hostname} ... +takes_value default_value(LOCALHOST)   "Computer to test" )
    (@arg PORT:       -p --port {valid_port}     ... +takes_value default_value(DEFAULTPORT) "Port to test"     )
    (@arg TIMEOUT: -w -t --timeout    --wait         +takes_value default_value(WAIT)        "Timeout in seconds or milliseconds")
    (@arg FILENAME:   -f --filename   --path         +takes_value                            "Sets the input file to use")
    (@arg RANGE:      -r --range                 ... +takes_value                            "Sets the input file to use")
    (@arg NAMESERVER: -n --nameserver --dns      +takes_value default_value(get_dnsserver()) "Sets the nameserver to use")
    (@arg VERBOSE:    -v --verbose                                                           "Print test information verbosely")
    (@arg NOHEADER:      --noheader                                                          "Omit header from output")
  ).get_matches()
}

//  fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
//  where P: AsRef<Path>, {
//    let file = File::open(filename)?;
//    Ok(io::BufReader::new(file).lines())
//  }
fn open_bufreader<P>(filename: P) -> io::Result<io::BufReader<File>>
where P: AsRef<Path>, {
  let file = File::open(filename)?;
  Ok(io::BufReader::new(file))
}

//  fn open_bufreader<T>(name: InputSource) -> io::Result<io::BufReader<T>>
//  where P: AsRef<Path>, {
//    let file = File::open(filename)?;
//    Ok(io::BufReader::new(file))
//  }


//  enum input_type {
//    STDIN,
//    FILE = &str
//  }
//
//  fn open_input<P>(filename: P) -> io::Result<io::BufReader<File>>
//  where P: AsRef<Path>, {
//    let file = File::open(filename)?;
//    Ok(io::BufReader::new(file))
//  }

// let f = File::open("foo.txt").unwrap();
// let f = BufReader::new(f);

// static OUT_FORMAT1: &'static str    = "{:<15} {:<20} {}";
// static OUT_FORMAT:  &'static String = String::from("{:<15} {:<20} {}");
//format argument must be a string literal

// help: you might be missing a string literal to format with: `"{} {} {} {} {}", `
//static LANGUAGE: &'static str = "Rust";


//  async fn funAsync(i: u32) {
//    print!(" {} ", i);
//    // todo!()
//  }

// fn fun (i: u32) {
//   print!(" {} ", i);
//   // todo!()
// }

// #[tokio::main]
// async

struct CheckConfig {
  wait:       u64,
  verbose:    bool,
  showheader: bool,
  nsAddress:  Vec<String>,
  ports:      Vec<String>,
}
fn main() {  // -> io::Result<()> {

  //let mut rt = tokio::runtime::Runtime::new().unwrap();
  // let future = app();
  // rt.block_on(future);

//  let mut handlers:        Vec<std::thread::JoinHandle<()>> = Vec::new();
//  for i in 0..9 {
//    let builder = std::thread::Builder::new();
//    handlers.push(builder.spawn(move || {
//      fun(i);
//    }).unwrap());
//  }
//
//  for h in handlers {
//    h.join();
//  }
//  return ();


  let matches               = parse_args();
  let showheader            = !matches.is_present("NOHEADER");
  let wait                  = matches.value_of("TIMEOUT").unwrap().parse::<u64>().expect("Cannot parse timeout");
  let verbose               = matches.is_present("VERBOSE");
  let from_file             = matches.is_present("FILENAME");
  let ports: Vec<String>    = matches.values_of("PORT").unwrap().map(|s| s.to_string()).collect();
  let nsAddress             = matches.value_of("NAMESERVER").unwrap();
  let nsSocket: SocketAddr  = format!("{}:53", nsAddress).parse().expect("Unable to parse socket address");
  let mut hosts:Vec<String> = Vec::with_capacity(128);
  let _range: Vec<String>   = parse_range(matches.value_of("RANGE").unwrap_or("---"));


//  enum InputSource {
//    STDIN,
//    NAME(String),
//  }

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
      let filename = matches.value_of("FILENAME").unwrap();
      let input = open_bufreader(filename);
      if let Ok(input) = input {
        for line in input.lines() {
          if let Ok(ip) = line { hosts.push(ip) }
        }
      }
    }
  } else {
    hosts = matches.values_of("HOST").unwrap().map(|s| s.to_string()).collect();
  }
  // let hostwidth = hosts.iter().min_by(|&&s| (s.len(), s));
  let mut hostwidth = 20;
  for h in hosts.iter() {
    if h.len() > hostwidth { hostwidth = h.len() }
  };
  let dnsServers = vec![dnsclient::UpstreamServer::new(nsSocket)];
  let dnsClient  = dnsclient::sync::DNSClient::new(dnsServers);
  let mut threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
  let port_count = ports.len();
  let port_names = ports.join("  \t");
  let all_fail   = vec!["false"; port_count].join("\t");


  if verbose { println!("port_count: {} {}", port_count, all_fail); }
  // let mut hostwidth: usize = 10;
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
    threads.push(std::thread::spawn(move || {
      test_tcp_portlist(&ipAddress, &host, &portlist, wait, hostwidth)
    }));
  }
  for t in threads { let _ = t.join(); }
  // Ok(())
}


fn test_tcp_socket_address(address: &str, port: &str, timeout: u64) -> bool {
  let socket_name = format!("{}:{}", address, port);
  let socket_addr = &socket_name.parse().expect("Unable to parse socket address");
  let timeout     = Duration::new(timeout, 0);
  TcpStream::connect_timeout(socket_addr, timeout).is_ok()
}


fn test_tcp_portlist(host: &String, name: &String, portlist: &Vec<String>, wait: u64, hostwidth: usize) {
  let mut threads:
  Vec<std::thread::JoinHandle<bool>> = vec![];
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
//  You can pass the width specifier as a format argument or you can use concat! if you have a literal.
  println!("{:<15} {:<width$} {}", host, name, results.join("\t"), width=hostwidth);
}

/*

hostname address maxwidth results


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



format!("{}{}{}", foo, "-".repeat(total_width - foo.len() - bar.len()), bar)

*/