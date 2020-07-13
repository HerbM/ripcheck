#![allow(non_snake_case)]
// use std::io::prelude::*;
use std::net::{SocketAddr, TcpStream};
// use std::net::{TcpStream};
use std::time::Duration;
use std::env;
use clap::clap_app;


/* struct IPTarget {
  name:String,
  ip:String
}
params adddress, ports
file addresses  (ports?)
  txt
  csv
  ??? excel, json, xml????
  output options (header, debugging)
     -t N or -w N  =  Wait Time N for connections to complete   time/wait
     -m THREADS    =  Maximum threads to use              maxthreads
     -h            =  show header on console              header
     -d            =  add debugging output                debugging info->verbose
        MaxThreads        = 500
        Threads requested = 1
        Actual Threads    = 1
        Display Width     = 20
        WaitForResponse   = 8000

*/


fn parse_args() -> clap::ArgMatches {
  clap_app!(myapp =>
    (version : "0.0.1")
    (author  : "HerbM <HerbMartin@gmail.com>")
    (about   : "Fast TCP Port Checker")
    (@arg CONFIG: -c --config +takes_value "Sets a custom config file")
    (@arg file: "Sets the input file to use")   // +required
    (@arg verbose: -v --verbose "Print test information verbosely")
    (@subcommand test =>
      (about: "controls testing features")
      (version: "1.3")
      (author: "Someone E. <someone_else@other.com>")
      (@arg debug: -d ... "Sets the level of debugging information")
    )  
  ).get_matches()  
}  


fn test_tcp_socket_address(address: &str, port: &str, timeout: u64) -> bool {
  // TODO:  Need to let address be Name and convert to IP  -- not here
  let tcp_socket_name = format!("{}:{}", address, port);
  let tcp_socket_addr:&SocketAddr = &tcp_socket_name.parse().expect("Unable to parse socket address");
  let timeout   = Duration::new(timeout, 0);
  match TcpStream::connect_timeout(tcp_socket_addr, timeout) { 
    Ok(_) => true,
    _     => false, 
  }
}


fn main() {
  let _string   = String::from("abcdef");
  let _clapArgs = parse_args();
  let args : Vec<String> = env::args().collect();
  let address   = &args[1];
  let port      = &args[2];
  let timeout   = args[3].parse::<u64>().expect("Unable to parse timeout");
  let result    = test_tcp_socket_address(address, port, timeout);
  print!("RPCheck {}:{} Result: {}", address, port, result);
}



/*
RustLang Project: Port Sniffer  YouTube Tensor Programming  code on Github
std::net::IpAddr
std::str::FromStr
enum IpAddr V4 | V6
struct Arguments { flag:String, ipaddr: IpAddr, threads: u16}
impl Arguments {
  fn new(args: &[String]) -> Result<Arguments, &'static str>{
    return Err("argument error")
  }
}
*/


// std::sync::Arc   let v = Arc::new(vec![1,2]);
// let v2 = v.clone()
// thread::spawn(move || {
//   code block here;
// });
// std::sync::Mutex &Mutex<i32>
//   let mut data: Guard<i32> = counter.lock()
//  std::sync::atomic::*
// AtomicUsize::new(10)  // lighter weight than Mutex
// std::sync::mpsc
// let (tx,rx) = mpsc::channel();
// tx2 = tx.clone();
//  thread::spawn(move|| tx.send(5));
//  thread::spawn(move|| tx2.send(4));
// println!("{:?}"), rx.recv());
// println!("{:?}"), rx.recv());   //unspecified order

// rayon fn input.par_iter().map(|&i| i * i ).sum()  // parallel iter
// crossbeam epoch-based, translate from GC, work stealing deque, MPMC queues
// ** Tokio mio + futures   cross-platform async I/O  (futures powered by TCP/UDP)
// Future (one value), Stream (multiple value over time), Sink (pushing)
//
/*
Rust Concurrency Explained https://www.youtube.com/watch?v=Dbytx0ivH7Q 1hr05min
Code Dive Concurrency Alex Crichton  1hr10min
https://www.youtube.com/watch?v=SiUBdUE7xnA

Intro to Rust (Concurrency, Threads, Channels, Mutex, Arc) "Tensor Programming" 17min
https://www.youtube.com/watch?v=_4fSLuvPMf8&t=896s
Rust Concurrency, Threads, Channels  CS196 SP20  43min
https://www.youtube.com/watch?v=JXDkdaGEuVU
Rust 10 videos Diving into Rust 1hr etc.
https://www.youtube.com/watch?v=_jMSrMex6R0&list=PLFjq8z-aGyQ6t_LGp7wqHsHTYO-pDDx84
Rust Crash Course Traversy Media
https://www.youtube.com/watch?v=zF34dRivLOw&t=4013s

Concurrency in Rust with Async/Await 48min
https://www.youtube.com/watch?v=hrNoTZMG2MU

*/

/*
Argument parsing
docopt/docopt.rs [docopt] — A Rust implementation of DocOpt burnt sushi
TeXitoi/structopt [structopt] — parse command line argument by defining a struct
killercup/quicli [quicli] — quickly build cool CLI apps in Rust
ksk001100/seahorse [seahorse] — A minimal CLI framework written in Rust Build status

gumdrop seems to be a smaller alternative to structopt that doesn't use clap
pico-args https://lib.rs/crates/pico-args
quicli   QUICKLY BUILD COOL CLI APPS IN RUST.

Serde for handling all things serializing and deserializing
failure for ergonomic error handling.



DashMap -- Blazingly fast concurrent associative array/hashmap in Rust.
...API similar to std::collections::HashMap with some slight changes to handle concurrency.
DashMap tries to be very simple to use and to be a direct replacement for RwLock<HashMap<K, V>>.
To accomplish these all methods take &self instead modifying methods taking &mut self.
This allows you to put a DashMap in an Arc<T> and share it between threads while being able to modify it.

Jim Fawcette Rust Error Handling code/slides CSIAC Webinars


fn main_args() -> clap::ArgMatches {
  clap_app!(myapp =>
    (version : "1.0")
    (author  : "Kevin K. <kbknapp@gmail.com>")
    (about   : "Does awesome things")
    (@arg CONFIG: -c --config +takes_value "Sets a custom config file")
    (@arg INPUT: +required "Sets the input file to use")
    (@arg verbose: -v --verbose "Print test information verbosely")
    (@subcommand test =>
      (about: "controls testing features")
      (version: "1.3")
      (author: "Someone E. <someone_else@other.com>")
      (@arg debug: -d ... "Sets the level of debugging information")
    )  
  ).get_matches()  
}  

*/
