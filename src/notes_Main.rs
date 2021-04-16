/*
  New structure plan
  Work channel for tasks MPMC
  Send "tasks"
    NEW (or INPUT???)
    PARSE?
    RESOLVE1,2-RESOLVEALL
    TEST
    FORMAT
  Output channel MPSC??
    Single threaded output (at least to each sink, through screen & file could be separated)
  
  Create two channels Work & Output
  Start threads that can RX & TX to these
  Send initial tasks (of type following NEW)  
  Start N threads based on MAX, DEFAULT, Size of input, CPU load?
  Each task is picked up by any thread, work performed, and then calls "get_next_task(current_task)"
  TEST is split into N threads (or async) to test each port/protocol
 
  INFO: https://lib.rs/crates/pnet
        https://lib.rs/crates/backoff
        https://lib.rs/crates/rustls-native-certs
        https://lib.rs/crates/etherparse
        https://lib.rs/crates/ipnetwork
        https://lib.rs/crates/trust-dns-client
        Schannel bindings for rust, allowing SSL/TLS (e.g. https) without openssl 
          https://lib.rs/crates/schannel
        https://lib.rs/crates/rsntp
        https://publicsuffix.org/learn/
        Robust and fast domain name parsing
          https://lib.rs/crates/addr
        tokio-tls An implementation of TLS/SSL streams for Tokio built on top of the [native-tls crate]
          https://lib.rs/crates/tokio-native-tls
        ipconfig Get network adapters information and network configuration for windows
          https://lib.rs/crates/ipconfig
        mdns A multicast DNS client library. Supports discovery of any mDNS device on a LAN
        network-address-resolution-protocol
          network is a set of Rust crates to make it easier to work with networking.
          https://crates.io/crates/network-address-resolution-protocol
        https://blog.dineshs91.com/post/send_arp/


   
*/

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




/*
# Didn't work after STARTING to understand lifetimes
#[derive(Debug)]
struct CheckConfig<'a> {
    useDNSdirect: bool,
    timeout: &'a Duration,
    outputType: OutputType,
    dnsserverlist: &'a Vec<String>,
    testports:  &'a Vec<String>,
    verbose:    bool,
    showheader: bool,
}

impl<'a> Default for CheckConfig<'a> {
    fn default() -> CheckConfig<'a> {
        CheckConfig {
      useDNSdirect:  false,
      timeout:       &Duration::new(3, 0),
      outputType:    OutputType::Table,
      dnsserverlist: &vec![],
      testports:     &vec!["80".to_string(), "135".to_string(),"445".to_string()],
      verbose:       false,
      showheader:    true,
    }
}
}
*/
