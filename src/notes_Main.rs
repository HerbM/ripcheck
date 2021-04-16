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
