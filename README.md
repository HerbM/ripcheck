# ripcheck

## Fast ARP &amp; TCP Port Checker in Rust versin 0.0.8

This is an early alpha version, and my first project as a beginner using Rust.

It has only been tested on Windows though it will eventually run on Linux etc.

**CAUTION:** It can cause excessive CPU or Network traffic with an injudicious parameter list.

    Option to limit thread count has been added.

    It may use Number of Hosts * Number of (Ports + 1) being checked.

Expect the parameters names and usage to change since it is currently more complicated than necessary.

### Example:
```
<# #> ./ripcheck.exe -A --cidr 172.16.248.0/28 -p 22 80 443 135

IPAddress      Host                MAC_ADDRESS        Port22    Port80    Port443   Port135
172.16.248.10  172.16.248.10                          true      false     false     true
172.16.248.6   172.16.248.6                           false     false     false     false
172.16.248.3   172.16.248.3                           false     false     false     false
172.16.248.4   172.16.248.4                           false     false     false     false
172.16.248.12  172.16.248.12                          false     false     false     false
172.16.248.7   172.16.248.7                           false     false     false     false
172.16.248.8   172.16.248.8                           false     false     false     false
172.16.248.11  172.16.248.11       66-6a-6d-5a-97-7d  false     false     false     false
172.16.248.13  172.16.248.13                          false     false     false     false
172.16.248.5   172.16.248.5                           false     false     false     false
172.16.248.14  172.16.248.14                          false     false     false     false
172.16.248.1   172.16.248.1        38-80-df-f7-ab-6c  false     true      false     false
172.16.248.2   172.16.248.2                           false     false     false     false
172.16.248.9   172.16.248.9                           false     false     false     false
```

### Usage:
```
ripcheck 0.0.8
HerbM <HerbMartin@GMail.com>
Fast ARP & TCP Port Checker in Rust

USAGE:
    ripcheck.exe [FLAGS] [OPTIONS] [--] [TARGETS]...

ARGS:
    <TARGETS>...    Query targets

FLAGS:
    -A, --ARP         ARP to resolve MAC address
    -s, --csvout      Output CSV results
    -l, --uselocal    Also try local DNS resolver
    -o, --omit        Omit header from output
    -v, --verbose     Print verbose information
    -h, --help        Prints help information
    -V, --version     Prints version information

OPTIONS:
        --cidr <CIDR>...             Query network ranges
    -d, --drain <DRAIN>              Drain threads to N% [default: 0]
    -f, --path <FILENAME>            Read targets from file(s)
    -a, --host <HOST>...             Query names or addresses
    -m, --maxthreads <MAXTHREADS>    Maximum thread count [default: 4000]
    -n, --dns <NAMESERVER>...        Nameservers to use
    -p, --port <PORT>...             Ports to test [default: 135]
    -r, --range <RANGE>...           Query Addresse ranges
    -t, --wait <TIMEOUT>             Timeout: seconds or milliseconds [default: 4000]
```

