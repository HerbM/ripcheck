# ***ripcheck***

## **Fast ARP &amp; TCP Port Checker in Rust version 0.0.14**

*ripcheck* v0.0.14 is now a beta version, and is my first project as a beginner using Rust.

It has only been tested on Windows, though it will eventually run on Linux etc.

**CAUTION:** It can cause excessive CPU or Network traffic with an injudicious parameter list.

    Option to limit thread count has been added -- **YOU MUST RESTRICT IT** for your environment.

    It may use:

    Number of Hosts * Number of Ports being checked + 1 ARP + 1 Reverse DNS.

    A /24 bit network will require about 1250 threads to check 3 ports plus ARP and Reverse DNS

Expect the parameters names and usage to change since it is currently more complicated than necessary.

### DNS, ARP, reverse DNS, and port checks are now separately threaded.

### MAC Vendor lookups are using the (excellent) phf

### MAC to vendor table
https://gitlab.com/wireshark/wireshark/-/raw/master/manuf   (42,562 entries)

### Example:
```
RipCheck 192.168.239.1 --range 192.168.239.10-192.168.239.24 --cidr 192.168.239.28/30 -p 135 445 3389 -R -A -M

IPAddress       Hostname                       MACaddress         MACvendor Port135 Port445 Port3389
192.168.239.10  host.docker.internal                                        true    true    true
192.168.239.30  NPIA9A823                      10-62-e5-a9-a8-23  HewlettP  false   false   false
192.168.239.24  192.168.239.24                 50-87-b8-30-3d-c2  Nuvyyo    false   false   false
192.168.239.12  192.168.239.12                                              false   false   false
192.168.239.14  192.168.239.14                                              false   false   false
192.168.239.19  192.168.239.19                                              false   false   false
192.168.239.13  192.168.239.13                                              false   false   false
192.168.239.11  192.168.239.11                 66-6a-6d-5a-97-7d            false   false   false
192.168.239.16  192.168.239.16                 44-91-60-71-14-dd  MurataMa  false   false   false
192.168.239.15  192.168.239.15                 8c-49-62-13-87-a1  Roku      false   false   false
192.168.239.21  192.168.239.21                                              false   false   false
192.168.239.1   192.168.239.1                  38-80-df-f7-ab-6c  Motorola  false   false   false
192.168.239.29  192.168.239.29                                              false   false   false
192.168.239.17  192.168.239.17                 10-30-47-30-29-77  SamsungE  false   false   false
192.168.239.23  192.168.239.23                 38-6a-77-3d-13-69  SamsungE  false   false   false
192.168.239.18  192.168.239.18                                              false   false   false
192.168.239.22  192.168.239.22                                              false   false   false
192.168.239.20  192.168.239.20                 58-fd-b1-0b-c7-dc  LGElectr  false   false   false

TimeThis :    Start Time :  Sat May 01 12:12:15 2021
TimeThis :      End Time :  Sat May 01 12:12:20 2021
TimeThis :  Elapsed Time :  00:00:05.044```

### Usage: RipCheck --help
```
ripcheck 0.0.14
HerbM <HerbMartin@GMail.com>
Fast ARP & TCP Port Checker in Rust

USAGE:
    ripcheck.exe [FLAGS] [OPTIONS] [--] [TARGETS]...

ARGS:
    <TARGETS>...    Query targets

FLAGS:
    -A, --arp         ARP to resolve MAC address
    -s, --csvout      Output CSV results
    -l, --uselocal    Also try local DNS resolver
    -o, --omit        Omit header from output
    -R, --reverse     Reverse IP to name
    -M, --vendor      Show NIC vendor
    -v, --verbose     Print verbose information
    -h, --help        Prints help information
    -V, --version     Prints version information

OPTIONS:
    -N, --cidr <CIDR>...             Query network ranges
    -d, --drain <DRAIN>              Drain threads to N% [default: 0]
    -f, --path <FILENAME>            Read targets from file(s)
    -a, --host <HOST>...             Query names or addresses
    -m, --maxthreads <MAXTHREADS>    Maximum thread count [default: 4000]
    -n, --dns <NAMESERVER>...        Nameservers to use
    -p, --port <PORT>...             Ports to test [default: 135]
    -r, --range <RANGE>...           Query Address ranges
    -t, --wait <TIMEOUT>             Timeout: seconds or milliseconds [default: 4000]
```

