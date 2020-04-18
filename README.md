# Pingutil

Pingutil is a linux `ping` command clone written in C++. It can send [ICMPv4](https://tools.ietf.org/html/rfc792)/[ICMPv6](https://tools.ietf.org/html/rfc4443) `ECHO_REQUEST` to network hosts. Currently, Pingutil only works on linux.

## Usage

Pingutil uses raw sockets (`SOCK_RAW`) hence requires root privileges to work.

```
>>> sudo ./pingutil google.com
PING del03s15-in-f14.1e100.net (172.217.167.14) with 56 bytes of data (icmp packet size = 64 bytes)
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=1 ttl=52 time=90.4496ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=2 ttl=52 time=123.118ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=3 ttl=52 time=133.439ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=4 ttl=52 time=113.994ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=5 ttl=52 time=119.671ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=6 ttl=52 time=120.836ms
64 bytes from del03s15-in-f14.1e100.net (172.217.167.14): icmp_seq=7 ttl=52 time=299.872ms
^C--- del03s15-in-f14.1e100.net ping statistics ---
7 packets transmitted, 7 received, 0.00% packet loss, time 1001.38ms
rtt min/avg/max/mdev = 90.45/143.05/299.87/22.40 ms

>>> sudo ./pingutil -6 google.com
PING del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e) with 56 bytes of data (icmp packet size = 64 bytes)
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=1 ttl=64 time=100.335ms
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=2 ttl=64 time=67.382ms
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=3 ttl=64 time=109.401ms
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=4 ttl=64 time=110.298ms
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=5 ttl=64 time=97.8638ms
64 bytes from del03s13-in-x0e.1e100.net (2404:6800:4002:808::200e): icmp_seq=6 ttl=64 time=99.9024ms
^C--- del03s13-in-x0e.1e100.net ping statistics ---
6 packets transmitted, 6 received, 0.00% packet loss, time 585.18ms
rtt min/avg/max/mdev = 67.38/97.53/110.30/0.40 ms

>>> sudo ./pingutil --count 5 8.8.8.8
PING dns.google (8.8.8.8) with 56 bytes of data (icmp packet size = 64 bytes)
64 bytes from dns.google (8.8.8.8): icmp_seq=1 ttl=52 time=70.9144ms
64 bytes from dns.google (8.8.8.8): icmp_seq=2 ttl=52 time=107.195ms
64 bytes from dns.google (8.8.8.8): icmp_seq=3 ttl=52 time=73.7835ms
64 bytes from dns.google (8.8.8.8): icmp_seq=4 ttl=52 time=87.993ms
64 bytes from dns.google (8.8.8.8): icmp_seq=5 ttl=52 time=109.696ms
--- dns.google ping statistics ---
5 packets transmitted, 5 received, 0.00% packet loss, time 449.58ms
rtt min/avg/max/mdev = 70.91/89.92/109.70/3.96 ms

```

## Features

1. Supports both [ICMPv4](https://tools.ietf.org/html/rfc792) and [ICMPv6](https://tools.ietf.org/html/rfc4443) protocols (can work with IPv4 and IPv6 addresses). Use arguments `-4` or `-6` to force pingutil to use ICMPv4 and ICMPv6 respectively.
2. Allows users to set Time to live (TTL) (or Hop Limit). Use argument `--ttl` to set TTL on outgoing packets.
3. Performs automatic reverse DNS lookup.
4. Argument `--count` allows users to send a given number of ICMP ECHO requests.

## Building from source

```
>>> make
```

or

```
>>> g++ pingutil.cc -o pingutil
```

## See it in action

[![asciicast](https://asciinema.org/a/321259.png)](https://asciinema.org/a/321259)