isochron
========

[![Coverity Scan Build Status](https://scan.coverity.com/projects/25104/badge.svg)](https://scan.coverity.com/projects/isochron)

The isochron program is a real-time application for testing Time
Sensitive Networking equipment. It works by monitoring the network
synchronization status and sending time-triggered Ethernet packets.

It has a server-client architecture and it measures network latency by
taking multiple timestamps (some hardware, some software) along the path
of the packets.

Complex packet collision patterns can be created and measured by
orchestrating (coordinating the transmission times of) isochron nodes on
multiple stations.

isochron requires a network interface with the ability to retrieve
hardware RX and TX timestamps of non-PTP packets. It also makes use of
additional network interface offloads, such as time-aware scheduling
(`tc-taprio`), or time specified departure (`tc-etf` and `SO_TXTIME`),
if those are available.

The full documentation is available in the `docs/` folder.

Building
--------

isochron links with the following libraries:
* libmnl (https://git.netfilter.org/libmnl/)

Building is simply a matter of running:

```bash
# Build everything
make
# Build just isochron
make isochron
# Build just the man pages using pandoc
make man
```

Installation requires running at least one of the following (by default,
`DESTDIR` is empty, and `prefix` is `/usr/local`):

```bash
# Install everything
make install DESTDIR=/path/to/target prefix=/usr
# Install just isochron
make install-binaries DESTDIR=/path/to/target prefix=/usr
# Install just the bash-completion script
make install-completion DESTDIR=/path/to/target prefix=/usr
# Install just the man pages
make install-manpages DESTDIR=/path/to/target prefix=/usr
```
