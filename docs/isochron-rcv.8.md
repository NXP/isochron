% isochron-rcv(8) | ISOCHRON

NAME
====

isochron-rcv - Start an isochron test in the role of a receiver

SYNOPSIS
========

**isochron** rcv \[_OPTIONS_\]

DESCRIPTION
===========

This command starts a long-running process that listens for connections
from an isochron sender, logs timestamps for the received test packets,
and sends the logged data back.

OPTIONS
=======

`-h`, `--help`

:   prints the short help message and exits

`-i`, `--interface` <`IFNAME`>

:   specify the network interface on which packets will be received

`-d`, `--dmac` <`MACADDRESS`>

:   specify the destination MAC address used by the application for
    recognizing test packets. Can be either unicast or multicast.
    Necessary only for the L2 transport (plain Ethernet). Optional,
    the interface's unicast MAC address is used by default.

`-e`, `--etype` <`NUMBER`>

:   specify the EtherType used by the application for recognizing test
    packets sent using the L2 transport. Optional, defaults to `0xdead`.

`-P`, `--stats-port` <`NUMBER`>

:   specify the TCP port on which the receiver program is listening for
    incoming connections. This socket is used for management and
    statistics. Optional, defaults to port 5000.

`-s`, `--frame-size` <`NUMBER`>

:   specify the size of test frames. The size is counted from the first
    octet of the destination MAC address until the last octet of data
    before the FCS.

`-S`, `--stats-address` <`NUMBER`>

:   specify the IP address on which the receiver program is listening
    for incoming connections. This socket is used for management and
    statistics. Supports binding to a given network device using the
    `address%device` syntax (example: `--stats-address ::%vrf0`).
    Optional, defaults to ::, with a fallback to 0.0.0.0 if IPv6 is not
    available.

`-q`, `--quiet`

:   this option suppresses error messages regarding invalid test
    packets. Optional, defaults to false.

`-f`, `--sched-fifo`

:   when set, the program requests the kernel to change its scheduling
    policy to `SCHED_FIFO` for the duration of the test.

`-r`, `--sched-rr`

:   when set, the program requests the kernel to change its scheduling
    policy to `SCHED_RR` for the duration of the test.

`-H`, `--sched-priority` <`NUMBER`>

:   when either `--sched-fifo` or `--sched-rr` is used, the program
    requests the kernel to change its scheduling priority for the
    duration of the test.

`-O`, `--utc-tai-offset` <`NUMBER`>

:   the program uses the `CLOCK_TAI` time base for its timers and for
    all reported timestamps, and this option specifies the correction in
    seconds to apply to software timestamps, which are taken by the
    kernel in the `CLOCK_REALTIME` (UTC) time base. If this option is
    present, isochron will also change the kernel's `CLOCK_TAI` offset
    to the specified value, to ensure that its timers fire correctly. If
    the option is absent, isochron queries the kernel's `CLOCK_TAI`
    offset and attempts to use that. If isochron can also query the UTC
    offset from ptp4l's `TIME_PROPERTIES_DATA_SET` using management
    messages, it does that and compares that offset to the kernel's UTC
    offset.  The UTC offset reported by ptp4l has the highest priority,
    and if the application detects that this is different from the
    kernel's `CLOCK_TAI` offset, it changes the kernel offset to the
    value queried from ptp4l.

`-2`, `--l2`

:   this option specifies that the plain Ethernet transport should be
    used for the test packets. Optional, defaults to true unless the
    sender overrides this via the management socket.

`-4`, `--l4`

:   this option specifies that the UDP transport should be used for test
    packets. Optional, defaults to false unless the sender overrides
    this via the management socket.

`-U`, `--unix-domain-socket` <`PATH`>

:   isochron queries ptp4l's state by creating and sending PTP
    management messages over a local UNIX domain socket. This option
    specifies the path of this socket in the filesystem. Optional,
    defaults to `/var/run/ptp4l`.

`-N`, `--domain-number` <`NUMBER`>

:   this option provides the domainNumber value to be used when
    constructing PTP management messages sent to the ptp4l process.
    It must coincide with the domainNumber used by ptp4l, otherwise it
    will not respond to management messages. Optional, defaults to 0.

`-t`, `--transport-specific` <`NUMBER`>

:   this option provides the transportSpecific value to be used when
    constructing PTP management messages sent to the ptp4l process.
    It must coincide with the transportSpecific used by ptp4l, otherwise
    it will not respond to management messages. Optional, defaults to 0.
    Note that PTP variants such as IEEE 802.1AS/gPTP require this value
    to be set to a different value such as 1.

`-R`, `--num-readings` <`NUMBER`>

:   isochron monitors the synchronization quality between the NIC's PTP
    Hardware Clock (PHC) and the system time by successively reading the
    system time, the PHC time and the system time again, several times
    in a row, and picking the group of 3 time readouts that took the
    least amount of time overall. This option specifies how many
    readouts should be performed before picking the fastest one.
    Optional, defaults to 5.

EXAMPLES
========

To start an isochron receiver with PTP synchronization:

```
ip link set eth0 up && ip addr add 192.168.100.2/24 dev eth0
ptp4l -i eth0 -2 -P --step_threshold 0.00002 &
phc2sys -a -rr --step_threshold 0.00002 &
isochron rcv \
	--interface eth0 \
	--quiet \
	--sched-rr \
	--sched-priority 98
```

AUTHOR
======

isochron was written by Vladimir Oltean <vladimir.oltean@nxp.com>

SEE ALSO
========

isochron(8)
isochron-send(8)
isochron-report(1)

COMMENTS
========

This man page was written using [pandoc](http://pandoc.org/) by the same author.
