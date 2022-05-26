% isochron-send(8) | ISOCHRON

NAME
====

isochron-send - Start an isochron test in the role of a sender

SYNOPSIS
========

**isochron** send \[_OPTIONS_\]

DESCRIPTION
===========

This command sends test packets using the specified transport (plain
Ethernet or UDP).

OPTIONS
=======

`-h`, `--help`

:   prints the short help message and exits

`-i`, `--interface` <`IFNAME`>

:   specify the network interface on which packets will be sent

`-d`, `--dmac` <`MACADDRESS`>

:   specify the destination MAC address to be used for the test packets.
    Should coincide with the MAC address that the receiver listens for.
    Can be either unicast or multicast. Necessary only for the L2
    transport (plain Ethernet). Optional if the `--client` option is
    also specified, case in which the sender can directly query the
    receiver for the destination MAC address it listens for.

`-A`, `--smac` <`MACADDRESS`>

:   specify the source MAC address to be used for the test packets.
    Optional, defaults to the network interface's unicast address.
    Necessary only for the L2 transport.

`-p`, `--priority` <`NUMBER`>

:   specify the `SO_PRIORITY` (traffic class) to communicate to the
    kernel for test packets. Used by qdiscs such as tc-mqprio or
    tc-taprio. Optional, defaults to 0.

`-P`, `--stats-port` <`NUMBER`>

:   specify the TCP port on which the receiver program is listening for
    incoming connections. This socket is used for management and
    statistics. Optional, defaults to port 5000.

`-b`, `--base-time` <`TIME`>

:   specify the scheduled transmission time for the first packet. This
    can be further shifted forward and backwards in time with the
    `--shift-time` argument. This time can be in the past, and in that
    case it is automatically advanced by an integer number of cycles
    until it becomes larger than the current time by at least one
    second. The time base is CLOCK_TAI. Optional, defaults to 0.

`-a`, `--advance-time` <`TIME`>

:   specify the amount in advance of the scheduled packet transmission
    time that isochron will wake up at. Optional, defaults to the cycle
    time minus the window size, so that the sender will wake up at the
    earliest possible moment and have the longest possible amount of
    time for preparing for transmission.

`-S`, `--shift-time` <`TIME`>

:   shift the base time by the specified amount of nanoseconds, either
    in the past or in the future. Useful when enqueuing packets into a
    NIC which uses a tc-taprio qdisc and the time slot corresponding to
    the applications's traffic class is not the first one. When used in
    this way, the base time of the application can be specified as equal
    to the base time of the tc-taprio schedule, and the shift time can
    be specified as the length of all time slots prior to the one in
    which the application should enqueue. Optional, defaults to 0.

`-c`, `--cycle-time` <`TIME`>

:   specify the interval between consecutive wakeup times for the
    purpose of sending a packet.

`-w`, `--window-size` <`TIME`>

:   in case the NIC uses a tc-taprio schedule, specify the duration in
    nanoseconds of the time slot corresponding to the application's
    priority. This will prevent isochron from waking up too early and
    potentially enqueuing the packet prematurely in its time slot from
    the previous cycle. With a correctly configured window size, the
    wakeup time will be set no earlier than the end of the previous time
    slot, making this condition impossible (assuming proper system clock
    synchronization). Optional, defaults to 0.

`-n`, `--num-frames` <`NUMBER`>

:   specify the number of packets to send for this test. Optional, if
    left unspecified the program will run indefinitely, but will not
    collect logs.

`-s`, `--frame-size` <`NUMBER`>

:   specify the size of test frames. The size is counted from the first
    octet of the destination MAC address until the last octet of data
    before the FCS.

`-T`, `--no-ts`

:   disable the process of collecting TX timestamps.

`-v`, `--vid` <`NUMBER`>

:   insert a VLAN header with the specified VLAN ID in the test packets.
    The VLAN PCP is set to be equal to the priority configured with
    `--priority`. This results in lower overhead compared to using a
    kernel VLAN interface to insert the VLAN tag. Optional, defaults to
    no VLAN header being inserted.

`-C`, `--client` <`IPADDRESS`>

:   specify the IPv4 or IPv6 address at which the receiver is listening
    for management/statistics connections. Optional, defaults to not
    attempting to connect to the receiver. In this case, the sender
    operates in a limited mode where it does not collect logs or check
    for the receiver's sync status or expected destination MAC address.
    The receiver will also not log packets unless the sender connects to
    it.

`-q`, `--quiet`

:   when not connected to the receiver's management/statistics socket,
    the sender will, by default, print the packets and their TX
    timestamps, to standard output at the end of the test. This option
    suppresses the print. Optional, defaults to false.

`-e`, `--etype` <`NUMBER`>

:   specify the EtherType for test packets sent using the L2 transport.
    Optional, defaults to `0xdead`.

`-o`, `--omit-sync`

:   when set, the sender will not monitor the local (and optionally
    remote, if `--client` is used) ptp4l and phc2sys processes for
    synchronization status, and will proceed to send test packets
    regardless. Optional, defaults to false.

`-y`, `--omit-remote-sync`

:   when set, will only monitor the sync status of the local station.
    The assumption is that the receiver interface is implicitly
    synchronized (shares the same PHC as the sender interface), and
    therefore no ptp4l instance runs on it, so the sync status cannot be
    monitored. Optional, defaults to false.

`-m`, `--tracemark`

:   when set, the sender will write to the kernel's ftrace buffer in
    order to mark the moment when it wakes up for transmitting a packet,
    and the moment after the packet has been enqueued into the kernel.
    The option is useful for debugging latency issues together with
    trace-cmd and kernelshark, since the packet's sequence number is
    logged, and therefore, latencies reported by `isochron report` can
    be quickly be associated with the kernel trace buffer. Optional,
    defaults to false.

`-Q`, `--taprio`

:   when set, the sender will record this information to the output
    file. This changes the interpretation of the logged data, for
    example TX timestamps with tc-taprio are expected to be higher than
    the scheduled transmission time, otherwise they are expected to be
    lower. The option is expected to be set when enqueuing to a NIC
    where tc-taprio is used as the qdisc.

`-x`, `--txtime`

:   when set, the sender will use the `SO_TXTIME` socket option when
    enqueuing packets to the kernel. This also changes the
    interpretation of logged data similar to `--taprio`. The TX time
    requested by the sender is equal to the scheduled transmission time
    for the packet. This option is expected to be set when enqueuing to
    a NIC where tc-etf is used as the qdisc.

`-D`, `--deadline`

:   when set, this sets the `SOF_TXTIME_DEADLINE_MODE` flag for the data
    socket. This can only be used together with `--txtime`. This option
    changes the kernel's interpretation of the TX time, in that it is no
    longer the PTP time at which the packet should be sent, but rather
    the latest moment in time at which the packet should be sent.

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

`-M`, `--cpu-mask` <`NUMBER`>

:   a bit mask of CPUs on which the sender thread is allowed to be
    scheduled. The other threads of the program are not affected by this
    selection. Optional, defaults to the CPU affinity of the isochron
    process.

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

`-J`, `--ip-destination` <`IPADDRESS`>

:   this option specifies the IPv4 or IPv6 address of the receiver,
    which will be placed in the test packet datagrams. Mandatory if the
    UDP transport is used. Note that when using the UDP transport, the
    destination IP address should have a static entry in the kernel's IP
    neighbor table, to avoid unpredictable latencies caused by the
    kernel's neighbor resolution process. The isochron program does not
    have control over which interface will be used for sending the test
    packets, so the user should ensure that the kernel's routing table
    will select the correct interface for this destination IP address.

`-2`, `--l2`

:   this option specifies that the plain Ethernet transport should be
    used for the test packets. Optional, defaults to true. Cannot be
    used together with `--l4`.

`-4`, `--l4`

:   this option specifies that the UDP transport should be used for test
    packets. Optional, defaults to false. Cannot be used together with
    `--l2`.

`-W`, `--data-port` <`NUMBER`>

:   if the UDP transport is used, this option specifies the destination
    UDP port for test packets. Optional, defaults to 6000.

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

`-X`, `--sync-threshold` <`TIME`>

:   when the program is configured to monitor the sync status of ptp4l
    and phc2sys, this option specifies the positive threshold in
    nanoseconds by which the absolute offset reported by these external
    programs is qualified as sufficient to start the test. Mandatory
    unless `--omit-sync` is specified.

`-R`, `--num-readings` <`NUMBER`>

:   isochron monitors the synchronization quality between the NIC's PTP
    Hardware Clock (PHC) and the system time by successively reading the
    system time, the PHC time and the system time again, several times
    in a row, and picking the group of 3 time readouts that took the
    least amount of time overall. This option specifies how many
    readouts should be performed before picking the fastest one.
    Optional, defaults to 5.

`-F`, `--output-file` <`PATH`>

:   save the packet timestamps to a file that can be queried at a later
    time using `isochron report`. Defaults to "isochron.dat". This
    requires the `--client` option, since logging only TX timestamps is
    not supported.

EXAMPLES
========

To start an isochron sender with PTP synchronization and a tc-taprio
qdisc:

```
ip link set eth0 up && ip addr add 192.168.100.1/24 dev eth0
ptp4l -i eth0 -2 -P --step_threshold 0.00002 &
phc2sys -a -rr --step_threshold 0.00002 &
tc qdisc add dev eth0 root taprio num_tc 5 \
	map 0 1 2 3 4 \
	queues 1@0 1@1 1@2 1@3 1@4 \
	base-time 0 \
	sched-entry S 10  50000 \
	sched-entry S 0f 450000 \
	flags 2
taskset $((1 << 0)) isochron send \
	--cpu-mask $((1 << 1)) \
	--interface eth0 \
	--cycle-time 0.0005 \
	--frame-size 64 \
	--num-frames 1000000 \
	--client 192.168.100.2 \
	--quiet \
	--sync-threshold 2000 \
	--output-file isochron.dat \
	--taprio \
	--priority 4 \
	--sched-rr \
	--sched-priority 98 \
	--window-size 50000
```

AUTHOR
======

isochron was written by Vladimir Oltean <vladimir.oltean@nxp.com>

SEE ALSO
========

isochron(8)
isochron-rcv(8)
isochron-report(1)

COMMENTS
========

This man page was written using [pandoc](http://pandoc.org/) by the same author.
