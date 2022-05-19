% isochron(8) | ISOCHRON

NAME
====

isochron - Time sensitive network testing tool

SYNOPSIS
========

**isochron** _VERB_ \[_OPTIONS_\]

_VERB_ := { daemon | orchestrate | send | rcv | report }

DESCRIPTION
===========

The isochron is a Linux user space application for testing timing
characteristics of endpoints and bridges in Ethernet networks.

The tool works by sending network packets between one instance of the
program (the sender) and another (the receiver) and taking timestamps at
various points along the way. The receiver has a second network socket
through which it transmits its collected timestamps back towards the
sender. The sender aggregates all timestamps and optionally records them
to a file which can be queried at a later time.

Timestamps are taken in 4 different time bases which must be in sync
with one another:

  * Software timestamping using the sender's system clock
  * Hardware timestamping inside the sender's NIC
  * Hardware timestamping inside the receiver's NIC
  * Software timestamping using the receiver's system clock

To ensure that direct comparison between timestamps from different time
bases is possible, the program monitors the synchronization status of
external programs like ptp4l (which synchronizes a local NIC to a remote
NIC) and phc2sys (which synchronizes the system clock to a local NIC)
from the linuxptp project.

Isochron (isochronous traffic == running at equal intervals) is intended
to be used in conjunction with Time Sensitive Networking equipment as
defined by IEEE 802.1 and IEEE 802.3. The measurements can be used for
profiling the software latency of the endpoints or the forwarding
latency of switches.

The isochron program, in both the sender and the receiver role, requires
a network card with the ability to perform hardware timestamping of any
packet, since the isochron test packets are not PTP event messages.

If used in a time sensitive network, isochron expects to be the
exclusive owner of a traffic class, and it must be informed of that that
traffic class' time slot length and offset within the global schedule.

Below is an example where isochron uses priority 5, ptp4l uses priority
7, these two traffic classes have media reservations using a time-aware
shaper, and the other applications are classified as best-effort and go
towards their own time slot.

```
 base-time                         base-time + cycle-time
|---------------------------------|---------------------------------|

Ethernet media reservation:

|xxxxxxxxxxxxxxxxxxxxxxx|---------|xxxxxxxxxxxxxxxxxxxxxxx|---------| tc012346
 <--------------------->           <--------------------->
 best effort                       best effort

|-----------------------|xxxx|----|-----------------------|xxxx|----| tc5
                         <-->                              <-->
                       isochron                          isochron

|----------------------------|xxxx|----------------------------|xxxx| tc7
                              <-->                              <-->
                              ptp4l                             ptp4l
```

Focusing on a single time slot (isochron's traffic class 5), the diagram
below overlaps a few timelines in order to detail how isochron
interprets the command line arguments and how the time is spent:

```
cycle (N - 1)                     cycle N               cycle (N + 1)
base-time - cycle-time            base-time    base-time + cycle-time
|                                 |                                 |
| Media reservation               |                                 |
| for isochron                    |                                 |
v                                 v                                 v
|-----------------------|xxxx|----|-----------------------|xxxx|----|-->
|                window T0   T1   |                window T2   T3   |
|                 size  <---->    |                 size  <---->    |
|                                 |                                 |
| The shift time specifies        |                                 |
| the offset of the time slot     |         shift-time (H)          |
| from the beginning of the cycle |---------------------->|         |
|                                 |                       |         |
|-----------------------|xxxx|----|-----------------------|xxxx|----|-->
|                                 |                                 |
| The advance time specifies      |                                 |
| how much in advance of the      |       advance-time (A)          |
| deadline to wake up        |<---------------------------|         |
|                            |    |                       |         |
|-----------------------|xxxx|----|-----------------------|xxxx|----|-->
|                                 |                                 |
| isochron schedules a wakeup     |                                 |
| at application base time b and  |                                 |
| actually wakes up at time w     |                                 |
|                                 |                                 |
|----------------------------|xxxxxxx|------------------------------|-->
|                            b    |  w                              |
|                                 |                                 |
| The time spent by isochron from |                                 |
| wakeup until it enqueues a      |                                 |
| packet is negligible and not    |                                 |
| measured. The next timestamp    |                                 |
| is the pre-qdisc software       |                                 |
| TX timestamp (s).               |                                 |
|                                 |                                 |
|---------------------------------|--|xxxxx|------------------------|-->
|                                 |  w     s                        |
| isochron requests the NIC       |                                 |
| driver to take a software TX    |                                 |
| timestamp (t).                  |                                 |
|                                 |                                 |
|---------------------------------|--------|xxxxx|------------------|-->
|                                 |        s     t                  |
| isochron requests the NIC       |                                 |
| driver to take a hardware TX    |                                 |
| timestamp (T).                  |                                 |
| There are multiple cases.       |                                 |
|                                 |                                 |
| If no TSN qdisc is used, the    |                                 |
| packet is transmitted right     |                                 |
| away, earlier than the          |                                 |
| scheduled TX time if all        |                                 |
| is well.                        |                                 |
|                                 |                       T2   T3   |
|---------------------------------|-----------------------|xxxx|----|-->
|---------------------------------|--------------|xxxxx|------------|-->
|                                 |              t     T            |
| If tc-taprio is used, the       |                                 |
| packet is transmitted as soon   |                                 |
| as the MAC gate opens (which    |                                 |
| may be a few hundred ns later   |                                 |
| than the scheduled TX time).    |                                 |
|                                 |                       T2   T3   |
|---------------------------------|-----------------------|xxxx|----|-->
|---------------------------------|--------------|xxxxxxxxx|--------|-->
|                                 |              t         T ~= S   |
| If tc-etf is used, the          |                                 |
| packet is transmitted according |                                 |
| to the specified SO_TXTIME cmsg |                                 |
| cmsg, and there is no MAC gate  |                                 |
| open/close event per se.        |                                 |
|                                 |                                 |
|---------------------------------|--------------|xxxxxxxxx|--------|-->
|                                 |              t         T ~= S   |

T0, T2: MAC gate open events for cyclic scheduled traffic
T1, T3: MAC gate close events
```

When a regular qdisc is used, the deadline which needs to be satisfied
by isochron is `(T < S)`.

When the tc-taprio qdisc is used, the deadline is `(t < T2)`.

When the tc-etf qdisc is used, the deadline is `(s + delta < S)`, where
`delta` is the "fudge factor" of the `tc-etf` qdisc.

BUGS
====

Versions starting with `0.x` should be expected to be unstable, and not
necessarily maintain binary compatibility on the network (between sender
and receiver) or on the filesystem (the format of the report file). When
using an unstable version, it is expected that the producer and the
consumer of the data are running the same version of isochron.

AUTHOR
======

isochron was written by Vladimir Oltean <vladimir.oltean@nxp.com>

SEE ALSO
========

isochron-daemon(8)
isochron-orchestrate(1)
isochron-send(8)
isochron-rcv(8)
isochron-report(1)
taprio(8)
etf(8)

COMMENTS
========

This man page was written using [pandoc](http://pandoc.org/) by the same author.
