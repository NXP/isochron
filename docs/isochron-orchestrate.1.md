% isochron-orchestrate(1) | ISOCHRON

NAME
====

isochron-orchestrate - Coordinate isochron daemons

SYNOPSIS
========

**isochron** orchestrate \[_OPTIONS_\]

DESCRIPTION
===========

This command opens an orchestration file containing descriptions of
daemons: how to reach them, their names, roles and parameters for the
test. It connects to these daemons, informs them of their parameters,
and coordinates them such that they start sending traffic only when
their synchronization offset becomes lower than the required threshold.
After the test is done, the packet logs are gathered by the orchestrator
from each sender and its associated receiver, and saved on the local
filesystem.

OPTIONS
=======

`-h`, `--help`

:   prints the short help message and exits

`-F`, `--input-file` <`PATH`>

:   specify the path to the input orchestration file.

ORCHESTRATION FILE FORMAT
=========================

The orchestration file has an INI-style format supporting multi-line
statements, and with comments being delineated by the # character.
Each section denotes an orchestration node, and the lines that follow
have a "key = value" format that describe parameters for this node.

`host`

:   denotes the IP address through which the isochron daemon can be
    reached by the orchestrator.

`port`

:   denotes the TCP port through which the isochron daemon can be
    reached by the orchestrator.

`exec`

:   denotes the command to be executed by the isochron daemon. The
    syntax is identical to what would be specified as command line
    arguments to `isochron-send`. The expected behavior of a daemon in
    the role of a sender is also identical to that of a dedicated
    sender, with some exceptions. The `--output-file` is interpreted by
    the orchestrator, not by the daemon (therefore, files are saved on
    the orchestrator's filesystem). Communication through the management
    socket does not take place between an orchestrated sender and its
    receiver. Instead, the orchestrator deduces the address and port of
    the receiver through the `--client` and `--stats-port` arguments of
    the sender, and connects by itself to the receiver. An orchestrated
    sender does not monitor sync status by itself and does not decide
    when to start sending test packets. Instead, these are controlled by
    the orchestrator.

EXAMPLES
========

It is possible to orchestrate two senders running on hosts A (10.0.0.1)
and B (10.0.0.2), sending towards two receivers both on host C
(10.0.0.3), from a management node D, for the purpose of creating packet
collisions and measuring the resulting latency.

The commands on nodes A and B are:

```
ptp4l -i eth0 -2 -P --step_threshold 0.00002 &
phc2sys -a -rr --step_threshold 0.00002 &
isochron daemon
```

The commands on node C are:

```
ptp4l -i eth0 -2 -P --step_threshold 0.00002 &
phc2sys -a -rr --step_threshold 0.00002 &
isochron rcv --interface eth0 --stats-port 5000 --etype 0xdead &
isochron rcv --interface eth0 --stats-port 5001 --etype 0xdeaf &
```

The commands on node D are (the double backslashes are to prevent the
shell from interpreting them when creating the heredoc, the resulting
file will have simple backslashes):

```
cat <<- EOF > orchestration.txt
[A]
host = 10.0.0.1
port = 5000
exec = isochron send \\
        --client 10.0.0.3 \\
        --stats-port 5000 \\
        --interface eth0 \\
        --num-frames 10 \\
        --base-time 0.000000000 \\
        --cycle-time 0.01 \\
        --frame-size 1500 \\
        --sync-threshold 100 \\
        --cpu-mask 0x1 \\
        --sched-fifo \\
        --sched-priority 98 \\
        --etype 0xdead \\
        --output-file isochron-host-a.dat

[B]
host = 10.0.0.2
port = 5000
exec = isochron send \\
        --client 10.0.0.3 \\
        --stats-port 5001 \\
        --interface eth0 \\
        --num-frames 10 \\
        --base-time 0.000000100 \\
        --cycle-time 0.01 \\
        --frame-size 1500 \\
        --sync-threshold 100 \\
        --cpu-mask 0x1 \\
        --sched-fifo \\
        --sched-priority 98 \\
        --etype 0xdeaf \\
        --output-file isochron-host-b.dat
EOF

isochron orchestrate --input-file orchestration.txt
isochron report --summary --input-file isochron-host-a.dat
isochron report --summary --input-file isochron-host-b.dat
```

AUTHOR
======

isochron was written by Vladimir Oltean <vladimir.oltean@nxp.com>

SEE ALSO
========

isochron(8)
isochron-send(8)
isochron-daemon(8)

COMMENTS
========

This man page was written using [pandoc](http://pandoc.org/) by the same author.
