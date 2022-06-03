% isochron-daemon(8) | ISOCHRON

NAME
====

isochron-daemon - Start an isochron program waiting for management commands

SYNOPSIS
========

**isochron** daemon \[_OPTIONS_\]

DESCRIPTION
===========

This command starts a long-running process that listens for connections
from an isochron orchestrator. The daemon can receive further
instructions from the orchestrator.

OPTIONS
=======

`-h`, `--help`

:   prints the short help message and exits

`-l`, `--log-file` <`PATH`>

:   after becoming a daemon, the program can redirect its standard
    output and standard error to the text file specified here.
    Optional, defaults to `/dev/null`.

`-p`, `--pid-file` <`PATH`>

:   after spawning a daemon process, the main program overwrites the
    text file provided here with a single line containing a decimal
    number representing the process ID of the daemon. Optional, defaults
    to no PID file being created.

`-P`, `--stats-port` <`NUMBER`>

:   specify the TCP port on which the daemon program is listening for
    incoming connections. This socket is used for management and
    statistics. Optional, defaults to port 5000.

`-S`, `--stats-address` <`NUMBER`>

:   specify the IP address on which the daemon program is listening for
    incoming connections. This socket is used for management and
    statistics. Supports binding to a given network device using the
    `address%device` syntax (example: `--stats-address ::%vrf0`).
    Optional, defaults to ::, with a fallback to 0.0.0.0 if IPv6 is not
    available.

EXAMPLES
========

To start and then stop a daemon and view its log file:

```
isochron daemon \
	--log-file isochron.log \
	--pid-file isochron.pid \
	--stats-port 5001
tail -F isochron.log &
kill $(pidof tail)
kill $(cat isochron.pid)
```

AUTHOR
======

isochron was written by Vladimir Oltean <vladimir.oltean@nxp.com>

SEE ALSO
========

isochron(8)
isochron-orchestrate(1)

COMMENTS
========

This man page was written using [pandoc](http://pandoc.org/) by the same author.
