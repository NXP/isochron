This archive contains a demonstration of 802.1Qbv on the NXP LS1028A-RDB board.
It covers both the standalone ENETC port as well as the Felix switch ports.
It has been tested on the OpenIL 1.5 Ubuntu rootfs image with BSP 0.3 kernel,
but it should work on the plain BSP 0.3 userspace image as well.
Copy this folder to the home directory of the root user on two boards and run
as follows:

[root@board1]# ./time-test 1 prepare
[root@board2]# ./time-test 2 prepare
[root@board1]# ./time-test 1 run

A Qbv latency report will be generated.

Systemd services for the linuxptp package suite will be installed on the target
board during the "prepare" phase. Be aware of this as they might overwrite
other such services (although NXP rootfs images do not provide them by
default).

The linuxptp suite itself is not provided as part of this package, and the
version bundled with the Ubuntu userspace is not recommended. Please get
linuxptp from its home git repository.

To change the scenario between ENETC and Felix, you need to edit the "scenario"
Bash variable from time-test.sh.

For cabling and further information, see the comments inside time-test.sh.
