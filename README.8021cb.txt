This archive contains a demonstration of 802.1CB on the NXP LS1028A-RDB board.
It has been tested on the OpenIL master branch (commit 4d07120a2c89
("configs/nxp_ls1021atsn_optee-sb: fix optee-os build issue")).

Perform the following changes to nxp_ls1028ardb-64b_defconfig:

diff --git a/configs/nxp_ls1028ardb-64b_defconfig b/configs/nxp_ls1028ardb-64b_defconfig
index ecd87d5b20c5..5a13571f3874 100644
--- a/configs/nxp_ls1028ardb-64b_defconfig
+++ b/configs/nxp_ls1028ardb-64b_defconfig
@@ -171,3 +171,7 @@ BR2_PACKAGE_IPERF=y
 BR2_TOOLCHAIN_HAS_THREADS=y
 BR2_PACKAGE_IPERF3=y
 BR2_PACKAGE_TCPDUMP=y
+BR2_PACKAGE_RSYNC=y
+BR2_PACKAGE_JQ=y
+
+BR2_GLOBAL_PATCH_DIR="board/nxp/ls1028ardb/patches/"

Add the tsn-scripts patches to the OpenIL kernel for LS1028A-RDB:

rsync -avr deps/patches /path/to/openil/board/nxp/ls1028ardb/

Build with:
make nxp_ls1028ardb-64b_defconfig O=output-ls1028ardb
make O=output-ls1028ardb | tee build.log

Copy this folder to the home directory of the root user on the three boards.
You can either do that after build, offline, or transfer the scripts over the network.

Offline:

[tsn-scripts] # rsync -avr . /path/to/openil/output-ls1028ardb/target/root/tsn-scripts
# Run "make" again to integrate the files newly added to the rootfs into the
# sdcard.img
[openil] # make O=output-ls1028ardb

Online:

[root@board1] # ip addr add 10.0.0.111/24 dev eno0
[root@board2] # ip addr add 10.0.0.112/24 dev eno0
[root@board3] # ip addr add 10.0.0.113/24 dev eno0
[tsn-scripts] # for board in 10.0.0.111 10.0.0.112 10.0.0.113; do rsync -avr . root@${board}:./tsn-scripts/; done

On each board, make sure that all Ethernet ports are up first. Typically this
is the task of a network manager (and for OpenIL it is already done), but if
you are not running one, it must be done manually:

[root@OpenIL]# for eth in eno2 eno3 swp0 swp1; do ip link set dev $eth up; done

[root@board1]# ./tsn-scripts/8021cb.sh 1
[root@board2]# ./tsn-scripts/8021cb.sh 2
[root@board3]# ./tsn-scripts/8021cb.sh 3

Then follow the commands printed by the scripts above. In the OpenIL rootfs,
tcpdump and iperf3 are installed by default.

Ping test:

[root@board1 ~] # ping 172.15.0.2
PING 172.15.0.2 (172.15.0.2): 56 data bytes
64 bytes from 172.15.0.2: seq=2 ttl=64 time=0.443 ms
64 bytes from 172.15.0.2: seq=3 ttl=64 time=0.368 ms
64 bytes from 172.15.0.2: seq=4 ttl=64 time=0.403 ms
64 bytes from 172.15.0.2: seq=5 ttl=64 time=0.378 ms
64 bytes from 172.15.0.2: seq=6 ttl=64 time=0.369 ms
64 bytes from 172.15.0.2: seq=7 ttl=64 time=0.374 ms
64 bytes from 172.15.0.2: seq=8 ttl=64 time=0.374 ms
64 bytes from 172.15.0.2: seq=9 ttl=64 time=0.401 ms
64 bytes from 172.15.0.2: seq=10 ttl=64 time=0.361 ms
64 bytes from 172.15.0.2: seq=11 ttl=64 time=0.393 ms
64 bytes from 172.15.0.2: seq=12 ttl=64 time=0.387 ms
64 bytes from 172.15.0.2: seq=13 ttl=64 time=0.374 ms
64 bytes from 172.15.0.2: seq=14 ttl=64 time=0.387 ms
64 bytes from 172.15.0.2: seq=15 ttl=64 time=0.399 ms
64 bytes from 172.15.0.2: seq=16 ttl=64 time=0.374 ms
64 bytes from 172.15.0.2: seq=17 ttl=64 time=0.419 ms
^C
--- 172.15.0.2 ping statistics ---
18 packets transmitted, 16 packets received, 11% packet loss
round-trip min/avg/max = 0.361/0.387/0.443 ms

Currently, due to an unidentified issue, the first 2 packets in a TSN stream
are always lost. No packet loss is expected afterwards.

iperf test:

[root@board2 ~] # iperf3 -s
[root@board1 ~] # iperf3 -c 172.15.0.2
Connecting to host 172.15.0.2, port 5201
[  5] local 172.15.0.1 port 35772 connected to 172.15.0.2 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   103 MBytes   860 Mbits/sec  1124   4.24 KBytes
[  5]   1.00-2.00   sec  87.1 MBytes   730 Mbits/sec  921   19.8 KBytes
[  5]   2.00-3.00   sec   105 MBytes   880 Mbits/sec  1064   17.0 KBytes
[  5]   3.00-4.00   sec   106 MBytes   888 Mbits/sec  1080   18.4 KBytes
[  5]   4.00-5.00   sec   106 MBytes   888 Mbits/sec  1099   26.9 KBytes
[  5]   5.00-6.00   sec   106 MBytes   889 Mbits/sec  1110   24.0 KBytes
[  5]   6.00-7.00   sec   106 MBytes   889 Mbits/sec  1045   24.0 KBytes
[  5]   7.00-8.00   sec   106 MBytes   887 Mbits/sec  1075   21.2 KBytes
[  5]   8.00-9.00   sec   106 MBytes   889 Mbits/sec  1118   18.4 KBytes
[  5]   9.00-10.00  sec   106 MBytes   888 Mbits/sec  1127   18.4 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  1.01 GBytes   869 Mbits/sec  10763             sender
[  5]   0.00-10.00  sec  1.01 GBytes   869 Mbits/sec                  receiver

iperf Done.


You may unplug any single cable at a time from the setup and still notice zero
downtime.

The third board is there in order to introduce asymmetric path delay between
board 2 (sender) and 1 (receiver) on the two member streams. This is a
challenge in 802.1CB as the history size of the sliding window needs to account
for such differences in path delay. This is currently a knob for the user to
tune depending on network. In lack of a third board, the scripts may be in
principle adapted to work in a 2-board ring setup.

For cabling and further information, see the comments inside 8021cb.sh. The TSN
streams recognized by each board are described in the .json files.
In principle the number of TSN streams in the network needs to scale with the
square of the number of boards, but this depends on what traffic paths are
required. In this case, there are 9 TSN streams in total. A TSN stream is
recognized by the pair formed by {destination MAC, VLAN ID} - called "NULL
stream identification". Each board has its own MAC address on eno2 which
identifies it as a sender, and also each board needs to send traffic using its
own VLAN ID which identifies it as a sender. So actually the number of TSN
streams is the # of senders times the # of receivers.
Out of the 9 TSN streams, each board needs to be aware of only 4 streams:
- The 2 TSN streams for traffic sent to the other boards: DMAC=$(other board's
  MAC), VID=$(my vid)
- The 2 TSN streams for traffic coming from each other board to itself:
  DMAC=$(my MAC), VID=$(other board's VID).
For the rest of 5 TSN streams, the board is a simple pass-through and performs
L2 forwarding.
