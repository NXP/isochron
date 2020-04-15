This archive contains a demonstration of 802.1CB on the NXP LS1028A-RDB board.
It has been tested on the OpenIL 1.6 Buildroot rootfs
(nxp_ls1028ardb-64b_defconfig) with the following changes:

BR2_PACKAGE_JQ=y
BR2_PACKAGE_TCPDUMP=y

and kernel LSDK-19.09-update-311219-V4.19:
https://source.codeaurora.org/external/qoriq/qoriq-components/linux/?h=LSDK-19.09-update-311219-V4.19

On each board, make sure that all Ethernet ports are up first. Typically this
is the task of a network manager, but if you are not running one, it must be
done manually:

[root@OpenIL]# for eth in eno2 eno3 swp0 swp1; do ip link set dev $eth up; done

Copy this folder to the home directory of the root user on three boards and run
as follows:

[root@board1]# ./tsn-scripts/8021cb.sh 1
[root@board2]# ./tsn-scripts/8021cb.sh 2
[root@board3]# ./tsn-scripts/8021cb.sh 3

Then follow the commands printed by the scripts above. Example:

[root@board1]# ./tsn-scripts/raw-l2-rcv -i eno2.101 -T
[root@board1]# ./tsn-scripts/raw-l2-send -i eno2 -T -d 00:04:9f:63:35:eb -v 102 -p 0 -b 0 -c 0.2 -n 20000 -s 100

You may unplug any single cable at a time from the setup and still notice zero
downtime (no skips in reported sequence numbers in raw-l2-rcv).

The third board is there in order to introduce asymmetric path delay between
board 2 (sender) and 1 (receiver) on the two member streams. This is a
challenge in 802.1CB as the history size of the sliding window needs to account
for such differences in path delay. This is currently a knob for the user to
tune depending on network. In lack of a third board, the scripts may be in
principle adapted to work in a 2-board ring setup.

For cabling and further information, see the comments inside 8021cb.sh.
