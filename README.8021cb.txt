This archive contains a demonstration of 802.1CB on the NXP LS1028A-RDB board.
It has been tested on the OpenIL 1.5 Ubuntu rootfs and requires the latest
OpenIL kernel from the master branch - current HEAD at d90d41818636 ("ipipe:
work around: force all interrupts to unlazy disable mode").
Copy this folder to the home directory of the root user on two boards and run
as follows:

[root@board1]# ./time-test 1 prepare
[root@board2]# ./time-test 2 prepare
[root@board3]# ./time-test 3 prepare

Then follow the commands printed by the scripts above. Example:

[root@board1]# /root/raw-l2-rcv eno2.100
[root@board1]# /root/raw-l2-send eno2.100 00:04:9f:05:de:0a 7 +0.1 0.0 0.2 30 64

You may unplug any single cable at a time from the setup and still notice zero
downtime (no skips in reported sequence numbers in raw-l2-rcv).

The third board is there in order to introduce asymmetric path delay between
board 2 (sender) and 1 (receiver) on the two member streams. This is a
challenge in 802.1CB as the history size of the sliding window needs to account
for such differences in path delay. This is currently a knob for the user to
tune depending on network. In lack of a third board, the scripts may be in
principle adapted to work in a 2-board ring setup.

For cabling and further information, see the comments inside 8021cb.sh.
