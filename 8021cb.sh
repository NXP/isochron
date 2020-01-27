#!/bin/bash
# For command line output debugging, append -x to the above line
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

set -e -u -o pipefail

export TOPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)

#   Board 1:
#
#   +---------------------------------------------------------------------------------+
#   |                                                                                 |
#   | +------------+   +------------+  +------------+  +------------+  +------------+ |
#   | |            |   | To Board 2 |  | To Board 2 |  |            |  |            | |
#   | |            | +-|    SW1     |  |    SW0     |  |            |  |            | |
#   | |            | | |            |  |            |  |            |  |            | |
#   +-+------------+-|-+------------+--+------------+--+------------+--+------------+-+
#          MAC0      |      SW0             SW1             SW2              SW3
#                    |                       |
#   Board 2:         |       +---------------+
#                    |       |
#   +----------------|-------|--------------------------------------------------------+
#   |                |       |                                                        |
#   | +------------+ | +------------+  +------------+  +------------+  +------------+ |
#   | |            | | | To Board 1 |  | To Board 1 |  |            |  |            | |
#   | |            | | |    SW1     |  |    SW0     |  |            |  |            | |
#   | |            | | |            |  |            |  |            |  |            | |
#   +-+------------+-|-+------------+--+------------+--+------------+--+------------+-+
#          MAC0      |      SW0             SW1             SW2              SW3
#                    |                       |
#                    +-----------------------+
#

usage() {
	echo "Usage:"
	echo "$0 1|2"
	return 1
}

board1_mac_address="00:04:9f:63:35:ea"
board2_mac_address="00:04:9f:63:35:eb"
board1_vid="101"
board2_vid="101"

# 1 -> 2: split at B1.SWP1, recover at B2.SWP4
# 2 -> 1: split at B2.SWP1, recover at B1.SWP4

[ $# = 1 ] || usage
num=$1; shift

eval $(echo my_mac=\$board${num}_mac_address)
eval $(echo my_vid=\$board${num}_vid)

ip link set dev eno2 address ${my_mac}
ip link set dev eno2 mtu 1496

for eth in eno2 eno3 swp0 swp1 swp2 swp3 swp4; do
	ip link set dev $eth up
done

sed     -e "s|%BOARD1_MAC_ADDRESS%|${board1_mac_address}|g" \
	-e "s|%BOARD2_MAC_ADDRESS%|${board2_mac_address}|g" \
	-e "s|%BOARD1_VID%|${board1_vid}|g" \
	-e "s|%BOARD2_VID%|${board2_vid}|g" \
	${TOPDIR}/8021cb-board${num}.json.template > \
	${TOPDIR}/8021cb-board${num}.json

${TOPDIR}/8021cb-load-config.sh -f ${TOPDIR}/8021cb-board${num}.json

for board in 1 2; do
	if [ ${board} = ${num} ]; then
		continue
	fi
	eval $(echo other_mac=\$board${board}_mac_address)
	eval $(echo other_vid=\$board${board}_vid)
	echo "To board ${board}:"
	echo "${TOPDIR}/raw-l2-send -i eno2 -d ${other_mac} -v ${other_vid} -p 0 -b 0 -c 0.2 -n 20000 -s 100 -T"
done

echo "To see traffic to this board:"
echo "${TOPDIR}/raw-l2-rcv -i eno2.${my_vid} -T"
echo "Or raw:"
echo "tcpdump -i eno2 -e -n -Q in"

# FIXME: This is an attempt to make IP traffic, such as ping, work between
# boards, through the redundancy VLANs. The trouble is the return path (ICMP
# reply), which will have the VID of the receiver, when it should really have
# the VID of the sender. We need a rule of some sorts to do the VLAN ID
# mangling.
# -> This was "fixed" by using one VLAN ID
#
# FIXME: ARP causes the network to become conjested for some reason.  Turn it
# off on the ring subnet and use static assingments as a workaround.
#
# From Board 1:
# ping 172.15.102.2 # to board 2
# From Board 2:
# ping 172.15.101.1 # to board 1

for vid in ${board1_vid}; do
	echo "*** Assigning eno2.vid IP addresses ***"
	ip link set dev eno2.${vid} arp off
	ip addr add 172.15.${vid}.${num}/24 dev eno2.${vid}
	for board in 1 2; do
		if [ ${board} = ${num} ]; then
			continue
		fi
		eval $(echo other_mac=\$board${board}_mac_address)
		arp -s 172.15.${vid}.${board} ${other_mac} dev eno2.${vid}
	done
done
