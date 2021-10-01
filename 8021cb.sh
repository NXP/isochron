#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

set -e -u -o pipefail

export TOPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)

#                                  +--------------------------------+
#   Board 3:                       |                                |
#                                  |                                |
#   +------------------------------|----------------------------+   |
#   |                              |                            |   |
#   | +--------+    +--------+ +--------+ +--------+ +--------+ |   |
#   | |        |    |        | |        | |        | |        | |   |
#   | |  MAC0  |    |  SWP0  | |  SWP1  | |  SWP2  | |  SWP3  | |   |
#   | |        |    |        | |        | |        | |        | |   |
#   +-+--------+----+--------+-+--------+-+--------+-+--------+-+   |
#                       |                                           |
#                       |                                           |
#                       +----------+                                |
#   Board 2:                       |                                |
#                                  |                                |
#   +------------------------------|----------------------------+   |
#   |                              |                            |   |
#   | +--------+    +--------+ +--------+ +--------+ +--------+ |   |
#   | |        |    |        | |        | |        | |        | |   |
#   | |  MAC0  |    |  SWP0  | |  SWP1  | |  SWP2  | |  SWP3  | |   |
#   | |        |    |        | |        | |        | |        | |   |
#   +-+--------+----+--------+-+--------+-+--------+-+--------+-+   |
#                       |                                           |
#                       |                                           |
#                       +----------+                                |
#   Board 1:                       |                                |
#                                  |                                |
#   +------------------------------|----------------------------+   |
#   |                              |                            |   |
#   | +--------+    +--------+ +--------+ +--------+ +--------+ |   |
#   | |        |    |        | |        | |        | |        | |   |
#   | |  MAC0  |    |  SWP0  | |  SWP1  | |  SWP2  | |  SWP3  | |   |
#   | |        |    |        | |        | |        | |        | |   |
#   +-+--------+----+--------+-+--------+-+--------+-+--------+-+   |
#                       |                                           |
#                       |                                           |
#                       +-------------------------------------------+

usage() {
	echo "Usage:"
	echo "$0 1|2|3"
	return 1
}

board1_ip_address="172.15.0.1"
board2_ip_address="172.15.0.2"
board3_ip_address="172.15.0.3"
board1_mac_address="00:04:9f:63:35:ea"
board2_mac_address="00:04:9f:63:35:eb"
board3_mac_address="00:04:9f:63:35:ec"
board1_vid="101"
board2_vid="102"
board3_vid="103"

# 1 -> 2: split at B1.SWP1, recover at B2.SWP4
# 1 -> 3: split at B1.SWP0, recover at B3.SWP4
# 2 -> 1: split at B2.SWP1, recover at B1.SWP4
# 2 -> 3: split at B2.SWP2, recover at B3.SWP4
# 3 -> 1: split at B3.SWP0, recover at B3.SWP4
# 3 -> 2: split at B3.SWP2, recover at B3.SWP4

[ $# = 1 ] || usage
num=$1; shift

eval $(echo my_ip=\$board${num}_ip_address)
eval $(echo my_mac=\$board${num}_mac_address)
eval $(echo my_vid=\$board${num}_vid)

ip link set dev eno2 address ${my_mac}
ip addr flush dev eno2 && ip addr add ${my_ip}/24 dev eno2

sed -e "s|%BOARD1_MAC_ADDRESS%|${board1_mac_address}|g" \
	-e "s|%BOARD2_MAC_ADDRESS%|${board2_mac_address}|g" \
	-e "s|%BOARD3_MAC_ADDRESS%|${board3_mac_address}|g" \
	-e "s|%BOARD1_VID%|${board1_vid}|g" \
	-e "s|%BOARD2_VID%|${board2_vid}|g" \
	-e "s|%BOARD3_VID%|${board3_vid}|g" \
	${TOPDIR}/8021cb-board${num}.json.template > \
	${TOPDIR}/8021cb-board${num}.json

${TOPDIR}/8021cb-load-config.sh -f ${TOPDIR}/8021cb-board${num}.json

echo "Adding VLAN mangling rules (see with 'tc filter show dev eno2 egress && tc filter show dev eno2 ingress')"

if tc qdisc show dev eno2 | grep clsact; then tc qdisc del dev eno2 clsact; fi
tc qdisc add dev eno2 clsact
tc filter add dev eno2 egress flower \
	dst_mac $board1_mac_address \
	action vlan push id $my_vid
tc filter add dev eno2 egress flower \
	dst_mac $board2_mac_address \
	action vlan push id $my_vid
tc filter add dev eno2 egress flower \
	dst_mac $board3_mac_address \
	action vlan push id $my_vid
tc filter add dev eno2 protocol 802.1Q ingress flower \
	dst_mac $my_mac vlan_id $board1_vid \
	action vlan pop
tc filter add dev eno2 protocol 802.1Q ingress flower \
	dst_mac $my_mac vlan_id $board2_vid \
	action vlan pop
tc filter add dev eno2 protocol 802.1Q ingress flower \
	dst_mac $my_mac vlan_id $board3_vid \
	action vlan pop
# Accept all VLAN tags on ingress
ethtool -K eno2 rx-vlan-filter off

echo "Populating the ARP table..."
for board in 1 2 3; do
	if [ ${board} = ${num} ]; then
		continue
	fi
	eval $(echo other_mac=\$board${board}_mac_address)
	eval $(echo other_ip=\$board${board}_ip_address)
	arp -s ${other_ip} ${other_mac} dev eno2
done

echo "Ready to send/receive traffic. IP address of board is ${my_ip}"
