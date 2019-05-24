#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

set -e -u -o pipefail

# This example will send a unidirectional traffic stream from Board 2 to
# Board 1 through two paths:
#
# - Directly through B2.SWP4 -> B2.SWP1 -> B1.SWP1 -> B1.SWP4
# - Through Board 3: B2.SWP4 -> B2.SWP2 -> B3.SWP2 -> B1.SWP0 -> B1.SWP4
#
#   Board 1:
#
#   +---------------------------------------------------------------------------------+
#   |                                                                                 |
#   | +------------+   +------------+  +------------+  +------------+  +------------+ |
#   | |            |   | To Board 3 |  | To Board 2 |  |            |  |            | |
#   | |            | +-|    SW0     |  |    SW1     |  |            |  |            | |
#   | |            | | |            |  |            |  |            |  |            | |
#   +-+------------+-|-+------------+--+------------+--+------------+--+------------+-+
#          MAC0      |      SW0             SW1             SW2              SW3
#                    |                       |
#   Board 2:         |                       |
#                    |                       |
#   +----------------|-----------------------+----------------------------------------+
#   |                |                       |                                        |
#   | +------------+ | +------------+  +------------+  +------------+  +------------+ |
#   | |            | | |            |  | To Board 1 |  | To Board 3 |  |            | |
#   | |            | | |            |  |    SW1     |  |    SW2     |  |            | |
#   | |            | | |            |  |            |  |            |  |            | |
#   +-+------------+-|-+------------+--+------------+--+------------+--+------------+-+
#          MAC0      |      SW0             SW1             SW2              SW3
#                    |                                       |
#                    |                                       |
#   Board 3:         |                                       |
#                    |                                       |
#   +----------------|---------------------------------------+------------------------+
#   |                |                                       |                        |
#   | +------------+ | +------------+  +------------+  +------------+  +------------+ |
#   | |            | | | To Board 1 |  |            |  | To Board 2 |  |            | |
#   | |            | +-|    SW0     |  |            |  |    SW2     |  |            | |
#   | |            |   |            |  |            |  |            |  |            | |
#   +-+------------+---+------------+--+------------+--+------------+--+------------+-+
#          MAC0             SW0             SW1             SW2              SW3

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}. Are all cables plugged in?"
	exit "${code}"
}
trap 'error ${LINENO}' ERR

usage() {
	echo "Usage:"
	echo "$0 1|2|3"
}

do_bridging() {
	[ -d /sys/class/net/br0 ] && ip link del dev br0

	ip link add name br0 type bridge stp_state 0 vlan_filtering 1 && ip link set br0 up
	for eth in $(ls /sys/bus/pci/devices/0000:00:00.5/net/); do
		ip addr flush dev ${eth};
		ip link set ${eth} master br0
		ip link set ${eth} up
		# No pvid by default
		bridge vlan del vid 1 dev ${eth}
	done
	ip link set br0 arp off
}

do_vlan() {
	local vid="$1"
	local ports="$2"
	local flags="$3"

	[ -d "/sys/class/net/eno2.${vid}" ] && ip link del dev "eno2.${vid}"

	ip link add link eno2 name "eno2.${vid}" type vlan id ${vid} \
		ingress-qos-map 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7 \
		egress-qos-map 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
	ip link set dev "eno2.${vid}" up

	for port in ${ports}; do
		bridge vlan add vid ${vid} dev ${port} ${flags}
	done
}

get_remote_mac() {
	local ip="$1"
	local format="$2"
	local awk_program=

	case "${format}" in
	tsntool)
		awk_program='							\
			/Unicast reply from/					\
			{							\
				mac=gensub(/^\[(.*)\]/, "\\1", "g", $5);	\
				split(mac, m, ":");				\
				print "0x" m[1] m[2] m[3] m[4] m[5] m[6];	\
			}'
		;;
	iproute2)
		awk_program='							\
			/Unicast reply from/					\
			{							\
			       mac=gensub(/^\[(.*)\]/, "\\1", "g", $5);		\
			       print mac;					\
			}'
		;;
	*)
		return
	esac

	arping -I eno2 -c 1 "${ip}" | awk "${awk_program}"
}

get_local_mac() {
	local port="$1"
	local format="$2"
	local awk_program=

	case "${format}" in
	tsntool)
		awk_program='							\
			/link[\/]ether/ {					\
				split($2, m, ":");				\
				print "0x" m[1] m[2] m[3] m[4] m[5] m[6];	\
			}'
		;;
	iproute2)
		awk_program='							\
			/link[\/]ether/ {					\
				print $2;					\
			}'
		;;
	*)
		return
	esac
	ip link show dev ${port} | awk "${awk_program}"
}

[ $# = 1 ] || usage
board=$1; shift

do_bridging
iptables -t nat --flush
iptables -t filter --flush

case "${board}" in
1)
	do_vlan 1 "swp0 swp1 swp4" "pvid untagged"
	ip addr flush dev eno2; ip addr add 192.168.1.1/24 dev eno2
	ip link set dev eno2 up

	# Terminates replicated, unidirectional L2 traffic from Board 1,
	# over VID 100
	do_vlan 100 "swp0 swp1 swp4" ""
	ip addr flush dev eno2.100; ip addr add 192.168.100.1/24 dev eno2.100
	board1=$(get_local_mac eno2 tsntool)
	tsntool cbstreamidset --device swp4 --streamhandle 1 \
		--nullstreamid --nulldmac "${board1}" --nullvid 100
	for eth in swp0 swp1; do
		tsntool cbrec --device "${eth}" --index 1 \
			--seq_len 16 --his_len 31 --rtag_pop_en
	done

	# And return path...
	board2=$(get_remote_mac 192.168.1.2 tsntool)
	tsntool cbstreamidset --device swp0 --streamhandle 2 \
		--nullstreamid --nulldmac "${board2}" --nullvid 100
	tsntool cbstreamidset --device swp1 --streamhandle 3 \
		--nullstreamid --nulldmac "${board2}" --nullvid 100
	tsntool cbgen --device swp5 --index 2 --seq_len 16 --seq_num 0 \
		--iport_mask $((1<<4)) --split_mask $((1<<1))
	tsntool cbgen --device swp5 --index 3 --seq_len 16 --seq_num 0 \
		--iport_mask $((1<<4)) --split_mask $((1<<0))

	board2=$(get_remote_mac 192.168.1.2 iproute2)
	arp -s 192.168.100.2 "${board2}" dev eno2.100

	echo "To test with traffic, run:"
	echo "./raw-l2-rcv eno2.100"
	echo "ip link set dev swp0 down"
	echo "ip link set dev swp0 up"
	echo "ip link set dev swp1 down"
	echo "ip link set dev swp1 up"
	;;
2)
	do_vlan 1 "swp1 swp2 swp4" "pvid untagged"
	ip addr flush dev eno2; ip addr add 192.168.1.2/24 dev eno2
	ip link set dev eno2 up

	# Originates replicated, unidirectional L2 traffic to Board 1
	do_vlan 100 "swp1 swp2 swp4" ""
	ip addr flush dev eno2.100; ip addr add 192.168.100.2/24 dev eno2.100
	board1=$(get_remote_mac 192.168.1.1 tsntool)
	# Configure two Seamless Stream IDs (SSID) for outbound traffic to
	# board 1.  This configuration needs to be applied over each switch
	# port that will be performing egress.  Otherwise when one of the
	# redundant links goes down, the SSID will no longer match that egress
	# port's PGID and splitting will no longer be performed.
	tsntool cbstreamidset --device swp1 --streamhandle 1 \
		--nullstreamid --nulldmac "${board1}" --nullvid 100
	tsntool cbstreamidset --device swp2 --streamhandle 2 \
		--nullstreamid --nulldmac "${board1}" --nullvid 100
	# The switch port specified as parameter to --device here does not
	# matter, it is simply an anchor for tsntool to talk to the switch
	# driver.  As a convention, swp5 will be used.
	#
	# The --index option points to the SSID for which the generation rule is
	# applied. It must match the --streamhandle option for cbstreamidset.
	#
	# The --iport_mask specifies on which ingress switch ports this
	# sequence generation rule will match. This is in contrast with
	# --device swp3 specified to cbstreamidset, which specifies the egress
	# switch port. By specifying e.g. the 0x3f port mask, the rule will
	# match traffic coming from any ingress port.
	#
	# The --split_mask argument configures the egress ports onto which this
	# stream generation rule will replicate the packets. This is in
	# addition to the standard L2 forwarding rules.
	tsntool cbgen --device swp5 --index 1 --seq_len 16 --seq_num 0 \
		--iport_mask $((1<<4)) --split_mask $((1<<2))
	tsntool cbgen --device swp5 --index 2 --seq_len 16 --seq_num 0 \
		--iport_mask $((1<<4)) --split_mask $((1<<1))

	board1=$(get_remote_mac 192.168.1.1 iproute2)
	arp -s 192.168.100.1 "${board1}" dev eno2.100

	# And return path...
	board2=$(get_local_mac eno2 tsntool)
	tsntool cbstreamidset --device swp4 --streamhandle 3 \
		--nullstreamid --nulldmac "${board2}" --nullvid 100
	for eth in swp1 swp2; do
		tsntool cbrec --device "${eth}" --index 3 \
			--seq_len 16 --his_len 31 --rtag_pop_en
	done
	# Rewrite destination address of ping request
	iptables -t nat -A PREROUTING -d 192.168.1.1 -p icmp --icmp-type echo-request -j DNAT --to 192.168.100.1
	iptables -t filter -A FORWARD -p icmp -d 192.168.100.1 -j ACCEPT
	iptables -t nat -A POSTROUTING -s 192.168.100.2 -p icmp --icmp-type echo-reply -j SNAT --to 192.168.1.2
	echo "To test with traffic, run:"
	echo "./raw-l2-send eno2.100 ${board1} 7 +0.1 0.2 10"
	;;
3)
	# The untagged port-based VLAN (pvid) has the loop intentionally broken
	# here at swp0.  This is similar, but not the same, as enabling STP
	# which would put the entire port in BLOCKING state, the latter being
	# undesirable as it would disallow the transmission of all VLAN-tagged
	# traffic.
	# We allow loops in the VID 100 used for redundancy but explicitly
	# control which frames are tagged with that VLAN.
	do_vlan 1 "swp2 swp4" "pvid untagged"
	ip addr flush dev eno2; ip addr add 192.168.1.3/24 dev eno2
	ip link set dev eno2 up

	# Forwards one member stream of the replicated traffic
	do_vlan 100 "swp0 swp2" ""
	echo "This board is forwarding redundant traffic, no further configuration needed."
	;;
*)
	usage
	;;
esac
