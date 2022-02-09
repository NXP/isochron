#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019-2021 NXP

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
	echo "usage:"
	echo "$0 [-t <total boards>] [-i <number>]"
	echo "i: a number set for this board(0 < 99)"
	echo "t: total boards in the ring(default 3)"
	echo "h: command parameter help"
}

board_number=0
total_devices=3
while getopts "i:e:t:h" opt; do
	case $opt in
		i)
			board_number=$((OPTARG))
			echo "board number is $board_number"
			;;
		t)
			total_devices=$((OPTARG))
			;;
		h)
			usage
			;;
		?)
			echo "error input parameters"
			usage
			;;
	esac
done

if [[ $board_number -eq 0 ]] ; then
	echo "ERROR: Set a board number (1~99)"
	echo ""
	usage
	exit
fi

base_vid=100

for (( i = 1; i <= total_devices * 3; i++ ));
do
	declare board${i}_ip_address="172.15.0.${i}";
	declare board${i}_mac_address="00:04:9f:63:35:$((i + 0x10))";
	declare board${i}_vid=$(expr $i + $base_vid);
	eval echo "board${i} ip" '$'"board"${i}"_ip_address"
	eval echo "board${i} mac address" '$'"board"${i}"_mac_address"
	eval echo "board${i} vid" '$'"board"${i}"_vid"
done

board_mac_address() {
	local num="${1}"
	local var="board${num}_mac_address"

	echo "${!var}"
}

board_vid() {
	local num="${1}"
	local var="board${num}_vid"

	echo "${!var}"
}

board_ip_address() {
	local num="${1}"
	local var="board${num}_ip_address"

	echo "${!var}"
}

# An example for 3 boards:
# 1 -> 2: split at B1.SWP1, recover at B2.SWP4
# 1 -> 3: split at B1.SWP0, recover at B3.SWP4
# 2 -> 1: split at B2.SWP1, recover at B1.SWP4
# 2 -> 3: split at B2.SWP2, recover at B3.SWP4
# 3 -> 1: split at B3.SWP0, recover at B3.SWP4
# 3 -> 2: split at B3.SWP2, recover at B3.SWP4

num=$board_number
file=${TOPDIR}/8021cb-board${num}.json
echo ${file}

if [ ! -f "$file" ] ; then
	touch "$file"
else
	echo `rm -rf ${file}`
	touch "$file"
fi

#start?
actions_all=""
create_rules() {
	local n=$1
	local external_port="${2}"
	echo "create_rules for parameter ${n}"
	eval $(echo my_ip=\$board${n}_ip_address)
	eval $(echo my_mac=\$board${n}_mac_address)
	eval $(echo my_vid=\$board${n}_vid)

	other_mac_array=""
	other_vid_array=""
	count=0
	for (( i = 1; i <= total_devices * 3 ; i++ ));
	do
		if [ "$(expr $i % $total_devices)" == "${num}" ] ; then
			continue
		fi

		other_mac_array[$count]=`eval echo '$'"board"${i}"_mac_address"`
		other_vid_array[$count]=`eval echo '$'"board"${i}"_vid"`
		count=$(expr $count + 1)
	done

	groups=`echo "${other_mac_array[@]}" `
	mac_array=`jq -c -n --arg groups "$groups" '$groups | split(" ")'`
	params=`echo "{\"ingress_port_mask\": \"$external_port\", \"dmacs\": $mac_array, \"vid\": \"$my_vid\"}"`
	split_action=`echo $params | jq '{
		"match" : {
			"ingress-port-mask": [.ingress_port_mask],
			dmac: .dmacs[],
			vid
		},
		"action" : {
			"type" : "split",
			"egress-port-mask": [ "swp0", "swp1" ]
		}}'`

	groups=`echo ${other_vid_array[@]}`
	vid_array=`jq -c -n --arg groups "$groups" '$groups | split(" ")'`
	params=`echo "{\"egress_port\": \"$external_port\", \"dmac\": \"$my_mac\", \"vids\": $vid_array}"`
	recover_action=`echo $params | jq '{
		"match" : {
			"egress-port": .egress_port,
			dmac,
			vid: .vids[]
		},
		"action" : {
			"type" : "recover"
		}}'`

	full_action=`echo -e "$split_action\n$recover_action"`
	full_action_temp=`echo $full_action | sed 's/} {/},{/g'`
	#action_json=`echo "[$full_action_temp]" | jq . `
	if [ "${actions_all}" == "" ] ; then
		actions_all=${full_action_temp}
	else
		actions_all=`echo -e "${actions_all},\n${full_action_temp}"`
	fi
}

number_swp4=$num
create_rules $number_swp4 "swp4"
number_swp2=$[$num + $total_devices]
create_rules $number_swp2 "swp2"
number_swp3=$[${num} + ${total_devices} * 2]
create_rules $number_swp3 "swp3"

full_action_json=`echo "[$actions_all]" | jq . `
echo -e "{\"rules\":$full_action_json}"
echo -e "{\"rules\":$full_action_json}" | jq . > ${TOPDIR}/8021cb-board${num}.json

${TOPDIR}/8021cb-load-config.sh -f ${TOPDIR}/8021cb-board${num}.json -m  "$(board_mac_address ${number_swp4}) $(board_mac_address ${number_swp2}) $(board_mac_address ${number_swp3})" -v "$(board_vid ${number_swp2}),$(board_vid ${number_swp3})"
#configure for the internal port eno2

limit_rogue_traffic() {
	local iface="$1"

	ip link set dev ${iface} multicast off
	echo 1 > /proc/sys/net/ipv6/conf/${iface}/disable_ipv6
}

limit_rogue_traffic eno2

eval $(echo internal_ip=\$board${num}_ip_address)
eval $(echo internal_mac=\$board${num}_mac_address)
eval $(echo internal_vid=\$board${num}_vid)

ip link set dev eno2 address ${internal_mac}
ip addr flush dev eno2 && ip addr add ${internal_ip}/24 dev eno2

echo "Adding VLAN mangling rules (see with 'tc filter show dev eno2 egress && tc filter show dev eno2 ingress')"

if tc qdisc show dev eno2 | grep clsact; then tc qdisc del dev eno2 clsact; fi
tc qdisc add dev eno2 clsact

for (( i = 1; i <= ${total_devices} * 3; i++ ));
do
	echo "push/pop vlan $(board_vid ${i}) for eno2"
tc filter add dev eno2 egress flower \
	dst_mac $(board_mac_address ${i}) \
	action vlan push id $internal_vid
tc filter add dev eno2 protocol 802.1Q ingress flower \
	dst_mac $internal_mac vlan_id $(board_vid ${i}) \
	action vlan pop
done

# Accept all VLAN tags on ingress
ethtool -K eno2 rx-vlan-filter off

echo "Populating the ARP table..."
for board in $(seq 1 $[$total_devices * 3] ); do
	if [ ${board} = ${num} ] ; then
		continue
	fi
	eval $(echo other_mac=\$board${board}_mac_address)
	eval $(echo other_ip=\$board${board}_ip_address)
	echo "arp:${other_ip}:${other_mac}"
	arp -s ${other_ip} ${other_mac} dev eno2
done

echo "Ready to send/receive traffic."
echo "IP address of eno2 is ${internal_ip}"
number=$[${num} + ${total_devices}]
echo "IP address links to swp2 is $(board_ip_address ${number})"
number=$[${num} + ${total_devices}*2]
echo "IP address links to swp3 is $(board_ip_address ${number})"
