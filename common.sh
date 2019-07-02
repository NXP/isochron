#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}. Are all cables plugged in?"
	exit "${code}"
}
trap 'error ${LINENO}' ERR

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

get_switch_ports() {
	local board=$1

	case "${board}" in
	ls1021atsn)
		ls /sys/devices/platform/soc/2100000.spi/spi_master/spi0/spi0.1/net/
		;;
	ls1028ardb)
		ls /sys/bus/pci/devices/0000:00:00.5/net/
		;;
	*)
		;;
	esac
}

do_bridging() {
	local board=$1

	[ -d /sys/class/net/br0 ] && ip link del dev br0

	ip link add name br0 type bridge stp_state 0 vlan_filtering 1
	ip link set br0 up
	for eth in $(get_switch_ports "${board}"); do
		ip addr flush dev ${eth};
		ip link set ${eth} master br0
		ip link set ${eth} up
	done
	ip link set br0 arp off
}

get_remote_mac() {
	local ip="$1"
	local format="$2"
	local iface="$3"
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

	arping -I "${iface}" -c 1 "${ip}" | gawk "${awk_program}"
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
	ip link show dev ${port} | gawk "${awk_program}"
}
