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

do_vlan_subinterface() {
	local iface="$1"
	local vid="$2"
	local ip="${3-}"
	local vlan_subiface="${iface}.${vid}"

	[ -d "/sys/class/net/${vlan_subiface}" ] && ip link del dev "${vlan_subiface}"

	ip link add link ${iface} name ${vlan_subiface} type vlan id ${vid} \
		ingress-qos-map 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7 \
		egress-qos-map 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7
	ip link set dev ${vlan_subiface} up
	if [ -n "${ip}" ]; then
		ip addr flush dev ${vlan_subiface}
		ip addr add ${ip} dev ${vlan_subiface}
	fi
}

do_switch_vlan() {
	local vid="$1"
	local ports="$2"
	local flags="$3"

	for port in ${ports}; do
		bridge vlan add vid ${vid} dev ${port} ${flags}
	done
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
	tsntool-reverse)
		awk_program='							\
			/Unicast reply from/					\
			{							\
				mac=gensub(/^\[(.*)\]/, "\\1", "g", $5);	\
				split(mac, m, ":");				\
				print "0x" m[6] m[5] m[4] m[3] m[2] m[1];	\
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
