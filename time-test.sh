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

b1_eno0="10.0.0.101"
b1_eno2="192.168.1.1"
b3_eno0="10.0.0.103"
b3_eno2="192.168.1.3"

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}. Are all cables plugged in?"
	exit "${code}"
}
trap 'error ${LINENO}' ERR

do_cleanup() {
	rm -f tx.log combined.log ptp.log
}
trap do_cleanup EXIT

usage() {
	echo "Usage:"
	echo "$0 1"
	echo "$0 2"
	echo "$0 3 start|stop|prepare"
}

do_bridging() {
	[ -d /sys/class/net/br0 ] && ip link del dev br0

	ip link add name br0 type bridge stp_state 0 vlan_filtering 1 && ip link set br0 up
	for eth in $(ls /sys/bus/pci/devices/0000:00:00.5/net/); do
		ip addr flush dev ${eth};
		ip link set ${eth} master br0
		ip link set ${eth} up
	done
	ip link set br0 arp off
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

do_8021qbv() {
	# https://www.tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.qdisc.filters.html
	# The below command creates an mqprio qdisc with 8 netdev queues. The
	# 'map' parameter means that queue 0 corresponds to TC 0, queue 1 to TC
	# 1, ... queue 7 to TC 7. Those TC values are what Qbv uses. The queues
	# are what 'tc filter' uses. A 1-to-1 mapping should be easy to manage.
	tc qdisc del dev eno2 root || :
	tc qdisc del dev eno2 clsact || :
	tc qdisc replace dev eno2 root handle 1: \
		mqprio num_tc 8 map 0 1 2 3 4 5 6 7 hw 1
	# Add the qdisc holding the classifiers
	tc qdisc add dev eno2 clsact
	# Match EtherType ETH_P_802_EX1.
	# Since we use u32 filter which starts from IP protocol,
	# we need to go back and specify -2 negative offset.
	tc filter add dev eno2 egress prio 1 u32 match u16 0x88b5 0xffff \
		action skbedit priority 5

	# raw-l2-send is configured to send at a cycle time of 0.01 seconds
	# (10,000,000 ns).
	# A bit time at 1Gbps is 1 ns => transmission time of a 64B frame
	# (plus 7 bytes preamble, 1 byte SFD, 4 bytes FCS and 12 bytes IFG)
	# is 704 ns.
	cat > qbv0.txt <<-EOF
		t0 00100000    1000
		t1 00000001 9999000
	EOF
	tsntool qbvset --device eno2 --disable
	tsntool qbvset --device eno2 --entryfile qbv0.txt --enable \
		--basetime "$((${base_time_nsec} + ${advance_time_nsec}))"
}

do_8021qci() {
	:
}

do_send_traffic() {
	remote="root@${b3_eno0}"
	iterations="100"
	period="0.01"
	length="64"
	txq=5

	check_sync

	printf "Opening receiver process... "
	ssh "${remote}" "./time-test.sh 3 start"

	printf "Getting destination MAC address... "
	dmac="$(get_remote_mac ${b3_eno2} iproute2)" || {
		echo "failed: $?"
		ssh "${remote}" "./time-test.sh 3 stop"
		return 1
	}
	echo "${dmac}"

	echo "Opening transmitter process..."
	./raw-l2-send eno2 "${dmac}" "${txq}" "${base_time}" \
		"${period}" "${iterations}" "${length}" > tx.log

	printf "Stopping receiver process... "
	ssh "${remote}" "./time-test.sh 3 stop"

	echo "Collecting logs..."
	scp "${remote}:rx.log" .

	[ -s rx.log ] || {
		echo "No frame received by ${remote} (MAC ${dmac})."
		exit 1
	}

	rm -f combined.log

	while IFS= read -r line; do
		seqid=$(echo "${line}" | awk '/seqid/ { print $6; }')
		otherline=$(cat rx.log | grep "seqid ${seqid} " || :)
		echo "${line} ${otherline}" >> combined.log
	done < tx.log

	cat combined.log | gawk --bignum -f time-test.awk \
		-v "period=${period}" \
		-v "base_time_nsec=${base_time_nsec}"
}

do_start_rcv_traffic() {
	check_sync

	rm -f ./raw-l2-rcv.pid
	start-stop-daemon -S -b -q -m -p "/var/run/raw-l2-rcv.pid" \
		--startas /bin/bash -- \
		-c 'exec ./raw-l2-rcv eno2 > rx.log 2>&1' \
		&& status=$? || status=$?
	[ ${status} = 0 ] && echo "OK" || echo "FAIL"
}

do_stop_rcv_traffic() {
	start-stop-daemon -K -p "/var/run/raw-l2-rcv.pid" \
		&& status=$? || status=$?
	[ ${status} = 0 ] && echo "OK" || echo "FAIL"
}

check_sync() {
	local system_clock_offset
	local phc_offset

	while :; do
		tail -50 /var/log/messages > ptp.log
		phc_offset=$(cat ptp.log | awk '/ptp4l/ { print $10; exit; }')
		if [ -z "${phc_offset}" ]; then
			if [ -z $(pidof ptp4l) ]; then
				echo "Please run '/etc/init.d/S65linuxptp start'"
				return 1
			else
				# Trying again
				continue
			fi
		fi
		echo "Master offset ${phc_offset} ns"
		if [ "${phc_offset}" -lt 0 ]; then
			phc_offset=$((-${phc_offset}))
		fi
		if [ "${phc_offset}" -gt 100 ]; then
			echo "PTP clock is not yet synchronized..."
			continue
		fi

		system_clock_offset=$(cat ptp.log | awk '/phc2sys/ { print $11; exit; }')
		if [ -z "${system_clock_offset}" ]; then
			if [ -z $(pidof phc2sys) ]; then
				echo "Please run '/etc/init.d/S65linuxptp start'"
				return 1
			else
				# Trying again
				continue
			fi
		fi
		if [ "${system_clock_offset}" -lt 0 ]; then
			system_clock_offset=$((-${system_clock_offset}))
		fi
		echo "System clock offset ${system_clock_offset} ns"
		if [ "${system_clock_offset}" -gt 100 ]; then
			echo "System clock is not yet synchronized..."
			continue
		fi
		# Success
		break
	done
}

do_cut_through() {
	for eth in $(ls /sys/bus/pci/devices/0000:00:00.5/net/); do
		tsntool ctset --device ${eth} --queue_stat 0xff;
	done
}

required_configs="CONFIG_NET_INGRESS"
for config in ${required_configs}; do
	if ! zcat /proc/config.gz | grep "${config}=y" >/dev/null; then
		echo "Please recompile kernel with ${config}=y"
		exit 1
	fi
done

do_bridging
do_cut_through

now=$(phc_ctl CLOCK_REALTIME get | awk '/clock time is/ { print $5; }')
# Round the base time to the start of the next second.
sec=$(echo "${now}" | awk -F. '{ print $1; }')
base_time="$((${sec} + 3)).0"
base_time_nsec="$(((${sec} + 3) * 1000000000))"
advance_time_nsec="70000"

if [ $# -lt 1 ]; then
	usage
	exit 1
fi
board="$1"; shift

case "${board}" in
1)
	ip addr flush dev eno0; ip addr add "${b1_eno0}/24" dev eno0; ip link set dev eno0 up
	ip addr flush dev eno2; ip addr add "${b1_eno2}/24" dev eno2; ip link set dev eno2 up
	do_8021qbv
	do_send_traffic
	;;
3)
	if [ $# -lt 1 ]; then
		usage
		exit 1
	fi
	cmd="$1"; shift
	case "${cmd}" in
	start)
		do_start_rcv_traffic
		;;
	stop)
		do_stop_rcv_traffic
		;;
	prepare)
		ip addr flush dev eno0; ip addr add "${b3_eno0}/24" dev eno0; ip link set dev eno0 up
		ip addr flush dev eno2; ip addr add "${b3_eno2}/24" dev eno2; ip link set dev eno2 up
		do_8021qci
		;;
	*)
		usage
		;;
	esac
	;;
*)
	usage
	;;
esac
