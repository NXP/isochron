#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

set -e -u -o pipefail

export TOPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)
source "${TOPDIR}/common.sh"

# This example will send a unidirectional traffic stream from Board 1 to
# Board 3 and measure its latency.
#
#   Board 1:
#
#   +---------------------------------------------------------------------------------+
#   |                   192.168.0.1     192.168.1.1 (on eno2.1)                       |
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
#   |                |                       | 192.168.1.2 (on br0)                   |
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
#   |                |  192.168.0.3                      192.|168.1.3 (on eno2.1)     |
#   | +------------+ | +------------+  +------------+  +------------+  +------------+ |
#   | |            | | | To Board 1 |  |            |  | To Board 2 |  |            | |
#   | |            | +-|    SW0     |  |            |  |    SW2     |  |            | |
#   | |            |   |            |  |            |  |            |  |            | |
#   +-+------------+---+------------+--+------------+--+------------+--+------------+-+
#          MAC0             SW0             SW1             SW2              SW3

NSEC_PER_SEC="1000000000"
receiver_open=false
SSH="ssh -o IPQoS=0"

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}. Are all cables plugged in?"
	exit "${code}"
}
trap 'error ${LINENO}' ERR

do_cleanup() {
	rm -f tx.log combined.log ptp.log
	if [ ${receiver_open} = true ]; then
		printf "Stopping receiver process... "
		${SSH} "${remote}" "./time-test.sh 3 stop"
	fi
}
trap do_cleanup EXIT

usage() {
	echo "Usage:"
	echo "$0 1 prepare|run"
	echo "$0 2"
	echo "$0 3 start|stop|prepare"
}

# Given @frame_len bytes, @count frames and @link_speed in Mbps,
# returns the minimum number of nanoseconds required to keep a Qbv gate open
# to transmit that.
qbv_window() {
	local frame_len=$1
	local count=$2
	local link_speed=$3
	local bit_time=$((1000 / ${link_speed}))
	# 7 bytes preamble, 1 byte SFD, 4 bytes FCS and 12 bytes IFG
	local overhead=24
	local octets=$((${frame_len} + ${overhead}))

	echo "$((${octets} * 8 * ${bit_time}))"
}

do_8021qbv() {
	local iface=$1

	# https://www.tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.qdisc.filters.html
	# The below command creates an mqprio qdisc with 8 netdev queues. The
	# 'map' parameter means that queue 0 corresponds to TC 0, queue 1 to TC
	# 1, ... queue 7 to TC 7. Those TC values are what Qbv uses. The queues
	# are what 'tc filter' uses. A 1-to-1 mapping should be easy to manage.
	tc qdisc del dev "${iface}" root || :
	tc qdisc del dev "${iface}" clsact || :
	tc qdisc replace dev "${iface}" root handle 1: \
		mqprio num_tc 8 map 0 1 2 3 4 5 6 7 hw 1
	# Add the qdisc holding the classifiers
	tc qdisc add dev "${iface}" clsact
	# Match EtherType ETH_P_802_EX1.
	# Since we use u32 filter which starts from IP protocol,
	# we need to go back and specify -2 negative offset.
	# You can see that this works because it overwrites the ${txq}
	# parameter given to raw-l2-send.
	tc filter add dev "${iface}" egress prio 1 u32 match u16 0x88b5 0xffff \
		action skbedit priority 5
	# Match L2 PTP frames by EtherType
	tc filter add dev "${iface}" egress prio 1 u32 match u16 0x88f7 0xffff \
		action skbedit priority 7

	speed_mbps=$(ethtool "${iface}" | gawk \
		'/Speed:/ { speed=gensub(/^(.*)Mb\/s/, "\\1", "g", $2); print speed; }')
	window="$(qbv_window 500 1 ${speed_mbps})"
	# raw-l2-send is configured to send at a cycle time of 0.01 seconds
	# (10,000,000 ns).
	cat > qbv0.txt <<-EOF
		t0 00100000 ${window} # raw-l2-send
		t1 10000000 ${window} # PTP
		t2 00000001 $((10000000 - 2 * ${window})) # everything else
	EOF
	tsntool qbvset --device "${iface}" --disable
	return
	tsntool qbvset --device "${iface}" --entryfile qbv0.txt --enable \
		--basetime "${mac_base_time_nsec}"
}

do_8021qci() {
	:
}

do_send_traffic() {
	local remote="root@192.168.0.3"

	check_sync ubuntu

	printf "Getting destination MAC address... "
	dmac="$(get_remote_mac 192.168.0.3 iproute2 swp0)" || {
		echo "failed: $?"
		echo "Have you run \"./time-test.sh 3 prepare\"?"
		${SSH} "${remote}" "./time-test.sh 3 stop"
		return 1
	}
	echo "${dmac}"

	printf "Opening receiver process... "
	${SSH} "${remote}" "./time-test.sh 3 start"

	receiver_open=true

	echo "Opening transmitter process..."
	./raw-l2-send eno2 "${dmac}" "${txq}" "${os_base_time}" \
		"${advance_time}" "${period}" "${frames}" \
		"${length}" > tx.log

	printf "Stopping receiver process... "
	${SSH} "${remote}" "./time-test.sh 3 stop"

	receiver_open=false

	echo "Collecting logs..."
	scp "${remote}:rx.log" .

	[ -s rx.log ] || {
		echo "No frame received by ${remote} (MAC ${dmac})."
		exit 1
	}

	rm -f combined.log

	while IFS= read -r line; do
		seqid=$(echo "${line}" | gawk '/seqid/ { print $6; }')
		otherline=$(cat rx.log | grep "seqid ${seqid} " || :)
		echo "${line} ${otherline}" >> combined.log
	done < tx.log

	cat combined.log | gawk -f time-test.awk \
		-v "period=${period}" \
		-v "mac_base_time=${mac_base_time}" \
		-v "advance_time=${advance_time}"
}

do_start_rcv_traffic() {
	check_sync ubuntu

	rm -f ./raw-l2-rcv.pid rx.log
	start-stop-daemon -S -b -q -m -p "/var/run/raw-l2-rcv.pid" \
		--startas /bin/bash -- \
		-c "exec ${TOPDIR}/raw-l2-rcv eno0 > ${TOPDIR}/rx.log 2>&1" \
		&& echo "OK" || echo "FAIL"
}

do_stop_rcv_traffic() {
	start-stop-daemon -K -p "/var/run/raw-l2-rcv.pid" \
		&& echo "OK" || echo "FAIL"
}

check_sync() {
	local distro=$1
	local system_clock_offset
	local phc_offset
	local awk_program
	local port_state

	echo "Checking synchronization status..."

	port_state=$(pmc -u -b 0 'GET PORT_DATA_SET' | \
			gawk '/portState/ { print $2; }')
	echo "port state is $port_state"
	if [ "${port_state}" = "MASTER" ]; then
		return
	fi

	while :; do
		case ${distro} in
		ubuntu)
			journalctl -b -u ptp4l | tail -50 > ptp.log
			awk_program='/ptp4l/ { print $9; exit; }'
			;;
		openil)
			tail -50 /var/log/messages > ptp.log
			awk_program='/ptp4l/ { print $10; exit; }'
			;;
		esac
		phc_offset=$(tac ptp.log | gawk "${awk_program}")
		# Got something, is it a number?
		case "${phc_offset}" in
		''|[!\-][!0-9]*)
			if [ -z $(pidof ptp4l) ]; then
				echo "Please run '/etc/init.d/S65linuxptp start'"
				return 1
			else
				echo "Trying again..."
				continue
			fi
			;;
		esac
		echo "Master offset ${phc_offset} ns"
		if [ "${phc_offset}" -lt 0 ]; then
			phc_offset=$((-${phc_offset}))
		fi
		if [ "${phc_offset}" -gt 100 ]; then
			echo "PTP clock is not yet synchronized..."
			continue
		fi

		case ${distro} in
		ubuntu)
			journalctl -b -u phc2sys | tail -50 > ptp.log
			awk_program='/phc2sys/ { print $9; exit; }'
			;;
		openil)
			awk_program='/phc2sys/ { print $11; exit; }'
		esac
		system_clock_offset=$(tac ptp.log | gawk "${awk_program}")
		# Got something, is it a number?
		case "${system_clock_offset}" in
		''|[!\-][!0-9]*)
			if [ -z $(pidof phc2sys) ]; then
				echo "Please run '/etc/init.d/S65linuxptp start'"
				return 1
			else
				echo "Trying again..."
				sleep 1
				continue
			fi
			;;
		esac
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

set_params() {
	local now=$(phc_ctl CLOCK_REALTIME get | gawk '/clock time is/ { print $5; }')
	# Round the base time to the start of the next second.
	local sec=$(echo "${now}" | gawk -F. '{ print $1; }')
	local utc_offset="36"

	os_base_time="$((${sec} + 3)).0"
	mac_base_time="$((${sec} + 3 + ${utc_offset})).0"
	mac_base_time_nsec="$(((${sec} + 3 + ${utc_offset}) * ${NSEC_PER_SEC}))"
	advance_time="0.0001"
	period="0.01"
	length="100"
	frames="100"
	txq=7
}

prerequisites() {
	required_configs="CONFIG_NET_INGRESS"
	for config in ${required_configs}; do
		if ! zcat /proc/config.gz | grep "${config}=y" >/dev/null; then
			echo "Please recompile kernel with ${config}=y"
			exit 1
		fi
	done
}

if [ $# -lt 1 ]; then
	usage
	exit 1
fi
board="$1"; shift

prerequisites

[ -d /sys/class/net/br0 ] && ip link del dev br0
ip link add name br0 type bridge stp_state 0 vlan_filtering 1
ip link set br0 arp off
ip link set br0 up

case "${board}" in
1)
	set_params

	if [ $# -lt 1 ]; then
		usage
		exit 1
	fi
	cmd="$1"; shift
	case "${cmd}" in
	prepare)
		for eth in swp1 swp4 swp5; do
			ip addr flush dev ${eth}
			ip link set ${eth} master br0
			ip link set ${eth} up
		done

		# This also creates eno2.1
		do_vlan 1 "swp1 swp4 swp5" "pvid untagged"
		bridge vlan add vid 1 dev swp4 pvid
		ip addr flush dev eno2.1
		ip addr add 192.168.1.1/24 dev eno2.1
		ip link set dev eno2.1 up

		ip addr flush dev swp0
		ip addr add 192.168.0.1/24 dev swp0
		ip link set dev swp0 up

		do_cut_through
		do_8021qbv eno2
		;;
	run)
		do_send_traffic
		;;
	*)
		usage
	esac
	;;
2)
	for eth in swp1 swp2 swp4 swp5; do
		ip addr flush dev ${eth}
		ip link set ${eth} master br0
		ip link set ${eth} up
	done

	# This also creates eno2.1
	do_vlan 1 "swp1 swp2 swp4 swp5" "pvid untagged"
	bridge vlan add vid 1 dev swp4 pvid
	ip addr flush dev eno2.1
	ip addr add 192.168.1.1/24 dev eno2.1
	ip link set dev eno2.1 up
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
		for eth in swp1 swp4 swp5; do
			ip addr flush dev ${eth}
			ip link set ${eth} master br0
			ip link set ${eth} up
		done

		# This also creates eno2.1
		do_vlan 1 "swp1 swp4 swp5" "pvid untagged"
		bridge vlan add vid 1 dev swp4 pvid
		ip addr flush dev eno2.1
		ip addr add 192.168.1.2/24 dev eno2.1
		ip link set dev eno2.1 up

		ip addr flush dev swp0
		ip addr add 192.168.0.3/24 dev swp0
		ip link set dev swp0 up

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
