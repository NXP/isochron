#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

set -e -u -o pipefail

export TOPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)
source "${TOPDIR}/common.sh"

# This example will send a unidirectional traffic stream from Board 1 to
# Board 2 and measure its latency by taking MAC TX and RX timestamp.
# This is currently not supported for the Felix switch ports. The switch
# is currently only used to pass SSH traffic.
# The 1588 hardware clocks of ENETC (/dev/ptp0) are kept in sync via the
# ptp4l which runs as a service, and the system clocks are kept in sync
# via phc2sys. One of the boards runs as PTP master and the other as PTP slave.
#
#   Board 1:
#
#   +---------------------------------------------------------------------------------+
#   |   10.0.0.101                                                                    |
#   | +------------+   +------------+  +------------+  +------------+  +------------+ |
#   | |            |   |            |  |            |  |            |  |            | |
#   | |            |-+ |            |  |            |  |            |  |            | |
#   | |            | | |            |  |            |  |            |  |            | |
#   +-+------------+-|-+------------+--+------------+--+------------+--+------------+-+
#          MAC0      |      SW0             SW1             SW2              SW3
#                    |
#   Board 2:         |
#                    |
#   +----------------|----------------------------------------------------------------+
#   |   10.0.0.102   |                                                                |
#   | +------------+ | +------------+  +------------+  +------------+  +------------+ |
#   | |            | | |            |  |            |  |            |  |            | |
#   | |            |-+ |            |  |            |  |            |  |            | |
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
		${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 stop"
	fi
}
trap do_cleanup EXIT

usage() {
	echo "Usage:"
	echo "$0 1 prepare|run|teardown"
	echo "$0 2 prepare|start|stop|teardown"
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
	# Match L2 PTP frames by EtherType
	# Since we use u32 filter which starts from IP protocol,
	# we need to go back and specify -2 negative offset.
	tc filter add dev "${iface}" egress prio 1 u32 match u16 0x88f7 0xffff \
		action skbedit priority 7

	speed_mbps=$(ethtool "${iface}" | gawk \
		'/Speed:/ { speed=gensub(/^(.*)Mb\/s/, "\\1", "g", $2); print speed; }')
	window="$(qbv_window 500 1 ${speed_mbps})"
	guard="$(qbv_window 64 1 ${speed_mbps})"
	best_effort="$((10000000 - 2 * ${window} - ${guard}))"
	# raw-l2-send is configured to send at a cycle time of 0.01 seconds
	# (10,000,000 ns).
	cat > qbv0.txt <<-EOF
		t0 00100000 ${window}      # raw-l2-send
		t1 10000000 ${window}      # PTP
		t2 00000001 ${best_effort} # everything else
		t3 00000000 ${guard}
	EOF
	tsntool qbvset --device "${iface}" --disable
	tsntool qbvset --device "${iface}" --entryfile qbv0.txt --enable \
		--basetime "${mac_base_time_nsec}"
}

do_8021qci() {
	local iface=$1
	local board1="$(get_remote_mac 10.0.0.101 tsntool-reverse eno0)"

	tsntool cbstreamidset --device "${iface}" --index 1 --streamhandle 100 \
		 --sourcemacvid --sourcemac "${board1}" --sourcetagged 3 --sourcevid 20
	tsntool qcisfiset --device "${iface}" --streamhandle 100 --index 1 --gateid 1

	speed_mbps=$(ethtool "${iface}" | gawk \
		'/Speed:/ { speed=gensub(/^(.*)Mb\/s/, "\\1", "g", $2); print speed; }')
	window="$(qbv_window 500 1 ${speed_mbps})"
	guard="$(qbv_window 64 1 ${speed_mbps})"
	best_effort="$((10000000 - 2 * ${window} - ${guard}))"

	cat > sgi1.txt <<-EOF
	# entry  gate status IPV delta (ns)     SDU limit
	t0       1b          1   ${window}      0   # raw-l2-send
	t1       1b          1   ${window}      0   # PTP
	t2       1b          0   ${best_effort} 0   # everything else
	t3       1b          0   ${guard}       0
	EOF
	tsntool qcisgiset --device "${iface}" --index 1 --initgate 0 \
		 --gatelistfile sgi1.txt --basetime "${mac_base_time_nsec}"
}

do_send_traffic() {
	local remote="root@192.168.1.2"

	check_sync ubuntu

	printf "Getting destination MAC address... "
	dmac="$(get_remote_mac 10.0.0.102 iproute2 eno0)" || {
		echo "failed: $?"
		echo "Have you run \"${TOPDIR}/time-test.sh 2 prepare\"?"
		${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 stop"
		return 1
	}
	echo "${dmac}"

	printf "Opening receiver process... "
	${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 start"

	receiver_open=true

	echo "Opening transmitter process..."
	"${TOPDIR}/raw-l2-send" eno0 "${dmac}" "${txq}" "${os_base_time}" \
		"${advance_time}" "${period}" "${frames}" \
		"${length}" > tx.log

	printf "Stopping receiver process... "
	${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 stop"

	receiver_open=false

	echo "Collecting logs..."
	scp "${remote}:${TOPDIR}/rx.log" .

	[ -s rx.log ] || {
		echo "No frame received by ${remote} (MAC ${dmac})."
		exit 1
	}

	rm -f combined.log

	while IFS= read -r line; do
		seqid=$(echo "${line}" | gawk '/seqid/ { print $9; }')
		otherline=$(cat rx.log | grep "seqid ${seqid} " || :)
		echo "${line} ${otherline}" >> combined.log
	done < tx.log

	cat combined.log | gawk -f "${TOPDIR}/time-test.awk" \
		-v utc_offset="${utc_offset}.0"
}

do_start_rcv_traffic() {
	check_sync ubuntu

	rm -f rx.log
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
	local threshold_ns=50
	local system_clock_offset
	local phc_offset
	local awk_program
	local port_state

	echo "Checking synchronization status..."

	while :; do
		port_state=$(pmc -u -b 0 'GET PORT_DATA_SET' | \
				gawk '/portState/ { print $2; }')
		echo "port state is $port_state"
		if [ "${port_state}" = "MASTER" ] &&
		   [ "${board}" = 1 ]; then
			return
		fi

		sleep 1

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
		if [ "${phc_offset}" -gt "${threshold_ns}" ]; then
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
				continue
			fi
			;;
		esac
		if [ "${system_clock_offset}" -lt 0 ]; then
			system_clock_offset=$((-${system_clock_offset}))
		fi
		echo "System clock offset ${system_clock_offset} ns"
		if [ "${system_clock_offset}" -gt "${threshold_ns}" ]; then
			echo "System clock is not yet synchronized..."
			continue
		fi
		# Success
		break
	done
}

# The PTP clocks tick Jan 1st 1970 at boot time.
# This function temporarily disables any PTP service and resets the PTP clock
# to a known state, be it master or slave. The time is based on the RTC clock
# and should be "in the ballpark" for the slave. For the master, CLOCK_REALTIME
# will also become the time source (phc2sys -r -r).
# We only care that the clocks are synchronized to one another.
# We make sure that the PTP clocks tick in 2019 and not in 1970 because there
# are bugs in phc2sys (?) when you try to discipline it to a retro time.
set_phc_time() {
	local phc=$1
	local distro=$2

	case "${distro}" in
	openil)
		# Make sure the S65linuxptp included in this archive is
		# installed at /etc/init.d/ on the board.
		/etc/init.d/S65linuxptp stop
		hwclock --hctosys
		phc_ctl "${phc}" set
		phc_ctl "${phc}" freq 0
		/etc/init.d/S65linuxptp start
		;;
	ubuntu)
		# Make sure /lib/systemd/system/phc2sys.service contains:
		#
		#   ExecStart=/usr/sbin/phc2sys -a -r -r
		#
		# and /lib/systemd/system/phc2sys.service contains:
		#
		#   ExecStart=/usr/sbin/ptp4l -f /etc/linuxptp/ptp4l.conf -i eno0 -2
		#
		# then run:
		# systemctl daemon-reload
		# systemctl enable phc2sys
		# systemctl restart phc2sys
		# systemctl enable ptp4l
		# systemctl restart ptp4l
		# systemctl disable systemd-timesyncd
		# systemctl stop systemd-timesyncd
		systemctl stop ptp4l
		systemctl stop phc2sys
		hwclock --hctosys
		phc_ctl "${phc}" set
		phc_ctl "${phc}" freq 0
		systemctl start ptp4l
		systemctl start phc2sys
		;;
	esac
}

do_cut_through() {
	for eth in swp0 swp1 swp2 swp3 swp5; do
		tsntool ctset --device ${eth} --queue_stat 0xff;
	done
	tsntool ctset --device swp4 --queue_stat 0x00
}

set_qbv_params() {
	local now=$(phc_ctl CLOCK_REALTIME get | gawk '/clock time is/ { print $5; }')
	# Round the base time to the start of the next second.
	local sec=$(echo "${now}" | gawk -F. '{ print $1; }')

	utc_offset=$(pmc -u -b 0 'GET TIME_PROPERTIES_DATA_SET' | \
			gawk '/\<currentUtcOffset\>/ { print $2; }')
	os_base_time="$((${sec} + 1)).0"
	mac_base_time="$((${sec} + 1 + ${utc_offset})).0"
	mac_base_time_nsec="$(((${sec} + 1 + ${utc_offset}) * ${NSEC_PER_SEC}))"
	advance_time="0.00818000"
	#advance_time="0.00018000" <- experimentally smallest possible at length 400
	period="0.01"
	length="100"
	frames="200"
	txq=5
}

prerequisites() {
	required_configs="CONFIG_NET_INGRESS"
	for config in ${required_configs}; do
		if ! zcat /proc/config.gz | grep "${config}=y" >/dev/null; then
			echo "Please recompile kernel with ${config}=y"
			exit 1
		fi
	done

	packages="arping gawk"
	for pkg in ${packages}; do
		if ! command -v ${pkg} > /dev/null; then
			echo "Please install the ${pkg} package"
			return 1
		fi
	done
}

if [ $# -lt 1 ]; then
	usage
	exit 1
fi
board="$1"; shift

prerequisites

case "${board}" in
1)
	if [ $# -lt 1 ]; then
		usage
		exit 1
	fi
	cmd="$1"; shift
	case "${cmd}" in
	prepare)
		[ -d /sys/class/net/br0 ] && ip link del dev br0
		ip link add name br0 type bridge stp_state 0 vlan_filtering 1
		ip link set br0 arp off
		ip link set br0 up

		for eth in swp1 swp4 swp5; do
			ip addr flush dev ${eth}
			ip link set ${eth} master br0
			ip link set ${eth} up
		done

		ip addr flush dev eno0
		ip addr add 10.0.0.101/24 dev eno0
		ip link set dev eno0 up

		set_phc_time /dev/ptp0 ubuntu

		do_cut_through

		echo "Configuration successful."
		;;
	run)
		set_qbv_params
		do_8021qbv eno0

		do_send_traffic
		;;
	teardown)
		tsntool qbvset --device eno0 --disable
		;;
	*)
		usage
	esac
	;;
2)
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
		[ -d /sys/class/net/br0 ] && ip link del dev br0
		ip link add name br0 type bridge stp_state 0 vlan_filtering 1
		ip link set br0 arp off
		ip link set br0 up

		for eth in swp1 swp4 swp5; do
			ip addr flush dev ${eth}
			ip link set ${eth} master br0
			ip link set ${eth} up
		done

		ip addr flush dev eno0
		ip addr add 10.0.0.102/24 dev eno0
		ip link set dev eno0 up

		set_qbv_params
		do_cut_through
		do_8021qci eno0

		set_phc_time /dev/ptp0 ubuntu

		echo "Configuration successful."
		;;
	teardown)
		[ -d "/sys/class/net/eno0.100" ] && ip link del dev eno0.100

		ip addr flush dev eno0
		ip addr add 10.0.0.102/24 dev eno0
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
