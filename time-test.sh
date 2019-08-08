#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 NXP Semiconductors

set -e -u -o pipefail

export TOPDIR=$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)
source "${TOPDIR}/common.sh"

# The script does not attempt to configure IP addresses, that is left
# up to the user. Modify these based on your setup.
board1_ip="172.15.0.1"
board2_ip="172.15.0.2"
scenario="felix"

# This example will send a unidirectional traffic stream from Board 1 to
# Board 2 and measure its latency by taking MAC TX and RX timestamp. It also
# illustrates how a link's bandwidth can be budgeted in order to allow a
# cyclic application to produce data that is forwarded with low jitter and
# arrives at the destination at a deterministic time. The iperf3-server and
# iperf3-client services can also be used to test the system under load.
#
# The interfaces on the sender and receiver board are kept in sync via ptp4l,
# so that the delta between the RX and TX timestamps makes sense.
#
# The 1588 hardware clocks of ENETC (/dev/ptp0) and Felix (/dev/ptp1) are kept
# in sync via the ptp4l which runs as a service, and the system clocks are kept
# in sync via phc2sys. One of the boards runs as PTP master and the other as
# PTP slave.
#
#   Board 1:
#
#   +---------------------------------------------------------------------------------+
#   |     scenario="enetc"     raw-l2-send       scenario="felix"                     |
#   | +------------+   +------------+  +------------+  +------------+  +------------+ |
#   | |            |   |            |  |            |  |            |  |            | |
#   | |            |-+ |            |  |            |-+|            |  |            | |
#   | |            | | |            |  |            | ||            |  |            | |
#   +-+------------+-|-+------------+--+------------+-|+------------+--+------------+-+
#          MAC0      |      SW0             SW1       |     SW2              SW3
#                    |                                |
#   Board 2:         |                                |
#                    |                                |
#   +----------------|--------------------------------|-------------------------------+
#   |                |         raw-l2-rcv             |                               |
#   | +------------+ | +------------+  +------------+ |+------------+  +------------+ |
#   | |            | | |            |  |            | ||            |  |            | |
#   | |            |-+ |            |  |            |-+|            |  |            | |
#   | |            |   |            |  |            |  |            |  |            | |
#   +-+------------+---+------------+--+------------+--+------------+--+------------+-+
#          MAC0             SW0             SW1             SW2              SW3
#
# In the case of Felix switch ports, a VLAN sub-interface of eno2 is used to
# originate traffic (due to QoS classification not being supported through the
# injection/extraction header yet). The traffic will physically traverse swp1.
# Inherently, this means that the timestamps reported by this script will be
# pre-Qbv in the case where scenario="felix".
#
# In the case of ENETC, the generated report looks like this:
#
#     Mean OS TX latency (OS TX - scheduled TX time): 8100011 ns
#     Standard deviation: 4711 ns
#     Mean MAC TX latency (MAC TX - gate event time): 446 ns
#     Standard deviation: 51 ns
#     Mean path delay (MAC RX - MAC TX): 1057 ns
#     Standard deviation: 47 ns
#     Mean OS RX latency (OS RX - MAC RX): 101138 ns
#     Standard deviation: 21354 ns
#
# Whereas for Felix, it looks like this:
#
#     Mean OS TX latency (OS TX - scheduled TX time): 8058995 ns
#     Standard deviation: 25373 ns
#     Mean MAC TX latency (MAC TX - gate event time): -8030331 ns
#     Standard deviation: 27460 ns
#     Mean path delay (MAC RX - MAC TX): 8032457 ns
#     Standard deviation: 27459 ns
#     Mean OS RX latency (OS RX - MAC RX): 97965 ns
#     Standard deviation: 23409 ns
#
# Because the timestamps are taken on the eno2 MAC (that's where the
# application socket is open), the advance time is immediately obvious in the
# (MAC TX - gate event time) delta. However, these are pre-Qbv timestamps, so
# the advance time is also visible in the path delay (here, eno2-to-eno2 vs the
# ideal swp1-to-swp1). However, by summing the two, one gets a "sort of path
# delay", aka the "swp1-to-eno2" hardware time, which still proves that Qbv on
# swp1 is active, and that its MAC transmission jitter is low.

NSEC_PER_SEC="1000000000"
receiver_open=false
SSH_OPTS="-o IPQoS=0 -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no"
SSH="ssh ${SSH_OPTS}"
SCP="scp ${SSH_OPTS}"

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

enetc_8021qbv_config() {
	local iface=$1
	local enetc_pf0="0x1F8000000"
	local enetc_pf2="0x1F8080000"
	local ierb="0x1F0800000"
	# Time gating lookahead scheduling time register
	local tglstr=
	# Port egress selection manager advance time offset register
	local pesmator=

	case "${iface}" in
	eno0)
		tglstr="$((${ierb} + 0xa200))"
		pesmator="$((${enetc_pf0} + 0x11A24))"
		;;
	eno2)
		tglstr="$((${ierb} + 0xa200))"
		pesmator="$((${enetc_pf2} + 0x11A24))"
		;;
	esac

	if [ -n "${tglstr}" ]; then
		busybox devmem "${tglstr}" 32 0x2ee
	fi

	# Advance time offset (ADV_TIME_OFFSET)
	# This value needs to be changed based on the line rate and the
	# protocol of the port to eliminate the added latency of the MAC and
	# MAC Merge layer.
	# XGMII
	# - 2.5G: 270ns
	# - 1G: 550ns
	# - 100M: 4870ns
	# - 10M: 48070ns
	# GMII
	# - 2.5G: 117ns
	# - 1G: 152ns
	# - 100M: 692ns
	# - 10M: 6092ns
	if [ -n "${pesmator}" ]; then
		case "${speed_mbps}" in
		10)
			busybox devmem "${pesmator}" 32 6092
			;;
		100)
			busybox devmem "${pesmator}" 32 692
			;;
		1000)
			busybox devmem "${pesmator}" 32 152
			;;
		esac
	fi

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
}

felix_8021qbv_config() {
	local iface=$1

	do_vlan_subinterface eno2 100
	for eth in ${iface} swp4; do
		bridge vlan add vid 100 dev "${eth}"
		tsntool pcpmap --device "${eth}" --enable 2&>1 /dev/null
	done
}

do_8021qbv() {
	local iface=

	case "${scenario}" in
	enetc)
		iface="eno0"
		;;
	felix)
		iface="swp1"
		;;
	esac

	speed_mbps=$(ethtool "${iface}" | gawk \
		'/Speed:/ { speed=gensub(/^(.*)Mb\/s/, "\\1", "g", $2); print speed; }')

	# This calls felix_8021qbv_config or enetc_8021qbv_config
	"${scenario}_8021qbv_config" "${iface}"

	window="$(qbv_window 500 1 ${speed_mbps})"
	guard="$(qbv_window 64 1 ${speed_mbps})"
	best_effort="$((10000000 - 2 * ${window} - ${guard}))"
	# raw-l2-send is configured to send at a cycle time of 0.01 seconds
	# (10,000,000 ns).
	cat > qbv0.txt <<-EOF
		t0 00100000 ${window}      # raw-l2-send
		t1 10000000 ${window}      # PTP
		t2 01011111 ${best_effort} # everything else
		t3 00000000 ${guard}
	EOF
	tsntool qbvset --device "${iface}" --disable
	tsntool qbvset --device "${iface}" --entryfile qbv0.txt --enable \
		--basetime "${mac_base_time_nsec}"
}

do_8021qci() {
	local iface=$1
	local mgmt_iface=$2
	local board1="$(get_remote_mac ${board1_ip} tsntool-reverse ${mgmt_iface})"

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
	local remote="root@${board2_ip}"
	local iface=
	local mgmt_iface=
	local err=false

	case "${scenario}" in
	enetc)
		iface="eno0.100"
		mgmt_iface="eno0"
		;;
	felix)
		iface="eno2"
		mgmt_iface="eno2"
		;;
	esac

	check_sync

	printf "Getting destination MAC address... "
	dmac="$(get_remote_mac ${board2_ip} iproute2 ${mgmt_iface})" || err=true
	if [ -z "${dmac}" ] || [ ${err} = true ]; then
		echo "failed: $?"
		echo "Have you run \"${TOPDIR}/time-test.sh 2 prepare\"?"
		${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 stop"
		return 1
	fi
	echo "${dmac}"

	printf "Opening receiver process... "
	${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 start"

	receiver_open=true

	echo "Opening transmitter process..."
	"${TOPDIR}/raw-l2-send" "${iface}" "${dmac}" "${txq}" "${os_base_time}" \
		"${advance_time}" "${period}" "${frames}" \
		"${length}" > tx.log

	printf "Stopping receiver process... "
	${SSH} "${remote}" "${TOPDIR}/time-test.sh 2 stop"

	receiver_open=false

	echo "Collecting logs..."
	${SCP} "${remote}:${TOPDIR}/rx.log" .

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
	local iface=

	case "${scenario}" in
	enetc)
		iface="eno0.100"
		;;
	felix)
		iface="eno2"
		;;
	esac

	check_sync

	rm -f rx.log
	start-stop-daemon -S -b -q -m -p "/var/run/raw-l2-rcv.pid" \
		--startas /bin/bash -- \
		-c "exec ${TOPDIR}/raw-l2-rcv ${iface} > ${TOPDIR}/rx.log 2>&1" \
		&& echo "OK" || echo "FAIL"
}

do_stop_rcv_traffic() {
	start-stop-daemon -K -p "/var/run/raw-l2-rcv.pid" \
		&& echo "OK" || echo "FAIL"
}

check_sync() {
	local threshold_ns=50
	local system_clock_offset
	local phc_to_phc_offset
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

		# Check slave PHC offset to its master
		journalctl -b -u ptp4l -n 50 > ptp.log
		awk_program='/ptp4l/ { print $9; exit; }'
		phc_offset=$(tac ptp.log | gawk "${awk_program}")
		# Got something, is it a number?
		case "${phc_offset}" in
		''|[!\-][!0-9]*)
			if [ -z $(pidof ptp4l) ]; then
				echo "Please start the ptp4l service."
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

		# Check offset between the ENETC and the Felix PHC
		journalctl -b -u phc-to-phc-sync -n 50 > ptp.log
		awk_program='/phc2sys/ { print $10; exit; }'
		phc_to_phc_offset=$(tac ptp.log | gawk "${awk_program}")
		# Got something, is it a number?
		case "${phc_to_phc_offset}" in
		''|[!\-][!0-9]*)
			if [ -z $(pidof phc2sys) ]; then
				echo "Please start the phc-to-phc-sync service."
				return 1
			else
				echo "Trying again..."
				continue
			fi
			;;
		esac
		if [ "${phc_to_phc_offset}" -lt 0 ]; then
			phc_to_phc_offset=$((-${phc_to_phc_offset}))
		fi
		echo "PHC-to-PHC offset ${phc_to_phc_offset} ns"
		if [ "${phc_to_phc_offset}" -gt "${threshold_ns}" ]; then
			echo "System clock is not yet synchronized..."
			continue
		fi

		# Check offset between the PHC and the system clock
		journalctl -b -u phc2sys -n 50 > ptp.log
		awk_program='/phc2sys/ { print $10; exit; }'
		system_clock_offset=$(tac ptp.log | gawk "${awk_program}")
		# Got something, is it a number?
		case "${system_clock_offset}" in
		''|[!\-][!0-9]*)
			if [ -z $(pidof phc2sys) ]; then
				echo "Please start the phc2sys service."
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

do_install_deps() {
	packages="arping gawk expect"
	for pkg in ${packages}; do
		if ! command -v ${pkg} > /dev/null; then
			apt install ${pkg}
		fi
	done
	install -Dm0644 "${TOPDIR}/deps/phc2sys.service" \
		"/lib/systemd/system/phc2sys.service"
	install -Dm0644 "${TOPDIR}/deps/phc-to-phc-sync.service" \
		"/lib/systemd/system/phc-to-phc-sync.service"
	install -Dm0644 "${TOPDIR}/deps/ptp4l.service" \
		"/lib/systemd/system/ptp4l.service"
	install -Dm0644 "${TOPDIR}/deps/iperf3-server.service" \
		"/lib/systemd/system/iperf3-server.service"
	install -Dm0644 "${TOPDIR}/deps/iperf3-client.service" \
		"/lib/systemd/system/iperf3-client.service"
	install -Dm0644 "${TOPDIR}/deps/ptp4l.conf" \
		"/etc/linuxptp/ptp4l.conf"
	systemctl daemon-reload
	systemctl restart ptp4l
	systemctl restart phc-to-phc-sync
	systemctl restart phc2sys
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

do_prepare() {
	case "${scenario}" in
	enetc)
		do_vlan_subinterface eno0 100
		;;
	felix)
		[ -d /sys/class/net/br0 ] && ip link del dev br0
		ip link add name br0 type bridge stp_state 0 vlan_filtering 1
		ip link set br0 arp off
		ip link set br0 up

		for eth in swp1 swp4 swp5; do
			ip addr flush dev ${eth}
			ip link set ${eth} master br0
			ip link set ${eth} up
		done

		do_cut_through
	esac
}

do_print_config_done() {
	local board=$1
	local iface=
	local ip=

	case "${board}" in
	1)
		ip="${board1_ip}"
		;;
	2)
		ip="${board2_ip}"
		;;
	esac

	case "${scenario}" in
	enetc)
		iface="eno0"
		;;
	felix)
		iface="eno2"
		;;
	esac

	echo "Configuration successful. Suggestion:"
	echo "ip addr flush dev ${iface} && ip addr add ${ip}/24 dev ${iface} && ip link set dev ${iface} up"
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
		do_install_deps
		do_prepare
		do_print_config_done ${board}
		;;
	run)
		set_qbv_params
		do_8021qbv

		do_send_traffic
		;;
	teardown)
		tsntool qbvset --device eno0 --disable
		[ -d "/sys/class/net/eno0.100" ] && ip link del dev eno0.100
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
		do_install_deps
		do_prepare
		do_print_config_done ${board}
		set_qbv_params
		;;
	teardown)
		[ -d "/sys/class/net/eno0.100" ] && ip link del dev eno0.100
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
