#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2019 NXP

set -e -u -o pipefail

total_port_list=
total_vid_list=

usage() {
	echo "Usage:"
	echo "$0: read from stdin"
	echo "$0 -h|--help: show usage"
	echo "$0 -f|--file <filename>: read from .json file"
	exit
}

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}, exiting."
	exit "${code}"
}
trap 'error ${LINENO}' ERR

tsntool_bin=$(which tsntool)

O=`getopt -l help,file: -- hf: "$@"` || exit 1
eval set -- "$O"
while true; do
	case "$1" in
	-h|--help)
		usage; exit 0;;
	-f|--file)
		file="$2"; shift 2;;
	--)
		shift; break;;
	*)
		echo "unrecognized argument $1"; exit 1;;
	esac
done

if [[ -z "${file+x}" ]]; then
	usage
fi

if ! [[ -f ${file} ]]; then
	echo "${file}: No such file or directory"
	exit 1
else
	json=$(jq "." ${file})
fi

strip_quotes() {
	sed -e 's|"||g'
}

tsntool_macaddr() {
	local macaddr=$1
	local awk_program='						\
		{							\
			split($1, m, ":");				\
			print "0x" m[1] m[2] m[3] m[4] m[5] m[6];	\
		}'

	echo "${macaddr}" | awk "${awk_program}"
}

tsntool() {
	echo tsntool $@
	${tsntool_bin} $@
}

clear_stream_table() {
	for eth in swp0 swp1 swp2 swp3 swp4; do
		for ssid in $(seq 0 127); do
			tsntool cbstreamidset --index $ssid --nullstreamid \
				--streamhandle $ssid --device $eth \
				--disable >/dev/null || :
		done
	done
}

# Recommended read: Figure 16-23. Overview of Per-Stream Filtering and Policing
# (Qci) from LS1028ARM.pdf
#
#          Stream Identity Table                                 Stream Filter Instance Table
#           (aka cbstreamidset)                                         (aka qcisfiset)
# +-----------+-----------+---------------+         +---------------+-----------+--------+-------+------+
# | Port list | Stream ID | Stream Handle |         | Stream Handle | Port list | Filter | Meter | Gate |
# +-----------+-----------+---------------+         +---------------+-----------+--------+-------+------+
# |     1     |    NULL   |      1234     |--+----->|      1234     |     1     | xxxxxx |   5   |  11  |
# |    ...    |    ...    |      ...      |  |      |      ...      |    ...    |   ...  |  ...  |  ... |
# |     3     |    NULL   |      1357     |-------->|      1357     |     3     | yyyyyy |   29  |  11  |
# |     2     | SMAC/VLAN |      5678     |-------->|      5678     |     2     | zzzzzz |   29  |  43  |
# |    ...    |    ...    |      ...      |  |      |      ...      |    ...    |   ...  |  ...  |  ... |
# |     1     |    NULL   |      1234     |--+      +---------------+-----------+--------+-------+------+
# +-----------+-----------+---------------+                                                  |       |
#                                                                                            |       |
#                            +---------------------------------------------------------------+       |
#                            |                                    +----------------------------------+
#                            |      Flow Meter Instance Table     |       Stream Gate Instance Table
#                            |           (aka qcifmiset)          |             (aka qcisgiset)
#                            |  +----------+-------------------+  |  +---------+------------+-----------+
#                            |  | Meter ID |  Meter Parameters |  |  | Gate ID | Gate State | Gate List |
#                            |  +----------+-------------------+  |  +---------+------------+-----------+
#                            +->|    29    | CIR, CBS, EIR etc |  +->|    11   |    Open    |   0..n    |
#                               |     5    | CIR, CBS, EIR etc |     |    43   |   Closed   |   0..m    |
#                               +----------+-------------------+     +---------+------------+-----------+
#
# The above is valid for both Felix and ENETC.
# On Felix only, the entries in the Stream Identity Table have not only a SFID
# for indexing the Stream Filter Instance Table, but also an optional SSID for
# indexing the Seamless Stream Table
#
# Seamless Stream Table with GEN_REC_TYPE=0 (Generation)
# +-------------+---------------------+----------------+----------------+----------------+------------+
# | Input ports | Enable stream split | Enable Seq Gen | Starting seqid | Seqid num bits | Split mask |
# +-------------+---------------------+----------------+----------------+----------------+------------+
# |             |                     |                |                |                |            |
# |             |                     |                |                |                |            |
# |             |                     |                |                |                |            |
# +-------------+---------------------+----------------+----------------+----------------+------------+
#
# Seamless Stream Table with GEN_REC_TYPE=1 (Recovery)
# +---------------------+----------------+-------------+-----------------+-----------+----------------+---------------------+
# | Enable Seq Recovery | Seqid num bits | Seq history | Seq history len | R-Tag Pop | Reset on Rogue | Force Store/Forward |
# +---------------------+----------------+-------------+-----------------+-----------+----------------+---------------------+
# |                     |                |             |                 |           |                |                     |
# |                     |                |             |                 |           |                |                     |
# |                     |                |             |                 |           |                |                     |
# +---------------------+----------------+-------------+-----------------+-----------+----------------+---------------------+
stream_rules=()
split_actions=()
recover_actions=()

add_stream_rule() {
	local ssid="$1"
	local match="$2"
	local egress_port="$3"
	local dmac="$(echo ${match} | jq '.dmac' | strip_quotes)"
	local vid="$(echo ${match} | jq '.vid' | strip_quotes)"

	# Configure a Seamless Stream IDs (SSID) for outbound traffic on this
	# port.
	stream_rules+=("tsntool cbstreamidset --device ${egress_port} --nullstreamid \
		--nulldmac $(tsntool_macaddr ${dmac}) --nullvid ${vid} \
		--streamhandle ${ssid} --index ${ssid} --enable")

	total_port_list="${total_port_list} ${egress_port}"
	total_vid_list="${total_vid_list} ${vid}"

	printf 'Stream rule %d: match {DMAC %s, VID %d} towards port %s\n' \
		"${ssid}" "${dmac}" "${vid}" "${egress_port}"
}

add_split_action() {
	local ssid="$1"
	local ingress_port_mask="$2"
	local egress_port_mask="$3"
	local ingress_ports=""
	local split_ports=""
	local iport_mask=0
	local split_mask=0
	local seq_len=16
	local seq_num=0

	for swp in $(echo "${ingress_port_mask}" | jq -r -c '.[]'); do
		local chip_port="${swp#swp}"
		ingress_ports="${ingress_ports} ${swp}"
		iport_mask=$((${iport_mask} | $((1 << chip_port))))

		total_port_list="${total_port_list} ${swp}"
	done

	for swp in $(echo "${egress_port_mask}" | jq -r '.[]'); do
		local chip_port="${swp#swp}"
		split_ports="${split_ports} ${swp}"
		split_mask=$((${split_mask} | $((1 << chip_port))))

		total_port_list="${total_port_list} ${swp}"
	done

	# The switch port specified as parameter to --device here does not
	# matter, it is simply an anchor for tsntool to talk to the switch
	# driver.  As a convention, swp0 will be used.
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
	split_actions+=("tsntool cbgen --device swp0 --index ${ssid} \
		--seq_len ${seq_len} --seq_num ${seq_num} \
		--iport_mask ${iport_mask} --split_mask ${split_mask}")

	printf 'Split action for rule %d: ingress ports: %s split ports: %s\n' \
		"${ssid}" "${ingress_ports}" "${split_ports}"
}

add_recover_action() {
	local ssid="$1"
	local passthrough="$2"
	local seq_len=16
	local his_len=31

	if [ $passthrough = true ]; then
		local opts=""
		local label="Passthrough"
	else
		local opts="--rtag_pop_en"
		local label="Sequence recovery"
	fi

	# The port does not matter
	recover_actions+=("tsntool cbrec --device swp0 --index ${ssid} \
		--seq_len ${seq_len} --his_len ${his_len} \
		${opts}")

	printf '%s action for rule %d\n' \
		"${label}" "${ssid}"
}

# The felix driver is very picky about the order of the tsntool commands. To be
# precise, the actions (cbgen, cbrec) can't come before the match
# (cbstreamidset). But this is chicken-and-egg, because we need to parse the
# action for cbgen to figure out the --device for cbstreamidset.
# So make it a 2-part system. The add_stream_rule, add_split_action and
# add_recover_action functions just add to their respective arrays, and apply
# them in the required order here.
apply_tsntool_commands() {
	for stream_rule in "${stream_rules[@]}"; do
		$stream_rule
	done
	for split_action in "${split_actions[@]}"; do
		$split_action
	done
	for recover_action in "${recover_actions[@]}"; do
		$recover_action
	done
}

do_bridging() {
	[ -d /sys/class/net/br0 ] && ip link del dev br0
	ip link add name br0 type bridge stp_state 0 vlan_filtering 1
	ip link set br0 arp off
	ip link set br0 up

	for swp in swp0 swp1 swp2 swp3 swp4; do
		ip link set dev ${swp} master br0
		# No pvid by default, so no untagged communication.
		bridge vlan del vid 1 dev ${swp}
	done
}

add_passthrough_vlans() {
	local vlan_list="$1"

	for vid in $(echo "${vlan_list}" | jq -r -c '.[]'); do
		echo "Passthrough vid $vid"
		total_vid_list="${total_vid_list} ${vid}"
	done
}

limit_rogue_traffic() {
	local iface="$1"

	ip link set dev ${iface} multicast off
	echo 1 > /proc/sys/net/ipv6/conf/${iface}/disable_ipv6
}

drop_looped_traffic() {
	local iface="$1"
	local this_host=$(ip link show dev eno2 | awk '/link\/ether/ {print $2; }')

	if tc qdisc show dev ${iface} | grep clsact; then tc qdisc del dev ${iface} clsact; fi
	tc qdisc add dev ${iface} clsact
	tc filter add dev ${iface} ingress flower skip_sw dst_mac ff:ff:ff:ff:ff:ff action drop
	tc filter add dev ${iface} ingress flower skip_sw src_mac ${this_host} action drop
}

install_vlans() {
	# Remove duplicates
	total_port_list=$(echo -e "${total_port_list// /\\n}" | sort -u)
	total_vid_list=$(echo -e "${total_vid_list// /\\n}" | sort -u)

	for vid in ${total_vid_list}; do
		for swp in ${total_port_list}; do
			bridge vlan add dev ${swp} vid ${vid}
		done
	done

	for port in ${total_port_list}; do
		# Don't drop traffic coming from the CPU port
		if [ ${port} = swp4 ]; then
			continue
		fi
		drop_looped_traffic "${port}"
	done
}

do_bridging
clear_stream_table

limit_rogue_traffic eno2

num_rules=$(jq '.rules|length' <<< "${json}")

for i in `seq 0 $((${num_rules}-1))`; do
	rule=$(jq ".rules[$i]" <<< "${json}")
	match=$(echo ${rule} | jq '.match')
	action=$(echo ${rule} | jq '.action')
	action_type=$(echo ${action} | jq ".type" | strip_quotes)

	# Add the action first, we need to fix up the match with info from it.
	case ${action_type} in
	"split")
		ingress_port_mask=$(echo "${match}" | jq -r '.["ingress-port-mask"]')
		egress_port_mask=$(echo "${action}" | jq -r '.["egress-port-mask"]')
		add_split_action "${i}" "${ingress_port_mask}" "${egress_port_mask}"

		# It is weird that for splitting, one port of the actions's
		# egress port mask also needs to be specified as part of the
		# match.  Hardware quirk.
		# Instead of taking the egress-port property from the match
		# rule as we do for recovery, take it to be the first port from
		# the egress-port-mask of the action.
		egress_port=$(echo "${egress_port_mask}" | jq -r -c '.[0]')
		;;
	"recover")
		add_recover_action "${i}" false

		egress_port=$(echo "${match}" | jq -r '.["egress-port"]')
		;;
	"passthrough")
		add_recover_action "${i}" true

		egress_port=$(echo "${match}" | jq -r '.["egress-port"]')
		;;
	*)
		echo "Invalid action type $action_type"
		exit 1
	esac

	add_stream_rule "${i}" "${match}" "${egress_port}"
done

apply_tsntool_commands

passthrough_vlans=$(jq '.["passthrough-vlans"]' <<< "${json}")

if ! [ "${passthrough_vlans}" = "null" ]; then
	add_passthrough_vlans "${passthrough_vlans}"
fi

install_vlans
