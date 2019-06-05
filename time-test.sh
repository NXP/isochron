#!/bin/bash

set -e -u -o pipefail

error() {
	local lineno="$1"
	local code="${2:-1}"

	echo "Error on line ${lineno}; status ${code}. Are all cables plugged in?"
	exit "${code}"
}
trap 'error ${LINENO}' ERR

eth="eno2"
dmac="00:04:9f:05:f6:28"
txq=7
period="0.01"
iterations="100"
remote="root@10.0.0.102"

now=$(phc_ctl CLOCK_REALTIME get | awk '/clock time is/ { print $5; }')
# Round the base time to the start of the next second.
sec=$(echo "${now}" | awk -F. '{ print $1; }')
base_time="$((${sec} + 1)).0"

ssh -tt "${remote}" ./raw-l2-rcv "${eth}" > rx.log &
pid=$!

./raw-l2-send "${eth}" "${dmac}" "${txq}" "${base_time}" \
	      "${period}" "${iterations}" | tee tx.log

kill ${pid}

rm -f combined.log

while IFS= read -r line; do
	seqid=$(echo "${line}" | awk '/seqid/ { print $6; }')
	otherline=$(cat rx.log | grep "seqid ${seqid}" || :)
	echo "${line} ${otherline}" >> combined.log
done < tx.log

awk_program='								\
	BEGIN								\
	{								\
		period_nsec = period * 1000000000;			\
		expect = 0;						\
	}								\
									\
	/Send frame/							\
	{								\
		seqid = $6;						\
		send_time = gensub(/^\[(.*)\]/, "\\1", "g", $1);	\
		split(send_time, t, ".");				\
		send_sec = t[1];					\
		send_nsec = t[2];					\
		send_delay[seqid] = send_nsec - expect;			\
		expect = expect + period_nsec;				\
		if (expect >= 1000000000)				\
			expect = expect - 1000000000;			\
		rcv_time = gensub(/^\[(.*)\]/, "\\1", "g", $7);	\
		split(rcv_time, t, ".");				\
		rcv_sec = t[1];						\
		rcv_nsec = t[2];					\
		path_delay_nsec[seqid]  = rcv_sec - send_sec;		\
		path_delay_nsec[seqid] *= 1000000000;			\
		path_delay_nsec[seqid] += rcv_nsec - send_nsec;		\
	};								\
									\
	END								\
	{								\
		sum = 0;						\
		for (i = 1; i <= seqid; i++) {				\
			sum += delay[i];				\
			sumsq += delay[i] ^ 2;				\
			print "path delay " path_delay_nsec[i];		\
		}							\
		mean = sum / seqid;					\
		sumsq = 0;						\
		for (i = 1; i <= seqid; i++) {				\
			sumsq += (delay[i] - mean) ^ 2;			\
		}							\
		stdev = sqrt(sumsq / seqid);				\
		print "Mean TX delay: " mean " ns";			\
		print "Standard deviation: " stdev " ns";		\
	}'
cat combined.log | gawk -v "period=${period}" "${awk_program}"
