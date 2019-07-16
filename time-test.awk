# WARNING: All timespec operations are simplified and assume positive times
# (including results of timespec_sub).
function timespec_from_string(ts, string) {
	split(string, t, ".");

	while (length(t[2]) < 9)
		t[2] = t[2] "0";

	ts["tv_sec"] = t[1];
	ts["tv_nsec"] = t[2];
}

function timespec_to_string(ts) {
	if (ts["tv_sec"] < 0 || ts["tv_nsec"] < 0)
		return "(missed)";

	return sprintf("%d.%09d", ts["tv_sec"], ts["tv_nsec"]);
}

function timespec_add(ts, a, b) {
	ts["tv_sec"] = a["tv_sec"] + b["tv_sec"];
	ts["tv_nsec"] = a["tv_nsec"] + b["tv_nsec"];
	if (ts["tv_nsec"] >= NSEC_PER_SEC) {
		ts["tv_nsec"] -= NSEC_PER_SEC;
		ts["tv_sec"]++;
	}
}

function timespec_sub(ts, a, b) {
	ts["tv_sec"] = a["tv_sec"] - b["tv_sec"];
	ts["tv_nsec"] = a["tv_nsec"] - b["tv_nsec"];
	if (ts["tv_nsec"] < 0) {
		ts["tv_nsec"] += NSEC_PER_SEC;
		ts["tv_sec"]--;
	}
}

function timespec_assign(to, from) {
	to["tv_sec"] = from["tv_sec"];
	to["tv_nsec"] = from["tv_nsec"];
}

function timespec_to_ns(ts) {
	return ts["tv_sec"] * NSEC_PER_SEC + ts["tv_nsec"];
}

function ns_to_timespec(ts, ns) {
	ts["tv_sec"] = ns / NSEC_PER_SEC;
	ts["tv_nsec"] = ns % NSEC_PER_SEC;

	return ts;
}

function get_mean(array, n) {
	count = 0;
	sum = 0;

	for (i = 1; i <= n; i++) {
		if (array[i] == "n/a")
			continue;
		sum += array[i];
		count++;
	}
	return sum / count;
}

function get_std_dev(array, n, mean) {
	sumsq = 0;
	count = 0;

	for (i = 1; i <= n; i++) {
		if (array[i] == "n/a")
			continue;
		sumsq += (array[i] - mean) ^ 2;
		count++;
	}

	return sqrt(sumsq / count);
}

BEGIN {
	NSEC_PER_SEC = 1000000000;
	timespec_from_string(utc_offset_ts, utc_offset);
}

# Sample tx.log output:
# [1562942866.668933107] Sent frame scheduled for 1562942866.668796787 with seqid 10 txtstamp 1562942902.668973166
# Sample rx.log output:
# [1560348942.609750141] src 00:04:9f:05:f6:27 dst 01:02:03:04:05:06 ethertype 0x88b5 seqid 1 rxtstamp 1560348978.609704376
/Sent frame/ {
	seqid = $9;

	timespec_from_string(os_tx_time_ts, gensub(/^\[(.*)\]/, "\\1", "g", $1));
	timespec_from_string(os_scheduled_tx_time_ts, $6);
	timespec_from_string(mac_tx_time_ts, $11);

	if (NF < 12) {
		# This frame was not received
		path_delay[seqid] = "n/a";
		os_rx_latency[seqid] = "n/a";
		next;
	}

	timespec_from_string(os_rx_time_ts, gensub(/^\[(.*)\]/, "\\1", "g", $12));
	timespec_from_string(mac_rx_time_ts, $22);

	timespec_add(mac_gate_time_ts, os_scheduled_tx_time_ts, utc_offset_ts);
	timespec_sub(os_tx_latency_ts, os_scheduled_tx_time_ts, os_tx_time_ts);
	timespec_add(tmp, os_rx_time_ts, utc_offset_ts);
	timespec_sub(os_rx_latency_ts, tmp, mac_rx_time_ts);
	timespec_sub(path_delay_ts, mac_rx_time_ts, mac_tx_time_ts);
	timespec_sub(mac_tx_latency_ts, mac_tx_time_ts, mac_gate_time_ts);

	# OS TX is latency of transmission compared to scheduled time ($2 - $1)"
	# OS RX is latency of OS reception compared to OS transmission time ($3 - $2)"
	# MAC TX is latency of transmission compared to gate event time ($5 - $4)"
	# MAC RX is latency of reception compared to MAC transmission time ($6 - $5)"
	print "seqid " seqid \
	      ", OS TX " timespec_to_string(os_tx_time_ts) \
	      ", OS scheduled TX +" timespec_to_string(os_tx_latency_ts) \
	      ", MAC gate time " timespec_to_string(mac_gate_time_ts) \
	      ", MAC TX +" timespec_to_string(mac_tx_latency_ts) \
	      ", MAC RX +" timespec_to_string(path_delay_ts) \
	      ", OS RX +" timespec_to_string(os_rx_latency_ts);

	os_tx_latency[seqid] = timespec_to_ns(os_tx_latency_ts);
	path_delay[seqid] = timespec_to_ns(path_delay_ts);
	os_rx_latency[seqid] = timespec_to_ns(os_rx_latency_ts);
	mac_tx_latency[seqid] = timespec_to_ns(mac_tx_latency_ts);
};

END {
	if (seqid < 1)
		exit;

	os_tx_latency_mean = get_mean(os_tx_latency, seqid);
	os_tx_latency_std_dev = get_std_dev(os_tx_latency, seqid,
					    os_tx_latency_mean);
	print "Mean OS TX latency (OS TX - scheduled TX time): " \
		int(os_tx_latency_mean) " ns";
	print "Standard deviation: " int(os_tx_latency_std_dev) " ns";

	mac_tx_latency_mean = get_mean(mac_tx_latency, seqid);
	mac_tx_latency_std_dev = get_std_dev(mac_tx_latency, seqid,
					     mac_tx_latency_mean);
	print "Mean MAC TX latency (MAC TX - gate event time): " \
		int(mac_tx_latency_mean) " ns";
	print "Standard deviation: " int(mac_tx_latency_std_dev) " ns";

	path_delay_mean = get_mean(path_delay, seqid);
	path_delay_std_dev = get_std_dev(path_delay, seqid,
					 path_delay_mean);
	print "Mean path delay (MAC RX - MAC TX): " int(path_delay_mean) " ns";
	print "Standard deviation: " int(path_delay_std_dev) " ns";

	os_rx_latency_mean = get_mean(os_rx_latency, seqid);
	os_rx_latency_std_dev = get_std_dev(os_rx_latency, seqid,
					    os_rx_latency_mean);
	print "Mean OS RX latency (OS RX - MAC RX): " \
		int(os_rx_latency_mean) " ns";
	print "Standard deviation: " int(os_rx_latency_std_dev) " ns";
}
