BEGIN {
	period_nsec = int(period) * 1000000000;
	expect = int(base_time_nsec);
}

function time_to_ns(time) {
	split(time, t, ".");
	sec = t[1];
	nsec = t[2];

	return int(sec) * 1000000000 + int(nsec);
}

function ns_to_time(time) {
	sec = int(time / 1000000000);
	nsec = int(time % 1000000000);

	return sprintf("%d.%09d", sec, nsec);
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

# Sample tx.log output:
# [1560349006.576843228] Sent frame with seqid 1 txtstamp 1560349042.576867991
# Sample rx.log output:
# [1560348942.609750141] src 00:04:9f:05:f6:27 dst 01:02:03:04:05:06 ethertype 0x88b5 seqid 1 rxtstamp 1560348978.609704376
/Sent frame/ {
	seqid = $6;

	os_tx_time = gensub(/^\[(.*)\]/, "\\1", "g", $1);
	os_tx_time = time_to_ns(os_tx_time);
	os_tx_jitter[seqid] = os_tx_time - expect;

	mac_tx_time = $8;
	mac_tx_time = time_to_ns(mac_tx_time);
	mac_tx_jitter[seqid] = mac_tx_time - expect;

	if (NF < 9) {
		# This frame was not received
		path_delay[seqid] = "n/a";
		next;
	}

	os_rx_time = gensub(/^\[(.*)\]/, "\\1", "g", $9);
	os_rx_time = time_to_ns(os_rx_time);

	mac_rx_time = $19;
	print "mac tx " mac_tx_time " mac rx " mac_rx_time;
	mac_rx_time = time_to_ns(mac_rx_time);

	path_delay[seqid] = mac_rx_time - mac_tx_time;
	print "seqid " seqid " path delay " path_delay[seqid] " ns";

	expect = expect + period_nsec;
};

END {
	path_delay_mean = get_mean(path_delay, seqid);
	path_delay_std_dev = get_std_dev(path_delay, seqid,
					 path_delay_mean);
	print "Mean path delay: " path_delay_mean " ns";
	print "Standard deviation: " path_delay_std_dev " ns";
}
