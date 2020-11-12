// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP Semiconductors */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 * Initial prototype based on:
 * https://gist.github.com/austinmarton/1922600
 * https://sourceforge.net/p/linuxptp/mailman/message/31998404/
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
/* For va_start and va_end */
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include "common.h"

#define BUF_SIZ		1522
#define TIME_FMT_LEN	27 /* "[%s] " */

struct prog_data {
	__u8 dest_mac[ETH_ALEN];
	__u8 src_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char sendbuf[BUF_SIZ];
	char stats_srv_addr[INET6_ADDRSTRLEN];
	struct sockaddr_ll socket_address;
	struct isochron_log log;
	long timestamped;
	long iterations;
	clockid_t clkid;
	__s64 advance_time;
	__s64 shift_time;
	__s64 cycle_time;
	__s64 base_time;
	long priority;
	long tx_len;
	int data_fd;
	long vid;
	bool do_ts;
	bool quiet;
	long etype;
	bool omit_sync;
	bool trace_mark;
	int trace_mark_fd;
	char tracebuf[BUF_SIZ];
};

static void trace(struct prog_data *prog, const char *fmt, ...)
{
	char now_buf[TIMESPEC_BUFSIZ];
	struct timespec now_ts;
	int len = TIME_FMT_LEN;
	va_list ap;
	__s64 now;

	if (!prog->trace_mark)
		return;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);
	ns_sprintf(now_buf, now);
	snprintf(prog->tracebuf, TIME_FMT_LEN + 1, "[%24s]  ", now_buf);

	va_start(ap, fmt);
	len += vsnprintf(prog->tracebuf + TIME_FMT_LEN, BUF_SIZ - TIME_FMT_LEN,
			 fmt, ap);
	va_end(ap);

	if (write(prog->trace_mark_fd, prog->tracebuf, len) < 0) {
		perror("trace");
		exit(0);
	}
}

static void process_txtstamp(struct prog_data *prog, const char *buf,
			     struct timestamp *tstamp)
{
	struct isochron_send_pkt_data send_pkt = {0};
	struct isochron_header *hdr;
	__s64 hwts, swts;

	hdr = (struct isochron_header *)(buf + sizeof(struct vlan_ethhdr));

	send_pkt.tx_time = __be64_to_cpu(hdr->tx_time);
	send_pkt.wakeup = __be64_to_cpu(hdr->wakeup);
	send_pkt.seqid = __be32_to_cpu(hdr->seqid);
	send_pkt.hwts = timespec_to_ns(&tstamp->hw);
	send_pkt.swts = timespec_to_ns(&tstamp->sw);

	isochron_log_data(&prog->log, &send_pkt, sizeof(send_pkt));

	prog->timestamped++;
}

static void log_no_tstamp(struct prog_data *prog, const char *buf)
{
	struct isochron_send_pkt_data send_pkt = {0};
	struct isochron_header *hdr;

	hdr = (struct isochron_header *)(buf + sizeof(struct vlan_ethhdr));

	send_pkt.tx_time = __be64_to_cpu(hdr->tx_time);
	send_pkt.wakeup = __be64_to_cpu(hdr->wakeup);
	send_pkt.seqid = __be32_to_cpu(hdr->seqid);

	isochron_log_data(&prog->log, &send_pkt, sizeof(send_pkt));
}

static int do_work(struct prog_data *prog, int iteration, __s64 scheduled)
{
	unsigned char err_pkt[BUF_SIZ];
	struct timestamp tstamp = {0};
	struct isochron_header *hdr;
	struct timespec now_ts;
	__s64 now;
	int rc;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);

	trace(prog, "send seqid %d start\n", iteration);

	hdr = (struct isochron_header *)(prog->sendbuf +
					 sizeof(struct vlan_ethhdr));
	hdr->tx_time = __cpu_to_be64(scheduled);
	hdr->wakeup = __cpu_to_be64(now);
	hdr->seqid = __cpu_to_be32(iteration);

	/* Send packet */
	rc = sendto(prog->data_fd, prog->sendbuf, prog->tx_len, 0,
		    (const struct sockaddr *)&prog->socket_address,
		    sizeof(struct sockaddr_ll));
	if (rc < 0) {
		perror("send\n");
		return rc;
	}

	trace(prog, "send seqid %d end\n", iteration);

	if (prog->do_ts) {
		rc = sk_receive(prog->data_fd, err_pkt, BUF_SIZ, &tstamp,
				MSG_ERRQUEUE, 0);
		if (rc == -EAGAIN)
			return 0;
		if (rc < 0)
			return rc;

		/* If a timestamp becomes available, process it now
		 * (don't wait for later)
		 */
		process_txtstamp(prog, err_pkt, &tstamp);
	} else {
		log_no_tstamp(prog, prog->sendbuf);
	}

	return 0;
}

static int wait_for_txtimestamps(struct prog_data *prog)
{
	unsigned char err_pkt[BUF_SIZ];
	struct timestamp tstamp;
	int rc;

	if (!prog->do_ts)
		return 0;

	while (prog->timestamped < prog->iterations) {
		rc = sk_receive(prog->data_fd, err_pkt, BUF_SIZ, &tstamp,
				MSG_ERRQUEUE, TXTSTAMP_TIMEOUT_MS);
		if (rc < 0) {
			fprintf(stderr,
				"Timed out waiting for TX timestamp: %d (%s)\n",
				rc, strerror(-rc));
			fprintf(stderr, "%ld timestamps unacknowledged\n",
				prog->iterations - prog->timestamped);
			return rc;
		}

		/* If a timestamp becomes available, process it now
		 * (don't wait for later)
		 */
		process_txtstamp(prog, err_pkt, &tstamp);
	}

	return 0;
}

static int run_nanosleep(struct prog_data *prog)
{
	char cycle_time_buf[TIMESPEC_BUFSIZ];
	char base_time_buf[TIMESPEC_BUFSIZ];
	__s64 wakeup = prog->base_time;
	__s64 scheduled;
	int rc;
	long i;

	ns_sprintf(base_time_buf, prog->base_time);
	ns_sprintf(cycle_time_buf, prog->cycle_time);
	fprintf(stderr, "%10s: %s\n", "Base time", base_time_buf);
	fprintf(stderr, "%10s: %s\n", "Cycle time", cycle_time_buf);

	/* Play nice with awk's array indexing */
	for (i = 1; i <= prog->iterations; i++) {
		struct timespec wakeup_ts = ns_to_timespec(wakeup);

		rc = clock_nanosleep(prog->clkid, TIMER_ABSTIME,
				     &wakeup_ts, NULL);
		switch (rc) {
		case 0:
			scheduled = wakeup + prog->advance_time;

			rc = do_work(prog, i, scheduled);
			if (rc < 0)
				break;

			wakeup += prog->cycle_time;
			break;
		case EINTR:
			continue;
		default:
			fprintf(stderr, "clock_nanosleep returned %d: %s\n",
				rc, strerror(rc));
			break;
		}
	}

	return wait_for_txtimestamps(prog);
}

/* Calculate the first base_time in the future that satisfies this
 * relationship:
 *
 * future_base_time = base_time + N x cycle_time >= now, or
 *
 *      now - base_time
 * N >= ---------------
 *         cycle_time
 */
static __s64 future_base_time(__s64 base_time, __s64 cycle_time, __s64 now)
{
	__s64 n;

	if (base_time >= now)
		return base_time;

	n = (now - base_time) / cycle_time;

	return base_time + (n + 1) * cycle_time;
}

static int prog_init(struct prog_data *prog)
{
	int i = sizeof(struct vlan_ethhdr);
	char now_buf[TIMESPEC_BUFSIZ];
	struct vlan_ethhdr *hdr;
	struct timespec now_ts;
	struct ifreq if_idx;
	struct ifreq if_mac;
	__s64 now;
	int rc;

	prog->clkid = CLOCK_REALTIME;
	/* Convert negative logic from cmdline to positive */
	prog->do_ts = !prog->do_ts;

	/* Open RAW socket to send on */
	prog->data_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (prog->data_fd < 0) {
		perror("socket");
		return -EINVAL;
	}

	rc = setsockopt(prog->data_fd, SOL_SOCKET, SO_PRIORITY, &prog->priority,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->data_fd);
		return rc;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(prog->data_fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		close(prog->data_fd);
		return rc;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(prog->data_fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		close(prog->data_fd);
		return rc;
	}

	if (!ether_addr_to_u64(prog->src_mac))
		memcpy(prog->src_mac, &if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

	if (!prog->etype)
		prog->etype = ETH_P_1588;

	if (prog->trace_mark) {
		prog->trace_mark_fd = trace_mark_open();
		if (prog->trace_mark_fd < 0) {
			perror("trace_mark_open");
			close(prog->data_fd);
			return prog->trace_mark_fd;
		}

		memset(prog->tracebuf, ' ', TIME_FMT_LEN + 1);
		prog->tracebuf[0] = '[';
		prog->tracebuf[TIME_FMT_LEN - 2] = ']';
	}

	/* Construct the Ethernet header */
	memset(prog->sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	hdr = (struct vlan_ethhdr *)prog->sendbuf;
	memcpy(hdr->h_source, prog->src_mac, ETH_ALEN);
	memcpy(hdr->h_dest, prog->dest_mac, ETH_ALEN);
	hdr->h_vlan_proto = htons(ETH_P_8021Q);
	/* Ethertype field */
	hdr->h_vlan_encapsulated_proto = htons(prog->etype);
	hdr->h_vlan_TCI = htons((prog->priority << VLAN_PRIO_SHIFT) |
				(prog->vid & VLAN_VID_MASK));

	/* Index of the network device */
	prog->socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	prog->socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	memcpy(prog->socket_address.sll_addr, prog->dest_mac, ETH_ALEN);

	rc = clock_gettime(prog->clkid, &now_ts);
	if (rc < 0) {
		perror("clock_gettime");
		close(prog->data_fd);
		return rc;
	}

	now = timespec_to_ns(&now_ts);
	prog->base_time += prog->shift_time;
	prog->base_time -= prog->advance_time;

	/* Make sure we get enough sleep at the beginning */
	prog->base_time = future_base_time(prog->base_time, prog->cycle_time,
					   now + NSEC_PER_SEC);

	ns_sprintf(now_buf, now);
	fprintf(stderr, "%10s: %s\n", "Now", now_buf);

	rc = isochron_log_init(&prog->log);
	if (rc < 0)
		return rc;

	/* Prevent the process's virtual memory from being swapped out, by
	 * locking all current and future pages
	 */
	rc = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rc < 0) {
		fprintf(stderr, "mlockall returned %d: %s\n",
			errno, strerror(errno));
		return rc;
	}

	if (prog->do_ts) {
		rc = sk_timestamping_init(prog->data_fd, prog->if_name, 1);
		if (rc < 0)
			return rc;
	}

	i = sizeof(struct vlan_ethhdr) + sizeof(struct isochron_header);

	/* Packet data */
	while (i < prog->tx_len) {
		prog->sendbuf[i++] = 0xde;
		prog->sendbuf[i++] = 0xad;
		prog->sendbuf[i++] = 0xbe;
		prog->sendbuf[i++] = 0xef;
	}

	return 0;
}

static int prog_collect_rcv_stats(struct prog_data *prog,
				  struct isochron_log *rcv_log)
{
	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(ISOCHRON_STATS_PORT),
	};
	int stats_fd;
	int rc;

	rc = inet_pton(serv_addr.sin_family, prog->stats_srv_addr,
		       &serv_addr.sin_addr);
	if (rc <= 0) {
		if (rc == 0)
			fprintf(stderr, "%s not in presentation format",
				prog->stats_srv_addr);
		else
			fprintf(stderr, "inet_pton returned %d: %s\n",
				errno, strerror(errno));
		return -EAFNOSUPPORT;
	}

	stats_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (stats_fd < 0) {
		fprintf(stderr, "socket returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	rc = connect(stats_fd, (struct sockaddr *)&serv_addr,
		     sizeof(serv_addr));
	if (rc < 0) {
		fprintf(stderr, "connect returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	return isochron_log_recv(rcv_log, stats_fd);
}

static struct isochron_rcv_pkt_data
*isochron_rcv_log_find(struct isochron_log *rcv_log, int seqid, __s64 tx_time)
{
	char *log_buf_end = rcv_log->buf + rcv_log->buf_len;
	struct isochron_rcv_pkt_data *rcv_pkt;

	for (rcv_pkt = (struct isochron_rcv_pkt_data *)rcv_log->buf;
	     (char *)rcv_pkt < log_buf_end; rcv_pkt++)
		if (rcv_pkt->seqid == seqid &&
		    rcv_pkt->tx_time == tx_time)
			return rcv_pkt;

	return NULL;
}

static void isochron_process_stat(struct prog_data *prog,
				  struct isochron_send_pkt_data *send_pkt,
				  struct isochron_rcv_pkt_data *rcv_pkt,
				  struct isochron_stats *stats)
{
	__s64 tx_ts_diff = send_pkt->hwts - utc_to_tai(send_pkt->swts);
	__s64 rx_ts_diff = utc_to_tai(rcv_pkt->swts) - rcv_pkt->hwts;
	struct isochron_stat_entry *entry;
	char scheduled_buf[TIMESPEC_BUFSIZ];
	char tx_hwts_buf[TIMESPEC_BUFSIZ];
	char tx_swts_buf[TIMESPEC_BUFSIZ];
	char rx_hwts_buf[TIMESPEC_BUFSIZ];
	char rx_swts_buf[TIMESPEC_BUFSIZ];
	char wakeup_buf[TIMESPEC_BUFSIZ];

	ns_sprintf(scheduled_buf, send_pkt->tx_time);
	ns_sprintf(tx_swts_buf, send_pkt->swts);
	ns_sprintf(tx_hwts_buf, send_pkt->hwts);
	ns_sprintf(rx_hwts_buf, rcv_pkt->hwts);
	ns_sprintf(rx_swts_buf, rcv_pkt->swts);
	ns_sprintf(wakeup_buf, send_pkt->wakeup);

	if (!prog->quiet)
		printf("seqid %d gate %s wakeup %s tx %s sw %s rx %s sw %s\n",
		       send_pkt->seqid, scheduled_buf, wakeup_buf, tx_hwts_buf,
		       tx_swts_buf, rx_hwts_buf, rx_swts_buf);

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->seqid = send_pkt->seqid;
	entry->hw_tx_deadline_delta = send_pkt->hwts -
				      utc_to_tai(send_pkt->tx_time);
	entry->sw_tx_deadline_delta = send_pkt->swts - send_pkt->tx_time;
	entry->hw_rx_deadline_delta = rcv_pkt->hwts -
				      utc_to_tai(rcv_pkt->tx_time);
	entry->sw_rx_deadline_delta = rcv_pkt->swts - rcv_pkt->tx_time;
	entry->path_delay = rcv_pkt->hwts - send_pkt->hwts;
	entry->wakeup_latency = send_pkt->wakeup - (send_pkt->tx_time -
						    prog->advance_time);

	if (entry->hw_tx_deadline_delta > 0)
		stats->hw_tx_deadline_misses++;
	if (entry->sw_tx_deadline_delta > 0)
		stats->sw_tx_deadline_misses++;

	stats->frame_count++;
	stats->tx_sync_offset_mean += send_pkt->hwts -
				      utc_to_tai(send_pkt->swts);
	stats->rx_sync_offset_mean += rcv_pkt->hwts -
				      utc_to_tai(rcv_pkt->swts);

	LIST_INSERT_HEAD(&stats->entries, entry, list);
}

static void isochron_print_one_stat(struct isochron_stats *stats,
				    int stat_offset,
				    const char *name)
{
	int seqid_of_max = 1, seqid_of_min = 1;
	__s64 min = LONG_MAX, max = LONG_MIN;
	double mean = 0, sumsqr = 0, stddev;
	struct isochron_stat_entry *entry;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *stat = (__s64 *)((char *)entry + stat_offset);

		if (*stat < min) {
			min = *stat;
			seqid_of_min = entry->seqid;
		}
		if (*stat > max) {
			max = *stat;
			seqid_of_max = entry->seqid;
		}
		mean += *stat;
	}

	mean /= (double)stats->frame_count;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *stat = (__s64 *)((char *)entry + stat_offset);
		double deviation = (double)*stat - mean;

		sumsqr += deviation * deviation;
	}

	stddev = sqrt(sumsqr / (double)stats->frame_count);

	printf("%s: min %lld max %lld mean %.3lf stddev %.3lf, "
	       "min at seqid %d, max at seqid %d\n",
	       name, min, max, mean, stddev, seqid_of_min, seqid_of_max);
}

static void isochron_print_stats(struct prog_data *prog,
				 struct isochron_log *send_log,
				 struct isochron_log *rcv_log)
{
	char *log_buf_end = send_log->buf + send_log->buf_len;
	struct isochron_send_pkt_data *send_pkt;
	struct isochron_stat_entry *entry, *tmp;
	struct isochron_stats stats = {0};

	LIST_INIT(&stats.entries);

	for (send_pkt = (struct isochron_send_pkt_data *)send_log->buf;
	     (char *)send_pkt < log_buf_end; send_pkt++) {
		struct isochron_rcv_pkt_data *rcv_pkt;

		rcv_pkt = isochron_rcv_log_find(rcv_log, send_pkt->seqid,
						send_pkt->tx_time);
		if (!rcv_pkt) {
			printf("seqid %d lost\n", send_pkt->seqid);
			continue;
		}

		isochron_process_stat(prog, send_pkt, rcv_pkt, &stats);
		isochron_log_remove(rcv_log, rcv_pkt, sizeof(*rcv_pkt));
	}

	stats.tx_sync_offset_mean /= stats.frame_count;
	stats.rx_sync_offset_mean /= stats.frame_count;

	if (llabs(stats.tx_sync_offset_mean) > NSEC_PER_SEC &&
	    !prog->omit_sync) {
		printf("Sender PHC not synchronized (mean PHC to system time "
		       "diff %lld ns larger than 1 second)\n",
		       stats.tx_sync_offset_mean);
		goto out;
	}
	if (llabs(stats.rx_sync_offset_mean) > NSEC_PER_SEC &&
	    !prog->omit_sync) {
		printf("Receiver PHC not synchronized (mean PHC to system time "
		       "diff %lld ns larger than 1 second)\n",
		       stats.rx_sync_offset_mean);
		goto out;
	}

	printf("Summary:\n");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				path_delay), "Path delay");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				hw_tx_deadline_delta), "HW TX deadline delta");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				sw_tx_deadline_delta), "SW TX deadline delta");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				hw_rx_deadline_delta), "HW RX deadline delta");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				sw_rx_deadline_delta), "SW RX deadline delta");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				wakeup_latency), "Wakeup latency");
	printf("HW TX deadline misses: %d (%.3lf%%)\n",
	       stats.hw_tx_deadline_misses,
	       100.0f * stats.hw_tx_deadline_misses / stats.frame_count);
	printf("SW TX deadline misses: %d (%.3lf%%)\n",
	       stats.sw_tx_deadline_misses,
	       100.0f * stats.sw_tx_deadline_misses / stats.frame_count);

out:
	LIST_FOREACH_SAFE(entry, &stats.entries, list, tmp) {
		LIST_REMOVE(entry, list);
		free(entry);
	}
}

static int prog_teardown(struct prog_data *prog)
{
	int rc;

	if (strlen(prog->stats_srv_addr)) {
		struct isochron_log rcv_log;

		printf("Collecting receiver stats\n");

		isochron_log_init(&rcv_log);
		rc = prog_collect_rcv_stats(prog, &rcv_log);
		if (rc)
			return rc;

		isochron_print_stats(prog, &prog->log, &rcv_log);

		isochron_log_teardown(&rcv_log);
	} else {
		if (!prog->quiet)
			isochron_send_log_print(&prog->log);
	}

	isochron_log_teardown(&prog->log);

	if (prog->trace_mark)
		trace_mark_close(prog->trace_mark_fd);

	return rc;
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	struct prog_arg args[] = {
		{
			.short_opt = "-i",
			.long_opt = "--interface",
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->if_name,
				.size = IFNAMSIZ - 1,
			},
		}, {
			.short_opt = "-d",
			.long_opt = "--dmac",
			.type = PROG_ARG_MAC_ADDR,
			.mac = {
				.buf = prog->dest_mac,
			},
		}, {
			.short_opt = "-A",
			.long_opt = "--smac",
			.type = PROG_ARG_MAC_ADDR,
			.mac = {
				.buf = prog->src_mac,
			},
			.optional = true,
		}, {
			.short_opt = "-p",
			.long_opt = "--priority",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->priority,
			},
		}, {
			.short_opt = "-b",
			.long_opt = "--base-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->base_time,
			},
		}, {
			.short_opt = "-a",
			.long_opt = "--advance-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->advance_time,
			},
			.optional = true,
		}, {
			.short_opt = "-S",
			.long_opt = "--shift-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->shift_time,
			},
			.optional = true,
		}, {
			.short_opt = "-c",
			.long_opt = "--cycle-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->cycle_time,
			},
		}, {
			.short_opt = "-n",
			.long_opt = "--num-frames",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->iterations,
			},
		}, {
			.short_opt = "-s",
			.long_opt = "--frame-size",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->tx_len,
			},
		}, {
			.short_opt = "-T",
			.long_opt = "--no-ts",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->do_ts,
			},
			.optional = true,
		}, {
			.short_opt = "-v",
			.long_opt = "--vid",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->vid,
			},
			.optional = true,
		}, {
			.short_opt = "-C",
			.long_opt = "--client",
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->stats_srv_addr,
				.size = INET6_ADDRSTRLEN,
			},
			.optional = true,
		}, {
			.short_opt = "-q",
			.long_opt = "--quiet",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->quiet,
			},
			.optional = true,
		}, {
			.short_opt = "-e",
			.long_opt = "--etype",
			.type = PROG_ARG_LONG,
			.long_ptr = {
			        .ptr = &prog->etype,
			},
			.optional = true,
		}, {
			.short_opt = "-o",
			.long_opt = "--omit-sync",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->omit_sync,
			},
			.optional = true,
		}, {
			.short_opt = "-m",
			.long_opt = "--tracemark",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->trace_mark,
			},
			.optional = true,
		},
	};
	int rc;

	rc = prog_parse_np_args(argc, argv, args, ARRAY_SIZE(args));

	/* Non-positional arguments left unconsumed */
	if (rc < 0) {
		fprintf(stderr, "Parsing returned %d: %s\n",
			-rc, strerror(-rc));
		return rc;
	} else if (rc < argc) {
		fprintf(stderr, "%d unconsumed arguments. First: %s\n",
			argc - rc, argv[rc]);
		prog_usage("isochron-send", args, ARRAY_SIZE(args));
		return -1;
	}

	/* No point in leaving this one's default to zero, if we know that
	 * means it will always be late for its gate event.
	 */
	if (!prog->advance_time)
		prog->advance_time = prog->cycle_time;

	if (prog->advance_time > prog->cycle_time) {
		fprintf(stderr,
			"Advance time cannot be higher than cycle time\n");
		return -EINVAL;
	}
	if (prog->shift_time > prog->cycle_time) {
		fprintf(stderr,
			"Shift time cannot be higher than cycle time\n");
		return -EINVAL;
	}

	return 0;
}

int isochron_send_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc_save, rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	rc_save = run_nanosleep(&prog);

	rc = prog_teardown(&prog);
	if (rc < 0)
		return rc;

	return rc_save;
}
