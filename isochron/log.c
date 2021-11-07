// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019-2021 NXP */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "endian.h"
#include "log.h"

#define ISOCHRON_LOG_VERSION	4

#define FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/

#define BIT(nr)			(1UL << (nr))

#define ISOCHRON_FLAG_OMIT_SYNC		BIT(0)
#define ISOCHRON_FLAG_DO_TS		BIT(1)
#define ISOCHRON_FLAG_TAPRIO		BIT(2)
#define ISOCHRON_FLAG_TXTIME		BIT(3)
#define ISOCHRON_FLAG_DEADLINE		BIT(4)

struct isochron_log_file_header {
	char		magic[8];
	__be32		version;
	__be32		packet_count;
	__be16		frame_size;
	__be16		flags;
	__be32		reserved;
	__be64		base_time;
	__be64		advance_time;
	__be64		shift_time;
	__be64		cycle_time;
	__be64		window_size;
	__be64		send_log_start;
	__be64		rcv_log_start;
	__be32		send_log_size;
	__be32		rcv_log_size;
	__be64		reserved2;
} __attribute((packed));

struct isochron_packet_metrics {
	LIST_ENTRY(isochron_packet_metrics) list;
	__s64 wakeup_to_hw_ts;
	__s64 hw_rx_deadline_delta;
	__s64 latency_budget;
	__s64 path_delay;
	__s64 wakeup_latency;
	__s64 sender_latency;
	__s64 driver_latency;
	__s64 arrival_latency;
	__u32 seqid;
};

struct isochron_stats {
	LIST_HEAD(stats_head, isochron_packet_metrics) entries;
	int frame_count;
	int hw_tx_deadline_misses;
	double tx_sync_offset_mean;
	double rx_sync_offset_mean;
	double path_delay_mean;
};

struct isochron_metric_stats {
	int seqid_of_min;
	int seqid_of_max;
	__s64 min;
	__s64 max;
	double mean;
	double stddev;
};

size_t isochron_log_buf_tlv_size(struct isochron_log *log)
{
	return sizeof(__be32) + /* log_version */
	       sizeof(__be32) + /* buf_len */
	       log->size;
}

/* Get a reference to an existing log entry */
void *isochron_log_get_entry(struct isochron_log *log, size_t entry_size,
			     int index)
{
	if (index * entry_size > log->size)
		return NULL;

	return log->buf + entry_size * index;
}

int isochron_log_send_pkt(struct isochron_log *log,
			  const struct isochron_send_pkt_data *send_pkt)
{
	__u32 index = __be32_to_cpu(send_pkt->seqid) - 1;
	struct isochron_send_pkt_data *dest;

	dest = isochron_log_get_entry(log, sizeof(*send_pkt), index);
	if (!dest) {
		fprintf(stderr, "cannot log send packet with index %u\n",
			index);
		return -EINVAL;
	}

	memcpy(dest, send_pkt, sizeof(*send_pkt));

	return 0;
}

int isochron_log_rcv_pkt(struct isochron_log *log,
			 const struct isochron_rcv_pkt_data *rcv_pkt)
{
	__u32 index = __be32_to_cpu(rcv_pkt->seqid) - 1;
	struct isochron_rcv_pkt_data *dest;

	dest = isochron_log_get_entry(log, sizeof(*rcv_pkt), index);
	if (!dest) {
		fprintf(stderr, "cannot log rcv packet with index %u\n",
			index);
		return -EINVAL;
	}

	memcpy(dest, rcv_pkt, sizeof(*rcv_pkt));

	return 0;
}

int isochron_log_xmit(struct isochron_log *log, int fd)
{
	__be32 log_version = __cpu_to_be32(ISOCHRON_LOG_VERSION);
	__be32 buf_len = __cpu_to_be32(log->size);
	ssize_t len;

	len = write_exact(fd, &log_version, sizeof(log_version));
	if (len <= 0) {
		fprintf(stderr, "log_version write returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	len = write_exact(fd, &buf_len, sizeof(buf_len));
	if (len <= 0) {
		fprintf(stderr, "buf_len write returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	if (log->size) {
		len = write_exact(fd, log->buf, log->size);
		if (len <= 0) {
			fprintf(stderr, "write returned %d: %s\n",
				errno, strerror(errno));
			return -errno;
		}
	}

	return 0;
}

int isochron_log_recv(struct isochron_log *log, int fd)
{
	__be32 log_version;
	__be32 buf_len;
	ssize_t len;
	int rc;

	len = read_exact(fd, &log_version, sizeof(log_version));
	if (len <= 0) {
		fprintf(stderr, "could not read buffer length: %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	if (__be32_to_cpu(log_version) != ISOCHRON_LOG_VERSION) {
		fprintf(stderr,
			"incompatible isochron log version %d, expected %d, exiting\n",
			__be32_to_cpu(log_version), ISOCHRON_LOG_VERSION);
		return -EINVAL;
	}

	len = read_exact(fd, &buf_len, sizeof(buf_len));
	if (len <= 0) {
		fprintf(stderr, "could not read buffer length: %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	rc = isochron_log_init(log, __be32_to_cpu(buf_len));
	if (rc)
		return rc;

	log->size = __be32_to_cpu(buf_len);
	if (log->size) {
		len = read_exact(fd, log->buf, log->size);
		if (len <= 0) {
			fprintf(stderr, "read of %zu bytes returned %d: %s\n",
				log->size, errno, strerror(errno));
			isochron_log_teardown(log);
			return -errno;
		}
	}

	return 0;
}

void isochron_rcv_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->size;
	struct isochron_rcv_pkt_data *rcv_pkt;

	for (rcv_pkt = (struct isochron_rcv_pkt_data *)log->buf;
	     (char *)rcv_pkt < log_buf_end; rcv_pkt++) {
		__s64 rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
		__s64 rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);

		/* Print packet */
		if (rcv_pkt->hwts) {
			char hwts_buf[TIMESPEC_BUFSIZ];
			char swts_buf[TIMESPEC_BUFSIZ];

			ns_sprintf(hwts_buf, rx_hwts);
			ns_sprintf(swts_buf, rx_swts);

			printf("seqid %d rxtstamp %s swts %s\n",
			       __be32_to_cpu(rcv_pkt->seqid),
			       hwts_buf, swts_buf);
		} else {
			printf("seqid %d\n", __be32_to_cpu(rcv_pkt->seqid));
		}
	}
}

void isochron_send_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->size;
	struct isochron_send_pkt_data *send_pkt;

	for (send_pkt = (struct isochron_send_pkt_data *)log->buf;
	     (char *)send_pkt < log_buf_end; send_pkt++) {
		__s64 tx_time = (__s64 )__be64_to_cpu(send_pkt->tx_time);
		__s64 tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
		__s64 tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
		char scheduled_buf[TIMESPEC_BUFSIZ];
		char hwts_buf[TIMESPEC_BUFSIZ];
		char swts_buf[TIMESPEC_BUFSIZ];

		ns_sprintf(scheduled_buf, tx_time);
		ns_sprintf(hwts_buf, tx_hwts);
		ns_sprintf(swts_buf, tx_swts);

		printf("[%s] seqid %d txtstamp %s swts %s\n",
		       scheduled_buf, __be32_to_cpu(send_pkt->seqid),
		       hwts_buf, swts_buf);
	}
}

static struct isochron_rcv_pkt_data
*isochron_rcv_log_find(struct isochron_log *rcv_log, __be32 seqid)
{
	struct isochron_rcv_pkt_data *rcv_pkt;
	__u32 index;

	index = __be32_to_cpu(seqid) - 1;
	rcv_pkt = isochron_log_get_entry(rcv_log, sizeof(*rcv_pkt), index);
	if (!rcv_pkt)
		return NULL;

	if (rcv_pkt->seqid != seqid)
		return NULL;

	return rcv_pkt;
}

static void isochron_process_stat(struct isochron_send_pkt_data *send_pkt,
				  struct isochron_rcv_pkt_data *rcv_pkt,
				  struct isochron_stats *stats,
				  bool quiet, bool taprio, bool txtime,
				  __s64 advance_time)
{
	__s64 tx_time = (__s64 )__be64_to_cpu(send_pkt->tx_time);
	__s64 tx_wakeup = (__s64 )__be64_to_cpu(send_pkt->wakeup);
	__s64 tx_sched = (__s64 )__be64_to_cpu(send_pkt->sched_ts);
	__s64 tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
	__s64 tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
	__s64 rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
	__s64 rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);
	__s64 arrival = (__s64 )__be64_to_cpu(rcv_pkt->arrival);
	struct isochron_packet_metrics *entry;
	char scheduled_buf[TIMESPEC_BUFSIZ];
	char tx_hwts_buf[TIMESPEC_BUFSIZ];
	char rx_hwts_buf[TIMESPEC_BUFSIZ];
	char arrival_buf[TIMESPEC_BUFSIZ];
	char wakeup_buf[TIMESPEC_BUFSIZ];

	ns_sprintf(scheduled_buf, tx_time);
	ns_sprintf(tx_hwts_buf, tx_hwts);
	ns_sprintf(rx_hwts_buf, rx_hwts);
	ns_sprintf(arrival_buf, arrival);
	ns_sprintf(wakeup_buf, tx_wakeup);

	if (!quiet)
		printf("seqid %d gate %s wakeup %s tx %s rx %s arrival %s\n",
		       __be32_to_cpu(send_pkt->seqid), scheduled_buf, wakeup_buf,
		       tx_hwts_buf, rx_hwts_buf, arrival_buf);

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->seqid = __be32_to_cpu(send_pkt->seqid);
	entry->wakeup_to_hw_ts = tx_hwts - tx_wakeup;
	entry->hw_rx_deadline_delta = rx_hwts - tx_time;
	/* When tc-taprio or tc-etf offload is enabled, we know that the
	 * MAC TX timestamp will be larger than the gate event, because the
	 * application's schedule should be the same as the NIC's schedule.
	 * The NIC will buffer that packet until the gate opens, something
	 * which does not happen normally. So when we operate on a NIC without
	 * tc-taprio offload, the reported deadline delta will be negative,
	 * i.e. the packet will be received before the deadline expired,
	 * precisely because isochron actually sends the packet in advance of
	 * the deadline.
	 * Avoid printing negative values and interpret this delta as either a
	 * positive "deadline delta" when we have tc-taprio (this should give
	 * us the latency of the hardware), or as a (still positive) latency
	 * budget, i.e. "how much we could still reduce the cycle time without
	 * losing deadlines".
	 */
	if (taprio || txtime)
		entry->latency_budget = tx_hwts - tx_time;
	else
		entry->latency_budget = tx_time - tx_hwts;
	entry->path_delay = rx_hwts - tx_hwts;
	entry->wakeup_latency = tx_wakeup - (tx_time - advance_time);
	entry->sender_latency = tx_swts - tx_wakeup;
	entry->driver_latency = tx_swts - tx_sched;
	entry->arrival_latency = arrival - rx_hwts;

	if (tx_hwts > tx_time)
		stats->hw_tx_deadline_misses++;

	stats->frame_count++;
	stats->tx_sync_offset_mean += tx_hwts - tx_swts;
	stats->rx_sync_offset_mean += rx_hwts - rx_swts;
	stats->path_delay_mean += entry->path_delay;

	LIST_INSERT_HEAD(&stats->entries, entry, list);
}

/* For a given metric, iterate through the list of metric structures of each
 * packet and calculate minimum, maximum, average, standard deviation.
 */
static void isochron_metric_compute_stats(const struct isochron_stats *stats,
					  struct isochron_metric_stats *ms,
					  int metric_offset,
					  bool interpret_in_reverse)
{
	struct isochron_packet_metrics *entry;
	double sumsqr = 0;

	ms->seqid_of_max = 1;
	ms->seqid_of_min = 1;
	ms->min = LONG_MAX;
	ms->max = LONG_MIN;
	ms->mean = 0;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *metric = (__s64 *)((char *)entry + metric_offset);
		__s64 val = interpret_in_reverse ? -(*metric) : *metric;

		if (val < ms->min) {
			ms->min = val;
			ms->seqid_of_min = entry->seqid;
		}
		if (val > ms->max) {
			ms->max = val;
			ms->seqid_of_max = entry->seqid;
		}
		ms->mean += val;
	}

	ms->mean /= (double)stats->frame_count;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *metric = (__s64 *)((char *)entry + metric_offset);
		__s64 val = interpret_in_reverse ? -(*metric) : *metric;
		double deviation = (double)val - ms->mean;

		sumsqr += deviation * deviation;
	}

	ms->stddev = sqrt(sumsqr / (double)stats->frame_count);
}

static void isochron_print_metric_stats(const char *name,
					const struct isochron_metric_stats *ms)
{
	printf("%s: min %lld max %lld mean %.3lf stddev %.3lf, "
	       "min at seqid %d, max at seqid %d\n",
	       name, ms->min, ms->max, ms->mean, ms->stddev,
	       ms->seqid_of_min, ms->seqid_of_max);
}

void isochron_print_stats(struct isochron_log *send_log,
			  struct isochron_log *rcv_log, long start, long stop,
			  bool omit_sync, bool quiet, bool taprio, bool txtime,
			  __s64 cycle_time, __s64 advance_time)
{
	char *log_buf_end = send_log->buf + send_log->size;
	struct isochron_metric_stats sender_latency_ms;
	struct isochron_metric_stats wakeup_latency_ms;
	struct isochron_metric_stats driver_latency_ms;
	struct isochron_packet_metrics *entry, *tmp;
	struct isochron_send_pkt_data *send_pkt;
	struct isochron_stats stats = {0};
	struct isochron_metric_stats ms;

	LIST_INIT(&stats.entries);

	for (send_pkt = (struct isochron_send_pkt_data *)send_log->buf;
	     (char *)send_pkt < log_buf_end; send_pkt++) {
		__u32 seqid = __be32_to_cpu(send_pkt->seqid);
		struct isochron_rcv_pkt_data *rcv_pkt;

		if (seqid < start || seqid > stop)
			continue;

		rcv_pkt = isochron_rcv_log_find(rcv_log, send_pkt->seqid);
		if (!rcv_pkt) {
			printf("seqid %d lost\n", __be32_to_cpu(send_pkt->seqid));
			continue;
		}

		isochron_process_stat(send_pkt, rcv_pkt, &stats,
				      quiet, taprio, txtime, advance_time);
	}

	stats.tx_sync_offset_mean /= stats.frame_count;
	stats.rx_sync_offset_mean /= stats.frame_count;
	stats.path_delay_mean /= stats.frame_count;

	if (llabs((long long)stats.tx_sync_offset_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Sender PHC not synchronized (mean PHC to system time "
		       "diff %.3lf ns larger than 1 second)\n",
		       stats.tx_sync_offset_mean);
		goto out;
	}
	if (llabs((long long)stats.rx_sync_offset_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Receiver PHC not synchronized (mean PHC to system time "
		       "diff %.3lf ns larger than 1 second)\n",
		       stats.rx_sync_offset_mean);
		goto out;
	}
	if (llabs((long long)stats.path_delay_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Sender and receiver not synchronized (mean path delay "
		       "%.3lf ns larger than 1 second)\n",
		       stats.path_delay_mean);
		goto out;
	}

	printf("Summary:\n");

	/* Path delay */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       path_delay), false);
	isochron_print_metric_stats("Path delay", &ms);

	/* Wakeup to HW TX timestamp */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       wakeup_to_hw_ts), false);
	isochron_print_metric_stats("Wakeup to HW TX timestamp", &ms);

	/* HW RX deadline delta (TX time to HW RX timestamp) */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       hw_rx_deadline_delta), false);
	if (ms.mean > 0) {
		isochron_print_metric_stats("Packets arrived later than scheduled. TX time to HW RX timestamp",
					    &ms);
	} else {
		isochron_metric_compute_stats(&stats, &ms,
					      offsetof(struct isochron_packet_metrics,
						       hw_rx_deadline_delta), true);
		isochron_print_metric_stats("Packets arrived earlier than scheduled. HW RX timestamp to TX time",
					    &ms);
	}

	/* Latency budget, interpreted differently depending on testing mode */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       latency_budget), false);
	if (taprio || txtime)
		isochron_print_metric_stats("MAC latency", &ms);
	else
		isochron_print_metric_stats("Application latency budget", &ms);

	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       sender_latency), false);
	isochron_print_metric_stats("Sender latency", &ms);
	sender_latency_ms = ms;

	/* Wakeup latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       wakeup_latency), false);
	wakeup_latency_ms = ms;
	isochron_print_metric_stats("Wakeup latency", &ms);

	/* Driver latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       driver_latency), false);
	driver_latency_ms = ms;
	isochron_print_metric_stats("Driver latency", &ms);

	/* Arrival latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       arrival_latency), false);
	isochron_print_metric_stats("Arrival latency", &ms);

	printf("Sending one packet takes on average %.3lf%% of the cycle time (min %.3lf%% max %.3lf%%)\n",
	       100.0f * sender_latency_ms.mean / cycle_time,
	       100.0f * sender_latency_ms.min / cycle_time,
	       100.0f * sender_latency_ms.max / cycle_time);
	printf("Waking up takes on average %.3lf%% of the cycle time (min %.3lf%% max %.3lf%%)\n",
	       100.0f * wakeup_latency_ms.mean / cycle_time,
	       100.0f * wakeup_latency_ms.min / cycle_time,
	       100.0f * wakeup_latency_ms.max / cycle_time);
	printf("Driver takes on average %.3lf%% of the cycle time to send a packet (min %.3lf%% max %.3lf%%)\n",
	       100.0f * driver_latency_ms.mean / cycle_time,
	       100.0f * driver_latency_ms.min / cycle_time,
	       100.0f * driver_latency_ms.max / cycle_time);

	/* HW TX deadline misses */
	if (!taprio && !txtime)
		printf("HW TX deadline misses: %d (%.3lf%%)\n",
		       stats.hw_tx_deadline_misses,
		       100.0f * stats.hw_tx_deadline_misses / stats.frame_count);

out:
	LIST_FOREACH_SAFE(entry, &stats.entries, list, tmp) {
		LIST_REMOVE(entry, list);
		free(entry);
	}
}

int isochron_log_init(struct isochron_log *log, size_t size)
{
	log->buf = calloc(sizeof(char), size);
	if (!log->buf)
		return -ENOMEM;

	log->size = size;

	return 0;
}

void isochron_log_teardown(struct isochron_log *log)
{
	free(log->buf);
}

int isochron_log_load(const char *file, struct isochron_log *send_log,
		      struct isochron_log *rcv_log, long *packet_count,
		      long *frame_size, bool *omit_sync, bool *do_ts,
		      bool *taprio, bool *txtime, bool *deadline,
		      __s64 *base_time, __s64 *advance_time, __s64 *shift_time,
		      __s64 *cycle_time, __s64 *window_size)
{
	struct isochron_log_file_header header;
	size_t len;
	int fd, rc;
	int flags;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		perror("open");
		rc = fd;
		goto out;
	}

	len = read_exact(fd, &header, sizeof(header));
	if (len <= 0) {
		perror("isochron log header write");
		rc = len;
		goto out_close;
	}

	if (strcmp(header.magic, "ISOCHRON")) {
		fprintf(stderr, "Unrecognized file format\n");
		rc = -EINVAL;
		goto out_close;
	}

	flags = __be16_to_cpu(header.flags);
	*omit_sync = !!(flags & ISOCHRON_FLAG_OMIT_SYNC);
	*do_ts = !!(flags & ISOCHRON_FLAG_DO_TS);
	*taprio = !!(flags & ISOCHRON_FLAG_TAPRIO);
	*txtime = !!(flags & ISOCHRON_FLAG_TXTIME);
	*deadline = !!(flags & ISOCHRON_FLAG_DEADLINE);

	*packet_count = __be32_to_cpu(header.packet_count);
	*frame_size = __be16_to_cpu(header.frame_size);
	*base_time = (__s64 )__be64_to_cpu(header.base_time);
	*advance_time = (__s64 )__be64_to_cpu(header.advance_time);
	*shift_time = (__s64 )__be64_to_cpu(header.shift_time);
	*cycle_time = (__s64 )__be64_to_cpu(header.cycle_time);
	*window_size = (__s64 )__be64_to_cpu(header.window_size);

	if (lseek(fd, __be64_to_cpu(header.send_log_start), SEEK_SET) < 0) {
		perror("isochron send log lseek");
		rc = -errno;
		goto out_close;
	}

	rc = isochron_log_init(send_log, __be32_to_cpu(header.send_log_size));
	if (rc) {
		fprintf(stderr, "failed to allocate memory for send log\n");
		goto out_close;
	}

	len = read_exact(fd, send_log->buf, send_log->size);
	if (len <= 0) {
		perror("isochron send log read");
		rc = len;
		goto out_send_log_teardown;
	}

	if (lseek(fd, __be64_to_cpu(header.rcv_log_start), SEEK_SET) < 0) {
		perror("isochron rcv log lseek");
		rc = -errno;
		goto out_send_log_teardown;
	}

	rc = isochron_log_init(rcv_log, __be32_to_cpu(header.rcv_log_size));
	if (rc) {
		fprintf(stderr, "failed to allocate memory for rcv log\n");
		goto out_send_log_teardown;
	}

	len = read_exact(fd, rcv_log->buf, rcv_log->size);
	if (len <= 0) {
		perror("isochron rcv log read");
		rc = len;
		goto out_rcv_log_teardown;
	}

	close(fd);

	return 0;

out_rcv_log_teardown:
	isochron_log_teardown(rcv_log);
out_send_log_teardown:
	isochron_log_teardown(send_log);
out_close:
	close(fd);
out:
	return rc;
}

int isochron_log_save(const char *file, const struct isochron_log *send_log,
		      const struct isochron_log *rcv_log, long packet_count,
		      long frame_size, bool omit_sync, bool do_ts, bool taprio,
		      bool txtime, bool deadline, __s64 base_time,
		      __s64 advance_time, __s64 shift_time, __s64 cycle_time,
		      __s64 window_size)
{
	struct isochron_log_file_header header = {
		.version	= __cpu_to_be32(ISOCHRON_LOG_VERSION),
		.packet_count	= __cpu_to_be32(packet_count),
		.frame_size	= __cpu_to_be16(frame_size),
		.base_time	= __cpu_to_be64(base_time),
		.advance_time	= __cpu_to_be64(advance_time),
		.shift_time	= __cpu_to_be64(shift_time),
		.cycle_time	= __cpu_to_be64(cycle_time),
		.window_size	= __cpu_to_be64(window_size),
	};
	int flags = 0;
	size_t len;
	int fd;

	if (omit_sync)
		flags |= ISOCHRON_FLAG_OMIT_SYNC;
	if (do_ts)
		flags |= ISOCHRON_FLAG_DO_TS;
	if (taprio)
		flags |= ISOCHRON_FLAG_TAPRIO;
	if (txtime)
		flags |= ISOCHRON_FLAG_TXTIME;
	if (deadline)
		flags |= ISOCHRON_FLAG_DEADLINE;

	strcpy(header.magic, "ISOCHRON");
	header.flags = __cpu_to_be16(flags);
	header.send_log_start = __cpu_to_be64(sizeof(header));
	header.send_log_size = __cpu_to_be32(send_log->size);
	header.rcv_log_start = __cpu_to_be64(sizeof(header) + send_log->size);
	header.rcv_log_size = __cpu_to_be32(rcv_log->size);

	fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, FILEMODE);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	len = write_exact(fd, &header, sizeof(header));
	if (len <= 0) {
		perror("isochron log header write");
		return len;
	}

	len = write_exact(fd, send_log->buf, send_log->size);
	if (len <= 0) {
		perror("isochron send log write");
		return len;
	}

	len = write_exact(fd, rcv_log->buf, rcv_log->size);
	if (len <= 0) {
		perror("isochron rcv log write");
		return len;
	}

	close(fd);

	return 0;
}
