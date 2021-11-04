// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 * Initial prototype based on:
 * https://gist.github.com/austinmarton/1922600
 * https://sourceforge.net/p/linuxptp/mailman/message/31998404/
 */
#include <inttypes.h>
#include <linux/if_packet.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
/* For va_start and va_end */
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <math.h>
#include "common.h"
#include "isochron.h"
#include "ptpmon.h"
#include "sysmon.h"
#include <linux/net_tstamp.h>

#define BUF_SIZ		10000
#define TIME_FMT_LEN	27 /* "[%s] " */

struct prog_data {
	unsigned char dest_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char uds_remote[UNIX_PATH_MAX];
	char sendbuf[BUF_SIZ];
	struct ptpmon *ptpmon;
	struct sysmon *sysmon;
	enum port_state last_local_port_state;
	enum port_state last_remote_port_state;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	char msg_control[CMSG_SPACE(sizeof(__s64))];
	struct ip_address stats_srv;
	union {
		struct sockaddr_ll l2;
		struct sockaddr_in udp4;
		struct sockaddr_in6 udp6;
	} sockaddr;
	size_t sockaddr_size;
	struct isochron_log log;
	long timestamped;
	long iterations;
	long sent;
	clockid_t clkid;
	__s64 advance_time;
	__s64 shift_time;
	__s64 cycle_time;
	__s64 base_time;
	__s64 window_size;
	long priority;
	long tx_len;
	int data_fd;
	int stats_fd;
	long vid;
	bool do_ts;
	bool quiet;
	long etype;
	bool omit_sync;
	bool trace_mark;
	int trace_mark_fd;
	char tracebuf[BUF_SIZ];
	long stats_port;
	bool taprio;
	bool txtime;
	bool deadline;
	bool do_vlan;
	int l2_header_len;
	int l4_header_len;
	bool sched_fifo;
	bool sched_rr;
	long sched_priority;
	long utc_tai_offset;
	struct ip_address ip_destination;
	bool l2;
	bool l4;
	long data_port;
	long domain_number;
	long transport_specific;
	long sync_threshold;
	long num_readings;
};

static int signal_received;

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
	/* The first 24 is for the minimum string width (for padding).
	 * The second .24 is for precision (maximum string length).
	 */
	snprintf(prog->tracebuf, TIME_FMT_LEN + 1, "[%24.24s] ", now_buf);
	prog->tracebuf[TIME_FMT_LEN] = ' ';

	va_start(ap, fmt);
	len += vsnprintf(prog->tracebuf + TIME_FMT_LEN + 1,
			 BUF_SIZ - TIME_FMT_LEN - 1, fmt, ap);
	va_end(ap);

	if (write(prog->trace_mark_fd, prog->tracebuf, len) < 0) {
		perror("trace");
		exit(0);
	}
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

static int prog_collect_rcv_stats(struct prog_data *prog,
				  struct isochron_log *rcv_log)
{
	struct isochron_management_message msg;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_GET, ISOCHRON_MID_LOG, 0);
	if (rc)
		return rc;

	len = recv_exact(prog->stats_fd, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	len = recv_exact(prog->stats_fd, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION ||
	    msg.action != ISOCHRON_RESPONSE ||
	    __be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT ||
	    __be16_to_cpu(tlv.management_id) != ISOCHRON_MID_LOG) {
		fprintf(stderr, "Unexpected reply from isochron receiver\n");
		return -EBADMSG;
	}

	return isochron_log_recv(rcv_log, prog->stats_fd);
}

static void isochron_drain_fd(int fd, size_t len)
{
	unsigned char junk[BUFSIZ];

	while (len) {
		size_t count = min(len, (size_t)BUFSIZ);

		recv_exact(fd, junk, count, 0);
		len -= count;
	};
}

static int isochron_query_mid(int fd, enum isochron_management_id mid,
			      void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(fd, ISOCHRON_GET, mid, 0);
	if (rc)
		return rc;

	len = recv_exact(fd, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Unexpected message version %d from isochron receiver\n",
			msg.version);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr, "Unexpected action %d from isochron receiver\n",
			msg.action);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		fprintf(stderr,
			"Expected payload length %zu from isochron receiver, got %zu\n",
			data_len + sizeof(tlv), payload_length);
		isochron_drain_fd(fd, payload_length);
		return -EBADMSG;
	}

	len = recv_exact(fd, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Expected TLV length %zu from isochron receiver, got %zu\n",
			data_len, tlv_length);
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Unexpected TLV type %d from isochron receiver\n",
			__be16_to_cpu(tlv.tlv_type));
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr, "Response for unexpected MID %d from isochron receiver\n",
			__be16_to_cpu(tlv.management_id));
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (data_len) {
		len = recv_exact(fd, data, data_len, 0);
		if (len <= 0)
			return len ? len : -ECONNRESET;
	}

	return 0;
}

static int isochron_update_mid(int fd, enum isochron_management_id mid,
			       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	unsigned char *tmp_buf;
	ssize_t len;
	int rc;

	tmp_buf = malloc(data_len);
	if (!tmp_buf)
		return -ENOMEM;

	rc = isochron_send_tlv(fd, ISOCHRON_SET, mid, data_len);
	if (rc) {
		free(tmp_buf);
		return rc;
	}

	len = write_exact(fd, data, data_len);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	len = recv_exact(fd, &msg, sizeof(msg), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Unexpected message version %d from isochron receiver\n",
			msg.version);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr, "Unexpected action %d from isochron receiver\n",
			msg.action);
		free(tmp_buf);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		fprintf(stderr,
			"Expected payload length %zu from isochron receiver, got %zu\n",
			data_len + sizeof(tlv), payload_length);
		isochron_drain_fd(fd, payload_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = recv_exact(fd, &tlv, sizeof(tlv), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Expected TLV length %zu from isochron receiver, got %zu\n",
			data_len, tlv_length);
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Unexpected TLV type %d from isochron receiver\n",
			__be16_to_cpu(tlv.tlv_type));
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr, "Response for unexpected MID %d from isochron receiver\n",
			__be16_to_cpu(tlv.management_id));
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = recv_exact(fd, tmp_buf, data_len, 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (memcmp(tmp_buf, data, data_len)) {
		fprintf(stderr,
			"Unexpected reply contents from isochron receiver\n");
		free(tmp_buf);
		return -EBADMSG;
	}

	free(tmp_buf);

	return 0;
}

static int prog_collect_receiver_sync_stats(struct prog_data *prog,
					    bool *have_remote_stats,
					    __s64 *sysmon_offset,
					    __s64 *ptpmon_offset,
					    int *utc_offset,
					    enum port_state *port_state,
					    struct clock_identity *gm_clkid)
{
	struct isochron_gm_clock_identity gm;
	struct isochron_sysmon_offset sysmon;
	struct isochron_ptpmon_offset ptpmon;
	struct isochron_port_state state;
	struct isochron_utc_offset utc;
	int fd = prog->stats_fd;
	int rc;

	if (!prog->stats_srv.family) {
		*have_remote_stats = false;
		return 0;
	}

	*have_remote_stats = true;

	rc = isochron_query_mid(fd, ISOCHRON_MID_SYSMON_OFFSET, &sysmon,
				sizeof(sysmon));
	if (rc) {
		fprintf(stderr, "sysmon offset missing from receiver reply\n");
		return rc;
	}

	rc = isochron_query_mid(fd, ISOCHRON_MID_PTPMON_OFFSET, &ptpmon,
				sizeof(ptpmon));
	if (rc) {
		fprintf(stderr, "ptpmon offset missing from receiver reply\n");
		return rc;
	}

	rc = isochron_query_mid(fd, ISOCHRON_MID_UTC_OFFSET, &utc,
				sizeof(utc));
	if (rc) {
		fprintf(stderr, "UTC offset missing from receiver reply\n");
		return rc;
	}

	rc = isochron_query_mid(fd, ISOCHRON_MID_PORT_STATE, &state,
				sizeof(state));
	if (rc) {
		fprintf(stderr, "port state missing from receiver reply\n");
		return rc;
	}

	rc = isochron_query_mid(fd, ISOCHRON_MID_GM_CLOCK_IDENTITY, &gm,
				sizeof(gm));
	if (rc) {
		fprintf(stderr, "GM clock identity missing from receiver reply: %d\n",
			rc);
		return rc;
	}

	*sysmon_offset = __be64_to_cpu(sysmon.offset);
	*ptpmon_offset = __be64_to_cpu(ptpmon.offset);
	*utc_offset = __be16_to_cpu(utc.offset);
	*port_state = state.state;
	memcpy(gm_clkid, &gm.clock_identity, sizeof(*gm_clkid));

	return 0;
}

static int prog_init_stats_socket(struct prog_data *prog)
{
	struct sockaddr_in6 serv_addr6;
	struct sockaddr_in serv_addr4;
	struct sockaddr *serv_addr;
	int stats_fd, size, rc;

	if (prog->stats_srv.family == AF_INET) {
		serv_addr = (struct sockaddr *)&serv_addr4;
		serv_addr4.sin_addr = prog->stats_srv.addr;
		serv_addr4.sin_port = htons(prog->stats_port);
		serv_addr4.sin_family = AF_INET;
		size = sizeof(struct sockaddr_in);
	} else if (prog->stats_srv.family == AF_INET6) {
		serv_addr = (struct sockaddr *)&serv_addr6;
		serv_addr6.sin6_addr = prog->stats_srv.addr6;
		serv_addr6.sin6_port = htons(prog->stats_port);
		serv_addr6.sin6_family = AF_INET6;
		size = sizeof(struct sockaddr_in6);
	} else {
		return 0;
	}

	stats_fd = socket(prog->stats_srv.family, SOCK_STREAM, 0);
	if (stats_fd < 0) {
		fprintf(stderr, "socket returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	rc = connect(stats_fd, serv_addr, size);
	if (rc < 0) {
		fprintf(stderr, "connect returned %d: %s\n",
			errno, strerror(errno));
		close(stats_fd);
		return -errno;
	}

	prog->stats_fd = stats_fd;

	return 0;
}

static void prog_teardown_stats_socket(struct prog_data *prog)
{
	if (!prog->stats_srv.family)
		return;

	close(prog->stats_fd);
}

static void process_txtstamp(struct prog_data *prog, const __u8 *buf,
			     struct isochron_timestamp *tstamp)
{
	struct isochron_send_pkt_data send_pkt = {0};
	struct isochron_header *hdr;

	if (prog->l2)
		hdr = (struct isochron_header *)(buf + prog->l2_header_len);
	else
		hdr = (struct isochron_header *)(buf + prog->l4_header_len);

	send_pkt.tx_time = hdr->tx_time;
	send_pkt.wakeup = hdr->wakeup;
	send_pkt.seqid = hdr->seqid;
	send_pkt.hwts = __cpu_to_be64(timespec_to_ns(&tstamp->hw));
	send_pkt.swts = __cpu_to_be64(utc_to_tai(timespec_to_ns(&tstamp->sw),
						 prog->utc_tai_offset));

	isochron_log_data(&prog->log, &send_pkt, sizeof(send_pkt));

	prog->timestamped++;
}

static void log_no_tstamp(struct prog_data *prog, const char *buf)
{
	struct isochron_send_pkt_data send_pkt = {0};
	struct isochron_header *hdr;

	/* Don't log if we're running indefinitely, there's no point */
	if (!prog->iterations)
		return;

	if (prog->l2)
		hdr = (struct isochron_header *)(buf + prog->l2_header_len);
	else
		hdr = (struct isochron_header *)buf;

	send_pkt.tx_time = hdr->tx_time;
	send_pkt.wakeup = hdr->wakeup;
	send_pkt.seqid = hdr->seqid;

	isochron_log_data(&prog->log, &send_pkt, sizeof(send_pkt));
}

static int do_work(struct prog_data *prog, int iteration, __s64 scheduled)
{
	struct isochron_timestamp tstamp = {0};
	struct isochron_header *hdr;
	struct timespec now_ts;
	__u8 err_pkt[BUF_SIZ];
	__s64 now;
	int rc;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);

	trace(prog, "send seqid %d start\n", iteration);

	if (prog->l2) {
		hdr = (struct isochron_header *)(prog->sendbuf +
						 prog->l2_header_len);
	} else {
		hdr = (struct isochron_header *)prog->sendbuf;
	}

	hdr->tx_time = __cpu_to_be64(scheduled);
	hdr->wakeup = __cpu_to_be64(now);
	hdr->seqid = __cpu_to_be32(iteration);

	if (prog->txtime)
		*((__u64 *)CMSG_DATA(prog->cmsg)) = (__u64)(scheduled);

	/* Send packet */
	rc = sendmsg(prog->data_fd, &prog->msg, 0);
	if (rc < 0) {
		perror("sendmsg");
		sk_receive(prog->data_fd, err_pkt, BUF_SIZ, NULL,
			   MSG_ERRQUEUE, 0);
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
	struct isochron_timestamp tstamp;
	int rc;

	if (!prog->do_ts)
		return 0;

	while (prog->timestamped < prog->sent) {
		rc = sk_receive(prog->data_fd, err_pkt, BUF_SIZ, &tstamp,
				MSG_ERRQUEUE, TXTSTAMP_TIMEOUT_MS);
		if (rc < 0) {
			fprintf(stderr,
				"Timed out waiting for TX timestamp: %d (%s)\n",
				rc, strerror(-rc));
			fprintf(stderr, "%ld timestamps unacknowledged\n",
				prog->sent - prog->timestamped);
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
	__u32 sched_policy = SCHED_OTHER;
	char now_buf[TIMESPEC_BUFSIZ];
	__s64 wakeup, scheduled, now;
	struct timespec now_ts;
	int rc;
	long i;

	rc = clock_gettime(prog->clkid, &now_ts);
	if (rc < 0) {
		perror("clock_gettime");
		return -errno;
	}

	now = timespec_to_ns(&now_ts);
	prog->base_time += prog->shift_time;
	prog->base_time -= prog->advance_time;

	/* Make sure we get enough sleep at the beginning */
	prog->base_time = future_base_time(prog->base_time, prog->cycle_time,
					   now + NSEC_PER_SEC);

	wakeup = prog->base_time;

	ns_sprintf(now_buf, now);
	fprintf(stderr, "%10s: %s\n", "Now", now_buf);

	if (prog->sched_fifo)
		sched_policy = SCHED_FIFO;
	if (prog->sched_rr)
		sched_policy = SCHED_RR;

	if (sched_policy != SCHED_OTHER) {
		struct sched_attr attr = {
			.size = sizeof(struct sched_attr),
			.sched_policy = sched_policy,
			.sched_priority = prog->sched_priority,
		};

		if (sched_setattr(getpid(), &attr, 0)) {
			fprintf(stderr, "sched_setattr returned %d: %s\n",
				errno, strerror(errno));
			return -errno;
		}
	}

	ns_sprintf(base_time_buf, prog->base_time);
	ns_sprintf(cycle_time_buf, prog->cycle_time);
	fprintf(stderr, "%10s: %s\n", "Base time", base_time_buf);
	fprintf(stderr, "%10s: %s\n", "Cycle time", cycle_time_buf);

	/* Play nice with awk's array indexing */
	for (i = 1; !prog->iterations || i <= prog->iterations; i++) {
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

		if (signal_received)
			break;
	}

	prog->sent = i - 1;

	/* Restore scheduling policy */
	if (sched_policy != SCHED_OTHER) {
		struct sched_attr attr = {
			.size = sizeof(struct sched_attr),
			.sched_policy = SCHED_OTHER,
			.sched_priority = 0,
		};

		if (sched_setattr(getpid(), &attr, 0)) {
			fprintf(stderr, "sched_setattr returned %d: %s\n",
				errno, strerror(errno));
			return -errno;
		}
	}

	if (rc)
		return rc;

	return wait_for_txtimestamps(prog);
}

static void sig_handler(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		signal_received = 1;
		break;
	default:
		break;
	}
}

static bool prog_sync_done(struct prog_data *prog)
{
	bool local_port_transient_state, remote_port_transient_state;
	bool remote_ptpmon_sync_done, remote_sysmon_sync_done;
	bool local_ptpmon_sync_done, local_sysmon_sync_done;
	enum port_state local_port_state, remote_port_state;
	__s64 rcv_sysmon_offset, rcv_ptpmon_offset;
	struct clock_identity rcv_gm_clkid;
	__s64 sysmon_offset, sysmon_delay;
	struct parent_data_set parent_ds;
	char now_buf[TIMESPEC_BUFSIZ];
	struct current_ds current_ds;
	bool have_remote_stats;
	__s64 ptpmon_offset;
	int rcv_utc_offset;
	__u64 sysmon_ts;
	int rc;

	rc = prog_collect_receiver_sync_stats(prog, &have_remote_stats,
					      &rcv_sysmon_offset,
					      &rcv_ptpmon_offset,
					      &rcv_utc_offset,
					      &remote_port_state,
					      &rcv_gm_clkid);
	if (rc)
		return false;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		fprintf(stderr,
			"Failed to query grandmaster clock id (%s), waiting for ptp4l\n",
			strerror(-rc));
		return false;
	}

	rc = ptpmon_query_port_state_by_name(prog->ptpmon, prog->if_name,
					     &local_port_state);
	if (rc) {
		fprintf(stderr,
			"Failed to query port state for %s (%s), waiting for ptp4l\n",
			prog->if_name, strerror(-rc));
		return false;
	}

	if (local_port_state != prog->last_local_port_state) {
		printf("Local port changed state to %s\n",
		       port_state_to_string(local_port_state));
		prog->last_local_port_state = local_port_state;
	}

	local_port_transient_state = local_port_state != PS_MASTER &&
				     local_port_state != PS_SLAVE;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		fprintf(stderr, "Failed to query CURRENT_DATA_SET: %d (%s)\n",
			rc, strerror(-rc));
		return false;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);

	rc = sysmon_get_offset(prog->sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc)
		return false;

	sysmon_offset += NSEC_PER_SEC * prog->utc_tai_offset;

	local_ptpmon_sync_done = !!(llabs(ptpmon_offset) <= prog->sync_threshold);
	local_sysmon_sync_done = !!(llabs(sysmon_offset) <= prog->sync_threshold);

	ns_sprintf(now_buf, sysmon_ts);

	if (have_remote_stats) {
		rcv_sysmon_offset += NSEC_PER_SEC * rcv_utc_offset;

		if (remote_port_state != prog->last_remote_port_state) {
			printf("Remote port changed state to %s\n",
			       port_state_to_string(remote_port_state));
			prog->last_remote_port_state = remote_port_state;
		}

		if (!clockid_eq(&parent_ds.grandmaster_identity,
				&rcv_gm_clkid)) {
			char remote_gm[CLOCKID_BUFSIZE];
			char local_gm[CLOCKID_BUFSIZE];

			clockid_to_string(&parent_ds.grandmaster_identity,
					  local_gm);
			clockid_to_string(&rcv_gm_clkid, remote_gm);

			printf("Sender and receiver not synchronized to the same grandmaster, sender has %s, receiver has %s\n",
			       local_gm, remote_gm);

			return false;
		}

		remote_port_transient_state = remote_port_state != PS_MASTER &&
					      remote_port_state != PS_SLAVE;

		remote_ptpmon_sync_done = !!(llabs(rcv_ptpmon_offset) <= prog->sync_threshold);
		remote_sysmon_sync_done = !!(llabs(rcv_sysmon_offset) <= prog->sync_threshold);

		printf("isochron[%s]: local ptpmon %10lld sysmon %10lld remote ptpmon %10lld sysmon %lld\n",
		       now_buf, ptpmon_offset, sysmon_offset, rcv_ptpmon_offset,
		       rcv_sysmon_offset);
	} else {
		remote_port_transient_state = false;
		remote_ptpmon_sync_done = true;
		remote_sysmon_sync_done = true;

		printf("isochron[%s]: ptpmon %10lld sysmon %10lld\n",
		       now_buf, ptpmon_offset, sysmon_offset);
	}

	return !local_port_transient_state && !remote_port_transient_state &&
	       local_ptpmon_sync_done && local_sysmon_sync_done &&
	       remote_ptpmon_sync_done && remote_sysmon_sync_done;
}

static int prog_check_sync(struct prog_data *prog)
{
	if (!prog->ptpmon)
		return 0;

	while (1) {
		if (signal_received)
			return -EINTR;

		if (prog_sync_done(prog))
			break;

		sleep(1);
	}

	return 0;
}

static int prog_query_utc_offset(struct prog_data *prog)
{
	struct time_properties_ds time_properties_ds;
	int ptp_utc_offset;
	int rc;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds,
				    sizeof(time_properties_ds));
	if (rc) {
		fprintf(stderr, "Failed to query TIME_PROPERTIES_DATA_SET: %d (%s)\n",
			rc, strerror(-rc));
		return rc;
	}

	ptp_utc_offset = __be16_to_cpu(time_properties_ds.current_utc_offset);
	isochron_fixup_kernel_utc_offset(ptp_utc_offset);
	prog->utc_tai_offset = ptp_utc_offset;

	return 0;
}

static int prog_query_dest_mac(struct prog_data *prog)
{
	struct isochron_destination_mac mac;
	char mac_buf[MACADDR_BUFSIZ];
	int rc;

	if (!prog->l2)
		return 0;

	if (!is_zero_ether_addr(prog->dest_mac))
		return 0;

	if (!prog->stats_srv.family) {
		fprintf(stderr, "Destination MAC address is only optional with --client\n");
		return -EINVAL;
	}

	rc = isochron_query_mid(prog->stats_fd, ISOCHRON_MID_DESTINATION_MAC,
				&mac, sizeof(mac));
	if (rc) {
		fprintf(stderr, "destination MAC missing from receiver reply\n");
		return rc;
	}

	ether_addr_copy(prog->dest_mac, mac.addr);

	mac_addr_sprintf(mac_buf, prog->dest_mac);
	printf("Destination MAC address is %s\n", mac_buf);

	return 0;
}

static int prog_prepare_receiver(struct prog_data *prog)
{
	struct isochron_packet_count packet_count = {
		.count = __cpu_to_be64(prog->iterations),
	};

	if (!prog->stats_srv.family)
		return 0;

	return isochron_update_mid(prog->stats_fd, ISOCHRON_MID_PACKET_COUNT,
				   &packet_count, sizeof(packet_count));
}

static int prog_prepare_session(struct prog_data *prog)
{
	int rc;

	rc = prog_check_sync(prog);
	if (rc) {
		fprintf(stderr, "Failed to check sync status: %s\n",
			strerror(-rc));
		return rc;
	}

	rc = prog_prepare_receiver(prog);
	if (rc) {
		fprintf(stderr, "Failed to prepare receiver for the test: %s\n",
			strerror(-rc));
		return rc;
	}

	return 0;
}

static int prog_init_ptpmon(struct prog_data *prog)
{
	char uds_local[UNIX_PATH_MAX];
	int rc;

	if (prog->omit_sync)
		return 0;

	snprintf(uds_local, sizeof(uds_local), "/var/run/isochron.%d", getpid());

	prog->ptpmon = ptpmon_create(prog->domain_number, prog->transport_specific,
				     uds_local, prog->uds_remote);
	if (!prog->ptpmon)
		return -ENOMEM;

	rc = ptpmon_open(prog->ptpmon);
	if (rc) {
		fprintf(stderr, "failed to connect to %s: %d (%s)\n",
			prog->uds_remote,  rc, strerror(-rc));
		goto out_destroy;
	}

	rc = prog_query_utc_offset(prog);
	if (rc)
		goto out_close;

	return 0;

out_close:
	ptpmon_close(prog->ptpmon);
out_destroy:
	ptpmon_destroy(prog->ptpmon);
	prog->ptpmon = NULL;

	return rc;
}

static void prog_teardown_ptpmon(struct prog_data *prog)
{
	if (!prog->ptpmon)
		return;

	ptpmon_close(prog->ptpmon);
	ptpmon_destroy(prog->ptpmon);
	prog->ptpmon = NULL;
}

static int prog_init_sysmon(struct prog_data *prog)
{
	if (prog->omit_sync)
		return 0;

	prog->sysmon = sysmon_create(prog->if_name, prog->num_readings);
	if (!prog->sysmon)
		return -ENOMEM;

	sysmon_print_method(prog->sysmon);

	return 0;
}

static void prog_teardown_sysmon(struct prog_data *prog)
{
	if (!prog->sysmon)
		return;

	sysmon_destroy(prog->sysmon);
}

static int prog_init_data_fd(struct prog_data *prog)
{
	struct ifreq if_idx;
	struct ifreq if_mac;
	int fd, rc;

	/* Open socket to send on */
	if (prog->l2)
		fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	else
		fd = socket(prog->ip_destination.family, SOCK_DGRAM,
			    IPPROTO_UDP);
	if (fd < 0) {
		perror("socket");
		goto out;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prog->priority,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		goto out_close;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		goto out_close;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		goto out_close;
	}

	if (is_zero_ether_addr(prog->src_mac))
		ether_addr_copy(prog->src_mac,
			        (unsigned char *)if_mac.ifr_hwaddr.sa_data);

	if (prog->txtime) {
		static struct sock_txtime sk_txtime = {
			.clockid = CLOCK_TAI,
			.flags = SOF_TXTIME_REPORT_ERRORS,
		};

		if (prog->deadline)
			sk_txtime.flags |= SOF_TXTIME_DEADLINE_MODE;

		rc = setsockopt(fd, SOL_SOCKET, SO_TXTIME,
				&sk_txtime, sizeof(sk_txtime));
		if (rc) {
			perror("setsockopt");
			close(fd);
			return -errno;
		}
	}

	if (prog->do_ts) {
		rc = sk_timestamping_init(fd, prog->if_name, true);
		if (rc < 0)
			goto out_close;
	}

	if (prog->l2) {
		/* Index of the network device */
		prog->sockaddr.l2.sll_ifindex = if_idx.ifr_ifindex;
		/* Address length */
		prog->sockaddr.l2.sll_halen = ETH_ALEN;
		/* Destination MAC */
		ether_addr_copy(prog->sockaddr.l2.sll_addr, prog->dest_mac);
		prog->sockaddr_size = sizeof(struct sockaddr_ll);
	} else if (prog->ip_destination.family == AF_INET) {
		prog->sockaddr.udp4.sin_addr = prog->ip_destination.addr;
		prog->sockaddr.udp4.sin_port = htons(prog->data_port);
		prog->sockaddr.udp4.sin_family = AF_INET;
		prog->sockaddr_size = sizeof(struct sockaddr_in);
	} else {
		prog->sockaddr.udp6.sin6_addr = prog->ip_destination.addr6;
		prog->sockaddr.udp6.sin6_port = htons(prog->data_port);
		prog->sockaddr.udp6.sin6_family = AF_INET6;
		prog->sockaddr_size = sizeof(struct sockaddr_in6);
	}

	prog->data_fd = fd;
	return 0;

out_close:
	close(fd);
out:
	return -errno;
}

static void prog_teardown_data_fd(struct prog_data *prog)
{
	close(prog->data_fd);
}

static void prog_init_data_packet(struct prog_data *prog)
{
	int i;

	/* Construct the Ethernet header */
	memset(prog->sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	if (prog->do_vlan) {
		struct vlan_ethhdr *hdr = (struct vlan_ethhdr *)prog->sendbuf;

		ether_addr_copy(hdr->h_source, prog->src_mac);
		ether_addr_copy(hdr->h_dest, prog->dest_mac);
		hdr->h_vlan_proto = __cpu_to_be16(ETH_P_8021Q);
		/* Ethertype field */
		hdr->h_vlan_encapsulated_proto = __cpu_to_be16(prog->etype);
		hdr->h_vlan_TCI = __cpu_to_be16((prog->priority << VLAN_PRIO_SHIFT) |
						(prog->vid & VLAN_VID_MASK));
	} else {
		struct ethhdr *hdr = (struct ethhdr *)prog->sendbuf;

		ether_addr_copy(hdr->h_source, prog->src_mac);
		ether_addr_copy(hdr->h_dest, prog->dest_mac);
		hdr->h_proto = __cpu_to_be16(prog->etype);
	}

	if (prog->ip_destination.family == AF_INET)
		prog->l4_header_len = sizeof(struct iphdr) + sizeof(struct udphdr);
	else if (prog->ip_destination.family == AF_INET6)
		prog->l4_header_len = sizeof(struct ip6_hdr) + sizeof(struct udphdr);

	if (prog->l4)
		prog->tx_len -= sizeof(struct ethhdr) + prog->l4_header_len;

	i = sizeof(struct isochron_header) + prog->l2_header_len;

	/* Packet data */
	while (i < prog->tx_len) {
		prog->sendbuf[i++] = 0xde;
		prog->sendbuf[i++] = 0xad;
		prog->sendbuf[i++] = 0xbe;
		prog->sendbuf[i++] = 0xef;
	}

	prog->iov.iov_base = prog->sendbuf;
	prog->iov.iov_len = prog->tx_len;

	memset(&prog->msg, 0, sizeof(prog->msg));
	prog->msg.msg_name = (struct sockaddr *)&prog->sockaddr;
	prog->msg.msg_namelen = prog->sockaddr_size;
	prog->msg.msg_iov = &prog->iov;
	prog->msg.msg_iovlen = 1;

	if (prog->txtime) {
		prog->msg.msg_control = prog->msg_control;
		prog->msg.msg_controllen = sizeof(prog->msg_control);

		prog->cmsg = CMSG_FIRSTHDR(&prog->msg);
		prog->cmsg->cmsg_level = SOL_SOCKET;
		prog->cmsg->cmsg_type = SCM_TXTIME;
		prog->cmsg->cmsg_len = CMSG_LEN(sizeof(__u64));
	}
}

static int prog_init_trace_mark(struct prog_data *prog)
{
	int fd;

	if (!prog->trace_mark)
		return 0;

	fd = trace_mark_open();
	if (fd < 0) {
		perror("trace_mark_open");
		return -errno;
	}

	memset(prog->tracebuf, ' ', TIME_FMT_LEN + 1);
	prog->tracebuf[0] = '[';
	prog->tracebuf[TIME_FMT_LEN - 2] = ']';
	prog->trace_mark_fd = fd;

	return 0;
}

static void prog_teardown_trace_mark(struct prog_data *prog)
{
	if (!prog->trace_mark)
		return;

	trace_mark_close(prog->trace_mark_fd);
}

static int prog_init(struct prog_data *prog)
{
	int rc;

	rc = isochron_handle_signals(sig_handler);
	if (rc)
		goto out;

	prog->clkid = CLOCK_TAI;

	rc = prog_init_stats_socket(prog);
	if (rc)
		goto out;

	rc = prog_query_dest_mac(prog);
	if (rc)
		goto out_stats_socket_teardown;

	rc = prog_init_data_fd(prog);
	if (rc)
		goto out_stats_socket_teardown;

	prog_init_data_packet(prog);

	rc = prog_init_trace_mark(prog);
	if (rc)
		goto out_close_data_fd;

	rc = isochron_log_init(&prog->log, prog->iterations *
			       sizeof(struct isochron_send_pkt_data));
	if (rc < 0)
		goto out_close_trace_mark_fd;

	/* Prevent the process's virtual memory from being swapped out, by
	 * locking all current and future pages
	 */
	rc = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rc < 0) {
		fprintf(stderr, "mlockall returned %d: %s\n",
			errno, strerror(errno));
		goto out_log_teardown;
	}

	rc = prog_init_ptpmon(prog);
	if (rc)
		goto out_munlock;

	rc = prog_init_sysmon(prog);
	if (rc)
		goto out_teardown_ptpmon;

	/* Drain potentially old packets from the isochron receiver */
	if (prog->stats_srv.family) {
		struct isochron_log rcv_log;

		rc = prog_collect_rcv_stats(prog, &rcv_log);
		if (rc)
			goto out_teardown_sysmon;

		isochron_log_teardown(&rcv_log);
	}

	return rc;

out_teardown_sysmon:
	prog_teardown_sysmon(prog);
out_teardown_ptpmon:
	prog_teardown_ptpmon(prog);
out_munlock:
	munlockall();
out_log_teardown:
	isochron_log_teardown(&prog->log);
out_close_trace_mark_fd:
	prog_teardown_trace_mark(prog);
out_close_data_fd:
	prog_teardown_data_fd(prog);
out_stats_socket_teardown:
	prog_teardown_stats_socket(prog);
out:
	return rc;
}

static struct isochron_rcv_pkt_data
*isochron_rcv_log_find(struct isochron_log *rcv_log, __be32 seqid, __be64 tx_time)
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

static void isochron_process_stat(struct isochron_send_pkt_data *send_pkt,
				  struct isochron_rcv_pkt_data *rcv_pkt,
				  struct isochron_stats *stats,
				  bool quiet, bool taprio, bool txtime,
				  __s64 advance_time)
{
	__s64 tx_time = (__s64 )__be64_to_cpu(send_pkt->tx_time);
	__s64 tx_wakeup = (__s64 )__be64_to_cpu(send_pkt->wakeup);
	__s64 tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
	__s64 tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
	__s64 rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
	__s64 rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);
	__s64 arrival = (__s64 )__be64_to_cpu(rcv_pkt->arrival);
	struct isochron_stat_entry *entry;
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
	entry->arrival_latency = arrival - rx_hwts;

	if (tx_hwts > tx_time)
		stats->hw_tx_deadline_misses++;

	stats->frame_count++;
	stats->tx_sync_offset_mean += tx_hwts - tx_swts;
	stats->rx_sync_offset_mean += rx_hwts - rx_swts;
	stats->path_delay_mean += entry->path_delay;

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

void isochron_print_stats(struct isochron_log *send_log,
			  struct isochron_log *rcv_log,
			  bool omit_sync, bool quiet, bool taprio, bool txtime,
			  __s64 advance_time)
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
			printf("seqid %d lost\n", __be32_to_cpu(send_pkt->seqid));
			continue;
		}

		isochron_process_stat(send_pkt, rcv_pkt, &stats,
				      quiet, taprio, txtime, advance_time);
		isochron_log_remove(rcv_log, rcv_pkt, sizeof(*rcv_pkt));
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
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				path_delay), "Path delay");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				wakeup_to_hw_ts), "Wakeup to HW TX timestamp");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				hw_rx_deadline_delta), "HW RX deadline delta (TX time to HW RX timestamp)");
	if (taprio || txtime)
		isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
					latency_budget), "MAC latency (TX time to HW TX timestamp)");
	else
		isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
					latency_budget), "Application latency budget (HW TX timestamp to TX time)");

	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				wakeup_latency), "Wakeup latency");
	isochron_print_one_stat(&stats, offsetof(struct isochron_stat_entry,
				arrival_latency), "Arrival latency (HW RX timestamp to application)");
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

static void prog_teardown(struct prog_data *prog)
{
	int rc;

	if (prog->stats_srv.family) {
		struct isochron_log rcv_log;

		printf("Collecting receiver stats\n");

		rc = prog_collect_rcv_stats(prog, &rcv_log);
		if (rc) {
			fprintf(stderr, "Failed to collect receiver stats: %s\n",
				strerror(-rc));
		} else {
			isochron_print_stats(&prog->log, &rcv_log,
					     prog->omit_sync, prog->quiet,
					     prog->taprio, prog->txtime,
					     prog->advance_time);

			isochron_log_teardown(&rcv_log);
		}
	} else {
		if (!prog->quiet)
			isochron_send_log_print(&prog->log);
	}

	prog_teardown_sysmon(prog);
	prog_teardown_ptpmon(prog);

	munlockall();

	isochron_log_teardown(&prog->log);
	prog_teardown_trace_mark(prog);
	prog_teardown_data_fd(prog);
	prog_teardown_stats_socket(prog);
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	bool help = false;
	struct prog_arg args[] = {
		{
			.short_opt = "-h",
			.long_opt = "--help",
			.type = PROG_ARG_HELP,
			.help_ptr = {
			        .ptr = &help,
			},
			.optional = true,
		}, {
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
			.optional = true,
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
			.optional = true,
		}, {
			.short_opt = "-P",
			.long_opt = "--stats-port",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->stats_port,
			},
			.optional = true,
		}, {
			.short_opt = "-b",
			.long_opt = "--base-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->base_time,
			},
			.optional = true,
		}, {
			.short_opt = "-a",
			.long_opt = "--advance-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->advance_time,
			},
			.optional = true,
		}, {
			.short_opt = "-S",
			.long_opt = "--shift-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->shift_time,
			},
			.optional = true,
		}, {
			.short_opt = "-c",
			.long_opt = "--cycle-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->cycle_time,
			},
		}, {
			.short_opt = "-w",
			.long_opt = "--window-size",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->window_size,
			},
			.optional = true,
		}, {
			.short_opt = "-n",
			.long_opt = "--num-frames",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->iterations,
			},
			.optional = true,
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
			.type = PROG_ARG_IP,
			.ip_ptr = {
				.ptr = &prog->stats_srv,
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
		}, {
			.short_opt = "-Q",
			.long_opt = "--taprio",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->taprio,
			},
			.optional = true,
		}, {
			.short_opt = "-x",
			.long_opt = "--txtime",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->txtime,
			},
			.optional = true,
		}, {
			.short_opt = "-D",
			.long_opt = "--deadline",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->deadline,
			},
			.optional = true,
		}, {
			.short_opt = "-H",
			.long_opt = "--sched-priority",
			.type = PROG_ARG_LONG,
			.long_ptr = {
			        .ptr = &prog->sched_priority,
			},
			.optional = true,
		}, {
			.short_opt = "-f",
			.long_opt = "--sched-fifo",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->sched_fifo,
			},
			.optional = true,
		}, {
			.short_opt = "-r",
			.long_opt = "--sched-rr",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->sched_rr,
			},
			.optional = true,
		}, {
			.short_opt = "-O",
			.long_opt = "--utc-tai-offset",
			.type = PROG_ARG_LONG,
			.long_ptr = {
			        .ptr = &prog->utc_tai_offset,
			},
			.optional = true,
		}, {
			.short_opt = "-J",
			.long_opt = "--ip-destination",
			.type = PROG_ARG_IP,
			.ip_ptr = {
			        .ptr = &prog->ip_destination,
			},
			.optional = true,
		}, {
			.short_opt = "-2",
			.long_opt = "--l2",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
				.ptr = &prog->l2,
			},
			.optional = true,
		}, {
			.short_opt = "-4",
			.long_opt = "--l4",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
				.ptr = &prog->l4,
			},
			.optional = true,
		}, {
			.short_opt = "-P",
			.long_opt = "--data-port",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->data_port,
			},
			.optional = true,
		}, {
			.short_opt = "-N",
			.long_opt = "--domain-number",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->domain_number,
			},
			.optional = true,
		}, {
			.short_opt = "-t",
			.long_opt = "--transport-specific",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->transport_specific,
			},
			.optional = true,
		}, {
			.short_opt = "-U",
			.long_opt = "--unix-domain-socket",
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->uds_remote,
				.size = UNIX_PATH_MAX - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-X",
			.long_opt = "--sync-threshold",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->sync_threshold,
			},
			.optional = true,
		}, {
			.short_opt = "-R",
			.long_opt = "--num-readings",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->num_readings,
			},
			.optional = true,
		},
	};
	int rc;

	prog->vid = -1;
	prog->utc_tai_offset = -1;

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

	if (help) {
		prog_usage("isochron-send", args, ARRAY_SIZE(args));
		return -1;
	}

	if (prog->txtime && prog->taprio) {
		fprintf(stderr,
			"Cannot enable txtime and taprio mode at the same time\n");
		return -EINVAL;
	}

	if (prog->deadline && !prog->txtime) {
		fprintf(stderr, "Deadline mode supported only with txtime\n");
		return -EINVAL;
	}

	/* No point in leaving this one's default to zero, if we know that
	 * means it will always be late for its gate event. So set the implicit
	 * advance time to be one full cycle early, but make sure to avoid
	 * premature transmission by delaying with the window size. I.e.
	 * don't send here:
	 *
	 *  base-time - cycle-time            base-time
	 * |------|--------------------------|------|--------------------------|
	 * ^<-------------------------------> window-size
	 * | advance-time                     <---->
	 * |
	 * here
	 *
	 * but here:
	 *
	 *  base-time - cycle-time            base-time
	 * |------|--------------------------|------|--------------------------|
	 *        ^<------------------------> window-size
	 *        | advance-time              <---->
	 *        |
	 *        here
	 */
	if (!prog->advance_time)
		prog->advance_time = prog->cycle_time - prog->window_size;

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
	if (prog->window_size > prog->cycle_time) {
		fprintf(stderr,
			"Window size cannot be higher than cycle time\n");
		return -EINVAL;
	}

	if (prog->sched_fifo && prog->sched_rr) {
		fprintf(stderr,
			"cannot have SCHED_FIFO and SCHED_RR at the same time\n");
		return -EINVAL;
	}

	if (prog->tx_len > BUF_SIZ) {
		fprintf(stderr,
			"Frame size cannot exceed %d octets\n", BUF_SIZ);
		return -EINVAL;
	}

	if (strlen(prog->uds_remote) == 0)
		sprintf(prog->uds_remote, "/var/run/ptp4l");

	if (!prog->stats_port)
		prog->stats_port = ISOCHRON_STATS_PORT;

	if (prog->l2 && prog->l4) {
		fprintf(stderr, "Choose transport as either L2 or L4!\n");
		return -EINVAL;
	}

	if (!prog->l2 && !prog->l4)
		prog->l2 = true;

	/* If we have a connection to the receiver, we can query it for the
	 * destination MAC for this test
	 */
	if (prog->l2 && is_zero_ether_addr(prog->dest_mac) &&
	    !prog->stats_srv.family) {
		fprintf(stderr, "Please specify destination MAC address\n");
		return -EINVAL;
	}

	if (prog->l2) {
		if (prog->vid == -1) {
			prog->do_vlan = false;
			prog->l2_header_len = sizeof(struct ethhdr);
		} else {
			prog->do_vlan = true;
			prog->l2_header_len = sizeof(struct vlan_ethhdr);
		}
	}

	if (!prog->data_port)
		prog->data_port = ISOCHRON_DATA_PORT;

	/* Convert negative logic from cmdline to positive */
	prog->do_ts = !prog->do_ts;

	if (prog->do_ts && !prog->iterations) {
		fprintf(stderr,
			"cannot take timestamps if running indefinitely\n");
		return -EINVAL;
	}

	if (!prog->num_readings)
		prog->num_readings = 5;

	if (!prog->etype)
		prog->etype = ETH_P_ISOCHRON;

	if (prog->utc_tai_offset == -1) {
		/* If we're using the ptpmon, we'll get the UTC offset
		 * from the PTP daemon.
		 */
		if (prog->omit_sync) {
			prog->utc_tai_offset = get_utc_tai_offset();
			fprintf(stderr, "Using the kernel UTC-TAI offset which is %ld\n",
				prog->utc_tai_offset);
		}
	} else {
		rc = set_utc_tai_offset(prog->utc_tai_offset);
		if (rc == -1) {
			perror("set_utc_tai_offset");
			return -errno;
		}
	}

	return 0;
}

int isochron_send_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	rc = prog_prepare_session(&prog);
	if (rc < 0)
		goto out;

	rc = run_nanosleep(&prog);

out:
	prog_teardown(&prog);

	return rc;
}
