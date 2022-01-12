// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 * Initial prototype based on:
 * https://gist.github.com/austinmarton/1922600
 * https://sourceforge.net/p/linuxptp/mailman/message/31998404/
 */
#define _GNU_SOURCE
#include <inttypes.h>
#include <time.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
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
#include <netinet/udp.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "log.h"
#include "management.h"
#include "ptpmon.h"
#include "sysmon.h"
#include <linux/net_tstamp.h>

#define BUF_SIZ		10000
#define TIME_FMT_LEN	27 /* "[%s] " */

struct prog_data {
	volatile bool send_tid_should_stop;
	volatile bool send_tid_stopped;
	unsigned char dest_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char uds_remote[UNIX_PATH_MAX];
	__u8 sendbuf[BUF_SIZ];
	struct ptpmon *ptpmon;
	struct sysmon *sysmon;
	struct mnl_socket *rtnl;
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
	unsigned long timestamped;
	unsigned long iterations;
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
	char output_file[PATH_MAX];
	pthread_t send_tid;
	pthread_t tx_timestamp_tid;
	int send_tid_rc;
	int tx_timestamp_tid_rc;
	unsigned long cpumask;
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
		perror("opening stats socket failed");
		return -errno;
	}

	rc = connect(stats_fd, serv_addr, size);
	if (rc < 0) {
		perror("connecting to stats socket failed");
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

/* Timestamps will come later */
static int prog_log_packet_no_tstamp(struct prog_data *prog,
				     const struct isochron_header *hdr)
{
	struct isochron_send_pkt_data *send_pkt;
	__u32 index;

	/* Don't log if we're running indefinitely, there's no point */
	if (!prog->iterations)
		return 0;

	index = __be32_to_cpu(hdr->seqid) - 1;

	send_pkt = isochron_log_get_entry(&prog->log, sizeof(*send_pkt),
					  index);
	if (!send_pkt) {
		fprintf(stderr, "Could not log send packet at index %u\n",
			index);
		return -EINVAL;
	}

	if (send_pkt->seqid) {
		fprintf(stderr,
			"There already exists a packet logged at index %u\n",
			index);
		return -EINVAL;
	}

	send_pkt->scheduled = hdr->scheduled;
	send_pkt->wakeup = hdr->wakeup;
	send_pkt->seqid = hdr->seqid;
	send_pkt->sched_ts = 0;
	send_pkt->swts = 0;
	send_pkt->hwts = 0;

	return 0;
}

static bool
isochron_pkt_fully_timestamped(struct isochron_send_pkt_data *send_pkt)
{
	return send_pkt->hwts && send_pkt->swts && send_pkt->sched_ts;
}

/* Propagates the return code from sk_receive, i.e. the number of bytes
 * read from the socket (if we could successfully read a timestamp),
 * or a negative error code.
 */
static int prog_poll_txtstamps(struct prog_data *prog, int timeout)
{
	struct isochron_send_pkt_data *send_pkt;
	struct isochron_timestamp tstamp = {};
	__be64 hwts, swts, swts_utc;
	__u8 err_pkt[BUF_SIZ];
	int rc;

	rc = sk_receive(prog->data_fd, err_pkt, BUF_SIZ, &tstamp, MSG_ERRQUEUE,
			timeout);
	if (rc <= 0)
		return rc;

	/* Since we log the packets in the same order as the kernel keeps
	 * track of timestamps using SOF_TIMESTAMPING_OPT_ID on the data
	 * socket, finding packets by timestamp key and patching their
	 * timestamp is a cheap hack to avoid a linear lookup.
	 */
	send_pkt = isochron_log_get_entry(&prog->log, sizeof(*send_pkt),
					  tstamp.tskey);
	if (!send_pkt) {
		fprintf(stderr,
			"received timestamp for unknown key %u\n",
			tstamp.tskey);
		return -EINVAL;
	}

	if (isochron_pkt_fully_timestamped(send_pkt)) {
		fprintf(stderr,
			"received duplicate timestamp for packet key %u already fully timestamped\n",
			tstamp.tskey);
		return -EINVAL;
	}

	swts = __cpu_to_be64(utc_to_tai(timespec_to_ns(&tstamp.sw),
					prog->utc_tai_offset));
	swts_utc = __cpu_to_be64(timespec_to_ns(&tstamp.sw));
	hwts = __cpu_to_be64(timespec_to_ns(&tstamp.hw));

	switch (tstamp.tstype) {
	case SCM_TSTAMP_SCHED:
		if (swts_utc)
			send_pkt->sched_ts = swts;
		break;
	case SCM_TSTAMP_SND:
		if (swts_utc)
			send_pkt->swts = swts;
		break;
	default:
		break;
	}

	if (hwts)
		send_pkt->hwts = hwts;

	if (isochron_pkt_fully_timestamped(send_pkt))
		prog->timestamped++;

	return rc;
}

static int do_work(struct prog_data *prog, int iteration, __s64 scheduled,
		   struct isochron_header *hdr)
{
	struct timespec now_ts;
	__u8 err_pkt[BUF_SIZ];
	__s64 now;
	int rc;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);

	trace(prog, "send seqid %d start\n", iteration);

	hdr->scheduled = __cpu_to_be64(scheduled);
	hdr->wakeup = __cpu_to_be64(now);
	hdr->seqid = __cpu_to_be32(iteration);

	if (prog->txtime)
		*((__u64 *)CMSG_DATA(prog->cmsg)) = (__u64)(scheduled);

	rc = prog_log_packet_no_tstamp(prog, hdr);
	if (rc)
		return rc;

	/* Send packet */
	rc = sendmsg(prog->data_fd, &prog->msg, 0);
	if (rc < 0) {
		perror("sendmsg failed");
		sk_receive(prog->data_fd, err_pkt, BUF_SIZ, NULL,
			   MSG_ERRQUEUE, 0);
		return rc;
	}

	trace(prog, "send seqid %d end\n", iteration);

	return 0;
}

static int wait_for_txtimestamps(struct prog_data *prog)
{
	int timeout_ms = 2 * MSEC_PER_SEC;
	int rc;

	while (prog->timestamped < prog->iterations) {
		rc = prog_poll_txtstamps(prog, timeout_ms);
		if (rc <= 0) {
			fprintf(stderr,
				"Timed out waiting for TX timestamps, %ld timestamps unacknowledged\n",
				prog->iterations - prog->timestamped);
			return rc;
		}
	}

	return 0;
}

static int run_nanosleep(struct prog_data *prog)
{
	char cycle_time_buf[TIMESPEC_BUFSIZ];
	char base_time_buf[TIMESPEC_BUFSIZ];
	char wakeup_buf[TIMESPEC_BUFSIZ];
	char now_buf[TIMESPEC_BUFSIZ];
	__s64 wakeup, scheduled, now;
	struct isochron_header *hdr;
	struct timespec now_ts;
	unsigned long i;
	int rc;

	if (prog->l2) {
		hdr = (struct isochron_header *)(prog->sendbuf +
						 prog->l2_header_len);
	} else {
		hdr = (struct isochron_header *)prog->sendbuf;
	}

	rc = clock_gettime(prog->clkid, &now_ts);
	if (rc < 0) {
		perror("clock_gettime failed");
		rc = -errno;
		return rc;
	}

	now = timespec_to_ns(&now_ts);
	prog->base_time += prog->shift_time;

	/* Make sure we get enough sleep at the beginning */
	prog->base_time = future_base_time(prog->base_time, prog->cycle_time,
					   now + NSEC_PER_SEC);

	wakeup = prog->base_time - prog->advance_time;

	ns_sprintf(now_buf, now);
	ns_sprintf(base_time_buf, prog->base_time);
	ns_sprintf(cycle_time_buf, prog->cycle_time);
	ns_sprintf(wakeup_buf, wakeup);
	fprintf(stderr, "%12s: %*s\n", "Now", TIMESPEC_BUFSIZ, now_buf);
	fprintf(stderr, "%12s: %*s\n", "First wakeup", TIMESPEC_BUFSIZ, wakeup_buf);
	fprintf(stderr, "%12s: %*s\n", "Base time", TIMESPEC_BUFSIZ, base_time_buf);
	fprintf(stderr, "%12s: %*s\n", "Cycle time", TIMESPEC_BUFSIZ, cycle_time_buf);

	/* Play nice with awk's array indexing */
	for (i = 1; !prog->iterations || i <= prog->iterations; i++) {
		struct timespec wakeup_ts = ns_to_timespec(wakeup);

		rc = clock_nanosleep(prog->clkid, TIMER_ABSTIME,
				     &wakeup_ts, NULL);
		switch (rc) {
		case 0:
			scheduled = wakeup + prog->advance_time;

			rc = do_work(prog, i, scheduled, hdr);
			if (rc < 0)
				return rc;

			wakeup += prog->cycle_time;
			break;
		case EINTR:
			continue;
		default:
			pr_err(-rc, "clock_nanosleep failed: %m\n");
			break;
		}

		if (signal_received || prog->send_tid_should_stop)
			break;
	}

	return 0;
}

static void *prog_send_thread(void *arg)
{
	struct prog_data *prog = arg;

	prog->send_tid_rc = run_nanosleep(prog);
	prog->send_tid_stopped = true;

	return &prog->send_tid_rc;
}

static void *prog_tx_timestamp_thread(void *arg)
{
	struct prog_data *prog = arg;

	prog->tx_timestamp_tid_rc = wait_for_txtimestamps(prog);

	return &prog->tx_timestamp_tid_rc;
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

static bool prog_sync_ok(struct prog_data *prog)
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

	if (!prog->ptpmon)
		return true;

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
		pr_err(rc, "ptpmon failed to query grandmaster clock id: %m\n");
		return false;
	}

	rc = ptpmon_query_port_state_by_name(prog->ptpmon, prog->if_name,
					     prog->rtnl, &local_port_state);
	if (rc) {
		pr_err(rc, "ptpmon failed to query port state: %m\n");
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
		pr_err(rc, "ptpmon failed to query CURRENT_DATA_SET: %m\n");
		return false;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);

	rc = sysmon_get_offset(prog->sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc)
		return false;

	sysmon_offset += NSEC_PER_SEC * prog->utc_tai_offset;
	sysmon_ts += NSEC_PER_SEC * prog->utc_tai_offset;

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

static int prog_wait_until_sync_ok(struct prog_data *prog)
{
	while (1) {
		if (signal_received)
			return -EINTR;

		if (prog_sync_ok(prog))
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
		pr_err(rc, "ptpmon failed to query TIME_PROPERTIES_DATA_SET: %m\n");
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

static int prog_send_thread_create(struct prog_data *prog)
{
	int sched_policy = SCHED_OTHER;
	pthread_attr_t attr;
	int rc;

	rc = pthread_attr_init(&attr);
	if (rc) {
		pr_err(-rc, "failed to init sender pthread attrs: %m\n");
		return rc;
	}

	if (prog->sched_fifo)
		sched_policy = SCHED_FIFO;
	if (prog->sched_rr)
		sched_policy = SCHED_RR;

	if (sched_policy != SCHED_OTHER) {
		struct sched_param sched_param = {
			.sched_priority = prog->sched_priority,
		};

		rc = pthread_attr_setschedpolicy(&attr, sched_policy);
		if (rc) {
			pr_err(-rc, "failed to set sender pthread sched policy: %m\n");
			goto err_destroy_attr;
		}

		rc = pthread_attr_setschedparam(&attr, &sched_param);
		if (rc) {
			pr_err(-rc, "failed to set sender pthread sched priority: %m\n");
			goto err_destroy_attr;
		}
	}

	if (prog->cpumask) {
		int cpu, num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
		cpu_set_t cpus;

		CPU_ZERO(&cpus);

		for (cpu = 0; cpu < num_cpus; cpu++)
			if (prog->cpumask & BIT(cpu))
				CPU_SET(cpu, &cpus);

		rc = pthread_attr_setaffinity_np(&attr, sizeof(cpus), &cpus);
		if (rc) {
			pr_err(-rc, "failed to set sender pthread cpu affinity: %m\n");
			goto err_destroy_attr;
		}
	}

	rc = pthread_create(&prog->send_tid, &attr, prog_send_thread, prog);
	if (rc) {
		pr_err(-rc, "failed to create sender pthread: %m\n");
		goto err_destroy_attr;
	}

err_destroy_attr:
	pthread_attr_destroy(&attr);

	return rc;
}

static void prog_send_thread_destroy(struct prog_data *prog)
{
	void *res;
	int rc;

	prog->send_tid_should_stop = true;

	rc = pthread_join(prog->send_tid, &res);
	if (rc) {
		pr_err(-rc, "failed to join with sender thread: %m\n");
		return;
	}

	rc = *((int *)res);
	if (rc)
		pr_err(rc, "sender thread failed: %m\n");
}

static int prog_tx_timestamp_thread_create(struct prog_data *prog)
{
	pthread_attr_t attr;
	int rc;

	if (!prog->do_ts)
		return 0;

	rc = pthread_attr_init(&attr);
	if (rc) {
		pr_err(-rc, "failed to init tx timestamp pthread attrs: %m\n");
		return rc;
	}

	rc = pthread_create(&prog->tx_timestamp_tid, &attr,
			    prog_tx_timestamp_thread, prog);
	if (rc) {
		pr_err(-rc, "failed to create tx timestamp pthread: %m\n");
		goto err_destroy_attr;
	}

err_destroy_attr:
	pthread_attr_destroy(&attr);

	return rc;
}

static void prog_tx_timestamp_thread_destroy(struct prog_data *prog)
{
	void *res;
	int rc;

	if (!prog->do_ts)
		return;

	rc = pthread_join(prog->tx_timestamp_tid, &res);
	if (rc) {
		pr_err(-rc, "failed to join with tx timestamp thread: %m\n");
		return;
	}

	rc = *((int *)res);
	if (rc)
		pr_err(rc, "tx timestamp thread failed: %m\n");
}

static int prog_start_threads(struct prog_data *prog)
{
	int rc;

	rc = prog_tx_timestamp_thread_create(prog);
	if (rc)
		return rc;

	rc = prog_send_thread_create(prog);
	if (rc) {
		prog_tx_timestamp_thread_destroy(prog);
		return rc;
	}

	return 0;
}

static void prog_stop_threads(struct prog_data *prog)
{
	prog_send_thread_destroy(prog);
	prog_tx_timestamp_thread_destroy(prog);
}

static int prog_prepare_session(struct prog_data *prog)
{
	int rc;

	prog->timestamped = 0;
	prog->send_tid_should_stop = false;
	prog->send_tid_stopped = false;

	rc = isochron_log_init(&prog->log, prog->iterations *
			       sizeof(struct isochron_send_pkt_data));
	if (rc)
		return rc;

	rc = prog_wait_until_sync_ok(prog);
	if (rc) {
		pr_err(rc, "Failed to check sync status: %m\n");
		goto out_teardown_log;
	}

	rc = prog_prepare_receiver(prog);
	if (rc) {
		pr_err(rc, "Failed to prepare receiver for the test: %m\n");
		goto out_teardown_log;
	}

	rc = prog_start_threads(prog);
	if (rc)
		goto out_teardown_log;

	return 0;

out_teardown_log:
	isochron_log_teardown(&prog->log);
	return rc;
}

static bool prog_monitor_sync(struct prog_data *prog)
{
	while (!prog->send_tid_stopped) {
		if (signal_received)
			return false;

		if (!prog_sync_ok(prog)) {
			fprintf(stderr,
				"Sync lost during the test, repeating\n");
			return false;
		}

		sleep(1);
	}

	return true;
}

static int prog_end_session(struct prog_data *prog, bool save_log)
{
	struct isochron_log rcv_log;
	int rc;

	prog_stop_threads(prog);

	if (!prog->stats_srv.family && !prog->quiet)
		isochron_send_log_print(&prog->log);

	if (!prog->stats_srv.family)
		goto skip_collecting_rcv_log;

	printf("Collecting receiver stats\n");

	rc = isochron_collect_rcv_log(prog->stats_fd, &rcv_log);
	if (rc) {
		pr_err(rc, "Failed to collect receiver stats: %m\n");
		return rc;
	}

	if (save_log && strlen(prog->output_file)) {
		rc = isochron_log_save(prog->output_file, &prog->log, &rcv_log,
				       prog->iterations, prog->tx_len,
				       prog->omit_sync, prog->do_ts,
				       prog->taprio, prog->txtime,
				       prog->deadline, prog->base_time,
				       prog->advance_time, prog->shift_time,
				       prog->cycle_time, prog->window_size);
	}

	isochron_log_teardown(&rcv_log);
skip_collecting_rcv_log:
	isochron_log_teardown(&prog->log);

	return rc;
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
		pr_err(rc, "failed to open ptpmon: %m\n");
		goto out_destroy;
	}

	while (prog_query_utc_offset(prog) == -ENOENT) {
		if (signal_received) {
			rc = -EINTR;
			goto out_close;
		}

		printf("waiting for ptp4l\n");
		sleep(1);
	}

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
		perror("opening data socket failed");
		goto out;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prog->priority,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt on data socket failed");
		goto out_close;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX failed");
		goto out_close;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR failed");
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
			perror("SO_TXTIME on data socket failed");
			goto out_close;
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

static int prog_rtnl_open(struct prog_data *prog)
{
	struct mnl_socket *nl;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		perror("mnl_socket_open");
		return -errno;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		return -errno;
	}

	prog->rtnl = nl;

	return 0;
}

static void prog_rtnl_close(struct prog_data *prog)
{
	struct mnl_socket *nl = prog->rtnl;

	prog->rtnl = NULL;
	mnl_socket_close(nl);
}

static int prog_init(struct prog_data *prog)
{
	int rc;

	rc = isochron_handle_signals(sig_handler);
	if (rc)
		goto out;

	prog->clkid = CLOCK_TAI;

	rc = prog_rtnl_open(prog);
	if (rc)
		goto out;

	rc = prog_init_stats_socket(prog);
	if (rc)
		goto out_close_rtnl;

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

	/* Prevent the process's virtual memory from being swapped out, by
	 * locking all current and future pages
	 */
	rc = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rc < 0) {
		perror("mlockall failed");
		goto out_close_trace_mark_fd;
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

		rc = isochron_collect_rcv_log(prog->stats_fd, &rcv_log);
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
out_close_trace_mark_fd:
	prog_teardown_trace_mark(prog);
out_close_data_fd:
	prog_teardown_data_fd(prog);
out_stats_socket_teardown:
	prog_teardown_stats_socket(prog);
out_close_rtnl:
	prog_rtnl_close(prog);
out:
	return rc;
}

static void prog_teardown(struct prog_data *prog)
{
	prog_teardown_sysmon(prog);
	prog_teardown_ptpmon(prog);

	munlockall();

	prog_teardown_trace_mark(prog);
	prog_teardown_data_fd(prog);
	prog_teardown_stats_socket(prog);
	prog_rtnl_close(prog);
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
			.type = PROG_ARG_IFNAME,
			.ifname = {
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
			.type = PROG_ARG_UNSIGNED,
			.unsigned_ptr = {
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
			.type = PROG_ARG_FILEPATH,
			.filepath = {
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
		}, {
			.short_opt = "-F",
			.long_opt = "--output-file",
			.type = PROG_ARG_FILEPATH,
			.filepath = {
				.buf = prog->output_file,
				.size = PATH_MAX - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-M",
			.long_opt = "--cpu-mask",
			.type = PROG_ARG_UNSIGNED,
			.unsigned_ptr = {
				.ptr = &prog->cpumask,
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
		pr_err(rc, "argument parsing failed: %m\n");
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

	if (strlen(prog->output_file) && !prog->stats_srv.family) {
		fprintf(stderr,
			"--client is mandatory when --output-file is used\n");
		return -EINVAL;
	}

	if (!strlen(prog->output_file))
		sprintf(prog->output_file, "isochron.dat");

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
	bool sync_ok;
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	do {
		rc = prog_init(&prog);
		if (rc)
			return rc;

		rc = prog_prepare_session(&prog);
		if (rc)
			break;

		sync_ok = prog_monitor_sync(&prog);

		rc = prog_end_session(&prog, sync_ok);
		if (rc)
			break;

		prog_teardown(&prog);
	} while (!sync_ok);

	if (rc)
		prog_teardown(&prog);

	return rc;
}
