// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 * Initial prototype based on:
 * - https://gist.github.com/austinmarton/2862515
 */
#include <linux/if_packet.h>
#include <linux/un.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "log.h"
#include "management.h"
#include "ptpmon.h"
#include "sysmon.h"

#define BUF_SIZ		10000

struct prog_data {
	char if_name[IFNAMSIZ];
	unsigned char dest_mac[ETH_ALEN];
	char uds_remote[UNIX_PATH_MAX];
	unsigned int if_index;
	__u8 rcvbuf[BUF_SIZ];
	struct isochron_log log;
	clockid_t clkid;
	struct ptpmon *ptpmon;
	struct sysmon *sysmon;
	int stats_listenfd;
	int stats_fd;
	int data_fd;
	int data_timeout_fd;
	bool have_client;
	bool client_waiting_for_log;
	bool quiet;
	long etype;
	long stats_port;
	unsigned long iterations;
	unsigned long received_pkt_count;
	bool sched_fifo;
	bool sched_rr;
	long sched_priority;
	long utc_tai_offset;
	bool l2;
	bool l4;
	long data_port;
	long domain_number;
	long transport_specific;
	long sync_threshold;
	long num_readings;
};

static int signal_received;

static int prog_rearm_data_timeout_fd(struct prog_data *prog)
{
	struct itimerspec timeout = {
		.it_value = {
			.tv_sec = 5,
			.tv_nsec = 0,
		},
		.it_interval = {
			.tv_sec = 0,
			.tv_nsec = 0,
		},
	};

	if (timerfd_settime(prog->data_timeout_fd, 0, &timeout, NULL) < 0) {
		perror("timerfd_settime");
		return -errno;
	}

	return 0;
}

static void prog_disarm_data_timeout_fd(struct prog_data *prog)
{
	struct itimerspec timeout = {};

	timerfd_settime(prog->data_timeout_fd, 0, &timeout, NULL);
}

static bool prog_received_all_packets(struct prog_data *prog)
{
	return prog->received_pkt_count == prog->iterations;
}

static int prog_forward_isochron_log(struct prog_data *prog)
{
	int rc;

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(&prog->log));
	if (rc)
		return 0;

	isochron_log_xmit(&prog->log, prog->stats_fd);
	isochron_log_teardown(&prog->log);
	return isochron_log_init(&prog->log, prog->iterations *
				 sizeof(struct isochron_rcv_pkt_data));
}

static int app_loop(struct prog_data *prog, __u8 *rcvbuf, size_t len,
		    const struct isochron_timestamp *tstamp)
{
	struct isochron_rcv_pkt_data rcv_pkt = {0};
	struct timespec now_ts;
	__u32 seqid;
	__s64 now;
	int rc;

	clock_gettime(prog->clkid, &now_ts);

	rc = prog_rearm_data_timeout_fd(prog);
	if (rc)
		return rc;

	now = timespec_to_ns(&now_ts);
	rcv_pkt.arrival = __cpu_to_be64(now);
	if (prog->l2) {
		struct ethhdr *eth_hdr = (struct ethhdr *)rcvbuf;
		struct isochron_header *hdr = (struct isochron_header *)(eth_hdr + 1);

		if (len < sizeof(*eth_hdr) + sizeof(*hdr)) {
			if (!prog->quiet)
				printf("Packet too short (%zu bytes)\n", len);
			return -1;
		}

		rcv_pkt.seqid = hdr->seqid;
		rcv_pkt.hwts = __cpu_to_be64(timespec_to_ns(&tstamp->hw));
		rcv_pkt.swts = __cpu_to_be64(utc_to_tai(timespec_to_ns(&tstamp->sw),
							prog->utc_tai_offset));
	} else {
		struct isochron_header *hdr = (struct isochron_header *)rcvbuf;

		if (len < sizeof(*hdr)) {
			if (!prog->quiet)
				printf("Packet too short (%zu bytes)\n", len);
			return -1;
		}

		rcv_pkt.seqid = hdr->seqid;
		rcv_pkt.hwts = __cpu_to_be64(timespec_to_ns(&tstamp->hw));
		rcv_pkt.swts = __cpu_to_be64(utc_to_tai(timespec_to_ns(&tstamp->sw),
							prog->utc_tai_offset));
	}

	seqid = __be32_to_cpu(rcv_pkt.seqid);
	if (seqid > prog->iterations) {
		if (!prog->quiet)
			printf("Discarding seqid %u\n", seqid);
		return -1;
	}

	rc = isochron_log_rcv_pkt(&prog->log, &rcv_pkt);
	if (rc)
		return rc;

	prog->received_pkt_count++;

	/* Expedite the log transmission if we're late */
	if (prog->client_waiting_for_log && prog_received_all_packets(prog))
		return prog_forward_isochron_log(prog);

	return 0;
}

/* Borrowed from raw_configure in linuxptp */
static int multicast_listen(int fd, unsigned int if_index,
			    unsigned char *macaddr, bool enable)
{
	struct packet_mreq mreq;
	int rc, option;

	if (enable)
		option = PACKET_ADD_MEMBERSHIP;
	else
		option = PACKET_DROP_MEMBERSHIP;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	ether_addr_copy(mreq.mr_address, macaddr);

	rc = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (!rc)
		return 0;

	perror("setsockopt PACKET_MR_MULTICAST failed");

	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_ALLMULTI;
	mreq.mr_alen = 0;
	rc = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (!rc)
		return 0;

	perror("setsockopt PACKET_MR_ALLMULTI failed");

	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;
	rc = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (!rc)
		return 0;

	perror("setsockopt PACKET_MR_PROMISC failed");

	fprintf(stderr, "all socket options failed\n");
	return -1;
}

static int prog_data_event(struct prog_data *prog)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)prog->rcvbuf;
	struct isochron_timestamp tstamp = {0};
	ssize_t len;

	len = sk_receive(prog->data_fd, prog->rcvbuf,
			 BUF_SIZ, &tstamp, 0, 0);
	/* Suppress "Interrupted system call" message */
	if (len < 0 && errno != EINTR) {
		perror("recvfrom failed");
		return -errno;
	}

	if (prog->l2 && !ether_addr_equal(prog->dest_mac, eth_hdr->h_dest))
		return 0;

	return app_loop(prog, prog->rcvbuf, len, &tstamp);
}

static int prog_data_fd_timeout(struct prog_data *prog)
{
	if (!prog->client_waiting_for_log)
		return 0;

	/* Ok, ok, time is up, let's send what we've got so far. */
	prog->client_waiting_for_log = false;

	prog_disarm_data_timeout_fd(prog);

	fprintf(stderr,
		"Timed out waiting for data packets, received %lu out of %lu expected\n",
		prog->received_pkt_count, prog->iterations);

	return prog_forward_isochron_log(prog);
}

static void prog_close_client_stats_session(struct prog_data *prog)
{
	prog_disarm_data_timeout_fd(prog);
	close(prog->stats_fd);
	prog->have_client = false;
	prog->client_waiting_for_log = false;
	prog->received_pkt_count = 0;
	prog->iterations = 0;
}

static int prog_client_connect_event(struct prog_data *prog)
{
	char client_addr[INET6_ADDRSTRLEN];
	struct sockaddr_in addr;
	socklen_t addr_len;

	addr_len = sizeof(struct sockaddr_in);
	prog->stats_fd = accept(prog->stats_listenfd, (struct sockaddr *)&addr,
				&addr_len);
	if (prog->stats_fd < 0) {
		if (errno != EINTR)
			perror("accept failed");
		return -errno;
	}

	if (!inet_ntop(addr.sin_family, &addr.sin_addr.s_addr,
		       client_addr, addr_len)) {
		perror("inet_pton failed");
		prog_close_client_stats_session(prog);
		return -errno;
	}

	printf("Accepted connection from %s\n", client_addr);

	prog->have_client = true;

	return 0;
}

static int prog_forward_sysmon_offset(struct prog_data *prog)
{
	struct isochron_sysmon_offset sysmon;
	__s64 sysmon_offset, sysmon_delay;
	__u64 sysmon_ts;
	int rc;

	rc = sysmon_get_offset(prog->sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc) {
		pr_err(rc, "Failed to read sysmon offset: %m\n");
		isochron_send_empty_tlv(prog->stats_fd, ISOCHRON_MID_SYSMON_OFFSET);
		return 0;
	}

	sysmon.offset = __cpu_to_be64(sysmon_offset);
	sysmon.time = __cpu_to_be64(sysmon_ts);
	sysmon.delay = __cpu_to_be64(sysmon_delay);

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_SYSMON_OFFSET,
			       sizeof(sysmon));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &sysmon, sizeof(sysmon));

	return 0;
}

static int prog_forward_ptpmon_offset(struct prog_data *prog)
{
	struct isochron_ptpmon_offset ptpmon;
	struct current_ds current_ds;
	__s64 ptpmon_offset;
	int rc;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon offset: %m\n");
		isochron_send_empty_tlv(prog->stats_fd, ISOCHRON_MID_PTPMON_OFFSET);
		return 0;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);
	ptpmon.offset = __cpu_to_be64(ptpmon_offset);

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PTPMON_OFFSET,
			       sizeof(ptpmon));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &ptpmon, sizeof(ptpmon));

	return 0;
}

static int prog_forward_utc_offset(struct prog_data *prog)
{
	struct time_properties_ds time_properties_ds;
	struct isochron_utc_offset utc;
	int rc;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds, sizeof(time_properties_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon UTC offset: %m\n");
		isochron_send_empty_tlv(prog->stats_fd, ISOCHRON_MID_UTC_OFFSET);
		return 0;
	}

	utc.offset = time_properties_ds.current_utc_offset;

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_UTC_OFFSET, sizeof(utc));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &utc, sizeof(utc));

	isochron_fixup_kernel_utc_offset(__be16_to_cpu(utc.offset));
	prog->utc_tai_offset = __be16_to_cpu(utc.offset);

	return 0;
}

static int prog_forward_port_state(struct prog_data *prog)
{
	struct isochron_port_state state;
	enum port_state port_state;
	int rc;

	rc = ptpmon_query_port_state_by_name(prog->ptpmon, prog->if_name,
					     &port_state);
	if (rc) {
		pr_err(rc, "Failed to read ptpmon port state: %m\n");
		isochron_send_empty_tlv(prog->stats_fd, ISOCHRON_MID_PORT_STATE);
		return 0;
	}

	state.state = port_state;

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_STATE, sizeof(state));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &state, sizeof(state));

	return 0;
}

static int prog_forward_gm_clock_identity(struct prog_data *prog)
{
	struct isochron_gm_clock_identity gm;
	struct parent_data_set parent_ds;
	int rc;

	rc = ptpmon_query_clock_mid(prog->ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon GM clockID: %m\n");
		isochron_send_empty_tlv(prog->stats_fd, ISOCHRON_MID_GM_CLOCK_IDENTITY);
		return 0;
	}

	memcpy(&gm.clock_identity, &parent_ds.grandmaster_identity,
	       sizeof(gm.clock_identity));

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_GM_CLOCK_IDENTITY,
			       sizeof(gm));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &gm, sizeof(gm));

	return 0;
}

static int prog_forward_destination_mac(struct prog_data *prog)
{
	struct isochron_destination_mac mac;
	int rc;

	memset(&mac, 0, sizeof(mac));
	ether_addr_copy(mac.addr, prog->dest_mac);

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_DESTINATION_MAC,
			       sizeof(mac));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, &mac, sizeof(mac));

	return 0;
}

static void isochron_tlv_next(struct isochron_tlv **tlv, size_t *len)
{
	size_t tlv_size_bytes;

	tlv_size_bytes = __be32_to_cpu((*tlv)->length_field) + sizeof(**tlv);
	*len += tlv_size_bytes;
	*tlv = (struct isochron_tlv *)((unsigned char *)tlv + tlv_size_bytes);
}

static void *isochron_tlv_data(struct isochron_tlv *tlv)
{
	return tlv + 1;
}

static int prog_set_packet_count(struct prog_data *prog,
				 struct isochron_packet_count *packet_count,
				 size_t struct_size)
{
	size_t iterations;
	int rc;

	if (struct_size != sizeof(*packet_count)) {
		fprintf(stderr,
			"Expected %zu bytes for PACKET_COUNT command, got %zu\n",
			sizeof(*packet_count), struct_size);
		isochron_send_empty_tlv(prog->stats_fd,
					ISOCHRON_MID_PACKET_COUNT);
		return 0;
	}

	iterations = __be64_to_cpu(packet_count->count);

	isochron_log_teardown(&prog->log);
	rc = isochron_log_init(&prog->log, iterations *
			       sizeof(struct isochron_rcv_pkt_data));
	if (rc) {
		pr_err(rc, "Could not allocate memory for %zu iterations: %m\n",
		       iterations);
		isochron_send_empty_tlv(prog->stats_fd,
					ISOCHRON_MID_PACKET_COUNT);
		return 0;
	}

	prog->iterations = iterations;

	/* Clock is ticking! */
	rc = prog_rearm_data_timeout_fd(prog);
	if (rc) {
		pr_err(rc, "Could not arm timeout timer: %m\n");
		isochron_send_empty_tlv(prog->stats_fd,
					ISOCHRON_MID_PACKET_COUNT);
		return 0;
	}

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PACKET_COUNT,
			       sizeof(*packet_count));
	if (rc)
		return 0;

	write_exact(prog->stats_fd, packet_count, sizeof(*packet_count));

	return 0;
}

static int isochron_set_parse_one_tlv(struct prog_data *prog,
				      struct isochron_tlv *tlv)
{
	enum isochron_management_id mid = __be16_to_cpu(tlv->management_id);

	switch (mid) {
	case ISOCHRON_MID_PACKET_COUNT:
		return prog_set_packet_count(prog, isochron_tlv_data(tlv),
					     __be32_to_cpu(tlv->length_field));
	default:
		isochron_send_empty_tlv(prog->stats_fd, mid);
		return 0;
	}
}

static int isochron_get_parse_one_tlv(struct prog_data *prog,
				      struct isochron_tlv *tlv)
{
	enum isochron_management_id mid = __be16_to_cpu(tlv->management_id);

	switch (mid) {
	case ISOCHRON_MID_LOG:
		/* Keep the client on hold */
		if (!prog_received_all_packets(prog)) {
			prog->client_waiting_for_log = true;
			return 0;
		}

		return prog_forward_isochron_log(prog);
	case ISOCHRON_MID_SYSMON_OFFSET:
		return prog_forward_sysmon_offset(prog);
	case ISOCHRON_MID_PTPMON_OFFSET:
		return prog_forward_ptpmon_offset(prog);
	case ISOCHRON_MID_UTC_OFFSET:
		return prog_forward_utc_offset(prog);
	case ISOCHRON_MID_PORT_STATE:
		return prog_forward_port_state(prog);
	case ISOCHRON_MID_GM_CLOCK_IDENTITY:
		return prog_forward_gm_clock_identity(prog);
	case ISOCHRON_MID_DESTINATION_MAC:
		return prog_forward_destination_mac(prog);
	default:
		isochron_send_empty_tlv(prog->stats_fd, mid);
		return 0;
	}
}

static int prog_client_mgmt_event(struct prog_data *prog)
{
	struct isochron_management_message msg;
	unsigned char buf[BUF_SIZ];
	struct isochron_tlv *tlv;
	size_t parsed_len = 0;
	ssize_t len;
	int rc;

	len = recv_exact(prog->stats_fd, &msg, sizeof(msg), 0);
	if (len <= 0)
		goto out_client_close_or_err;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr, "Expected management version %d, got %d\n",
			ISOCHRON_MANAGEMENT_VERSION, msg.version);
		return 0;
	}

	if (msg.action != ISOCHRON_GET && msg.action != ISOCHRON_SET) {
		fprintf(stderr, "Unexpected action %d\n", msg.action);
		return 0;
	}

	len = __be32_to_cpu(msg.payload_length);
	if (len >= BUF_SIZ) {
		fprintf(stderr, "GET message too large at %zd, max %d\n", len, BUF_SIZ);
		return 0;
	}

	len = recv_exact(prog->stats_fd, buf, len, 0);
	if (len <= 0)
		goto out_client_close_or_err;

	tlv = (struct isochron_tlv *)buf;

	while (parsed_len < (size_t)len) {
		if (__be16_to_cpu(tlv->tlv_type) != ISOCHRON_TLV_MANAGEMENT)
			continue;

		switch (msg.action) {
		case ISOCHRON_GET:
			rc = isochron_get_parse_one_tlv(prog, tlv);
			if (rc)
				return rc;
			break;
		case ISOCHRON_SET:
			rc = isochron_set_parse_one_tlv(prog, tlv);
			if (rc)
				return rc;
			break;
		default:
			break;
		}

		isochron_tlv_next(&tlv, &parsed_len);
	}

	return 0;

out_client_close_or_err:
	prog_close_client_stats_session(prog);

	return len;
}

static int server_loop(struct prog_data *prog)
{
	struct pollfd pfd[3] = {
		[0] = {
			.fd = prog->data_fd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[1] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[2] = {
			.fd = prog->data_timeout_fd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
	};
	__u32 sched_policy = SCHED_OTHER;
	int rc = 0;
	int cnt;

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
			perror("sched_setattr failed");
			return -errno;
		}
	}

	do {
		if (prog->have_client)
			pfd[1].fd = prog->stats_fd;
		else
			pfd[1].fd = prog->stats_listenfd;

		cnt = poll(pfd, ARRAY_SIZE(pfd), -1);
		if (cnt < 0) {
			if (errno == EINTR) {
				break;
			} else {
				perror("poll failed");
				rc = -errno;
				break;
			}
		} else if (!cnt) {
			break;
		}

		if (pfd[0].revents & (POLLIN | POLLERR | POLLPRI)) {
			rc = prog_data_event(prog);
			if (rc)
				break;
		}

		if (pfd[1].revents & (POLLIN | POLLERR | POLLPRI)) {
			if (prog->have_client) {
				rc = prog_client_mgmt_event(prog);
				if (rc)
					break;
			} else {
				rc = prog_client_connect_event(prog);
				if (rc)
					break;
			}
		}

		if (pfd[2].revents & (POLLIN | POLLERR | POLLPRI)) {
			__u64 expiry_count;

			rc = read_exact(prog->data_timeout_fd, &expiry_count,
					sizeof(expiry_count));
			if (rc < 0)
				break;

			rc = prog_data_fd_timeout(prog);
			if (rc)
				break;
		}

		if (signal_received)
			break;
	} while (1);

	if (prog->have_client)
		prog_close_client_stats_session(prog);

	/* Restore scheduling policy */
	if (sched_policy != SCHED_OTHER) {
		struct sched_attr attr = {
			.size = sizeof(struct sched_attr),
			.sched_policy = SCHED_OTHER,
			.sched_priority = 0,
		};

		if (sched_setattr(getpid(), &attr, 0)) {
			perror("sched_setattr failed");
			return -errno;
		}
	}

	return rc;
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

static int prog_init_ptpmon(struct prog_data *prog)
{
	char uds_local[UNIX_PATH_MAX];
	int rc;

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

	return 0;

out_destroy:
	ptpmon_destroy(prog->ptpmon);
	prog->ptpmon = NULL;

	return rc;
}

static void prog_teardown_ptpmon(struct prog_data *prog)
{
	ptpmon_close(prog->ptpmon);
	ptpmon_destroy(prog->ptpmon);
}

static int prog_init_sysmon(struct prog_data *prog)
{
	prog->sysmon = sysmon_create(prog->if_name, prog->num_readings);
	if (!prog->sysmon)
		return -ENOMEM;

	sysmon_print_method(prog->sysmon);

	return 0;
}

static void prog_teardown_sysmon(struct prog_data *prog)
{
	sysmon_destroy(prog->sysmon);
}

static int prog_init_stats_listenfd(struct prog_data *prog)
{
	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(prog->stats_port),
		.sin_zero = {0},
	};
	int sockopt = 1;
	int fd, rc;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("listener: stats socket");
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));
	if (rc < 0) {
		perror("setsockopt: stats socket");
		goto out;
	}

	rc = bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (rc < 0) {
		perror("bind: stats socket");
		goto out;
	}

	rc = listen(fd, 1);
	if (rc < 0) {
		perror("listen: stats socket");
		goto out;
	}

	prog->stats_listenfd = fd;

	return 0;

out:
	close(fd);
	return -errno;
}

static void prog_teardown_stats_listenfd(struct prog_data *prog)
{
	close(prog->stats_listenfd);
}

static int prog_init_data_fd(struct prog_data *prog)
{
	struct sockaddr_in serv_data_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(prog->data_port),
		.sin_zero = {0},
	};
	int sockopt = 1;
	int fd, rc;

	if (prog->l2)
		/* Open PF_PACKET socket, listening for the specified EtherType */
		fd = socket(PF_PACKET, SOCK_RAW, htons(prog->etype));
	else
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("listener: data socket");
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		goto out;
	}

	if (prog->l2) {
		/* Bind to device */
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, prog->if_name,
				IFNAMSIZ - 1);
	} else {
		rc = bind(fd, (struct sockaddr *)&serv_data_addr,
			  sizeof(serv_data_addr));
	}
	if (rc < 0) {
		perror("bind");
		goto out;
	}

	if (is_zero_ether_addr(prog->dest_mac)) {
		struct ifreq if_mac;

		memset(&if_mac, 0, sizeof(struct ifreq));
		strncpy(if_mac.ifr_name, prog->if_name, IFNAMSIZ - 1);
		if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
			perror("SIOCGIFHWADDR");
			goto out;
		}

		ether_addr_copy(prog->dest_mac,
			        (unsigned char *)if_mac.ifr_hwaddr.sa_data);
	}

	if (is_multicast_ether_addr(prog->dest_mac)) {
		rc = multicast_listen(fd, prog->if_index, prog->dest_mac, true);
		if (rc) {
			perror("multicast_listen");
			goto out;
		}
	}

	rc = sk_timestamping_init(fd, prog->if_name, true);
	if (rc)
		goto out;

	prog->data_fd = fd;

	return 0;

out:
	close(fd);
	return -errno;
}

static void prog_teardown_data_fd(struct prog_data *prog)
{
	if (is_multicast_ether_addr(prog->dest_mac))
		multicast_listen(prog->data_fd, prog->if_index,
				 prog->dest_mac, false);

	close(prog->data_fd);
}

static int prog_init_data_timeout_fd(struct prog_data *prog)
{
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		perror("timerfd_create");
		return -errno;
	}

	prog->data_timeout_fd = fd;

	return 0;
}

static void prog_teardown_data_timeout_fd(struct prog_data *prog)
{
	prog_disarm_data_timeout_fd(prog);
	close(prog->data_timeout_fd);
}

static int prog_init(struct prog_data *prog)
{
	int rc;

	rc = isochron_handle_signals(sig_handler);
	if (rc)
		return rc;

	rc = prog_init_ptpmon(prog);
	if (rc)
		return rc;

	rc = prog_init_sysmon(prog);
	if (rc)
		goto out_teardown_ptpmon;

	prog->clkid = CLOCK_TAI;

	prog->if_index = if_nametoindex(prog->if_name);
	if (!prog->if_index) {
		perror("if_nametoindex failed");
		rc = -errno;
		goto out_teardown_sysmon;
	}

	rc = prog_init_stats_listenfd(prog);
	if (rc)
		goto out_teardown_sysmon;

	rc = prog_init_data_fd(prog);
	if (rc)
		goto out_teardown_stats_listenfd;

	rc = prog_init_data_timeout_fd(prog);
	if (rc)
		goto out_teardown_data_fd;

	return 0;

out_teardown_data_fd:
	prog_teardown_data_fd(prog);
out_teardown_stats_listenfd:
	prog_teardown_stats_listenfd(prog);
out_teardown_sysmon:
	prog_teardown_sysmon(prog);
out_teardown_ptpmon:
	prog_teardown_ptpmon(prog);
	return rc;
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
			.short_opt = "-P",
			.long_opt = "--stats-port",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->stats_port,
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

	prog->utc_tai_offset = -1;

	rc = prog_parse_np_args(argc, argv, args, ARRAY_SIZE(args));

	/* Non-positional arguments left unconsumed */
	if (rc < 0) {
		pr_err(rc, "argument parsing failed: %m\n");
		return rc;
	} else if (rc < argc) {
		fprintf(stderr, "%d unconsumed arguments. First: %s\n",
			argc - rc, argv[rc]);
		prog_usage("isochron-rcv", args, ARRAY_SIZE(args));
		return -1;
	}

	if (help) {
		prog_usage("isochron-rcv", args, ARRAY_SIZE(args));
		return -1;
	}

	if (prog->sched_fifo && prog->sched_rr) {
		fprintf(stderr,
			"cannot have SCHED_FIFO and SCHED_RR at the same time\n");
		return -EINVAL;
	}

	if (!prog->stats_port)
		prog->stats_port = ISOCHRON_STATS_PORT;

	if (prog->l2 && prog->l4) {
		fprintf(stderr, "Choose transport as either L2 or L4!\n");
		return -EINVAL;
	}

	if (!prog->l2 && !prog->l4)
		prog->l2 = true;

	if (!prog->etype)
		prog->etype = ETH_P_ISOCHRON;

	if (!prog->data_port)
		prog->data_port = ISOCHRON_DATA_PORT;

	if (!prog->num_readings)
		prog->num_readings = 5;

	if (strlen(prog->uds_remote) == 0)
		sprintf(prog->uds_remote, "/var/run/ptp4l");

	if (prog->utc_tai_offset == -1) {
		prog->utc_tai_offset = get_utc_tai_offset();
		fprintf(stderr, "Using the kernel UTC-TAI offset which is %ld\n",
			prog->utc_tai_offset);
	} else {
		rc = set_utc_tai_offset(prog->utc_tai_offset);
		if (rc == -1) {
			perror("set_utc_tai_offset");
			return -errno;
		}
	}

	return 0;
}

static void prog_teardown(struct prog_data *prog)
{
	if (!prog->quiet)
		isochron_rcv_log_print(&prog->log);
	isochron_log_teardown(&prog->log);

	prog_teardown_data_timeout_fd(prog);
	prog_teardown_data_fd(prog);
	prog_teardown_stats_listenfd(prog);
	prog_teardown_sysmon(prog);
	prog_teardown_ptpmon(prog);
}

int isochron_rcv_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	rc = server_loop(&prog);

	prog_teardown(&prog);

	return rc;
}
