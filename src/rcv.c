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
#include <errno.h>
#include <poll.h>
#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "log.h"
#include "management.h"
#include "ptpmon.h"
#include "rtnl.h"
#include "sk.h"
#include "sysmon.h"

#define BUF_SIZ		10000

struct isochron_rcv {
	char if_name[IFNAMSIZ];
	unsigned char dest_mac[ETH_ALEN];
	char uds_remote[UNIX_PATH_MAX];
	unsigned int if_index;
	__u8 rcvbuf[BUF_SIZ];
	struct isochron_log log;
	clockid_t clkid;
	struct ptpmon *ptpmon;
	struct sysmon *sysmon;
	struct mnl_socket *rtnl;
	struct isochron_mgmt_handler *mgmt_handler;
	struct sk *mgmt_listen_sock;
	struct sk *mgmt_sock;
	struct sk *l4_sock;
	struct sk *l2_sock;
	int l2_data_fd;
	int l4_data_fd;
	int data_timeout_fd;
	bool have_client;
	bool client_waiting_for_log;
	bool data_fd_timed_out;
	bool quiet;
	long etype;
	long stats_port;
	struct ip_address stats_addr;
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

static int prog_rearm_data_timeout_fd(struct isochron_rcv *prog)
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

static void prog_disarm_data_timeout_fd(struct isochron_rcv *prog)
{
	struct itimerspec timeout = {};

	timerfd_settime(prog->data_timeout_fd, 0, &timeout, NULL);
}

static bool prog_received_all_packets(struct isochron_rcv *prog)
{
	return prog->received_pkt_count == prog->iterations;
}

static int prog_forward_isochron_log(struct isochron_rcv *prog)
{
	int rc;

	rc = isochron_send_tlv(prog->mgmt_sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(&prog->log));
	if (rc)
		return 0;

	isochron_log_xmit(&prog->log, prog->mgmt_sock);
	isochron_log_teardown(&prog->log);
	return isochron_log_init(&prog->log, prog->iterations *
				 sizeof(struct isochron_rcv_pkt_data));
}

static int app_loop(struct isochron_rcv *prog, __u8 *rcvbuf, size_t len,
		    bool l2, const struct isochron_timestamp *tstamp)
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
	if (l2) {
		struct ethhdr *eth_hdr = (struct ethhdr *)rcvbuf;
		struct isochron_header *hdr = (struct isochron_header *)(eth_hdr + 1);

		if (len < sizeof(*eth_hdr) + sizeof(*hdr)) {
			if (!prog->quiet)
				printf("Packet too short (%zu bytes)\n", len);
			return 0;
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
			return 0;
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
		return 0;
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

static int prog_init_l2_sock(struct isochron_rcv *prog)
{
	int fd, rc;

	if (!prog->l2)
		return 0;

	if (is_zero_ether_addr(prog->dest_mac)) {
		rc = sk_get_ether_addr(prog->if_name, prog->dest_mac);
		if (rc)
			return rc;
	}

	rc = sk_bind_l2(prog->dest_mac, prog->etype, prog->if_name,
			&prog->l2_sock);
	if (rc)
		return rc;

	fd = sk_fd(prog->l2_sock);

	if (is_multicast_ether_addr(prog->dest_mac)) {
		rc = multicast_listen(fd, prog->if_index, prog->dest_mac, true);
		if (rc) {
			perror("multicast_listen");
			goto out;
		}
	}

	rc = sk_timestamping_init(prog->l2_sock, prog->if_name, true);
	if (rc) {
		errno = -rc;
		goto out;
	}

	prog->l2_data_fd = fd;

	return 0;

out:
	sk_close(prog->l2_sock);
	return -errno;
}

static int prog_init_l4_sock(struct isochron_rcv *prog)
{
	struct ip_address any = {};
	int fd, rc;

	if (!prog->l4)
		return 0;

	rc = sk_bind_udp(&any, prog->data_port, &prog->l4_sock);
	if (rc)
		return rc;

	fd = sk_fd(prog->l4_sock);

	/* Bind to device */
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, prog->if_name,
			IFNAMSIZ - 1);
	if (rc < 0) {
		perror("setsockopt(SO_BINDTODEVICE) on data socket failed");
		goto out;
	}

	rc = sk_timestamping_init(prog->l4_sock, prog->if_name, true);
	if (rc) {
		errno = -rc;
		goto out;
	}

	prog->l4_data_fd = fd;

	return 0;

out:
	close(fd);
	return -errno;
}

static void prog_teardown_l2_sock(struct isochron_rcv *prog)
{
	if (!prog->l2_sock)
		return;

	if (is_multicast_ether_addr(prog->dest_mac))
		multicast_listen(prog->l2_data_fd, prog->if_index,
				 prog->dest_mac, false);

	sk_close(prog->l2_sock);
	prog->l2_sock = NULL;
}

static void prog_teardown_l4_sock(struct isochron_rcv *prog)
{
	if (!prog->l4_sock)
		return;

	sk_close(prog->l4_sock);
	prog->l4_sock = NULL;
}

static int prog_data_event(struct isochron_rcv *prog, struct sk *sock, bool l2)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)prog->rcvbuf;
	struct isochron_timestamp tstamp = {0};
	ssize_t len;

	len = sk_recvmsg(sock, prog->rcvbuf, BUF_SIZ, &tstamp, 0, 0);
	/* Suppress "Interrupted system call" message */
	if (len < 0 && errno != EINTR) {
		perror("recvfrom failed");
		return -errno;
	}

	if (l2 && !ether_addr_equal(prog->dest_mac, eth_hdr->h_dest))
		return 0;

	return app_loop(prog, prog->rcvbuf, len, l2, &tstamp);
}

static int prog_data_fd_timeout(struct isochron_rcv *prog)
{
	prog->data_fd_timed_out = true;

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

static void prog_close_client_stats_session(struct isochron_rcv *prog)
{
	prog_disarm_data_timeout_fd(prog);
	sk_close(prog->mgmt_sock);
	prog->have_client = false;
	prog->data_fd_timed_out = false;
	prog->client_waiting_for_log = false;
	prog->received_pkt_count = 0;
	prog->iterations = 0;
}

static int prog_client_connect_event(struct isochron_rcv *prog)
{
	int rc;

	rc = sk_accept(prog->mgmt_listen_sock, &prog->mgmt_sock);
	if (rc)
		return rc;

	prog->have_client = true;

	return 0;
}

static int prog_get_packet_log(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	/* Keep the client on hold */
	if (!prog_received_all_packets(prog) &&
	    !prog->data_fd_timed_out) {
		prog->client_waiting_for_log = true;
		return 0;
	}

	return prog_forward_isochron_log(prog);
}

static int prog_forward_sysmon_offset(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_sysmon_offset(prog->mgmt_sock, prog->sysmon,
					      extack);
}

static int prog_forward_ptpmon_offset(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_ptpmon_offset(prog->mgmt_sock, prog->ptpmon,
					      extack);
}

static int prog_forward_utc_offset(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;
	int rc, utc_offset;

	rc = isochron_forward_utc_offset(prog->mgmt_sock, prog->ptpmon,
					 &utc_offset, extack);
	if (rc)
		return rc;

	isochron_fixup_kernel_utc_offset(utc_offset);
	prog->utc_tai_offset = utc_offset;

	return 0;
}

static int prog_forward_port_state(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_port_state(prog->mgmt_sock, prog->ptpmon,
					   prog->if_name, prog->rtnl, extack);
}

static int prog_forward_port_link_state(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_port_link_state(prog->mgmt_sock,
						prog->if_name, prog->rtnl,
						extack);
}

static int prog_forward_gm_clock_identity(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_gm_clock_identity(prog->mgmt_sock,
						  prog->ptpmon, extack);
}

static int prog_forward_destination_mac(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;
	struct isochron_mac_addr mac;
	int rc;

	memset(&mac, 0, sizeof(mac));
	ether_addr_copy(mac.addr, prog->dest_mac);

	rc = isochron_send_tlv(prog->mgmt_sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_DESTINATION_MAC,
			       sizeof(mac));
	if (rc)
		return rc;

	sk_send(prog->mgmt_sock, &mac, sizeof(mac));

	return 0;
}

static int prog_forward_current_clock_tai(void *priv, char *extack)
{
	struct isochron_rcv *prog = priv;

	return isochron_forward_current_clock_tai(prog->mgmt_sock, extack);
}

static int prog_set_packet_count(void *priv, void *ptr, char *extack)
{
	struct isochron_packet_count *packet_count = ptr;
	struct isochron_rcv *prog = priv;
	size_t iterations;
	int rc;

	iterations = __be64_to_cpu(packet_count->count);

	isochron_log_teardown(&prog->log);
	rc = isochron_log_init(&prog->log, iterations *
			       sizeof(struct isochron_rcv_pkt_data));
	if (rc) {
		mgmt_extack(extack,
			    "Could not allocate log for %zu iterations",
			    iterations);
		return rc;
	}

	prog->iterations = iterations;

	/* Clock is ticking! */
	rc = prog_rearm_data_timeout_fd(prog);
	if (rc) {
		mgmt_extack(extack, "Could not arm timeout timer");
		return rc;
	}

	return 0;
}

static int prog_update_l2_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_rcv *prog = priv;
	int rc = 0;

	if (prog->l2 == f->enabled)
		return 0;

	prog->l2 = f->enabled;

	if (prog->l2)
		rc = prog_init_l2_sock(prog);
	else
		prog_teardown_l2_sock(prog);

	return rc;
}

static int prog_update_l4_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_rcv *prog = priv;
	int rc = 0;

	if (prog->l4 == f->enabled)
		return 0;

	prog->l4 = f->enabled;

	if (prog->l4)
		rc = prog_init_l4_sock(prog);
	else
		prog_teardown_l4_sock(prog);

	return rc;
}

static const struct isochron_mgmt_ops rcv_mgmt_ops[__ISOCHRON_MID_MAX] = {
	[ISOCHRON_MID_PACKET_COUNT] = {
		.set = prog_set_packet_count,
		.struct_size = sizeof(struct isochron_packet_count),
	},
	[ISOCHRON_MID_L2_ENABLED] = {
		.set = prog_update_l2_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_L4_ENABLED] = {
		.set = prog_update_l4_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_LOG] = {
		.get = prog_get_packet_log,
	},
	[ISOCHRON_MID_SYSMON_OFFSET] = {
		.get = prog_forward_sysmon_offset,
	},
	[ISOCHRON_MID_PTPMON_OFFSET] = {
		.get = prog_forward_ptpmon_offset,
	},
	[ISOCHRON_MID_UTC_OFFSET] = {
		.get = prog_forward_utc_offset,
	},
	[ISOCHRON_MID_PORT_STATE] = {
		.get = prog_forward_port_state,
	},
	[ISOCHRON_MID_PORT_LINK_STATE] = {
		.get = prog_forward_port_link_state,
	},
	[ISOCHRON_MID_GM_CLOCK_IDENTITY] = {
		.get = prog_forward_gm_clock_identity,
	},
	[ISOCHRON_MID_DESTINATION_MAC] = {
		.get = prog_forward_destination_mac,
	},
	[ISOCHRON_MID_CURRENT_CLOCK_TAI] = {
		.get = prog_forward_current_clock_tai,
	},
};

enum pollfd_type {
	PFD_MGMT,
	PFD_DATA_TIMEOUT,
	PFD_DATA1,
	PFD_DATA2,
	__PFD_MAX,
};

static void prog_fill_dynamic_pfds(struct isochron_rcv *prog,
				   struct pollfd *pfd, int *pfd_num,
				   int *l2_pfd, int *l4_pfd)
{
	*pfd_num = PFD_DATA1;
	*l2_pfd = -1;
	*l4_pfd = -1;

	if (prog->have_client)
		pfd[PFD_MGMT].fd = sk_fd(prog->mgmt_sock);
	else
		pfd[PFD_MGMT].fd = sk_fd(prog->mgmt_listen_sock);

	if (prog->l2) {
		*l2_pfd = *pfd_num;
		pfd[(*pfd_num)++].fd = prog->l2_data_fd;
	}

	if (prog->l4) {
		*l4_pfd = *pfd_num;
		pfd[(*pfd_num)++].fd = prog->l4_data_fd;
	}
}

static int server_loop(struct isochron_rcv *prog)
{
	struct pollfd pfd[__PFD_MAX] = {
		[PFD_MGMT] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[PFD_DATA_TIMEOUT] = {
			.fd = prog->data_timeout_fd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[PFD_DATA1] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[PFD_DATA2] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
	};
	__u32 sched_policy = SCHED_OTHER;
	int l2_pfd, l4_pfd;
	int pfd_num;
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
		prog_fill_dynamic_pfds(prog, pfd, &pfd_num, &l2_pfd, &l4_pfd);

		cnt = poll(pfd, pfd_num, -1);
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

		if (l2_pfd >= 0 && pfd[l2_pfd].revents & (POLLIN | POLLERR | POLLPRI)) {
			rc = prog_data_event(prog, prog->l2_sock, true);
			if (rc)
				break;
		}

		if (l4_pfd >= 0 && pfd[l4_pfd].revents & (POLLIN | POLLERR | POLLPRI)) {
			rc = prog_data_event(prog, prog->l4_sock, false);
			if (rc)
				break;
		}

		if (pfd[PFD_MGMT].revents & (POLLIN | POLLERR | POLLPRI)) {
			if (prog->have_client) {
				rc = isochron_mgmt_event(prog->mgmt_sock,
							 prog->mgmt_handler,
							 prog);
				if (sk_closed(prog->mgmt_sock))
					prog_close_client_stats_session(prog);
				else if (rc)
					break;
			} else {
				rc = prog_client_connect_event(prog);
				if (rc)
					break;
			}
		}

		if (pfd[PFD_DATA_TIMEOUT].revents & (POLLIN | POLLERR | POLLPRI)) {
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

static int prog_init_ptpmon(struct isochron_rcv *prog)
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

static void prog_teardown_ptpmon(struct isochron_rcv *prog)
{
	ptpmon_close(prog->ptpmon);
	ptpmon_destroy(prog->ptpmon);
}

static int prog_init_sysmon(struct isochron_rcv *prog)
{
	prog->sysmon = sysmon_create(prog->if_name, prog->num_readings);
	if (!prog->sysmon)
		return -ENOMEM;

	sysmon_print_method(prog->sysmon);

	return 0;
}

static void prog_teardown_sysmon(struct isochron_rcv *prog)
{
	sysmon_destroy(prog->sysmon);
}

static int prog_init_mgmt_listen_sock(struct isochron_rcv *prog)
{
	int rc;

	prog->mgmt_handler = isochron_mgmt_handler_create(rcv_mgmt_ops);
	if (!prog->mgmt_handler)
		return -ENOMEM;

	rc = sk_listen_tcp(&prog->stats_addr, prog->stats_port, 1,
			   &prog->mgmt_listen_sock);
	if (rc)
		isochron_mgmt_handler_destroy(prog->mgmt_handler);

	return rc;
}

static void prog_teardown_mgmt_listen_sock(struct isochron_rcv *prog)
{
	sk_close(prog->mgmt_listen_sock);
	isochron_mgmt_handler_destroy(prog->mgmt_handler);
}

static int prog_init_data_timeout_fd(struct isochron_rcv *prog)
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

static void prog_teardown_data_timeout_fd(struct isochron_rcv *prog)
{
	prog_disarm_data_timeout_fd(prog);
	close(prog->data_timeout_fd);
}

static int prog_rtnl_open(struct isochron_rcv *prog)
{
	struct mnl_socket *nl;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		perror("mnl_socket_open");
		return -errno;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		mnl_socket_close(nl);
		return -errno;
	}

	prog->rtnl = nl;

	return 0;
}

static void prog_rtnl_close(struct isochron_rcv *prog)
{
	struct mnl_socket *nl = prog->rtnl;

	prog->rtnl = NULL;
	mnl_socket_close(nl);
}

static int prog_check_admin_state(struct isochron_rcv *prog)
{
	bool up;
	int rc;

	rc = rtnl_query_admin_state(prog->rtnl, prog->if_name, &up);
	if (rc) {
		pr_err(rc, "Failed to query port %s admin state: %m\n",
		       prog->if_name);
		return rc;
	}

	if (!up) {
		fprintf(stderr, "Interface %s is administratively down\n",
			prog->if_name);
		return -ENETDOWN;
	}

	return 0;
}

static int prog_init(struct isochron_rcv *prog)
{
	int rc;

	rc = prog_rtnl_open(prog);
	if (rc)
		return rc;

	rc = prog_check_admin_state(prog);
	if (rc)
		goto out_close_rtnl;

	rc = sk_validate_ts_info(prog->if_name);
	if (rc)
		goto out_close_rtnl;

	rc = prog_init_ptpmon(prog);
	if (rc)
		goto out_close_rtnl;

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

	rc = prog_init_mgmt_listen_sock(prog);
	if (rc)
		goto out_teardown_sysmon;

	rc = prog_init_l2_sock(prog);
	if (rc)
		goto out_teardown_mgmt_listen_sock;

	rc = prog_init_l4_sock(prog);
	if (rc)
		goto out_teardown_l2_sock;

	rc = prog_init_data_timeout_fd(prog);
	if (rc)
		goto out_teardown_l4_sock;

	return 0;

out_teardown_l4_sock:
	prog_teardown_l4_sock(prog);
out_teardown_l2_sock:
	prog_teardown_l2_sock(prog);
out_teardown_mgmt_listen_sock:
	prog_teardown_mgmt_listen_sock(prog);
out_teardown_sysmon:
	prog_teardown_sysmon(prog);
out_teardown_ptpmon:
	prog_teardown_ptpmon(prog);
out_close_rtnl:
	prog_rtnl_close(prog);
	return rc;
}

static int prog_parse_args(int argc, char **argv, struct isochron_rcv *prog)
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
			.short_opt = "-S",
			.long_opt = "--stats-address",
			.type = PROG_ARG_IP,
			.ip_ptr = {
				.ptr = &prog->stats_addr,
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

static void prog_teardown(struct isochron_rcv *prog)
{
	if (!prog->quiet)
		isochron_rcv_log_print(&prog->log);
	isochron_log_teardown(&prog->log);

	prog_teardown_data_timeout_fd(prog);
	prog_teardown_l4_sock(prog);
	prog_teardown_l2_sock(prog);
	prog_teardown_mgmt_listen_sock(prog);
	prog_teardown_sysmon(prog);
	prog_teardown_ptpmon(prog);
	prog_rtnl_close(prog);
}

int isochron_rcv_main(int argc, char *argv[])
{
	struct isochron_rcv prog = {0};
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
