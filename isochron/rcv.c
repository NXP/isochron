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
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include "common.h"
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
	bool have_client;
	bool do_ts;
	bool quiet;
	long etype;
	long stats_port;
	long iterations;
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

static int app_loop(struct prog_data *prog, __u8 *rcvbuf, size_t len,
		    const struct isochron_timestamp *tstamp)
{
	struct isochron_rcv_pkt_data rcv_pkt = {0};
	struct timespec now_ts;
	__s64 now;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);
	rcv_pkt.arrival = now;
	if (prog->l2) {
		struct ethhdr *eth_hdr = (struct ethhdr *)rcvbuf;
		struct isochron_header *hdr = (struct isochron_header *)(eth_hdr + 1);

		if (len < sizeof(*eth_hdr) + sizeof(*hdr)) {
			if (!prog->quiet)
				printf("Packet too short (%zu bytes)\n", len);
			return -1;
		}

		rcv_pkt.tx_time = __be64_to_cpu(hdr->tx_time);
		rcv_pkt.etype = ntohs(eth_hdr->h_proto);
		ether_addr_copy(rcv_pkt.smac, eth_hdr->h_source);
		ether_addr_copy(rcv_pkt.dmac, eth_hdr->h_dest);
		rcv_pkt.seqid = __be32_to_cpu(hdr->seqid);
		rcv_pkt.hwts = timespec_to_ns(&tstamp->hw);
		rcv_pkt.swts = utc_to_tai(timespec_to_ns(&tstamp->sw),
					  prog->utc_tai_offset);
	} else {
		struct isochron_header *hdr = (struct isochron_header *)rcvbuf;

		if (len < sizeof(*hdr)) {
			if (!prog->quiet)
				printf("Packet too short (%zu bytes)\n", len);
			return -1;
		}

		rcv_pkt.tx_time = __be64_to_cpu(hdr->tx_time);
		rcv_pkt.seqid = __be32_to_cpu(hdr->seqid);
		rcv_pkt.hwts = timespec_to_ns(&tstamp->hw);
		rcv_pkt.swts = utc_to_tai(timespec_to_ns(&tstamp->sw),
					  prog->utc_tai_offset);
	}

	if (rcv_pkt.seqid > prog->iterations) {
		if (!prog->quiet)
			printf("Discarding seqid %d\n", rcv_pkt.seqid);
		return -1;
	}

	isochron_log_data(&prog->log, &rcv_pkt, sizeof(rcv_pkt));

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

	fprintf(stderr, "setsockopt PACKET_MR_MULTICAST failed: %s\n",
		strerror(errno));

	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_ALLMULTI;
	mreq.mr_alen = 0;
	rc = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (!rc)
		return 0;

	fprintf(stderr, "setsockopt PACKET_MR_ALLMULTI failed: %s\n",
		strerror(errno));

	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;
	rc = setsockopt(fd, SOL_PACKET, option, &mreq, sizeof(mreq));
	if (!rc)
		return 0;

	fprintf(stderr, "setsockopt PACKET_MR_PROMISC failed: %s\n",
		strerror(errno));

	fprintf(stderr, "all socket options failed\n");
	return -1;
}

static int prog_data_event(struct prog_data *prog)
{
	struct ethhdr *eth_hdr = (struct ethhdr *)prog->rcvbuf;
	struct isochron_timestamp tstamp = {0};
	ssize_t len;

	len = sk_receive(prog->data_fd, prog->rcvbuf,
			 BUF_SIZ, &tstamp, 0,
			 TXTSTAMP_TIMEOUT_MS);
	/* Suppress "Interrupted system call" message */
	if (len < 0 && errno != EINTR) {
		fprintf(stderr, "recvfrom returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	if (prog->l2 &&
	    ether_addr_to_u64(prog->dest_mac) &&
	    ether_addr_to_u64(prog->dest_mac) != ether_addr_to_u64(eth_hdr->h_dest))
		return 0;

	return app_loop(prog, prog->rcvbuf, len, &tstamp);
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
			fprintf(stderr, "accept returned %d: %s\n",
				errno, strerror(errno));
		return -errno;
	}

	if (!inet_ntop(addr.sin_family, &addr.sin_addr.s_addr,
		       client_addr, addr_len)) {
		fprintf(stderr, "inet_pton returned %d: %s\n",
			errno, strerror(errno));
		close(prog->stats_fd);
		return -errno;
	}

	printf("Accepted connection from %s\n", client_addr);

	prog->have_client = true;

	return 0;
}

static void isochron_tlv_next(struct isochron_tlv **tlv, size_t *len)
{
	size_t tlv_size_bytes;

	tlv_size_bytes = __be32_to_cpu((*tlv)->length_field) + sizeof(**tlv);
	*len += tlv_size_bytes;
	*tlv = (struct isochron_tlv *)((unsigned char *)tlv + tlv_size_bytes);
}

static int isochron_parse_one_tlv(struct prog_data *prog,
				  struct isochron_tlv *tlv)
{
	if (ntohs(tlv->tlv_type) != ISOCHRON_TLV_MANAGEMENT)
		return 0;

	switch (ntohs(tlv->management_id)) {
	case ISOCHRON_MID_LOG:
		isochron_log_xmit(&prog->log, prog->stats_fd);
		isochron_log_teardown(&prog->log);
		return isochron_log_init(&prog->log, prog->iterations *
					 sizeof(struct isochron_rcv_pkt_data));
	default:
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

	if (msg.action != ISOCHRON_GET) {
		fprintf(stderr, "Expected GET action, got %d\n", msg.action);
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
		rc = isochron_parse_one_tlv(prog, tlv);
		if (rc)
			return rc;

		isochron_tlv_next(&tlv, &parsed_len);
	}

	return 0;

out_client_close_or_err:
	close(prog->stats_fd);
	prog->have_client = false;

	return len;
}

static int server_loop(struct prog_data *prog)
{
	struct pollfd pfd[2] = {
		[0] = {
			.fd = prog->data_fd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[1] = {
			/* .fd to be filled in dynamically */
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
			fprintf(stderr, "sched_setattr returned %d: %s\n",
				errno, strerror(errno));
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
				fprintf(stderr, "poll returned %d: %s\n",
					errno, strerror(errno));
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

		if (signal_received)
			break;
	} while (1);

	if (prog->have_client)
		close(prog->stats_fd);

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
				     PTPMON_TIMEOUT_MS, uds_local, prog->uds_remote);
	if (!prog->ptpmon)
		return -ENOMEM;

	rc = ptpmon_open(prog->ptpmon);
	if (rc) {
		fprintf(stderr, "failed to connect to %s: %d (%s)\n",
			prog->uds_remote,  rc, strerror(-rc));
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

	return 0;
}

static void prog_teardown_sysmon(struct prog_data *prog)
{
	sysmon_destroy(prog->sysmon);
}

static int prog_init(struct prog_data *prog)
{
	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(prog->stats_port),
	};
	struct sockaddr_in serv_data_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(prog->data_port),
	};
	struct sigaction sa;
	int sockopt = 1;
	int rc;

	rc = prog_init_ptpmon(prog);
	if (rc)
		return rc;

	rc = prog_init_sysmon(prog);
	if (rc)
		goto out_teardown_ptpmon;

	rc = isochron_log_init(&prog->log, prog->iterations *
			       sizeof(struct isochron_rcv_pkt_data));
	if (rc < 0)
		goto out_teardown_sysmon;

	prog->clkid = CLOCK_TAI;
	/* Convert negative logic from cmdline to positive */
	prog->do_ts = !prog->do_ts;

	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	rc = sigaction(SIGTERM, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGTERM: %s\n", strerror(errno));
		rc = -errno;
		goto out_log_teardown;
	}
	rc = sigaction(SIGINT, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGINT: %s\n", strerror(errno));
		rc = -errno;
		goto out_log_teardown;
	}

	prog->if_index = if_nametoindex(prog->if_name);
	if (!prog->if_index) {
		fprintf(stderr, "if_nametoindex(%s) returned %s\n",
			prog->if_name, strerror(errno));
		rc = -errno;
		goto out_log_teardown;
	}

	prog->stats_listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (prog->stats_listenfd < 0) {
		perror("listener: stats socket");
		rc = -errno;
		goto out_log_teardown;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(prog->stats_listenfd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		rc = -errno;
		goto out_close_stats_listenfd;
	}

	rc = bind(prog->stats_listenfd, (struct sockaddr*)&serv_addr,
		  sizeof(serv_addr));
	if (rc < 0) {
		perror("listener: bind");
		rc = -errno;
		goto out_close_stats_listenfd;
	}

	rc = listen(prog->stats_listenfd, 1);
	if (rc < 0) {
		perror("listener: listen");
		rc = -errno;
		goto out_close_stats_listenfd;
	}

	if (prog->l2)
		/* Open PF_PACKET socket, listening for the specified EtherType */
		prog->data_fd = socket(PF_PACKET, SOCK_RAW, htons(prog->etype));
	else
		prog->data_fd = socket(AF_INET, SOCK_DGRAM,
				       IPPROTO_UDP);

	if (prog->data_fd < 0) {
		perror("listener: data socket");
		rc = -errno;
		goto out_close_stats_listenfd;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(prog->data_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->stats_listenfd);
		rc = -errno;
		goto out_close_datafd;
	}

	if (prog->l2) {
		/* Bind to device */
		rc = setsockopt(prog->data_fd, SOL_SOCKET, SO_BINDTODEVICE,
				prog->if_name, IFNAMSIZ - 1);
		if (rc < 0) {
			perror("SO_BINDTODEVICE");
			rc = -errno;
			goto out_close_datafd;
		}
	} else {
		rc = bind(prog->data_fd, (struct sockaddr *)&serv_data_addr,
			  sizeof(serv_data_addr));
		if (rc < 0) {
			perror("bind");
			rc = -errno;
			goto out_close_datafd;
		}
	}

	if (ether_addr_to_u64(prog->dest_mac)) {
		rc = multicast_listen(prog->data_fd, prog->if_index,
				      prog->dest_mac, true);
		if (rc) {
			perror("multicast_listen");
			rc = -errno;
			goto out_close_datafd;
		}
	}

	if (prog->do_ts) {
		rc = sk_timestamping_init(prog->data_fd, prog->if_name, true);
		if (rc)
			goto out_close_datafd;
	}

	return 0;

out_close_datafd:
	close(prog->data_fd);
out_close_stats_listenfd:
	close(prog->stats_listenfd);
out_log_teardown:
	isochron_log_teardown(&prog->log);
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
			.short_opt = "-T",
			.long_opt = "--no-ts",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->do_ts,
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
			.short_opt = "-n",
			.long_opt = "--num-frames",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->iterations,
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

	/* Default to the old behavior, which was to allocate a 10 MiB
	 * log buffer given a 56 byte size of struct isochron_rcv_pkt_data
	 */
	if (!prog->iterations)
		prog->iterations = 187245;

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

static int prog_teardown(struct prog_data *prog)
{
	if (!prog->quiet)
		isochron_rcv_log_print(&prog->log);
	isochron_log_teardown(&prog->log);

	if (ether_addr_to_u64(prog->dest_mac))
		multicast_listen(prog->data_fd, prog->if_index,
				 prog->dest_mac, false);

	close(prog->stats_listenfd);
	close(prog->data_fd);
	prog_teardown_sysmon(prog);
	prog_teardown_ptpmon(prog);

	return 0;
}

int isochron_rcv_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc, rc_save;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	rc_save = server_loop(&prog);

	rc = prog_teardown(&prog);
	if (rc < 0)
		return rc;

	return rc_save;
}
