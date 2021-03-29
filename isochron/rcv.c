// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP Semiconductors */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 * Initial prototype based on:
 * - https://gist.github.com/austinmarton/2862515
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include "common.h"

#define BUF_SIZ		10000

struct prog_data {
	char if_name[IFNAMSIZ];
	__u8 dest_mac[ETH_ALEN];
	unsigned int if_index;
	__u8 rcvbuf[BUF_SIZ];
	struct isochron_log log;
	clockid_t clkid;
	int stats_listenfd;
	int data_fd;
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
};

int signal_received;

static int app_loop(void *app_data, char *rcvbuf, size_t len,
		    const struct isochron_timestamp *tstamp)
{
	struct isochron_rcv_pkt_data rcv_pkt = {0};
	struct prog_data *prog = app_data;
	struct timespec now_ts;
	int i, rc;
	__s64 now;

	clock_gettime(prog->clkid, &now_ts);
	now = timespec_to_ns(&now_ts);
	rcv_pkt.arrival = now;
	if (prog->l2) {
		struct ethhdr *eth_hdr = (struct ethhdr *)rcvbuf;
		struct isochron_header *hdr = (struct isochron_header *)(eth_hdr + 1);

		rcv_pkt.tx_time = __be64_to_cpu(hdr->tx_time);
		rcv_pkt.etype = ntohs(eth_hdr->h_proto);
		memcpy(rcv_pkt.smac, eth_hdr->h_source, ETH_ALEN);
		memcpy(rcv_pkt.dmac, eth_hdr->h_dest, ETH_ALEN);
		rcv_pkt.seqid = __be32_to_cpu(hdr->seqid);
		rcv_pkt.hwts = timespec_to_ns(&tstamp->hw);
		rcv_pkt.swts = utc_to_tai(timespec_to_ns(&tstamp->sw),
					  prog->utc_tai_offset);
	} else {
		struct isochron_header *hdr = (struct isochron_header *)rcvbuf;

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
	int rc, filter_test, option;
	struct packet_mreq mreq;

	if (enable)
		option = PACKET_ADD_MEMBERSHIP;
	else
		option = PACKET_DROP_MEMBERSHIP;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = if_index;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(mreq.mr_address, macaddr, ETH_ALEN);

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

static int server_loop(struct prog_data *prog, void *app_data)
{
	struct isochron_timestamp tstamp = {0};
	struct pollfd pfd[2] = {
		[0] = {
			.fd = prog->data_fd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
		[1] = {
			.fd = prog->stats_listenfd,
			.events = POLLIN | POLLERR | POLLPRI,
		},
	};
	__u32 sched_policy = SCHED_OTHER;
	ssize_t len;
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
			struct ethhdr *eth_hdr = (struct ethhdr *)prog->rcvbuf;

			len = sk_receive(prog->data_fd, prog->rcvbuf,
					 BUF_SIZ, &tstamp, 0,
					 TXTSTAMP_TIMEOUT_MS);
			/* Suppress "Interrupted system call" message */
			if (len < 0 && errno != EINTR) {
				fprintf(stderr, "recvfrom returned %d: %s\n",
					errno, strerror(errno));
				rc = -errno;
				break;
			}
			if (prog->l2)
				if (ether_addr_to_u64(prog->dest_mac) &&
				    ether_addr_to_u64(prog->dest_mac) !=
				    ether_addr_to_u64(eth_hdr->h_dest))
					continue;

			rc = app_loop(app_data, prog->rcvbuf, len, &tstamp);
			if (rc < 0)
				break;
		}

		if (pfd[1].revents & (POLLIN | POLLERR | POLLPRI)) {
			char client_addr[INET6_ADDRSTRLEN];
			struct sockaddr_in addr;
			socklen_t addr_len;
			int stats_fd;

			addr_len = sizeof(struct sockaddr_in);
			rc = accept(prog->stats_listenfd,
				    (struct sockaddr *)&addr, &addr_len);
			if (rc < 0) {
				if (errno != EINTR)
					fprintf(stderr, "accept returned %d: %s\n",
						errno, strerror(errno));
				return -errno;
			}

			if (!inet_ntop(addr.sin_family, &addr.sin_addr.s_addr,
				       client_addr, addr_len)) {
				fprintf(stderr, "inet_pton returned %d: %s\n",
					errno, strerror(errno));
				return -errno;
			}

			printf("Accepted connection from %s\n", client_addr);

			stats_fd = rc;

			isochron_log_xmit(&prog->log, stats_fd);
			isochron_log_teardown(&prog->log);
			rc = isochron_log_init(&prog->log, prog->iterations *
					       sizeof(struct isochron_rcv_pkt_data));
			if (rc < 0)
				break;

			close(stats_fd);
		}
		if (signal_received)
			break;
	} while (1);

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

	rc = isochron_log_init(&prog->log, prog->iterations *
			       sizeof(struct isochron_rcv_pkt_data));
	if (rc < 0)
		return rc;

	prog->clkid = CLOCK_TAI;
	/* Convert negative logic from cmdline to positive */
	prog->do_ts = !prog->do_ts;

	sa.sa_handler = sig_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	rc = sigaction(SIGTERM, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGTERM: %s\n", strerror(errno));
		return -errno;
	}
	rc = sigaction(SIGINT, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGINT: %s\n", strerror(errno));
		return -errno;
	}

	prog->if_index = if_nametoindex(prog->if_name);
	if (!prog->if_index) {
		fprintf(stderr, "if_nametoindex(%s) returned %s\n",
			prog->if_name, strerror(errno));
		return -errno;
	}

	prog->stats_listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (prog->stats_listenfd < 0) {
		perror("listener: stats socket");
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(prog->stats_listenfd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->stats_listenfd);
		return -errno;
	}

	rc = bind(prog->stats_listenfd, (struct sockaddr*)&serv_addr,
		  sizeof(serv_addr));
	if (rc < 0) {
		perror("listener: bind");
		close(prog->stats_listenfd);
		return -errno;
	}

	rc = listen(prog->stats_listenfd, 1);
	if (rc < 0) {
		perror("listener: listen");
		close(prog->stats_listenfd);
		return -errno;
	}

	if (!prog->etype)
		prog->etype = ETH_P_ISOCHRON;

	if (prog->l2)
		/* Open PF_PACKET socket, listening for the specified EtherType */
		prog->data_fd = socket(PF_PACKET, SOCK_RAW, htons(prog->etype));
	else
		prog->data_fd = socket(AF_INET, SOCK_DGRAM,
				       IPPROTO_UDP);

	if (prog->data_fd < 0) {
		perror("listener: data socket");
		close(prog->stats_listenfd);
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(prog->data_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->stats_listenfd);
		close(prog->data_fd);
		return -errno;
	}

	if (prog->l2) {
		/* Bind to device */
		rc = setsockopt(prog->data_fd, SOL_SOCKET, SO_BINDTODEVICE,
				prog->if_name, IFNAMSIZ - 1);
		if (rc < 0) {
			perror("SO_BINDTODEVICE");
			close(prog->stats_listenfd);
			close(prog->data_fd);
			exit(EXIT_FAILURE);
		}
	} else {
		rc = bind(prog->data_fd, (struct sockaddr *)&serv_data_addr,
			  sizeof(serv_data_addr));
		if (rc < 0) {
			perror("bind");
			close(prog->stats_listenfd);
			close(prog->data_fd);
			return -errno;
		}
	}

	if (ether_addr_to_u64(prog->dest_mac)) {
		rc = multicast_listen(prog->data_fd, prog->if_index,
				      prog->dest_mac, true);
		if (rc) {
			perror("multicast_listen");
			close(prog->stats_listenfd);
			close(prog->data_fd);
			return rc;
		}
	}

	if (prog->do_ts)
		return sk_timestamping_init(prog->data_fd, prog->if_name, 1);

	return 0;
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

	if (!prog->data_port)
		prog->data_port = ISOCHRON_DATA_PORT;

	/* Default to the old behavior, which was to allocate a 10 MiB
	 * log buffer given a 56 byte size of struct isochron_rcv_pkt_data
	 */
	if (!prog->iterations)
		prog->iterations = 187245;

	if (prog->utc_tai_offset == -1) {
		prog->utc_tai_offset = get_utc_tai_offset();
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
	close(prog->stats_listenfd);
	close(prog->data_fd);

	if (ether_addr_to_u64(prog->dest_mac))
		multicast_listen(prog->data_fd, prog->if_index,
				 prog->dest_mac, false);

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

	rc_save = server_loop(&prog, &prog);

	rc = prog_teardown(&prog);
	if (rc < 0)
		return rc;

	return rc_save;
}
