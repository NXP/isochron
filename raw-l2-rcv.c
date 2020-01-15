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
#include "raw-l2-common.h"

#define BUF_SIZ		1522

struct prog_data {
	char if_name[IFNAMSIZ];
	__u8 dest_mac[ETH_ALEN];
	unsigned int if_index;
	__u8 rcvbuf[BUF_SIZ];
	clockid_t clkid;
	bool do_ts;
	int fd;
};

int signal_received;

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline __u64 ether_addr_to_u64(const unsigned char *addr)
{
	__u64 u = 0;
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		u = u << 8 | addr[i];

	return u;
}

static int app_loop(void *app_data, char *rcvbuf, size_t len,
		    const struct timestamp *tstamp)
{
	/* Header structures */
	struct ethhdr *eth_hdr = (struct ethhdr *)rcvbuf;
	struct app_header *app_hdr = (struct app_header *)(eth_hdr + 1);
	struct prog_data *prog = app_data;
	char gate_buf[TIMESPEC_BUFSIZ];
	char smac_buf[MACADDR_BUFSIZ];
	char dmac_buf[MACADDR_BUFSIZ];
	__s64 hwts, swts;
	int i, rc;

	hwts = timespec_to_ns(&tstamp->hw);
	swts = timespec_to_ns(&tstamp->sw);

	/* Print packet */
	ns_sprintf(gate_buf, __be64_to_cpu(app_hdr->tx_time));
	mac_addr_sprintf(smac_buf, eth_hdr->h_source);
	mac_addr_sprintf(dmac_buf, eth_hdr->h_dest);

	if (prog->do_ts) {
		char hwts_buf[TIMESPEC_BUFSIZ];
		char swts_buf[TIMESPEC_BUFSIZ];

		ns_sprintf(hwts_buf, hwts);
		ns_sprintf(swts_buf, swts);

		printf("[%s] src %s dst %s ethertype 0x%04x seqid %d rxtstamp %s swts %s\n",
		       gate_buf, smac_buf, dmac_buf, ntohs(eth_hdr->h_proto),
		       ntohs(app_hdr->seqid), hwts_buf, swts_buf);
	} else {
		printf("[%s] src %s dst %s ethertype 0x%04x seqid %d\n",
		       gate_buf, smac_buf, dmac_buf, ntohs(eth_hdr->h_proto),
		       ntohs(app_hdr->seqid));
	}

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
	struct ethhdr *eth_hdr = (struct ethhdr *)prog->rcvbuf;
	struct timestamp tstamp = {0};
	ssize_t len;
	int rc = 0;

	do {
		len = sk_receive(prog->fd, prog->rcvbuf, BUF_SIZ, &tstamp, 0,
				 TXTSTAMP_TIMEOUT_MS);
		/* Suppress "Interrupted system call" message */
		if (len < 0 && errno != EINTR) {
			fprintf(stderr, "recvfrom returned %d: %s\n",
				errno, strerror(errno));
			rc = -errno;
			break;
		}
		if (ether_addr_to_u64(prog->dest_mac) &&
		    ether_addr_to_u64(prog->dest_mac) !=
		    ether_addr_to_u64(eth_hdr->h_dest))
			continue;
		rc = app_loop(app_data, prog->rcvbuf, len, &tstamp);
		if (rc < 0)
			break;
		if (signal_received)
			break;
	} while (1);

	/* Avoid the nanosecond portion of last output line
	 * from getting truncated when process is killed
	 */
	fflush(stdout);

	close(prog->fd);

	if (ether_addr_to_u64(prog->dest_mac))
		rc = multicast_listen(prog->fd, prog->if_index,
				      prog->dest_mac, false);

	return rc;
}

void sig_handler(int signo)
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
	struct sigaction sa;
	int sockopt = 1;
	int rc;

	prog->clkid = CLOCK_REALTIME;
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

	/* Open PF_PACKET socket, listening for EtherType ETH_P_TSN */
	prog->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_TSN));
	if (prog->fd < 0) {
		perror("listener: socket");
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(prog->fd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->fd);
		return -errno;
	}
	/* Bind to device */
	rc = setsockopt(prog->fd, SOL_SOCKET, SO_BINDTODEVICE,
			prog->if_name, IFNAMSIZ - 1);
	if (rc < 0) {
		perror("SO_BINDTODEVICE");
		close(prog->fd);
		exit(EXIT_FAILURE);
	}

	if (ether_addr_to_u64(prog->dest_mac))
		rc = multicast_listen(prog->fd, prog->if_index,
				      prog->dest_mac, true);

	if (prog->do_ts)
		return sk_timestamping_init(prog->fd, prog->if_name, 1);

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
		},
	};
	char *prog_name = argv[0];
	int rc;

	/* Consume prog_name */
	argc--;
	argv++;

	rc = prog_parse_np_args(argc, argv, args, ARRAY_SIZE(args));

	/* Non-positional arguments left unconsumed */
	if (rc < 0) {
		fprintf(stderr, "Parsing returned %d: %s\n",
			-rc, strerror(-rc));
		return rc;
	} else if (rc < argc) {
		fprintf(stderr, "%d unconsumed arguments. First: %s\n",
			argc - rc, argv[rc]);
		prog_usage(prog_name, args, ARRAY_SIZE(args));
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	return server_loop(&prog, &prog);
}
