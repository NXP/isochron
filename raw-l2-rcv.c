// SPDX-License-Identifier: GPL-3.0+
/* Based on code from:
 * https://gist.github.com/austinmarton/2862515
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "raw-l2-common.h"

#define BUF_SIZ		1522

struct prog_data {
	uint8_t dest_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	uint8_t rcvbuf[BUF_SIZ];
	unsigned int if_index;
	int fd;
};

struct app_private {
	clockid_t clkid;
};

struct app_header {
	short seqid;
};

int signal_received = 0;

#define app_fmt \
	"[%ld.%09ld] src %02x:%02x:%02x:%02x:%02x:%02x dst %02x:%02x:%02x:%02x:%02x:%02x ethertype 0x%04x seqid %d rxtstamp %ld.%09ld\n"

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline uint64_t ether_addr_to_u64(const unsigned char *addr)
{
	uint64_t u = 0;
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		u = u << 8 | addr[i];

	return u;
}

static int app_loop(void *app_data, char *rcvbuf, size_t len,
		    const struct timespec *hwts)
{
	/* Header structures */
	struct ether_header *eth_hdr = (struct ether_header *)rcvbuf;
	struct app_header *app_hdr = (struct app_header *)(eth_hdr + 1);
	struct app_private *priv = app_data;
	struct timespec now;
	int i, rc;

	rc = clock_gettime(priv->clkid, &now);
	if (rc < 0) {
		fprintf(stderr, "clock_gettime returned %d: %s", errno,
			strerror(errno));
		return -errno;
	}

	/* Print packet */
	printf(app_fmt,
	       now.tv_sec, now.tv_nsec,
	       eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
	       eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
	       eth_hdr->ether_shost[4], eth_hdr->ether_shost[5],
	       eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
	       eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
	       eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5],
	       ntohs(eth_hdr->ether_type), ntohs(app_hdr->seqid),
	       hwts->tv_sec, hwts->tv_nsec);

	return 0;
}

/* Borrowed from raw_configure in linuxptp */
static int multicast_listen(int fd, unsigned int if_index,
			    unsigned char *macaddr, int enable)
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
	struct ether_header *eth_hdr = (struct ether_header *)prog->rcvbuf;
	struct timespec hwts;
	ssize_t len;
	int rc = 0;

	do {
		len = sk_receive(prog->fd, prog->rcvbuf, BUF_SIZ, &hwts, 0);
		/* Suppress "Interrupted system call" message */
		if (len < 0 && errno != EINTR) {
			fprintf(stderr, "recvfrom returned %d: %s\n",
				errno, strerror(errno));
			rc = -errno;
			break;
		}
		if (ether_addr_to_u64(prog->dest_mac) &&
		    ether_addr_to_u64(prog->dest_mac) != ether_addr_to_u64(eth_hdr->ether_dhost))
			continue;
		rc = app_loop(app_data, prog->rcvbuf, len, &hwts);
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
		rc = multicast_listen(prog->fd, prog->if_index, prog->dest_mac, 0);

	return rc;
}

static void app_init(void *data)
{
	struct app_private *priv = data;

	priv->clkid = CLOCK_REALTIME;
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
	struct sockaddr_ll addr;
	struct sigaction sa;
	int sockopt = 1;
	int rc;

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
		fprintf(stderr, "if_nametoindex(%s) returned %s\n", prog->if_name,
			strerror(errno));
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
			sizeof sockopt);
	if (rc < 0) {
		perror("setsockopt");
		close(prog->fd);
		return -errno;
	}
	memset(&addr, 0, sizeof(struct sockaddr_ll));
	addr.sll_ifindex = prog->if_index;
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	rc = bind(prog->fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll));
	if (rc < 0) {
		fprintf(stderr, "bind failed: %s\n", strerror(errno));
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
		rc = multicast_listen(prog->fd, prog->if_index, prog->dest_mac, 1);

	return sk_timestamping_init(prog->fd, prog->if_name, 1);
}

static void usage(char *progname)
{
	fprintf(stderr,
		"usage: \n"
		"%s <netdev> [<mac-addr>]\n"
		"\n",
		progname);
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	int rc;

	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

	/* Get interface name */
	if (argc > 1) {
		strncpy(prog->if_name, argv[1], IFNAMSIZ - 1);
		argc--; argv++;
	}

	/* Get destination MAC */
	if (argc > 1) {
		rc = mac_addr_from_string(prog->dest_mac, argv[1]);
		if (rc < 0) {
			fprintf(stderr, "Could not read MAC address: %s\n",
				strerror(-rc));
			return -1;
		}
		argc--; argv++;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct app_private priv = {0};
	struct prog_data prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	app_init(&priv);

	return server_loop(&prog, &priv);
}
