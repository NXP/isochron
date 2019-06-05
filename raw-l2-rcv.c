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
#include <errno.h>
#include <time.h>

#define BUF_SIZ		1522

struct prog_data {
	char if_name[IFNAMSIZ];
	uint8_t rcvbuf[BUF_SIZ];
	int fd;
};

struct app_private {
	clockid_t clkid;
};

struct app_header {
	short seqid;
};

#define app_fmt \
	"[%ld.%09ld] src %02x:%02x:%02x:%02x:%02x:%02x dst %02x:%02x:%02x:%02x:%02x:%02x ethertype 0x%04x seqid %d\n"

static int app_loop(void *app_data, char *rcvbuf, size_t len)
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
	       ntohs(eth_hdr->ether_type), ntohs(app_hdr->seqid));

	return 0;
}

static int server_loop(struct prog_data *prog, void *app_data)
{
	ssize_t len;
	int rc = 0;

	do {
		len = recvfrom(prog->fd, prog->rcvbuf, BUF_SIZ, 0, NULL, NULL);
		if (len < 0) {
			fprintf(stderr, "recvfrom returned %d: %s\n",
				errno, strerror(errno));
			rc = -errno;
			break;
		}
		rc = app_loop(app_data, prog->rcvbuf, len);
		if (rc < 0)
			break;
	} while (1);

	close(prog->fd);
	return rc;
}

static void app_init(void *data)
{
	struct app_private *priv = data;

	priv->clkid = CLOCK_REALTIME;
}

static int prog_init(struct prog_data *prog)
{
	int sockopt = 1;
	int rc;

	/* Open PF_PACKET socket, listening for EtherType ETH_P_802_EX1 */
	prog->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_802_EX1));
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
	/* Bind to device */
	rc = setsockopt(prog->fd, SOL_SOCKET, SO_BINDTODEVICE,
			prog->if_name, IFNAMSIZ - 1);
	if (rc < 0) {
		perror("SO_BINDTODEVICE");
		close(prog->fd);
		exit(EXIT_FAILURE);
	}

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"usage: \n"
		"%s <netdev>\n"
		"\n",
		progname);
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	int rc;

	if (argc != 2) {
		usage(argv[0]);
		return -1;
	}

	/* Get interface name */
	if (argc > 1) {
		strncpy(prog->if_name, argv[1], IFNAMSIZ - 1);
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

	rc= prog_init(&prog);
	if (rc < 0)
		return rc;

	app_init(&priv);

	return server_loop(&prog, &priv);
}
