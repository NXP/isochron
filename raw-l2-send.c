// SPDX-License-Identifier: GPL-3.0+
/* Based on code from:
 * https://gist.github.com/austinmarton/1922600
 * https://sourceforge.net/p/linuxptp/mailman/message/31998404/
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NSEC_PER_SEC	1000000000
#define BUF_SIZ		1522

struct prog_data {
	uint8_t dest_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char sendbuf[BUF_SIZ];
	struct sockaddr_ll socket_address;
	struct timespec base_time;
	struct timespec period;
	clockid_t clkid;
	long iterations;
	int priority;
	int tx_len;
	int fd;
};

struct app_private {
	struct sockaddr *sockaddr;
	char *sendbuf;
	int tx_len;
	int fd;
};

struct app_header {
	short seqid;
};

struct timespec timespec_add(struct timespec a, struct timespec b)
{
	struct timespec ts = {
		.tv_sec = a.tv_sec + b.tv_sec,
		.tv_nsec = a.tv_nsec + b.tv_nsec,
	};

	while (ts.tv_nsec >= NSEC_PER_SEC) {
		ts.tv_sec += 1;
		ts.tv_nsec -= NSEC_PER_SEC;
	}

	return ts;
}

static int do_work(void *data, int iteration, clockid_t clkid)
{
	struct app_private *priv = data;
	struct app_header *app_hdr;
	struct timespec ts;
	int rc;

	clock_gettime(clkid, &ts);
	printf("[%ld.%09ld] Send frame with seqid %d\n",
	       ts.tv_sec, ts.tv_nsec, iteration);
	app_hdr = (struct app_header *)(priv->sendbuf +
					sizeof(struct ether_header));
	app_hdr->seqid = htons(iteration);

	/* Send packet */
	rc = sendto(priv->fd, priv->sendbuf, priv->tx_len, 0,
		    priv->sockaddr, sizeof(struct sockaddr_ll));
	if (rc < 0) {
		perror("send\n");
		return rc;
	}

	return 0;
}

static int run_nanosleep(struct prog_data *prog, void *app_data)
{
	struct timespec ts = prog->base_time;
	long i;
	int rc;

	printf("%10s: %d.%09ld\n", "Base time", prog->base_time.tv_sec,
		prog->base_time.tv_nsec);
	printf("%10s: %d.%09ld\n", "Period", prog->period.tv_sec,
		prog->period.tv_nsec);

	/* Play nice with awk's array indexing */
	for (i = 1; i <= prog->iterations; i++) {
		rc = clock_nanosleep(prog->clkid, TIMER_ABSTIME, &ts, NULL);
		switch (rc) {
		case 0:
			rc = do_work(app_data, i, prog->clkid);
			if (rc < 0)
				break;

			ts = timespec_add(ts, prog->period);
			break;
		case EINTR:
			continue;
		default:
			fprintf(stderr, "clock_nanosleep returned %d: %s\n",
				rc, strerror(rc));
			break;
		}
	}

	return 0;
}

static void usage(char *progname)
{
	fprintf(stderr,
		"usage: \n"
		"%s <netdev> <dest-mac> <prio> <base-time> <period> <iterations> <length>\n"
		"\n",
		progname);
}

static void app_init(void *data)
{
	struct app_private *priv = data;
	int i = sizeof(struct ether_header);

	/* Packet data */
	while (i < priv->tx_len) {
		priv->sendbuf[i++] = 0xde;
		priv->sendbuf[i++] = 0xad;
		priv->sendbuf[i++] = 0xbe;
		priv->sendbuf[i++] = 0xef;
	}
}

static inline int timespec_smaller(struct timespec a, struct timespec b)
{
	if (a.tv_sec == b.tv_sec)
		return a.tv_nsec < b.tv_nsec;
	else
		return a.tv_sec < b.tv_sec;
}

static int prog_init(struct prog_data *prog)
{
	struct ether_header *eh;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct timespec now;
	int warn_once = 1;
	int rc;

	prog->clkid = CLOCK_REALTIME;

	/* Open RAW socket to send on */
	prog->fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (prog->fd < 0) {
		perror("socket");
		return -EINVAL;
	}

	rc = setsockopt(prog->fd, SOL_SOCKET, SO_PRIORITY, &prog->priority,
			sizeof(int));
	if (rc < 0) {
		perror("setsockopt");
		close(prog->fd);
		return rc;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(prog->fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		close(prog->fd);
		return rc;
	}

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, prog->if_name, IFNAMSIZ - 1);
	if (ioctl(prog->fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		close(prog->fd);
		return rc;
	}

	/* Construct the Ethernet header */
	memset(prog->sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh = (struct ether_header *) prog->sendbuf;
	memcpy(eh->ether_shost, &if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
	memcpy(eh->ether_dhost, prog->dest_mac, ETH_ALEN);
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_802_EX1);

	/* Index of the network device */
	prog->socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	prog->socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	memcpy(prog->socket_address.sll_addr, prog->dest_mac, ETH_ALEN);

	rc = clock_gettime(prog->clkid, &now);
	if (rc < 0) {
		perror("clock_gettime");
		close(prog->fd);
		return rc;
	}

	while (timespec_smaller(prog->base_time, now)) {
		if (warn_once) {
			fprintf(stderr,
				"Base time %ld.%09ld is in the past, "
				"winding it into the future\n",
				prog->base_time.tv_sec,
				prog->base_time.tv_nsec);
			warn_once = 0;
		}
		prog->base_time = timespec_add(prog->base_time, prog->period);
	}

	printf("%10s: %d.%09ld\n", "Now", now.tv_sec, now.tv_nsec);

	return 0;
}

static int mac_addr_from_string(uint8_t *to, char *from)
{
	unsigned long byte;
	char *p = from;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		byte = strtoul(p, &p, 16);
		to[i] = (uint8_t )byte;
		if (i == (ETH_ALEN - 1) && *p != 0)
			/* 6 bytes processed but more are present */
			return -EFBIG;
		else if (i != (ETH_ALEN - 1) && *p == ':')
			p++;
	}

	return 0;
}

static int get_time_from_string(clockid_t clkid, struct timespec *to,
				char *from)
{
	char nsec_buf[] = "000000000";
	struct timespec now = {0};
	__kernel_time_t sec;
	int read_nsec = 0;
	int relative = 0;
	char *nsec_str;
	long nsec = 0;
	int size;
	int rc;

	if (from[0] == '+') {
		relative = 1;
		from++;
	}

	errno = 0;
	sec = strtol(from, &from, 0);
	if (errno) {
		fprintf(stderr, "Failed to read seconds: %s\n",
			strerror(errno));
		return -EINVAL;
	}
	if (from[0] == '.') {
		read_nsec = 1;
		from++;
	}
	if (read_nsec) {
		size = snprintf(nsec_buf, 9, "%s", from);
		if (size < 9)
			nsec_buf[size] = '0';

		errno = 0;
		/* Force base 10 here, since leading zeroes will make
		 * strtol think this is an octal number.
		 */
		nsec = strtol(nsec_buf, NULL, 10);
		if (errno) {
			fprintf(stderr, "Failed to extract ns info: %s\n",
				strerror(errno));
			return -EINVAL;
		}
	}

	if (relative)
		clock_gettime(clkid, &now);

	*to = (struct timespec) {
		.tv_sec = sec,
		.tv_nsec = nsec,
	};

	*to = timespec_add(now, *to);

	return 0;
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	int rc;

	if (argc != 8) {
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

	/* Get socket priority */
	if (argc > 1) {
		errno = 0;
		prog->priority = strtol(argv[1], NULL, 0);
		if (errno) {
			fprintf(stderr, "Could not read priority: %s\n",
				strerror(errno));
			return -1;
		}
		argc--; argv++;
	}

	/* Get base time */
	if (argc > 1) {
		rc = get_time_from_string(prog->clkid, &prog->base_time,
					  argv[1]);
		if (rc < 0) {
			fprintf(stderr, "Could not read base time: %s\n",
				strerror(-rc));
			return -1;
		}
		argc--; argv++;
	}

	/* Get period */
	if (argc > 1) {
		rc = get_time_from_string(prog->clkid, &prog->period, argv[1]);
		if (rc < 0) {
			fprintf(stderr, "Could not read period: %s\n",
				strerror(-rc));
			return -1;
		}
		argc--; argv++;
	}

	/* Get number of iterations */
	if (argc > 1) {
		errno = 0;
		prog->iterations = strtol(argv[1], NULL, 0);
		if (errno) {
			printf("Integer overflow occured while reading iterations: %s\n",
				strerror(errno));
			return -1;
		}
		argc--; argv++;
	}

	/* Get frame length */
	if (argc > 1) {
		errno = 0;
		prog->tx_len = strtol(argv[1], NULL, 0);
		if (errno) {
			printf("Integer overflow occured while reading length: %s\n",
				strerror(errno));
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

	priv.sockaddr = (struct sockaddr *)&prog.socket_address;
	priv.sendbuf = prog.sendbuf;
	priv.fd = prog.fd;
	priv.tx_len = prog.tx_len;

	app_init(&priv);

	return run_nanosleep(&prog, &priv);
}
