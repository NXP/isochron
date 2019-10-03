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
#include "raw-l2-common.h"

#define BUF_SIZ		1522

struct prog_data {
	u8 dest_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char sendbuf[BUF_SIZ];
	struct sockaddr_ll socket_address;
	long iterations;
	clockid_t clkid;
	u64 advance_time;
	u64 base_time;
	u64 period;
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

static int do_work(void *data, int iteration, u64 scheduled, clockid_t clkid)
{
	struct app_private *priv = data;
	unsigned char err_pkt[BUF_SIZ];
	char scheduled_buf[TIMESPEC_BUFSIZ];
	char tstamp_buf[TIMESPEC_BUFSIZ];
	char now_buf[TIMESPEC_BUFSIZ];
	struct timespec now_ts, hwts;
	struct app_header *app_hdr;
	u64 now, tstamp;
	int rc;

	clock_gettime(clkid, &now_ts);
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
	rc = sk_receive(priv->fd, err_pkt, BUF_SIZ, &hwts, MSG_ERRQUEUE);
	if (rc < 0)
		return rc;

	tstamp = timespec_to_ns(&hwts);
	now = timespec_to_ns(&now_ts);

	ns_sprintf(scheduled_buf, scheduled);
	ns_sprintf(tstamp_buf, tstamp);
	ns_sprintf(now_buf, now);
	printf("[%s] Sent frame scheduled for %s with seqid %d txtstamp %s\n",
	       now_buf, scheduled_buf, iteration, tstamp_buf);
	return 0;
}

static int run_nanosleep(struct prog_data *prog, void *app_data)
{
	u64 scheduled = prog->base_time + prog->advance_time;
	char base_time_buf[TIMESPEC_BUFSIZ];
	char period_buf[TIMESPEC_BUFSIZ];
	u64 wakeup = prog->base_time;
	struct timespec wakeup_ts;
	long i;
	int rc;

	ns_sprintf(base_time_buf, prog->base_time);
	ns_sprintf(period_buf, prog->period);
	fprintf(stderr, "%10s: %s\n", "Base time", base_time_buf);
	fprintf(stderr, "%10s: %s\n", "Period", period_buf);

	/* Play nice with awk's array indexing */
	for (i = 1; i <= prog->iterations; i++) {
		struct timespec wakeup_ts = ns_to_timespec(wakeup);

		rc = clock_nanosleep(prog->clkid, TIMER_ABSTIME,
				     &wakeup_ts, NULL);
		switch (rc) {
		case 0:
			rc = do_work(app_data, i, scheduled, prog->clkid);
			if (rc < 0)
				break;

			wakeup += prog->period;
			scheduled = wakeup + prog->advance_time;
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
		"%s <netdev> <dest-mac> <prio> <base-time> <advance-time> <period> <iterations> <length>\n"
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

static int prog_init(struct prog_data *prog)
{
	char now_buf[TIMESPEC_BUFSIZ];
	struct ether_header *eh;
	struct timespec now_ts;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int warn_once = 1;
	u64 now;
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
	eh->ether_type = htons(ETH_P_TSN);

	/* Index of the network device */
	prog->socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	prog->socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	memcpy(prog->socket_address.sll_addr, prog->dest_mac, ETH_ALEN);

	rc = clock_gettime(prog->clkid, &now_ts);
	if (rc < 0) {
		perror("clock_gettime");
		close(prog->fd);
		return rc;
	}

	now = timespec_to_ns(&now_ts);
	prog->base_time -= prog->advance_time;

	while (prog->base_time < now) {
		if (warn_once) {
			char base_time_buf[TIMESPEC_BUFSIZ];

			ns_sprintf(base_time_buf, prog->base_time);
			fprintf(stderr,
				"Base time %s is in the past, "
				"winding it into the future\n",
				base_time_buf);
			warn_once = 0;
		}
		prog->base_time += prog->period;
	}

	ns_sprintf(now_buf, now);
	fprintf(stderr, "%10s: %s\n", "Now", now_buf);

	return sk_timestamping_init(prog->fd, prog->if_name, 1);
}

static int get_time_from_string(clockid_t clkid, u64 *to, char *from)
{
	char nsec_buf[] = "000000000";
	struct timespec now_ts = {0};
	__kernel_time_t sec;
	int read_nsec = 0;
	int relative = 0;
	char *nsec_str;
	long nsec = 0;
	int size, rc;
	u64 now = 0;

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

	if (relative) {
		clock_gettime(clkid, &now_ts);
		now = timespec_to_ns(&now_ts);
	}

	*to = sec * NSEC_PER_SEC + nsec;
	*to += now;

	return 0;
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	int rc;

	if (argc != 9) {
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

	/* Get advance time */
	if (argc > 1) {
		rc = get_time_from_string(prog->clkid, &prog->advance_time, argv[1]);
		if (rc < 0) {
			fprintf(stderr, "Could not read advance_time: %s\n",
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
