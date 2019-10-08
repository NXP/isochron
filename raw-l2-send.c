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
#include <sys/mman.h>
#include <unistd.h>
/* For va_start and va_end */
#include <stdarg.h>
#include "raw-l2-common.h"

#define BUF_SIZ		1522
#define LOGBUF_SIZ	(10 * 1024 * 1024) /* 10 MiB */

struct app_private {
	struct sockaddr *sockaddr;
	char *sendbuf;
	int tx_len;
	int fd;
};

struct prog_data {
	u8 dest_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char sendbuf[BUF_SIZ];
	struct sockaddr_ll socket_address;
	long iterations;
	clockid_t clkid;
	s64 advance_time;
	s64 shift_time;
	s64 cycle_time;
	s64 base_time;
	long priority;
	int log_buf_len;
	char *log_buf;
	long tx_len;
	int fd;
	struct app_private priv;
};

struct app_header {
	short seqid;
};

static int rtprintf(struct prog_data *prog, char *fmt, ...)
{
	char *buf = prog->log_buf + prog->log_buf_len + 1;
	va_list args;
	int rc;

	va_start(args, fmt);

	rc = vsnprintf(buf, LOGBUF_SIZ - prog->log_buf_len, fmt, args);
	prog->log_buf_len += (rc + 1);

	va_end(args);

	return rc;
}

static void rtflush(struct prog_data *prog)
{
	int rc, i = 0;

	while (i < prog->log_buf_len && prog->log_buf[i]) {
		rc = printf(prog->log_buf + i);
		i += (rc + 1);
	}
}

static int do_work(struct prog_data *prog, int iteration, s64 scheduled,
		   clockid_t clkid)
{
	struct app_private *priv = &prog->priv;
	unsigned char err_pkt[BUF_SIZ];
	char scheduled_buf[TIMESPEC_BUFSIZ];
	char hwts_buf[TIMESPEC_BUFSIZ];
	char swts_buf[TIMESPEC_BUFSIZ];
	char now_buf[TIMESPEC_BUFSIZ];
	struct app_header *app_hdr;
	struct timestamp tstamp;
	struct timespec now_ts;
	s64 now, hwts, swts;
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
	rc = sk_receive(priv->fd, err_pkt, BUF_SIZ, &tstamp, MSG_ERRQUEUE);
	if (rc < 0)
		return rc;

	hwts = timespec_to_ns(&tstamp.hw);
	swts = timespec_to_ns(&tstamp.sw);
	now = timespec_to_ns(&now_ts);

	ns_sprintf(scheduled_buf, scheduled);
	ns_sprintf(hwts_buf, hwts);
	ns_sprintf(swts_buf, swts);
	ns_sprintf(now_buf, now);
	rtprintf(prog, "[%s] Sent frame scheduled for %s with seqid %d txtstamp %s swts %s\n",
		 now_buf, scheduled_buf, iteration, hwts_buf, swts_buf);
	return 0;
}

static int run_nanosleep(struct prog_data *prog)
{
	char cycle_time_buf[TIMESPEC_BUFSIZ];
	char base_time_buf[TIMESPEC_BUFSIZ];
	s64 wakeup = prog->base_time;
	s64 scheduled;
	int rc;
	long i;

	ns_sprintf(base_time_buf, prog->base_time);
	ns_sprintf(cycle_time_buf, prog->cycle_time);
	fprintf(stderr, "%10s: %s\n", "Base time", base_time_buf);
	fprintf(stderr, "%10s: %s\n", "Cycle time", cycle_time_buf);

	/* Play nice with awk's array indexing */
	for (i = 1; i <= prog->iterations; i++) {
		struct timespec wakeup_ts = ns_to_timespec(wakeup);

		rc = clock_nanosleep(prog->clkid, TIMER_ABSTIME,
				     &wakeup_ts, NULL);
		switch (rc) {
		case 0:
			scheduled = wakeup + prog->advance_time;

			rc = do_work(prog, i, scheduled, prog->clkid);
			if (rc < 0)
				break;

			wakeup += prog->cycle_time;
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

static int prog_configure_rt(struct prog_data *prog)
{
	struct sched_attr attr = {
		.size = sizeof(struct sched_attr),
		.sched_policy = SCHED_DEADLINE,
		.sched_runtime = prog->advance_time,
		.sched_deadline = prog->advance_time,
		.sched_period = prog->cycle_time,
	};
	int rc;

	/* Prevent the process's virtual memory from being swapped out, by
	 * locking all current and future pages
	 */
	rc = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rc < 0) {
		fprintf(stderr, "mlockall returned %d: %s\n",
			errno, strerror(errno));
		return rc;
	}

	rc = sched_setattr(getpid(), &attr, 0);
	if (rc < 0) {
		fprintf(stderr, "sched_setattr returned %d: %s\n",
			errno, strerror(errno));
		fprintf(stderr,
			"Make sure the cycle-time and advance-time values are reasonable\n");
		return rc;
	}

	return 0;
}

/* Calculate the first base_time in the future that satisfies this
 * relationship:
 *
 * future_base_time = base_time + N x cycle_time >= now, or
 *
 *      now - base_time
 * N >= ---------------
 *         cycle_time
 *
 * Because N is an integer, the ceiling value of the above "a / b" ratio
 * is in fact precisely the floor value of "(a + b - 1) / b", which is
 * easier to calculate only having integer division tools.
 */
static s64 future_base_time(s64 base_time, s64 cycle_time, s64 now)
{
	s64 a, b, n;

	if (base_time >= now)
		return base_time;

	a = now - base_time;
	b = cycle_time;
	n = (a + b - 1) / b;

	return base_time + n * cycle_time;
}

static int prog_init(struct prog_data *prog)
{
	char now_buf[TIMESPEC_BUFSIZ];
	struct ether_header *eh;
	struct timespec now_ts;
	struct ifreq if_idx;
	struct ifreq if_mac;
	s64 now;
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
	prog->base_time += prog->shift_time;
	prog->base_time -= prog->advance_time;

	if (prog->base_time < now) {
		char base_time_buf[TIMESPEC_BUFSIZ];

		ns_sprintf(base_time_buf, prog->base_time);
		fprintf(stderr,
			"Base time %s is in the past, "
			"winding it into the future\n",
			base_time_buf);

		prog->base_time = future_base_time(prog->base_time, now,
						   prog->cycle_time);
	}

	ns_sprintf(now_buf, now);
	fprintf(stderr, "%10s: %s\n", "Now", now_buf);

	prog->log_buf = calloc(sizeof(char), LOGBUF_SIZ);
	if (!prog->log_buf)
		return -ENOMEM;
	prog->log_buf_len = -1;

	rc = prog_configure_rt(prog);
	if (rc < 0)
		return rc;

	return sk_timestamping_init(prog->fd, prog->if_name, 1);
}

static int prog_teardown(struct prog_data *prog)
{
	rtflush(prog);
	free(prog->log_buf);

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
		}, {
			.short_opt = "-p",
			.long_opt = "--priority",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->priority,
			},
		}, {
			.short_opt = "-b",
			.long_opt = "--base-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->base_time,
			},
		}, {
			.short_opt = "-a",
			.long_opt = "--advance-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->advance_time,
			},
			.optional = true,
		}, {
			.short_opt = "-S",
			.long_opt = "--shift-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->shift_time,
			},
			.optional = true,
		}, {
			.short_opt = "-c",
			.long_opt = "--cycle-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_REALTIME,
				.ns = &prog->cycle_time,
			},
		}, {
			.short_opt = "-n",
			.long_opt = "--num-frames",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->iterations,
			},
		}, {
			.short_opt = "-s",
			.long_opt = "--frame-size",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->tx_len,
			},
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

	/* No point in leaving this one's default to zero, if we know that
	 * means it will always be late for its gate event.
	 */
	if (!prog->advance_time)
		prog->advance_time = prog->cycle_time;

	if (prog->advance_time > prog->cycle_time) {
		fprintf(stderr, "Advance time cannot be higher than cycle time\n");
		return -EINVAL;
	}
	if (prog->shift_time > prog->cycle_time) {
		fprintf(stderr, "Shift time cannot be higher than cycle time\n");
		return -EINVAL;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	struct app_private *priv = &prog.priv;
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	priv->sockaddr = (struct sockaddr *)&prog.socket_address;
	priv->sendbuf = prog.sendbuf;
	priv->fd = prog.fd;
	priv->tx_len = prog.tx_len;

	app_init(priv);

	rc = run_nanosleep(&prog);
	if (rc < 0)
		return rc;

	return prog_teardown(&prog);
}
