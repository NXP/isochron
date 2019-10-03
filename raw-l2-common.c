// SPDX-License-Identifier: GPL-3.0+

#include <linux/net_tstamp.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include "raw-l2-common.h"

#define TXTSTAMP_TIMEOUT_MS	100

int sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags)
{
	return syscall(__NR_sched_setattr, pid, attr, flags);
}

int mac_addr_from_string(u8 *to, char *from)
{
	unsigned long byte;
	char *p = from;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		byte = strtoul(p, &p, 16);
		to[i] = (u8 )byte;
		if (i == (ETH_ALEN - 1) && *p != 0)
			/* 6 bytes processed but more are present */
			return -EFBIG;
		else if (i != (ETH_ALEN - 1) && *p == ':')
			p++;
	}

	return 0;
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

/* Parse non-positional arguments and return the number of
 * arguments consumed. Return on first positional argument
 * found.
 */
int prog_parse_np_args(int argc, char **argv, struct prog_arg *prog_args,
		       int prog_args_size)
{
	struct prog_arg_string string;
	struct prog_arg_time time;
	int rc, i, parsed = 0;
	long int *long_ptr;
	bool *parsed_arr;
	char *arg;

	parsed_arr = calloc(sizeof(bool), prog_args_size);
	if (!parsed_arr)
		return -ENOMEM;

	while (argc) {
		for (i = 0; i < prog_args_size; i++) {
			arg = argv[0];

			if (strcmp(arg, prog_args[i].short_opt) &&
			    strcmp(arg, prog_args[i].long_opt))
				continue;

			/* Consume argument specifier */
			parsed++;
			argc--;
			argv++;

			if (!argc) {
				fprintf(stderr, "Value expected after %s\n",
					arg);
				free(parsed_arr);
				return -EINVAL;
			}

			switch (prog_args[i].type) {
			case PROG_ARG_MAC_ADDR:
				rc = mac_addr_from_string(prog_args[i].mac.buf,
							  argv[0]);
				if (rc < 0) {
					fprintf(stderr, "Could not read %s: %s\n",
						prog_args[i].long_opt,
						strerror(-rc));
					free(parsed_arr);
					return rc;
				}
				break;
			case PROG_ARG_LONG:
				long_ptr = prog_args[i].long_ptr.ptr;

				errno = 0;
				*long_ptr = strtol(argv[0], NULL, 0);
				if (errno) {
					fprintf(stderr, "Could not read %s: %s\n",
						prog_args[i].long_opt,
						strerror(errno));
					free(parsed_arr);
					return -1;
				}
				break;
			case PROG_ARG_TIME:
				time = prog_args[i].time;

				rc = get_time_from_string(time.clkid, time.ns,
							  argv[0]);
				if (rc < 0) {
					fprintf(stderr, "Could not read base time: %s\n",
						strerror(-rc));
					free(parsed_arr);
					return -1;
				}
				break;
			case PROG_ARG_STRING:
				string = prog_args[i].string;
				strncpy(string.buf, argv[0], string.size);
				break;
			default:
				fprintf(stderr, "Unknown argument type %d\n",
					prog_args[i].type);
				free(parsed_arr);
				return -EINVAL;
			}

			/* Consume actual argument */
			parsed++;
			argc--;
			argv++;
			parsed_arr[i] = true;

			/* Success, stop searching */
			break;
		}
		if (i == prog_args_size)
			break;
	}

	for (i = 0; i < prog_args_size; i++) {
		if (!prog_args[i].optional && !parsed_arr[i]) {
			fprintf(stderr, "Please specify %s\n",
				prog_args[i].long_opt);
			free(parsed_arr);
			return -EINVAL;
		}
	}

	return parsed;
}

static const char *prog_arg_type_str[] = {
	[PROG_ARG_MAC_ADDR] = "MAC address",
	[PROG_ARG_LONG] = "Long integer",
	[PROG_ARG_TIME] = "Time in sec.nsec format",
	[PROG_ARG_STRING] = "String",
};

void prog_usage(char *prog_name, struct prog_arg *prog_args, int prog_args_size)
{
	int i;

	fprintf(stderr, "%s usage:\n", prog_name);

	for (i = 0; i < prog_args_size; i++)
		fprintf(stderr, "%s|%s: %s\n",
			prog_args[i].short_opt, prog_args[i].long_opt,
			prog_arg_type_str[prog_args[i].type]);
}

void mac_addr_sprintf(char *buf, u8 *addr)
{
	snprintf(buf, MACADDR_BUFSIZ, "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

u64 timespec_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

struct timespec ns_to_timespec(u64 ns)
{
	return (struct timespec) {
		.tv_sec = ns / NSEC_PER_SEC,
		.tv_nsec = ns % NSEC_PER_SEC,
	};
}

void ns_sprintf(char *buf, u64 ns)
{
	struct timespec ts = ns_to_timespec(ns);

	snprintf(buf, TIMESPEC_BUFSIZ, "%ld.%09ld", ts.tv_sec, ts.tv_nsec);
}

static void init_ifreq(struct ifreq *ifreq, struct hwtstamp_config *cfg,
		       const char *if_name)
{
	memset(ifreq, 0, sizeof(*ifreq));
	memset(cfg, 0, sizeof(*cfg));

	strncpy(ifreq->ifr_name, if_name, sizeof(ifreq->ifr_name) - 1);

	ifreq->ifr_data = (void *) cfg;
}

static int hwts_init(int fd, const char *if_name, int rx_filter, int tx_type)
{
	struct hwtstamp_config cfg;
	struct ifreq ifreq;
	int rc;

	init_ifreq(&ifreq, &cfg, if_name);

	cfg.tx_type   = tx_type;
	cfg.rx_filter = rx_filter;
	rc = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
	if (rc < 0) {
		fprintf(stderr, "ioctl SIOCSHWTSTAMP failed: %s\n",
			strerror(errno));
		return rc;
	}

	if (cfg.tx_type != tx_type || cfg.rx_filter != rx_filter) {
		fprintf(stderr, "tx_type   %d not %d\n", cfg.tx_type, tx_type);
		fprintf(stderr, "rx_filter %d not %d\n", cfg.rx_filter, rx_filter);
		fprintf(stderr, "The current filter does not match the required\n");
	}

	return 0;
}

int sk_timestamping_init(int fd, const char *if_name, int on)
{
	int rc, filter, flags, tx_type;

	flags = SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	filter = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;

	if (on)
		tx_type = HWTSTAMP_TX_ON;
	else
		tx_type = HWTSTAMP_TX_OFF;

	rc = hwts_init(fd, if_name, filter, tx_type);
	if (rc)
		return rc;

	rc = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
		        &flags, sizeof(flags));
	if (rc < 0) {
		fprintf(stderr, "ioctl SO_TIMESTAMPING failed: %s\n",
			strerror(errno));
		return -1;
	}

	flags = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
		        &flags, sizeof(flags));
	if (rc < 0) {
		fprintf(stderr, "%s: SO_SELECT_ERR_QUEUE: %s", if_name,
			strerror(errno));
		return rc;
	}

	return 0;
}

int sk_receive(int fd, void *buf, int buflen, struct timespec *hwts, int flags)
{
	struct iovec iov = { buf, buflen };
	struct timespec *ts;
	struct cmsghdr *cm;
	struct msghdr msg;
	char control[256];
	ssize_t len;
	int rc = 0;

	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (flags == MSG_ERRQUEUE) {
		struct pollfd pfd = { fd, POLLPRI, 0 };
		rc = poll(&pfd, 1, TXTSTAMP_TIMEOUT_MS);
		if (rc == 0) {
			fprintf(stderr, "timed out while polling for tx timestamp\n");
		} else if (rc < 0) {
			fprintf(stderr, "poll for tx timestamp failed: %s\n",
				strerror(rc));
			return rc;
		} else if (!(pfd.revents & POLLPRI)) {
			fprintf(stderr, "poll for tx timestamp woke up on non ERR event\n");
			return -1;
		}
		/* On success a positive number is returned */
	}

	len = recvmsg(fd, &msg, flags);
	/* Suppress "Interrupted system call" message */
	if (len < 1 && errno != EINTR)
		fprintf(stderr, "recvmsg%sfailed: %s\n",
			flags == MSG_ERRQUEUE ? " tx timestamp " : " ",
			strerror(errno));

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMPING) {
			if (cm->cmsg_len < sizeof(*ts) * 3) {
				fprintf(stderr, "short SO_TIMESTAMPING message\n");
				return -1;
			}
			ts = (struct timespec *) CMSG_DATA(cm);
			*hwts = ts[2];
		}
	}

	return len;
}
