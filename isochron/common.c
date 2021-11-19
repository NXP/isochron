// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 */
#include <time.h>
#include <linux/net_tstamp.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <linux/errqueue.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
/* For va_start and va_end */
#include <stdarg.h>
#include "common.h"

void pr_err(int rc, const char *fmt, ...)
{
	va_list ap;

	errno = -rc;
	va_start(ap, fmt);
	fprintf(stderr, fmt, ap);
	va_end(ap);
}

ssize_t recv_exact(int sockfd, void *buf, size_t len, int flags)
{
	size_t received = 0;
	ssize_t ret;

	do {
		ret = recv(sockfd, buf + received, len - received, flags);
		if (ret <= 0)
			return ret;
		received += ret;
	} while (received != len);

	return received;
}

ssize_t read_exact(int fd, void *buf, size_t count)
{
	size_t total_read = 0;
	ssize_t ret;

	do {
		ret = read(fd, buf + total_read, count - total_read);
		if (ret <= 0)
			return ret;
		total_read += ret;
	} while (total_read != count);

	return total_read;
}

ssize_t write_exact(int fd, const void *buf, size_t count)
{
	size_t written = 0;
	ssize_t ret;

	do {
		ret = write(fd, buf + written, count - written);
		if (ret <= 0)
			return ret;
		written += ret;
	} while (written != count);

	return written;
}

void mac_addr_sprintf(char *buf, unsigned char *addr)
{
	snprintf(buf, MACADDR_BUFSIZ, "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

__s64 timespec_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

struct timespec ns_to_timespec(__s64 ns)
{
	return (struct timespec) {
		.tv_sec = ns / NSEC_PER_SEC,
		.tv_nsec = llabs(ns) % NSEC_PER_SEC,
	};
}

void ns_sprintf(char *buf, __s64 ns)
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
		perror("ioctl SIOCSHWTSTAMP failed");
		return rc;
	}

	if (cfg.tx_type != tx_type)
		fprintf(stderr, "tx_type   %d not %d\n",
			cfg.tx_type, tx_type);
	if (cfg.rx_filter != rx_filter)
		fprintf(stderr, "rx_filter %d not %d\n",
			cfg.rx_filter, rx_filter);
	if (cfg.tx_type != tx_type || cfg.rx_filter != rx_filter)
		fprintf(stderr,
			"The current filter does not match the required\n");

	return 0;
}

int sk_timestamping_init(int fd, const char *if_name, bool on)
{
	int rc, filter, flags, tx_type;

	flags = SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_TX_SCHED |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE |
		SOF_TIMESTAMPING_OPT_TX_SWHW |
		SOF_TIMESTAMPING_OPT_ID;

	filter = HWTSTAMP_FILTER_ALL;

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
		perror("ioctl SO_TIMESTAMPING failed");
		return -1;
	}

	flags = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
			&flags, sizeof(flags));
	if (rc < 0) {
		perror("SO_SELECT_ERR_QUEUE failed");
		return rc;
	}

	return 0;
}

int sk_receive(int fd, void *buf, int buflen, struct isochron_timestamp *tstamp,
	       int flags, int timeout)
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

		rc = poll(&pfd, 1, timeout);
		if (rc == 0) {
			return 0;
		} else if (rc < 0) {
			perror("poll for tx timestamp failed");
			return rc;
		} else if (!(pfd.revents & POLLPRI)) {
			fprintf(stderr, "poll woke up on non ERR event\n");
			return -1;
		}
		/* On success a positive number is returned */
	}

	len = recvmsg(fd, &msg, flags);
	/* Suppress "Interrupted system call" message */
	if (len < 1 && errno != EINTR)
		perror("recvmsg failed");

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		int level = cm->cmsg_level;
		int type  = cm->cmsg_type;

		if (level == SOL_SOCKET && type == SCM_TIMESTAMPING) {
			struct scm_timestamping *tss;

			if (cm->cmsg_len < sizeof(*ts) * 3) {
				fprintf(stderr, "short SO_TIMESTAMPING message\n");
				return -1;
			}

			tss = (struct scm_timestamping *)CMSG_DATA(cm);

			if (tstamp) {
				tstamp->sw = tss->ts[0];
				tstamp->hw = tss->ts[2];
			}
		} else if (level == SOL_PACKET && type == PACKET_TX_TIMESTAMP) {
			struct sock_extended_err *sock_err;
			char txtime_buf[TIMESPEC_BUFSIZ];
			__u64 txtime;

			sock_err = (struct sock_extended_err *)CMSG_DATA(cm);
			if (!sock_err)
				continue;

			switch (sock_err->ee_origin) {
			case SO_EE_ORIGIN_TIMESTAMPING:
				if (!tstamp)
					break;

				tstamp->tskey = sock_err->ee_data;
				tstamp->tstype = sock_err->ee_info;
				break;
			case SO_EE_ORIGIN_TXTIME:
				txtime = ((__u64)sock_err->ee_data << 32) +
					 sock_err->ee_info;
				ns_sprintf(txtime_buf, txtime);

				switch (sock_err->ee_code) {
				case SO_EE_CODE_TXTIME_INVALID_PARAM:
					fprintf(stderr,
						"packet with txtime %s dropped due to invalid params\n",
						txtime_buf);
					return -1;
				case SO_EE_CODE_TXTIME_MISSED:
					fprintf(stderr,
						"packet with txtime %s dropped due to missed deadline\n",
						txtime_buf);
					return -1;
				default:
					return -1;
				}
				break;
			default:
				pr_err(-sock_err->ee_errno,
				       "unknown socket error %d, origin %d code %d: %m\n",
				       sock_err->ee_errno, sock_err->ee_origin,
				       sock_err->ee_code);
				break;
			}
		} else {
			fprintf(stderr, "unknown cmsg level %d type %d\n",
				level, type);
		}
	}

	return len;
}

static const char * const trace_marker_paths[] = {
	"/sys/kernel/debug/tracing/trace_marker",
	"/debug/tracing/trace_marker",
	"/debugfs/tracing/trace_marker",
};

int trace_mark_open(void)
{
	struct stat st;
	unsigned int i;
	int rc, fd;

	for (i = 0; i < ARRAY_SIZE(trace_marker_paths); i++) {
		rc = stat(trace_marker_paths[i], &st);
		if (rc < 0)
			continue;

		fd = open(trace_marker_paths[i], O_WRONLY);
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

void trace_mark_close(int fd)
{
	close(fd);
}

int set_utc_tai_offset(int offset)
{
	struct timex tx;

	memset(&tx, 0, sizeof(tx));

	tx.modes = ADJ_TAI;
	tx.constant = offset;

	return adjtimex(&tx);
}

int get_utc_tai_offset(void)
{
	struct timex tx;

	memset(&tx, 0, sizeof(tx));

	adjtimex(&tx);
	return tx.tai;
}

void isochron_fixup_kernel_utc_offset(int ptp_utc_offset)
{
	int kernel_offset = get_utc_tai_offset();

	if (ptp_utc_offset == kernel_offset)
		return;

	printf("Kernel UTC-TAI offset of %d seems out of date, updating it to %d\n",
	       kernel_offset, ptp_utc_offset);

	set_utc_tai_offset(ptp_utc_offset);
}

int ptpmon_query_port_state_by_name(struct ptpmon *ptpmon, const char *iface,
				    enum port_state *port_state)
{
	struct default_ds default_ds;
	int portnum, num_ports;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_DEFAULT_DATA_SET,
				    &default_ds, sizeof(default_ds));
	if (rc) {
		pr_err(rc, "Failed to query DEFAULT_DATA_SET: %m\n");
		return rc;
	}

	num_ports = __be16_to_cpu(default_ds.number_ports);

	for (portnum = 1; portnum <= num_ports; portnum++) {
		struct port_properties_np port_properties_np;
		struct port_identity portid;

		portid_set(&portid, &default_ds.clock_identity, portnum);

		rc = ptpmon_query_port_mid_extra(ptpmon, &portid,
						 MID_PORT_PROPERTIES_NP,
						 &port_properties_np,
						 sizeof(port_properties_np),
						 MAX_IFACE_LEN);
		if (rc) {
			pr_err(rc, "Failed to query PORT_PROPERTIES_NP: %m\n");
			return rc;
		}

		if (strcmp(port_properties_np.iface, iface))
			continue;

		*port_state = port_properties_np.port_state;

		return 0;
	}

	return -ENODEV;
}

int isochron_handle_signals(void (*handler)(int signo))
{
	struct sigaction sa;
	int rc;

	sa.sa_handler = handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	rc = sigaction(SIGTERM, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGTERM");
		return -errno;
	}

	rc = sigaction(SIGINT, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGINT");
		return -errno;
	}

	rc = sigaction(SIGPIPE, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGPIPE");
		return -errno;
	}

	return 0;
}
