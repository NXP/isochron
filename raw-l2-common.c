// SPDX-License-Identifier: GPL-3.0+

#include <linux/net_tstamp.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <sys/poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "raw-l2-common.h"

#define TXTSTAMP_TIMEOUT_MS	100

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
