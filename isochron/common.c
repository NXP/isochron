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

int mac_addr_from_string(unsigned char *to, char *from)
{
	unsigned long byte;
	char *p = from;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		byte = strtoul(p, &p, 16);
		to[i] = (unsigned char)byte;
		if (i == (ETH_ALEN - 1) && *p != 0)
			/* 6 bytes processed but more are present */
			return -EFBIG;
		else if (i != (ETH_ALEN - 1) && *p == ':')
			p++;
	}

	return 0;
}

int get_time_from_string(clockid_t clkid, __s64 *to, char *from)
{
	struct timespec now_ts = {0};
	__kernel_time_t sec;
	int relative = 0;
	long nsec = 0;
	__s64 now = 0;
	int size;

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
		char nsec_buf[] = "000000000";
		int i;

		/* The format is "sec.nsec" */
		from++;
		if (strlen(from) > 9) {
			fprintf(stderr,
				"Nanosecond format too long, would truncate: %s\n",
				from);
			return -ERANGE;
		}
		size = sprintf(nsec_buf, "%s", from);
		for (i = size; i < 9; i++)
			nsec_buf[i] = '0';

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
	} else {
		/* The format is "nsec" */
		nsec = sec;
		sec = 0;
	}

	if (relative) {
		clock_gettime(clkid, &now_ts);
		now = timespec_to_ns(&now_ts);
	}

	*to = sec * NSEC_PER_SEC + nsec;
	*to += now;

	return 0;
}

static const char * const prog_arg_type_str[] = {
	[PROG_ARG_MAC_ADDR] = "MAC address",
	[PROG_ARG_LONG] = "Long integer",
	[PROG_ARG_TIME] = "Time in sec.nsec format",
	[PROG_ARG_STRING] = "String",
	[PROG_ARG_BOOL] = "Boolean",
	[PROG_ARG_IP] = "IP address",
	[PROG_ARG_HELP] = "Help text",
};

static int required_args[] = {
	[PROG_ARG_MAC_ADDR] = 1,
	[PROG_ARG_LONG] = 1,
	[PROG_ARG_TIME] = 1,
	[PROG_ARG_STRING] = 1,
	[PROG_ARG_BOOL] = 0,
	[PROG_ARG_IP] = 1,
	[PROG_ARG_HELP] = 0,
};

void prog_usage(const char *prog_name, struct prog_arg *prog_args,
		int prog_args_size)
{
	int i;

	fprintf(stderr, "%s usage:\n", prog_name);

	for (i = 0; i < prog_args_size; i++)
		fprintf(stderr, "%s|%s: %s%s\n",
			prog_args[i].short_opt, prog_args[i].long_opt,
			prog_arg_type_str[prog_args[i].type],
			prog_args[i].optional ? " (optional)" : "");
}

static int prog_parse_one_arg(char *val, const struct prog_arg *match)
{
	struct prog_arg_string string;
	struct prog_arg_time time;
	struct ip_address *ip_ptr;
	bool *boolean_ptr;
	long *long_ptr;
	bool *help_ptr;
	int rc;

	switch (match->type) {
	case PROG_ARG_MAC_ADDR:
		rc = mac_addr_from_string(match->mac.buf, val);
		if (rc < 0) {
			fprintf(stderr, "Could not read %s: %s\n",
				match->long_opt, strerror(-rc));
			return rc;
		}
		break;
	case PROG_ARG_LONG:
		long_ptr = match->long_ptr.ptr;

		errno = 0;
		*long_ptr = strtol(val, NULL, 0);
		if (errno) {
			fprintf(stderr, "Could not read %s: %s\n",
				match->long_opt, strerror(errno));
			return -1;
		}
		break;
	case PROG_ARG_IP:
		ip_ptr = match->ip_ptr.ptr;

		rc = inet_pton(AF_INET6, val, &ip_ptr->addr6);
		if (rc > 0) {
			ip_ptr->family = AF_INET6;
		} else {
			rc = inet_pton(AF_INET, val, &ip_ptr->addr);
			if (rc > 0) {
				ip_ptr->family = AF_INET;
			} else {
				fprintf(stderr, "IP address %s not in known format: %d (%s)\n",
					val, errno, strerror(errno));
				return -1;
			}
		}
		break;
	case PROG_ARG_TIME:
		time = match->time;

		rc = get_time_from_string(time.clkid, time.ns, val);
		if (rc < 0) {
			fprintf(stderr, "Could not read base time: %s\n",
				strerror(-rc));
			return -1;
		}
		break;
	case PROG_ARG_BOOL:
		boolean_ptr = match->boolean_ptr.ptr;

		*boolean_ptr = true;
		break;
	case PROG_ARG_STRING:
		string = match->string;
		strncpy(string.buf, val, string.size);
		break;
	case PROG_ARG_HELP:
		help_ptr = match->help_ptr.ptr;

		*help_ptr = true;
		break;
	default:
		fprintf(stderr, "Unknown argument type %d\n",
			match->type);
		return -EINVAL;
	}

	return 0;
}

/* Parse non-positional arguments and return the number of
 * arguments consumed. Return on first positional argument
 * found.
 */
int prog_parse_np_args(int argc, char **argv, struct prog_arg *prog_args,
		       int prog_args_size)
{
	bool help_requested = false;
	int rc, i, parsed = 0;
	bool *parsed_arr;

	parsed_arr = calloc(sizeof(bool), prog_args_size);
	if (!parsed_arr)
		return -ENOMEM;

	while (argc) {
		char *arg = argv[0], *val;
		char *equals = NULL;

		equals = strchr(arg, '=');
		if (equals) {
			*equals = 0;
			val = equals + 1;
		} else {
			val = argv[1];
		}

		for (i = 0; i < prog_args_size; i++) {
			if (strcmp(arg, prog_args[i].short_opt) &&
			    strcmp(arg, prog_args[i].long_opt))
				continue;

			/* Consume argument specifier */
			parsed++;
			argc--;
			argv++;

			if (!val && argc < required_args[prog_args[i].type]) {
				fprintf(stderr, "Value expected after %s\n",
					arg);
				free(parsed_arr);
				return -EINVAL;
			}

			rc = prog_parse_one_arg(val, &prog_args[i]);
			if (rc) {
				free(parsed_arr);
				return rc;
			}

			if (prog_args[i].type == PROG_ARG_HELP)
				help_requested = true;

			/* Consume actual argument value, unless it was
			 * separated from the argument string by an "=" sign,
			 * case in which it's really the same string
			 */
			if (!equals) {
				parsed += required_args[prog_args[i].type];
				argc -= required_args[prog_args[i].type];
				argv += required_args[prog_args[i].type];
			}
			parsed_arr[i] = true;

			/* Success, stop searching */
			break;
		}
		if (i == prog_args_size) {
			fprintf(stderr, "Unrecognized option %s\n", arg);
			free(parsed_arr);
			return -EINVAL;
		}
	}

	for (i = 0; i < prog_args_size; i++) {
		/* Mandatory arguments are only mandatory if the user doesn't
		 * specify --help.
		 */
		if (!prog_args[i].optional && !parsed_arr[i] &&
		    !help_requested) {
			fprintf(stderr, "Please specify %s\n",
				prog_args[i].long_opt);
			free(parsed_arr);
			return -EINVAL;
		}
	}

	free(parsed_arr);

	return parsed;
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
		fprintf(stderr, "ioctl SIOCSHWTSTAMP failed: %s\n",
			strerror(errno));
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
			fprintf(stderr, "poll for tx timestamp failed: %s\n",
				strerror(rc));
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
		fprintf(stderr, "recvmsg%sfailed: %s\n",
			flags == MSG_ERRQUEUE ? " tx timestamp " : " ",
			strerror(errno));

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
				if (tstamp)
					tstamp->tskey = sock_err->ee_data;
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
				fprintf(stderr,
					"unknown socket error %d, origin %d code %d: %s\n",
					sock_err->ee_errno, sock_err->ee_origin,
					sock_err->ee_code,
					strerror(sock_err->ee_errno));
				break;
			}
		} else {
			fprintf(stderr, "unknown cmsg level %d type %d\n",
				level, type);
		}
	}

	return len;
}

int isochron_log_init(struct isochron_log *log, size_t size)
{
	log->buf = calloc(sizeof(char), size);
	if (!log->buf)
		return -ENOMEM;

	log->buf_total_size = size;
	log->buf_len = 0;

	return 0;
}

void isochron_log_teardown(struct isochron_log *log)
{
	free(log->buf);
}

void isochron_log_data(struct isochron_log *log, void *data, int len)
{
	char *p = log->buf + log->buf_len;

	if (log->buf_len + len > log->buf_total_size) {
		fprintf(stderr,
			"Not logging event, buffer size of %lu exceeded\n",
			log->buf_total_size);
		return;
	}

	memcpy(p, data, len);
	log->buf_len += len;
}

/* Get a reference to an existing log entry */
void *isochron_log_get_entry(struct isochron_log *log, size_t entry_size,
			     int index)
{
	if (index * entry_size > log->buf_len)
		return NULL;

	return log->buf + entry_size * index;
}

int isochron_log_xmit(struct isochron_log *log, int fd)
{
	__be32 log_version = __cpu_to_be32(ISOCHRON_LOG_VERSION);
	__be32 buf_len = __cpu_to_be32(log->buf_len);
	ssize_t len;

	len = write_exact(fd, &log_version, sizeof(log_version));
	if (len <= 0) {
		fprintf(stderr, "log_version write returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	len = write_exact(fd, &buf_len, sizeof(buf_len));
	if (len <= 0) {
		fprintf(stderr, "buf_len write returned %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	if (log->buf_len) {
		len = write_exact(fd, log->buf, log->buf_len);
		if (len <= 0) {
			fprintf(stderr, "write returned %d: %s\n",
				errno, strerror(errno));
			return -errno;
		}
	}

	return 0;
}

int isochron_log_recv(struct isochron_log *log, int fd)
{
	__be32 log_version;
	__be32 buf_len;
	ssize_t len;
	int rc;

	len = read_exact(fd, &log_version, sizeof(log_version));
	if (len <= 0) {
		fprintf(stderr, "could not read buffer length: %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	if (__be32_to_cpu(log_version) != ISOCHRON_LOG_VERSION) {
		fprintf(stderr,
			"incompatible isochron log version %d, expected %d, exiting\n",
			__be32_to_cpu(log_version), ISOCHRON_LOG_VERSION);
		return -EINVAL;
	}

	len = read_exact(fd, &buf_len, sizeof(buf_len));
	if (len <= 0) {
		fprintf(stderr, "could not read buffer length: %d: %s\n",
			errno, strerror(errno));
		return -errno;
	}

	rc = isochron_log_init(log, __be32_to_cpu(buf_len));
	if (rc)
		return rc;

	log->buf_total_size = __be32_to_cpu(buf_len);
	log->buf_len = log->buf_total_size;

	if (log->buf_len) {
		len = read_exact(fd, log->buf, log->buf_len);
		if (len <= 0) {
			fprintf(stderr, "read of %zu bytes returned %d: %s\n",
				log->buf_len, errno, strerror(errno));
			isochron_log_teardown(log);
			return -errno;
		}
	}

	return 0;
}

void isochron_rcv_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->buf_len;
	struct isochron_rcv_pkt_data *rcv_pkt;

	for (rcv_pkt = (struct isochron_rcv_pkt_data *)log->buf;
	     (char *)rcv_pkt < log_buf_end; rcv_pkt++) {
		__s64 tx_time = (__s64 )__be64_to_cpu(rcv_pkt->tx_time);
		__s64 rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
		__s64 rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);
		char scheduled_buf[TIMESPEC_BUFSIZ];
		char smac_buf[MACADDR_BUFSIZ];
		char dmac_buf[MACADDR_BUFSIZ];

		/* Print packet */
		ns_sprintf(scheduled_buf, tx_time);
		mac_addr_sprintf(smac_buf, rcv_pkt->smac);
		mac_addr_sprintf(dmac_buf, rcv_pkt->dmac);

		if (rcv_pkt->hwts) {
			char hwts_buf[TIMESPEC_BUFSIZ];
			char swts_buf[TIMESPEC_BUFSIZ];

			ns_sprintf(hwts_buf, rx_hwts);
			ns_sprintf(swts_buf, rx_swts);

			printf("[%s] src %s dst %s ethertype 0x%04x seqid %d rxtstamp %s swts %s\n",
			       scheduled_buf, smac_buf, dmac_buf, __be16_to_cpu(rcv_pkt->etype),
			       __be32_to_cpu(rcv_pkt->seqid), hwts_buf, swts_buf);
		} else {
			printf("[%s] src %s dst %s ethertype 0x%04x seqid %d\n",
			       scheduled_buf, smac_buf, dmac_buf, __be16_to_cpu(rcv_pkt->etype),
			       __be32_to_cpu(rcv_pkt->seqid));
		}
	}
}

void isochron_send_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->buf_len;
	struct isochron_send_pkt_data *send_pkt;

	for (send_pkt = (struct isochron_send_pkt_data *)log->buf;
	     (char *)send_pkt < log_buf_end; send_pkt++) {
		__s64 tx_time = (__s64 )__be64_to_cpu(send_pkt->tx_time);
		__s64 tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
		__s64 tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
		char scheduled_buf[TIMESPEC_BUFSIZ];
		char hwts_buf[TIMESPEC_BUFSIZ];
		char swts_buf[TIMESPEC_BUFSIZ];

		ns_sprintf(scheduled_buf, tx_time);
		ns_sprintf(hwts_buf, tx_hwts);
		ns_sprintf(swts_buf, tx_swts);

		printf("[%s] seqid %d txtstamp %s swts %s\n",
		       scheduled_buf, __be32_to_cpu(send_pkt->seqid),
		       hwts_buf, swts_buf);
	}
}

void isochron_log_remove(struct isochron_log *log, void *p, size_t len)
{
	memmove(p, p + len, log->buf_len - len);
	log->buf_len -= len;
}

int isochron_send_tlv(int fd, enum isochron_management_action action,
		      enum isochron_management_id mid, size_t size)
{
	struct isochron_management_message *msg;
	unsigned char buf[BUFSIZ];
	struct isochron_tlv *tlv;
	ssize_t len;

	memset(buf, 0, sizeof(*msg) + sizeof(*tlv));

	msg = (struct isochron_management_message *)buf;
	msg->version = ISOCHRON_MANAGEMENT_VERSION;
	msg->action = action;
	msg->payload_length = __cpu_to_be32(sizeof(*tlv) + size);

	tlv = (struct isochron_tlv *)(msg + 1);
	tlv->tlv_type = __cpu_to_be16(ISOCHRON_TLV_MANAGEMENT);
	tlv->management_id = __cpu_to_be16(mid);
	tlv->length_field = __cpu_to_be32(size);

	len = write_exact(fd, buf, sizeof(*msg) + sizeof(*tlv));
	if (len < 0)
		return len;
	if (len == 0)
		return -ECONNRESET;
	return 0;
}

size_t isochron_log_buf_tlv_size(struct isochron_log *log)
{
	return sizeof(__be32) + /* log_version */
	       sizeof(__be32) + /* buf_len */
	       log->buf_len;
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
		fprintf(stderr, "Failed to query DEFAULT_DATA_SET: %d (%s)\n",
			rc, strerror(-rc));
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
			fprintf(stderr,
				"Failed to query PORT_PROPERTIES_NP: %d (%s)\n",
				rc, strerror(-rc));
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
		fprintf(stderr, "can't catch SIGTERM: %s\n", strerror(errno));
		return -errno;
	}

	rc = sigaction(SIGINT, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGINT: %s\n", strerror(errno));
		return -errno;
	}

	rc = sigaction(SIGPIPE, &sa, NULL);
	if (rc < 0) {
		fprintf(stderr, "can't catch SIGPIPE: %s\n", strerror(errno));
		return -errno;
	}

	return 0;
}
