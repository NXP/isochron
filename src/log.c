// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019-2021 NXP */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "endian.h"
#include "log.h"

#define ISOCHRON_LOG_VERSION	4

#define FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/

#define ISOCHRON_FLAG_OMIT_SYNC		BIT(0)
#define ISOCHRON_FLAG_DO_TS		BIT(1)
#define ISOCHRON_FLAG_TAPRIO		BIT(2)
#define ISOCHRON_FLAG_TXTIME		BIT(3)
#define ISOCHRON_FLAG_DEADLINE		BIT(4)

static const char *isochron_magic = "ISOCHRON";

struct isochron_log_file_header {
	char		magic[8];
	__be32		version;
	__be32		packet_count;
	__be16		frame_size;
	__be16		flags;
	__be32		reserved;
	__be64		base_time;
	__be64		advance_time;
	__be64		shift_time;
	__be64		cycle_time;
	__be64		window_size;
	__be64		send_log_start;
	__be64		rcv_log_start;
	__be32		send_log_size;
	__be32		rcv_log_size;
	__be64		reserved2;
} __attribute((packed));

struct isochron_packet_metrics {
	LIST_ENTRY(isochron_packet_metrics) list;
	__s64 wakeup_to_hw_ts;
	__s64 hw_rx_deadline_delta;
	__s64 latency_budget;
	__s64 path_delay;
	__s64 wakeup_latency;
	__s64 sender_latency;
	__s64 driver_latency;
	__s64 arrival_latency;
	__u32 seqid;
};

struct isochron_stats {
	LIST_HEAD(stats_head, isochron_packet_metrics) entries;
	int frame_count;
	int hw_tx_deadline_misses;
	double tx_sync_offset_mean;
	double rx_sync_offset_mean;
	double path_delay_mean;
};

struct isochron_metric_stats {
	int seqid_of_min;
	int seqid_of_max;
	__s64 min;
	__s64 max;
	double mean;
	double stddev;
};

#define ISOCHRON_FMT_TIME		BIT(0)
#define ISOCHRON_FMT_SIGNED		BIT(1)
#define ISOCHRON_FMT_UNSIGNED		BIT(2)
#define ISOCHRON_FMT_HEX		BIT(3)

struct isochron_printf_variables {
	__s64 advance_time;	/* A */
	__s64 base_time;	/* B */
	__s64 cycle_time;	/* C */
	__s64 shift_time;	/* H */
	__s64 window_size;	/* W */
	__s64 tx_scheduled;	/* S */
	__s64 tx_wakeup;	/* w */
	__s64 tx_hwts;		/* T */
	__s64 tx_swts;		/* t */
	__s64 tx_sched;		/* s */
	__u32 seqid;		/* q */
	__s64 arrival;		/* a */
	__s64 rx_hwts;		/* R */
	__s64 rx_swts;		/* r */
};

struct isochron_variable_code {
	size_t offset;
	size_t size;
	unsigned long valid_formats;
};

static const struct isochron_variable_code variable_codes[256] = {
	['A'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   advance_time),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['B'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   base_time),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['C'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   cycle_time),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['H'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   shift_time),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['W'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   window_size),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['S'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   tx_scheduled),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['w'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   tx_wakeup),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['T'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   tx_hwts),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['t'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   tx_swts),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['s'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   tx_sched),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['q'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   seqid),
		.size = sizeof(__u32),
		.valid_formats = ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['a'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   arrival),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['R'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   rx_hwts),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
	['r'] = {
		.offset = offsetof(struct isochron_printf_variables,
				   rx_swts),
		.size = sizeof(__s64),
		.valid_formats = ISOCHRON_FMT_TIME |
				 ISOCHRON_FMT_SIGNED |
				 ISOCHRON_FMT_UNSIGNED |
				 ISOCHRON_FMT_HEX,
	},
};

size_t isochron_log_buf_tlv_size(struct isochron_log *log)
{
	return sizeof(__be32) + /* log_version */
	       sizeof(__be32) + /* buf_len */
	       log->size;
}

/* Get a reference to an existing log entry */
void *isochron_log_get_entry(struct isochron_log *log, size_t entry_size,
			     int index)
{
	if (index * entry_size > log->size)
		return NULL;

	return log->buf + entry_size * index;
}

int isochron_log_send_pkt(struct isochron_log *log,
			  const struct isochron_send_pkt_data *send_pkt)
{
	__u32 index = __be32_to_cpu(send_pkt->seqid) - 1;
	struct isochron_send_pkt_data *dest;

	dest = isochron_log_get_entry(log, sizeof(*send_pkt), index);
	if (!dest) {
		fprintf(stderr, "cannot log send packet with index %u\n",
			index);
		return -EINVAL;
	}

	memcpy(dest, send_pkt, sizeof(*send_pkt));

	return 0;
}

int isochron_log_rcv_pkt(struct isochron_log *log,
			 const struct isochron_rcv_pkt_data *rcv_pkt)
{
	__u32 index = __be32_to_cpu(rcv_pkt->seqid) - 1;
	struct isochron_rcv_pkt_data *dest;

	dest = isochron_log_get_entry(log, sizeof(*rcv_pkt), index);
	if (!dest) {
		fprintf(stderr, "cannot log rcv packet with index %u\n",
			index);
		return -EINVAL;
	}

	memcpy(dest, rcv_pkt, sizeof(*rcv_pkt));

	return 0;
}

int isochron_log_xmit(struct isochron_log *log, struct sk *sock)
{
	__be32 log_version = __cpu_to_be32(ISOCHRON_LOG_VERSION);
	__be32 buf_len = __cpu_to_be32(log->size);
	int rc;

	rc = sk_send(sock, &log_version, sizeof(log_version));
	if (rc) {
		sk_err(sock, rc, "Failed to write log version to socket: %m\n");
		return -errno;
	}

	rc = sk_send(sock, &buf_len, sizeof(buf_len));
	if (rc) {
		sk_err(sock, rc, "Failed to write log length to socket: %m\n");
		return -errno;
	}

	if (log->size) {
		rc = sk_send(sock, log->buf, log->size);
		if (rc) {
			sk_err(sock, rc, "Failed to write log to socket: %m\n");
			return -errno;
		}
	}

	return 0;
}

int isochron_log_recv(struct isochron_log *log, struct sk *sock)
{
	__be32 log_version;
	__be32 buf_len;
	int rc;

	rc = sk_recv(sock, &log_version, sizeof(log_version), 0);
	if (rc) {
		sk_err(sock, rc, "could not read log version: %m\n");
		return rc;
	}

	if (__be32_to_cpu(log_version) != ISOCHRON_LOG_VERSION) {
		fprintf(stderr,
			"incompatible isochron log version %d, expected %d, exiting\n",
			__be32_to_cpu(log_version), ISOCHRON_LOG_VERSION);
		return -EINVAL;
	}

	rc = sk_recv(sock, &buf_len, sizeof(buf_len), 0);
	if (rc) {
		sk_err(sock, rc, "could not read buffer length: %m\n");
		return rc;
	}

	rc = isochron_log_init(log, __be32_to_cpu(buf_len));
	if (rc)
		return rc;

	log->size = __be32_to_cpu(buf_len);
	if (log->size) {
		rc = sk_recv(sock, log->buf, log->size, 0);
		if (rc) {
			sk_err(sock, rc, "could not read log: %m");
			isochron_log_teardown(log);
			return rc;
		}
	}

	return 0;
}

void isochron_rcv_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->size;
	struct isochron_rcv_pkt_data *rcv_pkt;

	for (rcv_pkt = (struct isochron_rcv_pkt_data *)log->buf;
	     (char *)rcv_pkt < log_buf_end; rcv_pkt++) {
		__s64 rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
		__s64 rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);
		__u32 seqid = __be32_to_cpu(rcv_pkt->seqid);

		/* Print packet */
		if (rcv_pkt->hwts) {
			char hwts_buf[TIMESPEC_BUFSIZ];
			char swts_buf[TIMESPEC_BUFSIZ];

			ns_sprintf(hwts_buf, rx_hwts);
			ns_sprintf(swts_buf, rx_swts);

			printf("seqid %u rxtstamp %s swts %s\n",
			       seqid, hwts_buf, swts_buf);
		} else if (seqid) {
			printf("seqid %u\n", seqid);
		}
	}
}

void isochron_send_log_print(struct isochron_log *log)
{
	char *log_buf_end = log->buf + log->size;
	struct isochron_send_pkt_data *send_pkt;

	for (send_pkt = (struct isochron_send_pkt_data *)log->buf;
	     (char *)send_pkt < log_buf_end; send_pkt++) {
		__s64 tx_scheduled = (__s64 )__be64_to_cpu(send_pkt->scheduled);
		__s64 tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
		__s64 tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
		char scheduled_buf[TIMESPEC_BUFSIZ];
		char hwts_buf[TIMESPEC_BUFSIZ];
		char swts_buf[TIMESPEC_BUFSIZ];

		ns_sprintf(scheduled_buf, tx_scheduled);
		ns_sprintf(hwts_buf, tx_hwts);
		ns_sprintf(swts_buf, tx_swts);

		printf("[%s] seqid %d txtstamp %s swts %s\n",
		       scheduled_buf, __be32_to_cpu(send_pkt->seqid),
		       hwts_buf, swts_buf);
	}
}

static struct isochron_rcv_pkt_data
*isochron_rcv_log_find(struct isochron_log *rcv_log, __be32 seqid)
{
	struct isochron_rcv_pkt_data *rcv_pkt;
	__u32 index;

	index = __be32_to_cpu(seqid) - 1;
	rcv_pkt = isochron_log_get_entry(rcv_log, sizeof(*rcv_pkt), index);
	if (!rcv_pkt)
		return NULL;

	if (rcv_pkt->seqid != seqid)
		return NULL;

	return rcv_pkt;
}

static void
isochron_printf_vars_get(const struct isochron_send_pkt_data *send_pkt,
			 const struct isochron_rcv_pkt_data *rcv_pkt,
			 __s64 base_time, __s64 advance_time, __s64 shift_time,
			 __s64 cycle_time, __s64 window_size,
			 struct isochron_printf_variables *v)
{
	v->base_time = base_time;
	v->advance_time = advance_time;
	v->shift_time = shift_time;
	v->cycle_time = cycle_time;
	v->window_size = window_size;
	v->tx_scheduled = (__s64 )__be64_to_cpu(send_pkt->scheduled);
	v->tx_wakeup = (__s64 )__be64_to_cpu(send_pkt->wakeup);
	v->tx_hwts = (__s64 )__be64_to_cpu(send_pkt->hwts);
	v->tx_swts = (__s64 )__be64_to_cpu(send_pkt->swts);
	v->tx_sched = (__s64 )__be64_to_cpu(send_pkt->sched_ts);
	v->rx_hwts = (__s64 )__be64_to_cpu(rcv_pkt->hwts);
	v->rx_swts = (__s64 )__be64_to_cpu(rcv_pkt->swts);
	v->arrival = (__s64 )__be64_to_cpu(rcv_pkt->arrival);
	v->seqid = (__u32 )__be32_to_cpu(send_pkt->seqid);
}

static int
isochron_printf_signed_int(char *buf, const char *buf_end_ptr,
			   const struct isochron_variable_code *vc,
			   const struct isochron_printf_variables *v)
{
	__s64 *var64 = (__s64 *)((char *)v + vc->offset);
	__s32 *var32 = (__s32 *)((char *)v + vc->offset);
	char tmp[30];
	size_t size;

	switch (vc->size) {
	case sizeof(__s64):
		sprintf(tmp, "%lld", *var64);
		break;
	case sizeof(__s32):
		sprintf(tmp, "%d", *var32);
		break;
	default:
		fprintf(stderr,
			"Unrecognized variable size %zu for a signed int\n",
			vc->size);
		return -EINVAL;
	}

	size = strlen(tmp);

	if (buf + size >= buf_end_ptr) {
		fprintf(stderr,
			"Destination buffer not large enough to print signed int\n");
		return -EINVAL;
	}

	strcpy(buf, tmp);

	return size;
}

static int
isochron_printf_unsigned_int(char *buf, const char *buf_end_ptr,
			     const struct isochron_variable_code *vc,
			     const struct isochron_printf_variables *v)
{
	__u64 *var64 = (__u64 *)((char *)v + vc->offset);
	__u32 *var32 = (__u32 *)((char *)v + vc->offset);
	char tmp[30];
	size_t size;

	switch (vc->size) {
	case sizeof(__u64):
		sprintf(tmp, "%llu", *var64);
		break;
	case sizeof(__u32):
		sprintf(tmp, "%u", *var32);
		break;
	default:
		fprintf(stderr,
			"Unrecognized variable size %zu for a signed int\n",
			vc->size);
		return -EINVAL;
	}

	size = strlen(tmp);

	if (buf + size >= buf_end_ptr) {
		fprintf(stderr,
			"Destination buffer not large enough to print unsigned int\n");
		return -EINVAL;
	}

	strcpy(buf, tmp);

	return size;
}

static int
isochron_printf_hex_int(char *buf, const char *buf_end_ptr,
			const struct isochron_variable_code *vc,
			const struct isochron_printf_variables *v)
{
	__u64 *var64 = (__u64 *)((char *)v + vc->offset);
	__u32 *var32 = (__u32 *)((char *)v + vc->offset);
	char tmp[30];
	size_t size;

	switch (vc->size) {
	case sizeof(__u64):
		sprintf(tmp, "%llx", *var64);
		break;
	case sizeof(__u32):
		sprintf(tmp, "%x", *var32);
		break;
	default:
		fprintf(stderr,
			"Unrecognized variable size %zu for a signed int\n",
			vc->size);
		return -EINVAL;
	}

	size = strlen(tmp);

	if (buf + size >= buf_end_ptr) {
		fprintf(stderr,
			"Destination buffer not large enough to print hex int\n");
		return -EINVAL;
	}

	strcpy(buf, tmp);

	return size;
}

static int
isochron_printf_time(char *buf, const char *buf_end_ptr,
		     const struct isochron_variable_code *vc,
		     const struct isochron_printf_variables *v)
{
	__u64 *var64 = (__u64 *)((char *)v + vc->offset);
	char tmp[TIMESPEC_BUFSIZ];

	if (vc->size != sizeof(__s64)) {
		fprintf(stderr, "Unexpected size %zu for a time format\n",
			vc->size);
		return -EINVAL;
	}

	ns_sprintf(tmp, *var64);

	if (buf + strlen(tmp) >= buf_end_ptr) {
		fprintf(stderr,
			"Destination buffer not large enough to print time\n");
		return -EINVAL;
	}

	strcpy(buf, tmp);

	return strlen(tmp);
}

static int
isochron_printf_one_var(char *buf_ptr, const char *buf_end_ptr,
			const struct isochron_printf_variables *v,
			char var_code, char printf_code)
{
	const struct isochron_variable_code *vc = &variable_codes[(__u8 )var_code];

	if (!vc->valid_formats) {
		fprintf(stderr, "Unknown variable code '%c'\n", var_code);
		return -EINVAL;
	}

	switch (printf_code) {
	case 'd':
		if (!(vc->valid_formats & ISOCHRON_FMT_SIGNED)) {
			fprintf(stderr,
				"Variable '%c' cannot be printed as signed int\n",
				var_code);
			return -EINVAL;
		}

		return isochron_printf_signed_int(buf_ptr, buf_end_ptr, vc, v);
	case 'u':
		if (!(vc->valid_formats & ISOCHRON_FMT_UNSIGNED)) {
			fprintf(stderr,
				"Variable '%c' cannot be printed as signed int\n",
				var_code);
			return -EINVAL;
		}

		return isochron_printf_unsigned_int(buf_ptr, buf_end_ptr, vc, v);
	case 'x':
		if (!(vc->valid_formats & ISOCHRON_FMT_HEX)) {
			fprintf(stderr,
				"Variable '%c' cannot be printed as hexadecimal\n",
				var_code);
			return -EINVAL;
		}

		return isochron_printf_hex_int(buf_ptr, buf_end_ptr, vc, v);
	case 'T':
		if (!(vc->valid_formats & ISOCHRON_FMT_TIME)) {
			fprintf(stderr,
				"Variable '%c' cannot be printed as time\n",
				var_code);
			return -EINVAL;
		}

		return isochron_printf_time(buf_ptr, buf_end_ptr, vc, v);
	default:
		fprintf(stderr, "Unknown printf code '%c'\n", printf_code);
		return -EINVAL;
	}
}

static int buf_copy_verbatim(char *dest, const char *dest_end, const char *src,
			     size_t size)
{
	if (dest + size >= dest_end) {
		fprintf(stderr,
			"Buffer not large enough for printf format\n");
		return -EINVAL;
	}

	memcpy(dest, src, size);
	return size;
}

static int
isochron_printf_one_packet(const struct isochron_printf_variables *v,
			   const char *printf_fmt, const char *printf_args)
{
	const char *fmt_end_ptr = printf_fmt + strlen(printf_fmt);
	char buf[ISOCHRON_LOG_PRINTF_BUF_SIZE];
	const char *args_ptr = printf_args;
	const char *fmt_ptr = printf_fmt;
	const char *args_end_ptr;
	char *buf_ptr = buf;
	char *percent, code;
	char *buf_end_ptr;
	int rc;

	buf_end_ptr = buf + ISOCHRON_LOG_PRINTF_BUF_SIZE - 1;
	args_end_ptr = printf_args + strlen(printf_args);

	do {
		percent = strchr(fmt_ptr, '%');
		if (!percent) {
			rc = buf_copy_verbatim(buf_ptr, buf_end_ptr, fmt_ptr,
					       strlen(fmt_ptr));
			if (rc < 0)
				return rc;

			buf_ptr += rc;
		} else {
			if (percent + 1 >= fmt_end_ptr) {
				fprintf(stderr,
					"Illegal percent placement at the end of the printf format\n");
				return -EINVAL;
			}

			code = *(percent + 1);
			/* Escaped %% */
			if (code == '%') {
				/* Copy up to and including the first percent */
				rc = buf_copy_verbatim(buf_ptr, buf_end_ptr, fmt_ptr,
						       percent + 1 - fmt_ptr);
				if (rc < 0)
					return rc;

				buf_ptr += rc;
				/* Jump past both percent signs */
				fmt_ptr = percent + 2;
				continue;
			}

			if (args_ptr >= args_end_ptr) {
				fprintf(stderr,
					"Not enough arguments for format\n");
				return -EINVAL;
			}

			/* First copy verbatim up to the percent sign */
			rc = buf_copy_verbatim(buf_ptr, buf_end_ptr, fmt_ptr,
					       (percent - fmt_ptr));
			if (rc < 0)
				return rc;
			buf_ptr += rc;

			rc = isochron_printf_one_var(buf_ptr, buf_end_ptr,
						     v, *args_ptr, code);
			if (rc < 0)
				return rc;

			/* Advance past what we've just printed */
			buf_ptr += rc;

			/* Jump past the percent and past the code character */
			fmt_ptr = percent + 2;

			/* Consume one argument */
			args_ptr++;
		}
	} while (percent);

	/* Avoid uselessly memsetting the whole buffer to zero,
	 * just make sure it is NULL-terminated
	 */
	*buf_ptr = 0;

	if (args_ptr < args_end_ptr) {
		fprintf(stderr, "printf arguments left unconsumed\n");
		return -EINVAL;
	}

	if (buf[0])
		fputs(buf, stdout);

	return 0;
}

static void isochron_process_stat(const struct isochron_printf_variables *v,
				  struct isochron_stats *stats,
				  bool taprio, bool txtime)
{
	struct isochron_packet_metrics *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->seqid = v->seqid;
	entry->wakeup_to_hw_ts = v->tx_hwts - v->tx_wakeup;
	entry->hw_rx_deadline_delta = v->rx_hwts - v->tx_scheduled;
	/* When tc-taprio or tc-etf offload is enabled, we know that the
	 * MAC TX timestamp will be larger than the gate event, because the
	 * application's schedule should be the same as the NIC's schedule.
	 * The NIC will buffer that packet until the gate opens, something
	 * which does not happen normally. So when we operate on a NIC without
	 * tc-taprio offload, the reported deadline delta will be negative,
	 * i.e. the packet will be received before the deadline expired,
	 * precisely because isochron actually sends the packet in advance of
	 * the deadline.
	 * Avoid printing negative values and interpret this delta as either a
	 * positive "deadline delta" when we have tc-taprio (this should give
	 * us the latency of the hardware), or as a (still positive) latency
	 * budget, i.e. "how much we could still reduce the cycle time without
	 * losing deadlines".
	 */
	if (taprio || txtime)
		entry->latency_budget = v->tx_hwts - v->tx_scheduled;
	else
		entry->latency_budget = v->tx_scheduled - v->tx_hwts;
	entry->path_delay = v->rx_hwts - v->tx_hwts;
	entry->wakeup_latency = v->tx_wakeup -
				(v->tx_scheduled - v->advance_time);
	entry->sender_latency = v->tx_swts - v->tx_wakeup;
	entry->driver_latency = v->tx_swts - v->tx_sched;
	entry->arrival_latency = v->arrival - v->rx_hwts;

	if (v->tx_hwts > v->tx_scheduled)
		stats->hw_tx_deadline_misses++;

	stats->frame_count++;
	stats->tx_sync_offset_mean += v->tx_hwts - v->tx_swts;
	stats->rx_sync_offset_mean += v->rx_hwts - v->rx_swts;
	stats->path_delay_mean += entry->path_delay;

	LIST_INSERT_HEAD(&stats->entries, entry, list);
}

/* For a given metric, iterate through the list of metric structures of each
 * packet and calculate minimum, maximum, average, standard deviation.
 */
static void isochron_metric_compute_stats(const struct isochron_stats *stats,
					  struct isochron_metric_stats *ms,
					  int metric_offset,
					  bool interpret_in_reverse)
{
	struct isochron_packet_metrics *entry;
	double sumsqr = 0;

	ms->seqid_of_max = 1;
	ms->seqid_of_min = 1;
	ms->min = LONG_MAX;
	ms->max = LONG_MIN;
	ms->mean = 0;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *metric = (__s64 *)((char *)entry + metric_offset);
		__s64 val = interpret_in_reverse ? -(*metric) : *metric;

		if (val < ms->min) {
			ms->min = val;
			ms->seqid_of_min = entry->seqid;
		}
		if (val > ms->max) {
			ms->max = val;
			ms->seqid_of_max = entry->seqid;
		}
		ms->mean += val;
	}

	ms->mean /= (double)stats->frame_count;

	LIST_FOREACH(entry, &stats->entries, list) {
		__s64 *metric = (__s64 *)((char *)entry + metric_offset);
		__s64 val = interpret_in_reverse ? -(*metric) : *metric;
		double deviation = (double)val - ms->mean;

		sumsqr += deviation * deviation;
	}

	ms->stddev = sqrt(sumsqr / (double)stats->frame_count);
}

static void isochron_print_metric_stats(const char *name,
					const struct isochron_metric_stats *ms)
{
	printf("%s: min %lld max %lld mean %.3lf stddev %.3lf, "
	       "min at seqid %d, max at seqid %d\n",
	       name, ms->min, ms->max, ms->mean, ms->stddev,
	       ms->seqid_of_min, ms->seqid_of_max);
}

int isochron_print_stats(struct isochron_log *send_log,
			 struct isochron_log *rcv_log,
			 const char *printf_fmt, const char *printf_args,
			 unsigned long start, unsigned long stop, bool summary,
			 bool omit_sync, bool taprio, bool txtime,
			 __s64 base_time, __s64 advance_time, __s64 shift_time,
			 __s64 cycle_time, __s64 window_size)
{
	struct isochron_rcv_pkt_data dummy_rcv_pkt = {};
	struct isochron_metric_stats sender_latency_ms;
	struct isochron_metric_stats wakeup_latency_ms;
	struct isochron_metric_stats driver_latency_ms;
	struct isochron_packet_metrics *entry, *tmp;
	struct isochron_send_pkt_data *pkt_arr;
	struct isochron_stats stats = {0};
	struct isochron_metric_stats ms;
	__u64 not_tx_timestamped = 0;
	__u64 not_received = 0;
	size_t pkt_arr_size;
	__u32 seqid;
	int rc = 0;

	LIST_INIT(&stats.entries);

	pkt_arr = (struct isochron_send_pkt_data *)send_log->buf;
	pkt_arr_size = send_log->size / sizeof(*pkt_arr);

	if (start == 0 || start > pkt_arr_size ||
	    stop == 0 || stop > pkt_arr_size) {
		fprintf(stderr, "Trying to index an out-of-bounds element\n");
		return -ERANGE;
	}

	for (seqid = start; seqid <= stop; seqid++) {
		struct isochron_send_pkt_data *send_pkt = &pkt_arr[seqid - 1];
		struct isochron_rcv_pkt_data *rcv_pkt;
		struct isochron_printf_variables v;
		bool missing = false;

		if (seqid != __be32_to_cpu(send_pkt->seqid))
			/* Incomplete log, send_pkt->seqid is 0, exit */
			break;

		if (!__be64_to_cpu(send_pkt->swts) ||
		    !__be64_to_cpu(send_pkt->sched_ts) ||
		    !__be64_to_cpu(send_pkt->hwts)) {
			not_tx_timestamped++;
			missing = true;
		}

		/* For packets that didn't reach the receiver, at least report
		 * the TX timestamps and seqid for debugging purposes, and use
		 * a dummy received packet with all RX timestamps set to zero
		 */
		rcv_pkt = isochron_rcv_log_find(rcv_log, send_pkt->seqid);
		if (!rcv_pkt) {
			rcv_pkt = &dummy_rcv_pkt;
			missing = true;
			not_received++;
		}

		isochron_printf_vars_get(send_pkt, rcv_pkt, base_time,
					 advance_time, shift_time, cycle_time,
					 window_size, &v);

		rc = isochron_printf_one_packet(&v, printf_fmt, printf_args);
		if (rc)
			goto out;

		if (summary && !missing)
			isochron_process_stat(&v, &stats, taprio, txtime);
	}

	if (!summary)
		return 0;

	if (not_tx_timestamped) {
		printf("Packets not completely TX timestamped: %llu (%.3lf%%)\n",
		       not_tx_timestamped,
		       100.0f * not_tx_timestamped / pkt_arr_size);
	}

	if (not_received) {
		printf("Packets not received: %llu (%.3lf%%)\n", not_received,
		       100.0f * not_received / pkt_arr_size);
	}

	if (!stats.frame_count) {
		printf("Could not calculate statistics, no packets were received\n");
		return 0;
	}

	stats.tx_sync_offset_mean /= stats.frame_count;
	stats.rx_sync_offset_mean /= stats.frame_count;
	stats.path_delay_mean /= stats.frame_count;

	if (llabs((long long)stats.tx_sync_offset_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Sender PHC not synchronized (mean PHC to system time "
		       "diff %.3lf ns larger than 1 second)\n",
		       stats.tx_sync_offset_mean);
	}
	if (llabs((long long)stats.rx_sync_offset_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Receiver PHC not synchronized (mean PHC to system time "
		       "diff %.3lf ns larger than 1 second)\n",
		       stats.rx_sync_offset_mean);
	}
	if (llabs((long long)stats.path_delay_mean) > NSEC_PER_SEC &&
	    !omit_sync) {
		printf("Sender and receiver not synchronized (mean path delay "
		       "%.3lf ns larger than 1 second)\n",
		       stats.path_delay_mean);
	}

	printf("Summary:\n");

	/* Path delay */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       path_delay), false);
	isochron_print_metric_stats("Path delay", &ms);

	/* Wakeup to HW TX timestamp */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       wakeup_to_hw_ts), false);
	isochron_print_metric_stats("Wakeup to HW TX timestamp", &ms);

	/* HW RX deadline delta (TX time to HW RX timestamp) */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       hw_rx_deadline_delta), false);
	if (ms.mean > 0) {
		isochron_print_metric_stats("Packets arrived later than scheduled. TX time to HW RX timestamp",
					    &ms);
	} else {
		isochron_metric_compute_stats(&stats, &ms,
					      offsetof(struct isochron_packet_metrics,
						       hw_rx_deadline_delta), true);
		isochron_print_metric_stats("Packets arrived earlier than scheduled. HW RX timestamp to TX time",
					    &ms);
	}

	/* Latency budget, interpreted differently depending on testing mode */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       latency_budget), false);
	if (taprio || txtime)
		isochron_print_metric_stats("MAC latency", &ms);
	else
		isochron_print_metric_stats("Application latency budget", &ms);

	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       sender_latency), false);
	isochron_print_metric_stats("Sender latency", &ms);
	sender_latency_ms = ms;

	/* Wakeup latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       wakeup_latency), false);
	wakeup_latency_ms = ms;
	isochron_print_metric_stats("Wakeup latency", &ms);

	/* Driver latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       driver_latency), false);
	driver_latency_ms = ms;
	isochron_print_metric_stats("Driver latency", &ms);

	/* Arrival latency */
	isochron_metric_compute_stats(&stats, &ms,
				      offsetof(struct isochron_packet_metrics,
					       arrival_latency), false);
	isochron_print_metric_stats("Arrival latency", &ms);

	printf("Sending one packet takes on average %.3lf%% of the cycle time (min %.3lf%% max %.3lf%%)\n",
	       100.0f * sender_latency_ms.mean / cycle_time,
	       100.0f * sender_latency_ms.min / cycle_time,
	       100.0f * sender_latency_ms.max / cycle_time);
	printf("Waking up takes on average %.3lf%% of the cycle time (min %.3lf%% max %.3lf%%)\n",
	       100.0f * wakeup_latency_ms.mean / cycle_time,
	       100.0f * wakeup_latency_ms.min / cycle_time,
	       100.0f * wakeup_latency_ms.max / cycle_time);
	printf("Driver takes on average %.3lf%% of the cycle time to send a packet (min %.3lf%% max %.3lf%%)\n",
	       100.0f * driver_latency_ms.mean / cycle_time,
	       100.0f * driver_latency_ms.min / cycle_time,
	       100.0f * driver_latency_ms.max / cycle_time);

	/* HW TX deadline misses */
	if (!taprio && !txtime)
		printf("HW TX deadline misses: %d (%.3lf%%)\n",
		       stats.hw_tx_deadline_misses,
		       100.0f * stats.hw_tx_deadline_misses / stats.frame_count);

out:
	LIST_FOREACH_SAFE(entry, &stats.entries, list, tmp) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	return rc;
}

int isochron_log_init(struct isochron_log *log, size_t size)
{
	log->buf = calloc(sizeof(char), size);
	if (!log->buf)
		return -ENOMEM;

	log->size = size;

	return 0;
}

void isochron_log_teardown(struct isochron_log *log)
{
	free(log->buf);
}

int isochron_log_for_each_pkt(struct isochron_log *log, size_t pkt_size,
			      void *priv, isochron_log_walk_cb_t cb)
{
	size_t i, pkt_arr_size = log->size / pkt_size;
	int rc;

	for (i = 0; i < pkt_arr_size; i++) {
		void *pkt = (void *)((__u8 *)log->buf + i * pkt_size);

		rc = cb(priv, pkt);
		if (rc)
			return rc;
	}

	return 0;
}

int isochron_log_load(const char *file, struct isochron_log *send_log,
		      struct isochron_log *rcv_log, long *packet_count,
		      long *frame_size, bool *omit_sync, bool *do_ts,
		      bool *taprio, bool *txtime, bool *deadline,
		      __s64 *base_time, __s64 *advance_time, __s64 *shift_time,
		      __s64 *cycle_time, __s64 *window_size)
{
	struct isochron_log_file_header header;
	size_t len;
	int fd, rc;
	int flags;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open file %s: %m\n", file);
		rc = fd;
		goto out;
	}

	len = read_exact(fd, &header, sizeof(header));
	if (len <= 0) {
		perror("Failed to read log header from file");
		rc = len;
		goto out_close;
	}

	if (memcmp(header.magic, isochron_magic, strlen(isochron_magic))) {
		fprintf(stderr, "Unrecognized file format\n");
		rc = -EINVAL;
		goto out_close;
	}

	flags = __be16_to_cpu(header.flags);
	*omit_sync = !!(flags & ISOCHRON_FLAG_OMIT_SYNC);
	*do_ts = !!(flags & ISOCHRON_FLAG_DO_TS);
	*taprio = !!(flags & ISOCHRON_FLAG_TAPRIO);
	*txtime = !!(flags & ISOCHRON_FLAG_TXTIME);
	*deadline = !!(flags & ISOCHRON_FLAG_DEADLINE);

	*packet_count = __be32_to_cpu(header.packet_count);
	*frame_size = __be16_to_cpu(header.frame_size);
	*base_time = (__s64 )__be64_to_cpu(header.base_time);
	*advance_time = (__s64 )__be64_to_cpu(header.advance_time);
	*shift_time = (__s64 )__be64_to_cpu(header.shift_time);
	*cycle_time = (__s64 )__be64_to_cpu(header.cycle_time);
	*window_size = (__s64 )__be64_to_cpu(header.window_size);

	if (lseek(fd, __be64_to_cpu(header.send_log_start), SEEK_SET) < 0) {
		perror("Failed to seek to the sender log");
		rc = -errno;
		goto out_close;
	}

	rc = isochron_log_init(send_log, __be32_to_cpu(header.send_log_size));
	if (rc) {
		fprintf(stderr, "failed to allocate memory for send log\n");
		goto out_close;
	}

	len = read_exact(fd, send_log->buf, send_log->size);
	if (len <= 0) {
		perror("Failed to read sender log");
		rc = len;
		goto out_send_log_teardown;
	}

	if (lseek(fd, __be64_to_cpu(header.rcv_log_start), SEEK_SET) < 0) {
		perror("Failed to seek to the receiver log");
		rc = -errno;
		goto out_send_log_teardown;
	}

	rc = isochron_log_init(rcv_log, __be32_to_cpu(header.rcv_log_size));
	if (rc) {
		fprintf(stderr, "failed to allocate memory for rcv log\n");
		goto out_send_log_teardown;
	}

	len = read_exact(fd, rcv_log->buf, rcv_log->size);
	if (len <= 0) {
		perror("Failed to read receiver log");
		rc = len;
		goto out_rcv_log_teardown;
	}

	close(fd);

	return 0;

out_rcv_log_teardown:
	isochron_log_teardown(rcv_log);
out_send_log_teardown:
	isochron_log_teardown(send_log);
out_close:
	close(fd);
out:
	return rc;
}

int isochron_log_save(const char *file, const struct isochron_log *send_log,
		      const struct isochron_log *rcv_log, long packet_count,
		      long frame_size, bool omit_sync, bool do_ts, bool taprio,
		      bool txtime, bool deadline, __s64 base_time,
		      __s64 advance_time, __s64 shift_time, __s64 cycle_time,
		      __s64 window_size)
{
	struct isochron_log_file_header header = {
		.version	= __cpu_to_be32(ISOCHRON_LOG_VERSION),
		.packet_count	= __cpu_to_be32(packet_count),
		.frame_size	= __cpu_to_be16(frame_size),
		.base_time	= __cpu_to_be64(base_time),
		.advance_time	= __cpu_to_be64(advance_time),
		.shift_time	= __cpu_to_be64(shift_time),
		.cycle_time	= __cpu_to_be64(cycle_time),
		.window_size	= __cpu_to_be64(window_size),
	};
	int flags = 0;
	size_t len;
	int fd;

	if (omit_sync)
		flags |= ISOCHRON_FLAG_OMIT_SYNC;
	if (do_ts)
		flags |= ISOCHRON_FLAG_DO_TS;
	if (taprio)
		flags |= ISOCHRON_FLAG_TAPRIO;
	if (txtime)
		flags |= ISOCHRON_FLAG_TXTIME;
	if (deadline)
		flags |= ISOCHRON_FLAG_DEADLINE;

	memcpy(header.magic, isochron_magic, strlen(isochron_magic));
	header.flags = __cpu_to_be16(flags);
	header.send_log_start = __cpu_to_be64(sizeof(header));
	header.send_log_size = __cpu_to_be32(send_log->size);
	header.rcv_log_start = __cpu_to_be64(sizeof(header) + send_log->size);
	header.rcv_log_size = __cpu_to_be32(rcv_log->size);

	fd = open(file, O_CREAT | O_WRONLY | O_TRUNC, FILEMODE);
	if (fd < 0) {
		perror("open");
		return fd;
	}

	len = write_exact(fd, &header, sizeof(header));
	if (len <= 0) {
		perror("Failed to write log header to file");
		close(fd);
		return len;
	}

	len = write_exact(fd, send_log->buf, send_log->size);
	if (len <= 0) {
		perror("Failed to write send log to file");
		close(fd);
		return len;
	}

	len = write_exact(fd, rcv_log->buf, rcv_log->size);
	if (len <= 0) {
		perror("Failed to write receive log to file");
		close(fd);
		return len;
	}

	close(fd);

	return 0;
}
