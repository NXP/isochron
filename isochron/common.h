/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - libnfnetlink.h
 * - The Linux kernel
 * - The linuxptp project
 */
#ifndef _COMMON_H
#define _COMMON_H

#include <arpa/inet.h>
#include <linux/types.h>
#include <netinet/ether.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "ptpmon.h"

#define PTPMON_TIMEOUT_MS	10

struct sched_attr {
	__u32 size;		/* Size of this structure */
	__u32 sched_policy;	/* Policy (SCHED_*) */
	__u64 sched_flags;	/* Flags */
	__s32 sched_nice;	/* Nice value (SCHED_OTHER,
				   SCHED_BATCH) */
	__u32 sched_priority;	/* Static priority (SCHED_FIFO,
				   SCHED_RR) */
	/* Remaining fields are for SCHED_DEADLINE */
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
};

static inline int sched_setattr(pid_t pid, const struct sched_attr *attr,
				unsigned int flags)
{
	return syscall(SYS_sched_setattr, pid, attr, flags);
}

#ifndef SO_TXTIME
#define SO_TXTIME		61
#define SCM_TXTIME		SO_TXTIME

struct sock_txtime {
	clockid_t clockid;
	uint16_t flags;
};

enum txtime_flags {
	SOF_TXTIME_DEADLINE_MODE = (1 << 0),
	SOF_TXTIME_REPORT_ERRORS = (1 << 1),

	SOF_TXTIME_FLAGS_LAST = SOF_TXTIME_REPORT_ERRORS,
	SOF_TXTIME_FLAGS_MASK = (SOF_TXTIME_FLAGS_LAST - 1) |
				 SOF_TXTIME_FLAGS_LAST
};
#endif

#ifndef PACKET_TX_TIMESTAMP
#define PACKET_TX_TIMESTAMP		16
#endif

#ifndef SO_EE_ORIGIN_TXTIME
#define SO_EE_ORIGIN_TXTIME		6
#define SO_EE_CODE_TXTIME_INVALID_PARAM	1
#define SO_EE_CODE_TXTIME_MISSED	2
#endif

struct isochron_header {
	__s64			tx_time;
	__s64			wakeup;
	__u32			seqid;
}  __attribute__((packed));

#define NSEC_PER_SEC	1000000000LL
#define ETH_P_ISOCHRON	0xdead

#define TIMESPEC_BUFSIZ	32
#define MACADDR_BUFSIZ	32

#define TXTSTAMP_TIMEOUT_MS	10

/* From include/uapi/linux/net_tstamp.h */
#ifndef HAVE_TX_SWHW
enum {
	SOF_TIMESTAMPING_OPT_TX_SWHW = (1<<14),
};
#endif

#define ARRAY_SIZE(array) \
	(sizeof(array) / sizeof(*array))

#ifndef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

/* Copied from libnfnetlink.h */

/* Pablo: What is the equivalence of be64_to_cpu in userspace?
 *
 * Harald: Good question.  I don't think there's a standard way [yet?],
 * so I'd suggest manually implementing it by "#if little endian" bitshift
 * operations in C (at least for now).
 *
 * All the payload of any nfattr will always be in network byte order.
 * This would allow easy transport over a real network in the future
 * (e.g. jamal's netlink2).
 *
 * Pablo: I've called it __be64_to_cpu instead of be64_to_cpu, since maybe
 * there will one in the userspace headers someday. We don't want to
 * pollute POSIX space naming,
 */
#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#  ifndef __be32_to_cpu
#  define __be32_to_cpu(x)	(x)
#  endif
#  ifndef __cpu_to_be32
#  define __cpu_to_be32(x)	(x)
#  endif
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	(x)
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef __be32_to_cpu
#  define __be32_to_cpu(x)	__bswap_32(x)
#  endif
#  ifndef __cpu_to_be32
#  define __cpu_to_be32(x)	__bswap_32(x)
#  endif
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	__bswap_64(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	__bswap_64(x)
#  endif
# endif
#endif

/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

struct isochron_log {
	__u32		buf_len;
	char		*buf;
};

int isochron_log_init(struct isochron_log *log, size_t size);
void isochron_log_data(struct isochron_log *log, void *data, int len);
int isochron_log_xmit(struct isochron_log *log, int fd);
int isochron_log_recv(struct isochron_log *log, int fd);
void isochron_log_teardown(struct isochron_log *log);
void isochron_rcv_log_print(struct isochron_log *log);
void isochron_send_log_print(struct isochron_log *log);
void isochron_log_remove(struct isochron_log *log, void *p, int len);

enum isochron_management_id {
	ISOCHRON_MID_LOG,
};

enum isochron_management_action {
	ISOCHRON_GET = 0,
	ISOCHRON_SET,
	ISOCHRON_RESPONSE,
};

enum isochron_tlv_type {
	ISOCHRON_TLV_MANAGEMENT = 0,
};

struct isochron_management_message {
	__u8		version;
	__u8		action;
	__be16		reserved;
	__be32		payload_length;
	/* TLVs follow */
} __attribute((packed));

struct isochron_tlv {
	__be16		tlv_type;
	__be16		management_id;
	__be32		length_field;
} __attribute((packed));

#define ISOCHRON_STATS_PORT	5000 /* TCP */
#define ISOCHRON_DATA_PORT	6000 /* UDP */
#define ISOCHRON_LOG_VERSION	1
#define ISOCHRON_MANAGEMENT_VERSION 2

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator / Drop Eligible Indicator */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_N_VID		4096

struct ip_address {
	int family;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

enum prog_arg_type {
	PROG_ARG_MAC_ADDR,
	PROG_ARG_LONG,
	PROG_ARG_TIME,
	PROG_ARG_STRING,
	PROG_ARG_BOOL,
	PROG_ARG_IP,
	PROG_ARG_HELP,
};

struct prog_arg_string {
	char *buf;
	int size;
};

struct prog_arg_time {
	clockid_t clkid;
	__s64 *ns;
};

struct prog_arg_long {
	long *ptr;
};

struct prog_arg_mac_addr {
	unsigned char *buf;
};

struct prog_arg_boolean {
	bool *ptr;
};

struct prog_arg_ip {
	struct ip_address *ptr;
};

struct prog_arg_help {
	bool *ptr;
};

struct prog_arg {
	const char *short_opt;
	const char *long_opt;
	bool optional;
	enum prog_arg_type type;
	union {
		struct prog_arg_string string;
		struct prog_arg_time time;
		struct prog_arg_long long_ptr;
		struct prog_arg_mac_addr mac;
		struct prog_arg_boolean boolean_ptr;
		struct prog_arg_ip ip_ptr;
		struct prog_arg_help help_ptr;
	};
};

int prog_parse_np_args(int argc, char **argv,
		       struct prog_arg *prog_args,
		       int prog_args_size);
void prog_usage(const char *prog_name, struct prog_arg *prog_args,
		int prog_args_size);

struct isochron_timestamp {
	struct timespec		hw;
	struct timespec		sw;
};

struct isochron_send_pkt_data {
	__s64 tx_time;
	__s64 wakeup;
	__s64 hwts;
	__s64 swts;
	__u32 seqid;
};

struct isochron_rcv_pkt_data {
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
	__s64 tx_time;
	__s64 arrival;
	__s64 hwts;
	__s64 swts;
	__u16 etype;
	__u32 seqid;
};

struct isochron_stat_entry {
	LIST_ENTRY(isochron_stat_entry) list;
	__s64 wakeup_to_hw_ts;
	__s64 hw_rx_deadline_delta;
	__s64 latency_budget;
	__s64 path_delay;
	__s64 wakeup_latency;
	__s64 arrival_latency;
	__u32 seqid;
};

struct isochron_stats {
	LIST_HEAD(stats_head, isochron_stat_entry) entries;
	int frame_count;
	int hw_tx_deadline_misses;
	double tx_sync_offset_mean;
	double rx_sync_offset_mean;
	double path_delay_mean;
};

ssize_t recv_exact(int sockfd, void *buf, size_t len, int flags);
ssize_t write_exact(int fd, const void *buf, size_t count);

int mac_addr_from_string(unsigned char *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, bool on);
int sk_receive(int fd, void *buf, int buflen, struct isochron_timestamp *tstamp,
	       int flags, int timeout);
__s64 timespec_to_ns(const struct timespec *ts);
struct timespec ns_to_timespec(__s64 ns);
void mac_addr_sprintf(char *buf, unsigned char *addr);
void ns_sprintf(char *buf, __s64 ns);

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline __u64 ether_addr_to_u64(const unsigned char *addr)
{
	__u64 u = 0;
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		u = u << 8 | addr[i];

	return u;
}

/**
 * ether_addr_copy - Copy an Ethernet address
 * @dst: Pointer to a six-byte array Ethernet address destination
 * @src: Pointer to a six-byte array Ethernet address source
 *
 * Please note: dst & src must both be aligned to u16.
 */
static inline void ether_addr_copy(unsigned char *dst, const unsigned char *src)
{
	*(__u32 *)dst = *(const __u32 *)src;
	*(__u16 *)(dst + 4) = *(const __u16 *)(src + 4);
}

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_zero_ether_addr(const unsigned char *addr)
{
	return ((*(const __u32 *)addr) | (*(const __u16 *)(addr + 4))) == 0;
}

int trace_mark_open();
void trace_mark_close(int fd);

int set_utc_tai_offset(int offset);
int get_utc_tai_offset();

static inline __s64 utc_to_tai(__s64 utc, __s64 offset)
{
	return utc + offset * NSEC_PER_SEC;
}

int get_time_from_string(clockid_t clkid, __s64 *to, char *from);

static inline __s64
master_offset_from_current_ds(const struct current_ds *current_ds)
{
	return (__s64 )(__be64_to_cpu(current_ds->offset_from_master)) >> 16;
}

#endif
