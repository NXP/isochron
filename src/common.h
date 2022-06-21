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
#include <libmnl/libmnl.h>
#include <linux/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "endian.h"
#include "ptpmon.h"

#define min(a,b) \
({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; \
})

#define max(a,b) \
({ \
	__typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a > _b ? _a : _b; \
})

#define BIT(nr)			(1UL << (nr))

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
	__be64			scheduled;
	__be64			wakeup;
	__be32			seqid;
}  __attribute__((packed));

#define NSEC_PER_SEC	1000000000LL
#define MSEC_PER_SEC	1000L
#define ETH_P_ISOCHRON	0xdead

/* Error margin for all that is unknown or uncalculable */
#define TIME_MARGIN	(NSEC_PER_SEC / 2)

#define TIMESPEC_BUFSIZ	22
#define MACADDR_BUFSIZ	18

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

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator / Drop Eligible Indicator */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_N_VID		4096

ssize_t read_exact(int fd, void *buf, size_t count);
ssize_t write_exact(int fd, const void *buf, size_t count);

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

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
static inline bool is_multicast_ether_addr(const unsigned char *addr)
{
	return addr[0] & 0x01;
}

/**
 * ether_addr_equal - Compare two Ethernet addresses
 * @a: Pointer to a six-byte array containing the Ethernet address
 * @b: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two Ethernet addresses, returns true if equal
 *
 * Please note: a & b must both be aligned to u16.
 */
static inline bool ether_addr_equal(const unsigned char *a,
				    const unsigned char *b)
{
	__u32 fold = ((*(const __u32 *)a) ^ (*(const __u32 *)b)) |
		     ((*(const __u16 *)(a + 4)) ^ (*(const __u16 *)(b + 4)));

	return fold == 0;
}

int trace_mark_open(void);
void trace_mark_close(int fd);

int set_utc_tai_offset(int offset);
int get_utc_tai_offset(void);
void isochron_fixup_kernel_utc_offset(int ptp_utc_offset);

static inline __s64 utc_to_tai(__s64 utc, __s64 offset)
{
	return utc + offset * NSEC_PER_SEC;
}

static inline __s64
master_offset_from_current_ds(const struct current_ds *current_ds)
{
	return (__s64 )(__be64_to_cpu(current_ds->offset_from_master)) >> 16;
}

int ptpmon_query_port_state_by_name(struct ptpmon *ptpmon, const char *iface,
				    struct mnl_socket *rtnl,
				    enum port_state *port_state);

void pr_err(int rc, const char *fmt, ...);

/* Calculate the first base_time in the future that satisfies this
 * relationship:
 *
 * future_base_time = base_time + N x cycle_time >= now, or
 *
 *      now - base_time
 * N >= ---------------
 *         cycle_time
 */
static inline __s64 future_base_time(__s64 base_time, __s64 cycle_time, __s64 now)
{
	__s64 n;

	if (base_time >= now)
		return base_time;

	n = (now - base_time) / cycle_time;

	return base_time + (n + 1) * cycle_time;
}

int if_name_copy(char dest[IFNAMSIZ], const char src[IFNAMSIZ]);
int uds_copy(char dest[UNIX_PATH_MAX], const char src[UNIX_PATH_MAX]);

#endif
