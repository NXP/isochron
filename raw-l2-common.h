/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019 NXP Semiconductors */
/* This file contains code snippets from:
 * - libnfnetlink.h
 * - The Linux kernel
 * - The linuxptp project
 */
#ifndef _COMMON_H
#define _COMMON_H

#define NSEC_PER_SEC	1000000000LL
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/

#define TIMESPEC_BUFSIZ	32
#define MACADDR_BUFSIZ	32

#define TXTSTAMP_TIMEOUT_MS	10

/* From include/uapi/linux/net_tstamp.h */
#ifndef SOF_TIMESTAMPING_OPT_TX_SWHW
#define SOF_TIMESTAMPING_OPT_TX_SWHW	(1<<14)
#endif

typedef _Bool		bool;
enum {
	false	= 0,
	true	= 1
};

#define ARRAY_SIZE(array) \
	(sizeof(array) / sizeof(*array))

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
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	(x)
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
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

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator / Drop Eligible Indicator */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_N_VID		4096

enum prog_arg_type {
	PROG_ARG_MAC_ADDR,
	PROG_ARG_LONG,
	PROG_ARG_TIME,
	PROG_ARG_STRING,
	PROG_ARG_BOOL,
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
	char *buf;
};

struct prog_arg_boolean {
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
	};
};

int prog_parse_np_args(int argc, char **argv,
		       struct prog_arg *prog_args,
		       int prog_args_size);
void prog_usage(char *prog_name, struct prog_arg *prog_args,
		int prog_args_size);

struct app_header {
	__s64			tx_time;
	short			seqid;
};

struct timestamp {
	struct timespec		hw;
	struct timespec		sw;
};

int mac_addr_from_string(__u8 *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, int on);
int sk_receive(int fd, void *buf, int buflen, struct timestamp *tstamp,
	       int flags, int timeout);
__s64 timespec_to_ns(const struct timespec *ts);
struct timespec ns_to_timespec(__s64 ns);
void mac_addr_sprintf(char *buf, __u8 *addr);
void ns_sprintf(char *buf, __s64 ns);

#endif
