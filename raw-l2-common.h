// SPDX-License-Identifier: GPL-3.0+
#ifndef _COMMON_H
#define _COMMON_H

#define _GNU_SOURCE
#include <linux/sched.h>
#include <sys/types.h>
#include <stdint.h>
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

struct sched_attr {
	uint32_t size;

	uint32_t sched_policy;
	uint64_t sched_flags;

	/* SCHED_NORMAL, SCHED_BATCH */
	int32_t sched_nice;

	/* SCHED_FIFO, SCHED_RR */
	uint32_t sched_priority;

	/* SCHED_DEADLINE (nsec) */
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;
};

typedef uint64_t	u64;
typedef int64_t		s64;
typedef uint32_t	u32;
typedef int32_t		s32;
typedef uint8_t		u8;

int sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags);

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

enum prog_arg_type {
	PROG_ARG_MAC_ADDR,
	PROG_ARG_LONG,
	PROG_ARG_TIME,
	PROG_ARG_STRING,
};

struct prog_arg_string {
	char *buf;
	int size;
};

struct prog_arg_time {
	clockid_t clkid;
	s64 *ns;
};

struct prog_arg_long {
	long int *ptr;
};

struct prog_arg_mac_addr {
	char *buf;
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
	};
};

int prog_parse_np_args(int argc, char **argv,
		       struct prog_arg *prog_args,
		       int prog_args_size);
void prog_usage(char *prog_name, struct prog_arg *prog_args,
		int prog_args_size);

struct app_header {
	s64			tx_time;
	short			seqid;
};

struct timestamp {
	struct timespec		hw;
	struct timespec		sw;
	s64			tx_time;
	short			seqid;
};

int mac_addr_from_string(u8 *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, int on);
int sk_receive(int fd, void *buf, int buflen, struct timestamp *tstamp,
	       int flags, int timeout);
s64 timespec_to_ns(const struct timespec *ts);
struct timespec ns_to_timespec(s64 ns);
void mac_addr_sprintf(char *buf, u8 *addr);
void ns_sprintf(char *buf, s64 ns);

#endif
