// SPDX-License-Identifier: GPL-3.0+
#ifndef _COMMON_H
#define _COMMON_H

#define _GNU_SOURCE
#include <linux/sched.h>
#include <sys/types.h>
#include <stdint.h>
#define NSEC_PER_SEC	1000000000ULL
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/
#define TIMESPEC_BUFSIZ	32
#define MACADDR_BUFSIZ	32

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
typedef uint8_t		u8;

int sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags);

int mac_addr_from_string(u8 *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, int on);
int sk_receive(int fd, void *buf, int buflen, struct timespec *hwts, int flags);
u64 timespec_to_ns(const struct timespec *ts);
struct timespec ns_to_timespec(u64 ns);
void mac_addr_sprintf(char *buf, u8 *addr);
void ns_sprintf(char *buf, u64 ns);

#endif
