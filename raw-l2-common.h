// SPDX-License-Identifier: GPL-3.0+
#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>
#define NSEC_PER_SEC	1000000000ULL
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/
#define TIMESPEC_BUFSIZ	32
#define MACADDR_BUFSIZ	32

typedef uint64_t	u64;
typedef int64_t		s64;
typedef uint8_t		u8;

int mac_addr_from_string(u8 *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, int on);
int sk_receive(int fd, void *buf, int buflen, struct timespec *hwts, int flags);
u64 timespec_to_ns(const struct timespec *ts);
struct timespec ns_to_timespec(u64 ns);
void mac_addr_sprintf(char *buf, u8 *addr);
void ns_sprintf(char *buf, u64 ns);

#endif
