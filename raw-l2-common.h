// SPDX-License-Identifier: GPL-3.0+
#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>
#define ETH_P_TSN	0x22F0		/* TSN (IEEE 1722) packet	*/

int mac_addr_from_string(uint8_t *to, char *from);
int sk_timestamping_init(int fd, const char *if_name, int on);
int sk_receive(int fd, void *buf, int buflen, struct timespec *hwts, int flags);

#endif
