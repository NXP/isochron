// SPDX-License-Identifier: GPL-3.0+

#include <netinet/ether.h>
#include <stdint.h>
#include <errno.h>

int mac_addr_from_string(uint8_t *to, char *from)
{
	unsigned long byte;
	char *p = from;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		byte = strtoul(p, &p, 16);
		to[i] = (uint8_t )byte;
		if (i == (ETH_ALEN - 1) && *p != 0)
			/* 6 bytes processed but more are present */
			return -EFBIG;
		else if (i != (ETH_ALEN - 1) && *p == ':')
			p++;
	}

	return 0;
}
