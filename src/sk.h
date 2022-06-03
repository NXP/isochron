/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _ISOCHRON_SK_H
#define _ISOCHRON_SK_H

#include <stdbool.h>
#include "argparser.h"

struct isochron_timestamp {
	struct timespec hw;
	struct timespec sw;
	struct timespec sched;
	struct timespec txtime;
	__u32 tskey;
	__u32 tstype;
};

struct sk;
struct sk_msg;

/* Connection-oriented */
int sk_listen_tcp(const struct ip_address *ip, int port, int backlog,
		  struct sk **listen_sock);
int sk_accept(const struct sk *listen_sock, struct sk **sock);
int sk_connect_tcp(const struct ip_address *ip, int port, struct sk **sock);
ssize_t sk_recv(const struct sk *sock, void *buf, size_t len, int flags);
ssize_t sk_send(const struct sk *sock, const void *buf, size_t count);

/* Connection-less */
int sk_udp(const struct ip_address *dest, int port, struct sk **sock);
int sk_bind_udp(const struct ip_address *dest, int port, struct sk **sock);
int sk_bind_l2(const unsigned char addr[ETH_ALEN], __u16 ethertype,
	       const char *if_name, struct sk **sock);
struct sk_msg *sk_msg_create(const struct sk *sock, void *buf, size_t len,
			     size_t cmsg_len);
void sk_msg_destroy(struct sk_msg *msg);
struct cmsghdr *sk_msg_add_cmsg(struct sk_msg *msg, int level, int type,
				size_t len);
int sk_sendmsg(struct sk *sock, const struct sk_msg *msg, int flags);
int sk_recvmsg(struct sk *sock, void *buf, int buflen,
	       struct isochron_timestamp *tstamp, int flags, int timeout);
int sk_timestamping_init(struct sk *sock, const char *if_name, bool on);
int sk_recvmsg(struct sk *sock, void *buf, int buflen,
	       struct isochron_timestamp *tstamp, int flags, int timeout);

/* Common */
void sk_close(struct sk *sock);
int sk_fd(const struct sk *sock);

/* Others */
int sk_validate_ts_info(const char *if_name);

#endif
