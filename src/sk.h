/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _ISOCHRON_SK_H
#define _ISOCHRON_SK_H

#include <stdbool.h>
#include "argparser.h"

struct sk;

/* Connection-oriented */
int sk_listen_tcp_any(int port, int backlog, struct sk **listen_sock);
int sk_accept(const struct sk *listen_sock, struct sk **sock);
int sk_connect_tcp(const struct ip_address *ip, int port, struct sk **sock);
ssize_t sk_recv(const struct sk *sock, void *buf, size_t len, int flags);
ssize_t sk_send(const struct sk *sock, const void *buf, size_t count);

/* Common */
void sk_close(struct sk *sock);
int sk_fd(const struct sk *sock);

#endif
