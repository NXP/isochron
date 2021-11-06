/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019-2021 NXP */
#ifndef _ISOCHRON_LOG_H
#define _ISOCHRON_LOG_H

#include <linux/types.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/types.h>

struct isochron_send_pkt_data {
	__be64 tx_time;
	__be64 wakeup;
	__be64 hwts;
	__be64 swts;
	__be32 seqid;
};

struct isochron_rcv_pkt_data {
	unsigned char smac[ETH_ALEN];
	unsigned char dmac[ETH_ALEN];
	__be64 tx_time;
	__be64 arrival;
	__be64 hwts;
	__be64 swts;
	__be16 etype;
	__be32 seqid;
};

struct isochron_log {
	size_t		size;
	char		*buf;
};

int isochron_log_init(struct isochron_log *log, size_t size);
void *isochron_log_get_entry(struct isochron_log *log, size_t entry_size,
			     int index);
int isochron_log_xmit(struct isochron_log *log, int fd);
int isochron_log_recv(struct isochron_log *log, int fd);
void isochron_log_teardown(struct isochron_log *log);
void isochron_rcv_log_print(struct isochron_log *log);
void isochron_send_log_print(struct isochron_log *log);

int isochron_log_send_pkt(struct isochron_log *log,
			  const struct isochron_send_pkt_data *send_pkt);
int isochron_log_rcv_pkt(struct isochron_log *log,
			 const struct isochron_rcv_pkt_data *rcv_pkt);

void isochron_print_stats(struct isochron_log *send_log,
			  struct isochron_log *rcv_log,
			  bool omit_sync, bool quiet, bool taprio, bool txtime,
			  __s64 cycle_time, __s64 advance_time);

size_t isochron_log_buf_tlv_size(struct isochron_log *log);

#endif
