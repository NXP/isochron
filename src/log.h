/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019-2021 NXP */
#ifndef _ISOCHRON_LOG_H
#define _ISOCHRON_LOG_H

#include <linux/types.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <sys/types.h>
#include "sk.h"

#define ISOCHRON_LOG_PRINTF_MAX_NUM_ARGS		256
#define ISOCHRON_LOG_PRINTF_BUF_SIZE			4096

struct isochron_send_pkt_data {
	__be32 seqid;
	__be32 reserved;
	__be64 scheduled;
	__be64 wakeup;
	__be64 hwts;
	__be64 swts;
	__be64 sched_ts;
} __attribute((packed));

struct isochron_rcv_pkt_data {
	__be32 seqid;
	__be32 reserved;
	__be64 arrival;
	__be64 hwts;
	__be64 swts;
} __attribute((packed));

struct isochron_log {
	size_t		size;
	char		*buf;
};

int isochron_log_init(struct isochron_log *log, size_t size);
void *isochron_log_get_entry(struct isochron_log *log, size_t entry_size,
			     int index);
int isochron_log_xmit(struct isochron_log *log, struct sk *sock);
int isochron_log_recv(struct isochron_log *log, struct sk *sock);
void isochron_log_teardown(struct isochron_log *log);
void isochron_rcv_log_print(struct isochron_log *log);
void isochron_send_log_print(struct isochron_log *log);

typedef int isochron_log_walk_cb_t(void *priv, void *pkt);
int isochron_log_for_each_pkt(struct isochron_log *log, size_t pkt_size,
			      void *priv, isochron_log_walk_cb_t cb);

int isochron_log_send_pkt(struct isochron_log *log,
			  const struct isochron_send_pkt_data *send_pkt);
int isochron_log_rcv_pkt(struct isochron_log *log,
			 const struct isochron_rcv_pkt_data *rcv_pkt);

int isochron_print_stats(struct isochron_log *send_log,
			 struct isochron_log *rcv_log,
			 const char *printf_fmt, const char *printf_args,
			 unsigned long start, unsigned long stop, bool summary,
			 bool omit_sync, bool taprio, bool txtime,
			 __s64 base_time, __s64 advance_time, __s64 shift_time,
			 __s64 cycle_time, __s64 window_size);

size_t isochron_log_buf_tlv_size(struct isochron_log *log);

int isochron_log_load(const char *file, struct isochron_log *send_log,
		      struct isochron_log *rcv_log, long *packet_count,
		      long *frame_size, bool *omit_sync, bool *do_ts,
		      bool *taprio, bool *txtime, bool *deadline,
		      __s64 *base_time, __s64 *advance_time, __s64 *shift_time,
		      __s64 *cycle_time, __s64 *window_size);

int isochron_log_save(const char *file, const struct isochron_log *send_log,
		      const struct isochron_log *rcv_log, long packet_count,
		      long frame_size, bool omit_sync, bool do_ts, bool taprio,
		      bool txtime, bool deadline, __s64 base_time,
		      __s64 advance_time, __s64 shift_time, __s64 cycle_time,
		      __s64 window_size);

#endif
