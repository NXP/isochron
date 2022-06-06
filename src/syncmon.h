/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _ISOCHRON_SYNCMON_H
#define _ISOCHRON_SYNCMON_H

#include <libmnl/libmnl.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#include "ptpmon.h"
#include "sk.h"
#include "sysmon.h"

struct syncmon;
struct syncmon_node;

typedef bool syncmon_stop_fn_t(void *priv);

struct syncmon *syncmon_create(void);
void syncmon_destroy(struct syncmon *syncmon);
void syncmon_init(struct syncmon *syncmon);
int syncmon_wait_until_ok(struct syncmon *syncmon);
bool syncmon_monitor(struct syncmon *syncmon, syncmon_stop_fn_t stop, void *priv);

struct syncmon_node *
syncmon_add_local_sender_no_sync(struct syncmon *syncmon, const char *name,
				 struct mnl_socket *rtnl, const char *if_name,
				 size_t num_pkts, __s64 cycle_time);
struct syncmon_node *syncmon_add_local_sender(struct syncmon *syncmon,
					      const char *name,
					      struct mnl_socket *rtnl,
					      const char *if_name,
					      size_t num_pkts, __s64 cycle_time,
					      struct ptpmon *ptpmon,
					      struct sysmon *sysmon,
					      __s64 sync_threshold);
struct syncmon_node *
syncmon_add_remote_sender_no_sync(struct syncmon *syncmon, const char *name,
				  struct sk *mgmt_sock, size_t num_pkts,
				  __s64 cycle_time);
struct syncmon_node *syncmon_add_remote_sender(struct syncmon *syncmon,
					       const char *name,
					       struct sk *mgmt_sock,
					       size_t num_pkts,
					       __s64 cycle_time,
					       __s64 sync_threshold);
struct syncmon_node *
syncmon_add_remote_receiver_no_sync(struct syncmon *syncmon, const char *name,
				    struct sk *mgmt_sock,
				    struct syncmon_node *pair);
struct syncmon_node *syncmon_add_remote_receiver(struct syncmon *syncmon,
						 const char *name,
						 struct sk *mgmt_sock,
						 struct syncmon_node *pair,
						 __s64 sync_threshold);

#endif
