/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _ISOCHRON_SEND_H
#define _ISOCHRON_SEND_H

#include <pthread.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <linux/un.h>

#include "log.h"
#include "ptpmon.h"
#include "syncmon.h"
#include "sysmon.h"

#define BUF_SIZ		10000

struct isochron_send {
	volatile bool send_tid_should_stop;
	volatile bool send_tid_stopped;
	volatile bool tx_tstamp_tid_stopped;
	unsigned char dest_mac[ETH_ALEN];
	unsigned char src_mac[ETH_ALEN];
	char if_name[IFNAMSIZ];
	char uds_remote[UNIX_PATH_MAX];
	__u8 sendbuf[BUF_SIZ];
	struct ptpmon *ptpmon;
	struct sysmon *sysmon;
	struct mnl_socket *rtnl;
	enum port_link_state link_state;
	enum port_state last_local_port_state;
	enum port_state last_remote_port_state;
	struct cmsghdr *txtime_cmsg;
	struct sk_msg *msg;
	struct sk_addr *sa;
	struct ip_address stats_srv;
	struct isochron_log log;
	unsigned long timestamped;
	unsigned long iterations;
	clockid_t clkid;
	__s64 session_start;
	__s64 advance_time;
	__s64 shift_time;
	__s64 cycle_time;
	__s64 base_time;
	__s64 oper_base_time;
	__s64 window_size;
	long priority;
	long tx_len;
	struct sk *data_sock;
	struct sk *mgmt_sock;
	long vid;
	bool do_ts;
	bool quiet;
	long etype;
	bool omit_sync;
	bool omit_remote_sync;
	bool trace_mark;
	int trace_mark_fd;
	char tracebuf[BUF_SIZ];
	long stats_port;
	bool taprio;
	bool txtime;
	bool deadline;
	bool do_vlan;
	int l2_header_len;
	int l4_header_len;
	bool sched_fifo;
	bool sched_rr;
	long sched_priority;
	long utc_tai_offset;
	struct ip_address ip_destination;
	bool l2;
	bool l4;
	long data_port;
	long domain_number;
	long transport_specific;
	long sync_threshold;
	long num_readings;
	char output_file[PATH_MAX];
	pthread_t send_tid;
	pthread_t tx_timestamp_tid;
	int send_tid_rc;
	int tx_timestamp_tid_rc;
	unsigned long cpumask;
	struct syncmon *syncmon;
};

int isochron_send_parse_args(int argc, char **argv, struct isochron_send *prog);
void isochron_send_prepare_default_args(struct isochron_send *prog);
int isochron_send_interpret_args(struct isochron_send *prog);
void isochron_send_init_thread_state(struct isochron_send *prog);
void isochron_send_init_data_packet(struct isochron_send *prog);
int isochron_send_init_data_sock(struct isochron_send *prog);
void isochron_send_teardown_data_sock(struct isochron_send *prog);
int isochron_send_init_sysmon(struct isochron_send *prog);
int isochron_send_init_ptpmon(struct isochron_send *prog);
void isochron_send_teardown_sysmon(struct isochron_send *prog);
void isochron_send_teardown_ptpmon(struct isochron_send *prog);
int isochron_send_update_session_start_time(struct isochron_send *prog);
int isochron_send_start_threads(struct isochron_send *prog);
void isochron_send_stop_threads(struct isochron_send *prog);
int isochron_prepare_receiver(struct isochron_send *prog, struct sk *mgmt_sock);
__s64 isochron_send_first_base_time(struct isochron_send *prog);

#endif
