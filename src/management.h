// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 NXP */
#ifndef _ISOCHRON_MANAGEMENT_H
#define _ISOCHRON_MANAGEMENT_H

#include <linux/types.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/un.h>
#include "log.h"
#include "ptpmon.h"
#include "sk.h"
#include "sysmon.h"

#define ISOCHRON_STATS_PORT	5000 /* TCP */
#define ISOCHRON_DATA_PORT	6000 /* UDP */
#define ISOCHRON_MANAGEMENT_VERSION 2
#define ISOCHRON_EXTACK_SIZE	1020

/* Don't forget to update mid_to_string() when adding new members */
enum isochron_management_id {
	ISOCHRON_MID_LOG,
	ISOCHRON_MID_SYSMON_OFFSET,
	ISOCHRON_MID_PTPMON_OFFSET,
	ISOCHRON_MID_UTC_OFFSET,
	ISOCHRON_MID_PORT_STATE,
	ISOCHRON_MID_GM_CLOCK_IDENTITY,
	ISOCHRON_MID_PACKET_COUNT,
	ISOCHRON_MID_DESTINATION_MAC,
	ISOCHRON_MID_SOURCE_MAC,
	ISOCHRON_MID_NODE_ROLE,
	ISOCHRON_MID_PACKET_SIZE,
	ISOCHRON_MID_IF_NAME,
	ISOCHRON_MID_PRIORITY,
	ISOCHRON_MID_STATS_PORT,
	ISOCHRON_MID_BASE_TIME,
	ISOCHRON_MID_ADVANCE_TIME,
	ISOCHRON_MID_SHIFT_TIME,
	ISOCHRON_MID_CYCLE_TIME,
	ISOCHRON_MID_WINDOW_SIZE,
	ISOCHRON_MID_SYSMON_ENABLED,
	ISOCHRON_MID_PTPMON_ENABLED,
	ISOCHRON_MID_UDS,
	ISOCHRON_MID_DOMAIN_NUMBER,
	ISOCHRON_MID_TRANSPORT_SPECIFIC,
	ISOCHRON_MID_NUM_READINGS,
	ISOCHRON_MID_TS_ENABLED,
	ISOCHRON_MID_VID,
	ISOCHRON_MID_ETHERTYPE,
	ISOCHRON_MID_QUIET_ENABLED,
	ISOCHRON_MID_TAPRIO_ENABLED,
	ISOCHRON_MID_TXTIME_ENABLED,
	ISOCHRON_MID_DEADLINE_ENABLED,
	ISOCHRON_MID_IP_DESTINATION,
	ISOCHRON_MID_L2_ENABLED,
	ISOCHRON_MID_L4_ENABLED,
	ISOCHRON_MID_DATA_PORT,
	ISOCHRON_MID_SCHED_FIFO_ENABLED,
	ISOCHRON_MID_SCHED_RR_ENABLED,
	ISOCHRON_MID_SCHED_PRIORITY,
	ISOCHRON_MID_CPU_MASK,
	ISOCHRON_MID_TEST_STATE,
	ISOCHRON_MID_SYNC_MONITOR_ENABLED,
	ISOCHRON_MID_PORT_LINK_STATE,
	ISOCHRON_MID_CURRENT_CLOCK_TAI,
	ISOCHRON_MID_OPER_BASE_TIME,
	__ISOCHRON_MID_MAX,
};

enum isochron_management_action {
	ISOCHRON_GET = 0,
	ISOCHRON_SET,
	ISOCHRON_RESPONSE,
	ISOCHRON_GET_ERROR,
};

enum isochron_role {
	ISOCHRON_ROLE_SEND,
	ISOCHRON_ROLE_RCV,
};

enum test_state {
	ISOCHRON_TEST_STATE_IDLE,
	ISOCHRON_TEST_STATE_RUNNING,
	ISOCHRON_TEST_STATE_FAILED,
};

enum port_link_state {
	PORT_LINK_STATE_UNKNOWN,
	PORT_LINK_STATE_DOWN,
	PORT_LINK_STATE_RUNNING,
};

enum isochron_tlv_type {
	ISOCHRON_TLV_MANAGEMENT = 0,
};

struct isochron_management_message {
	__u8		version;
	__u8		action;
	__be16		reserved;
	__be32		payload_length;
	/* TLVs follow */
} __attribute((packed));

struct isochron_tlv {
	__be16		tlv_type;
	__be16		management_id;
	__be32		length_field;
} __attribute((packed));

/* ISOCHRON_MID_SYSMON_OFFSET */
struct isochron_sysmon_offset {
	__be64			offset;
	__be64			time;
	__be64			delay;
} __attribute((packed));

/* ISOCHRON_MID_PTPMON_OFFSET */
struct isochron_ptpmon_offset {
	__be64			offset;
} __attribute((packed));

/* ISOCHRON_MID_UTC_OFFSET */
struct isochron_utc_offset {
	__be16			offset;
} __attribute((packed));

/* ISOCHRON_MID_PORT_STATE */
struct isochron_port_state {
	__u8			state;
} __attribute((packed));

/* ISOCHRON_MID_GM_CLOCK_IDENTITY */
struct isochron_gm_clock_identity {
	struct clock_identity	clock_identity;
} __attribute((packed));

/* ISOCHRON_MID_PACKET_COUNT */
struct isochron_packet_count {
	__be64			count;
};

/* ISOCHRON_MID_DESTINATION_MAC */
/* ISOCHRON_MID_SOURCE_MAC */
struct isochron_mac_addr {
	unsigned char		addr[ETH_ALEN];
	__u8			reserved[2];
} __attribute((packed));

/* ISOCHRON_MID_NODE_ROLE */
struct isochron_node_role {
	__be32			role;
} __attribute((packed));

/* ISOCHRON_MID_PACKET_SIZE */
struct isochron_packet_size {
	__be32			size;
} __attribute((packed));

/* ISOCHRON_MID_IF_NAME */
struct isochron_if_name {
	char			name[IFNAMSIZ];
} __attribute((packed));

/* ISOCHRON_MID_PRIORITY */
struct isochron_priority {
	__be32			priority;
} __attribute((packed));

/* ISOCHRON_MID_STATS_PORT */
/* ISOCHRON_MID_DATA_PORT */
struct isochron_port {
	__be16			port;
} __attribute((packed));

/* ISOCHRON_MID_BASE_TIME */
/* ISOCHRON_MID_ADVANCE_TIME */
/* ISOCHRON_MID_SHIFT_TIME */
/* ISOCHRON_MID_CYCLE_TIME */
/* ISOCHRON_MID_WINDOW_SIZE */
/* ISOCHRON_MID_CURRENT_CLOCK_TAI */
/* ISOCHRON_MID_OPER_BASE_TIME */
struct isochron_time {
	__be64			time;
} __attribute((packed));

/* ISOCHRON_MID_SYSMON_ENABLED */
/* ISOCHRON_MID_PTPMON_ENABLED */
/* ISOCHRON_MID_TS_ENABLED */
/* ISOCHRON_MID_QUIET_ENABLED */
/* ISOCHRON_MID_TAPRIO_ENABLED */
/* ISOCHRON_MID_TXTIME_ENABLED */
/* ISOCHRON_MID_DEADLINE_ENABLED */
/* ISOCHRON_MID_L2_ENABLED */
/* ISOCHRON_MID_L4_ENABLED */
/* ISOCHRON_MID_SCHED_FIFO_ENABLED */
/* ISOCHRON_MID_SCHED_RR_ENABLED */
struct isochron_feature_enabled {
	__u8			enabled;
	__u8			reserved[3];
} __attribute((packed));

/* ISOCHRON_MID_UDS */
struct isochron_uds {
	char			name[UNIX_PATH_MAX];
} __attribute((packed));

/* ISOCHRON_MID_DOMAIN_NUMBER */
struct isochron_domain_number {
	__u8			domain_number;
	__u8			reserved[3];
} __attribute((packed));

/* ISOCHRON_MID_TRANSPORT_SPECIFIC */
struct isochron_transport_specific {
	__u8			transport_specific;
	__u8			reserved[3];
} __attribute((packed));

/* ISOCHRON_MID_NUM_READINGS */
struct isochron_num_readings {
	__be32			num_readings;
} __attribute((packed));

/* ISOCHRON_MID_VID */
struct isochron_vid {
	__be16			vid;
	__u8			reserved[2];
} __attribute((packed));

/* ISOCHRON_MID_ETHERTYPE */
struct isochron_ethertype {
	__be16			ethertype;
	__u8			reserved[2];
} __attribute((packed));

/* ISOCHRON_MID_IP_DESTINATION */
struct isochron_ip_address {
	__be32			family;
	__u8			addr[16];
	char			bound_if_name[IFNAMSIZ];
} __attribute((packed));

/* ISOCHRON_MID_SCHED_PRIORITY */
struct isochron_sched_priority {
	__be32			sched_priority;
} __attribute((packed));

/* ISOCHRON_MID_CPU_MASK */
struct isochron_cpu_mask {
	__be64			cpu_mask;
} __attribute((packed));

/* ISOCHRON_MID_TEST_STATE */
struct isochron_test_state {
	__u8			test_state;
	__u8			reserved[3];
} __attribute((packed));

/* ISOCHRON_MID_PORT_LINK_STATE */
struct isochron_port_link_state {
	__u8			link_state;
	__u8			reserved[3];
} __attribute((packed));

const char *mid_to_string(enum isochron_management_id mid);

int isochron_send_tlv(struct sk *sock, enum isochron_management_action action,
		      enum isochron_management_id mid, size_t size);
int isochron_collect_rcv_log(struct sk *sock, struct isochron_log *rcv_log);
int isochron_query_mid(struct sk *sock, enum isochron_management_id mid,
		       void *data, size_t data_len);

int isochron_update_packet_count(struct sk *sock, long count);
int isochron_update_packet_size(struct sk *sock, int size);
int isochron_update_destination_mac(struct sk *sock, unsigned char *addr);
int isochron_update_source_mac(struct sk *sock, unsigned char *addr);
int isochron_update_node_role(struct sk *sock, enum isochron_role role);
int isochron_update_if_name(struct sk *sock, const char if_name[IFNAMSIZ]);
int isochron_update_priority(struct sk *sock, int priority);
int isochron_update_stats_port(struct sk *sock, __u16 port);
int isochron_update_base_time(struct sk *sock, __u64 base_time);
int isochron_update_advance_time(struct sk *sock, __u64 advance_time);
int isochron_update_shift_time(struct sk *sock, __u64 shift_time);
int isochron_update_cycle_time(struct sk *sock, __u64 cycle_time);
int isochron_update_window_size(struct sk *sock, __u64 window_time);
int isochron_update_domain_number(struct sk *sock, int domain_number);
int isochron_update_transport_specific(struct sk *sock, int transport_specific);
int isochron_update_uds(struct sk *sock, const char uds_remote[UNIX_PATH_MAX]);
int isochron_update_num_readings(struct sk *sock, int num_readings);
int isochron_update_sysmon_enabled(struct sk *sock, bool enabled);
int isochron_update_ptpmon_enabled(struct sk *sock, bool enabled);
int isochron_update_sync_monitor_enabled(struct sk *sock, bool enabled);
int isochron_update_ts_enabled(struct sk *sock, bool enabled);
int isochron_update_vid(struct sk *sock, __u16 vid);
int isochron_update_ethertype(struct sk *sock, __u16 etype);
int isochron_update_quiet_enabled(struct sk *sock, bool enabled);
int isochron_update_taprio_enabled(struct sk *sock, bool enabled);
int isochron_update_txtime_enabled(struct sk *sock, bool enabled);
int isochron_update_deadline_enabled(struct sk *sock, bool enabled);
int isochron_update_utc_offset(struct sk *sock, int offset);
int isochron_update_ip_destination(struct sk *sock, struct ip_address *addr);
int isochron_update_l2_enabled(struct sk *sock, bool enabled);
int isochron_update_l4_enabled(struct sk *sock, bool enabled);
int isochron_update_data_port(struct sk *sock, __u16 port);
int isochron_update_sched_fifo(struct sk *sock, bool enabled);
int isochron_update_sched_rr(struct sk *sock, bool enabled);
int isochron_update_sched_priority(struct sk *sock, int priority);
int isochron_update_cpu_mask(struct sk *sock, unsigned long cpumask);
int isochron_update_test_state(struct sk *sock, enum test_state state);

static inline void *isochron_tlv_data(struct isochron_tlv *tlv)
{
	return tlv + 1;
}

typedef int isochron_tlv_cb_t(void *priv, struct isochron_tlv *tlv);
typedef int isochron_mgmt_tlv_set_cb_t(void *priv, void *ptr);

int isochron_forward_log(struct sk *sock, struct isochron_log *log,
			 size_t size, char *extack);
int isochron_forward_sysmon_offset(struct sk *sock, struct sysmon *sysmon,
				   char *extack);
int isochron_forward_ptpmon_offset(struct sk *sock, struct ptpmon *ptpmon,
				   char *extack);
int isochron_forward_utc_offset(struct sk *sock, struct ptpmon *ptpmon,
				int *utc_offset, char *extack);
int isochron_forward_port_state(struct sk *sock, struct ptpmon *ptpmon,
				const char *if_name, struct mnl_socket *rtnl,
				char *extack);
int isochron_forward_test_state(struct sk *sock, enum test_state state,
				char *extack);
int isochron_forward_port_link_state(struct sk *sock, const char *if_name,
				     struct mnl_socket *rtnl, char *extack);
int isochron_forward_gm_clock_identity(struct sk *sock, struct ptpmon *ptpmon,
				       char *extack);
int isochron_forward_current_clock_tai(struct sk *sock, char *extack);

int isochron_collect_sync_stats(struct sk *sock, __s64 *sysmon_offset,
				__s64 *ptpmon_offset, int *utc_offset,
				enum port_state *port_state,
				struct clock_identity *gm_clkid);

int isochron_query_current_clock_tai(struct sk *sock, __s64 *clock_tai);
int isochron_query_oper_base_time(struct sk *sock, __s64 *base_time);

struct isochron_error {
	int rc;
	char extack[ISOCHRON_EXTACK_SIZE];
};

void mgmt_extack(char *extack, const char *fmt, ...);

struct isochron_mgmt_ops {
	int (*get)(void *priv, char *extack);
	int (*set)(void *priv, void *ptr, char *extack);
	size_t struct_size;
};

struct isochron_mgmt_handler;

struct isochron_mgmt_handler *
isochron_mgmt_handler_create(const struct isochron_mgmt_ops *ops);
void isochron_mgmt_handler_destroy(struct isochron_mgmt_handler *handler);

int isochron_mgmt_event(struct sk *sock, struct isochron_mgmt_handler *handler,
			void *priv);

int isochron_query_mid_error(struct sk *sock, enum isochron_management_id mid,
			     struct isochron_error *err);

#endif
