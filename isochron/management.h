// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 NXP */
#ifndef _ISOCHRON_MANAGEMENT_H
#define _ISOCHRON_MANAGEMENT_H

#include <linux/types.h>
#include <netinet/ether.h>
#include "log.h"
#include "ptpmon.h"
#include "sysmon.h"

#define ISOCHRON_STATS_PORT	5000 /* TCP */
#define ISOCHRON_DATA_PORT	6000 /* UDP */
#define ISOCHRON_MANAGEMENT_VERSION 2

enum isochron_management_id {
	ISOCHRON_MID_LOG,
	ISOCHRON_MID_SYSMON_OFFSET,
	ISOCHRON_MID_PTPMON_OFFSET,
	ISOCHRON_MID_UTC_OFFSET,
	ISOCHRON_MID_PORT_STATE,
	ISOCHRON_MID_GM_CLOCK_IDENTITY,
	ISOCHRON_MID_PACKET_COUNT,
	ISOCHRON_MID_DESTINATION_MAC,
};

enum isochron_management_action {
	ISOCHRON_GET = 0,
	ISOCHRON_SET,
	ISOCHRON_RESPONSE,
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
struct isochron_destination_mac {
	unsigned char		addr[ETH_ALEN];
	__u8			reserved[2];
} __attribute((packed));

int isochron_send_tlv(int fd, enum isochron_management_action action,
		      enum isochron_management_id mid, size_t size);
void isochron_send_empty_tlv(int fd, enum isochron_management_id mid);
int isochron_collect_rcv_log(int fd, struct isochron_log *rcv_log);
int isochron_query_mid(int fd, enum isochron_management_id mid,
		       void *data, size_t data_len);

int isochron_update_packet_count(int fd, long count);

static inline void *isochron_tlv_data(struct isochron_tlv *tlv)
{
	return tlv + 1;
}

typedef int isochron_tlv_cb_t(void *priv, struct isochron_tlv *tlv);
typedef int isochron_mgmt_tlv_set_cb_t(void *priv, void *ptr);

int isochron_mgmt_event(int fd, void *priv, isochron_tlv_cb_t get_cb,
			isochron_tlv_cb_t set_cb, bool *socket_closed);
int isochron_mgmt_tlv_set(int fd, struct isochron_tlv *tlv, void *priv,
			  enum isochron_management_id mid,
			  size_t struct_size, isochron_mgmt_tlv_set_cb_t cb);

int isochron_forward_log(int fd, struct isochron_log *log, size_t size);
int isochron_forward_sysmon_offset(int fd, struct sysmon *sysmon);
int isochron_forward_ptpmon_offset(int fd, struct ptpmon *ptpmon);
int isochron_forward_utc_offset(int fd, struct ptpmon *ptpmon, int *utc_offset);
int isochron_forward_port_state(int fd, struct ptpmon *ptpmon,
				const char *if_name, struct mnl_socket *rtnl);
int isochron_forward_gm_clock_identity(int fd, struct ptpmon *ptpmon);

int isochron_collect_sync_stats(int fd, __s64 *sysmon_offset,
				__s64 *ptpmon_offset, int *utc_offset,
				enum port_state *port_state,
				struct clock_identity *gm_clkid);

#endif
