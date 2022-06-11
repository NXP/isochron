/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 */
#ifndef _PTPMON_H
#define _PTPMON_H

#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/un.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "endian.h"

#define MAX_IFACE_LEN					255

enum ptp_management_id {
	/* Clock management ID values */
	MID_USER_DESCRIPTION				= 0x0002,
	MID_SAVE_IN_NON_VOLATILE_STORAGE		= 0x0003,
	MID_RESET_NON_VOLATILE_STORAGE			= 0x0004,
	MID_INITIALIZE					= 0x0005,
	MID_FAULT_LOG					= 0x0006,
	MID_FAULT_LOG_RESET				= 0x0007,
	MID_DEFAULT_DATA_SET				= 0x2000,
	MID_CURRENT_DATA_SET				= 0x2001,
	MID_PARENT_DATA_SET				= 0x2002,
	MID_TIME_PROPERTIES_DATA_SET			= 0x2003,
	MID_PRIORITY1					= 0x2005,
	MID_PRIORITY2					= 0x2006,
	MID_DOMAIN					= 0x2007,
	MID_SLAVE_ONLY					= 0x2008,
	MID_TIME					= 0x200F,
	MID_CLOCK_ACCURACY				= 0x2010,
	MID_UTC_PROPERTIES				= 0x2011,
	MID_TRACEABILITY_PROPERTIES			= 0x2012,
	MID_TIMESCALE_PROPERTIES			= 0x2013,
	MID_PATH_TRACE_LIST				= 0x2015,
	MID_PATH_TRACE_ENABLE				= 0x2016,
	MID_GRANDMASTER_CLUSTER_TABLE			= 0x2017,
	MID_ACCEPTABLE_MASTER_TABLE			= 0x201A,
	MID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE		= 0x201C,
	MID_ALTERNATE_TIME_OFFSET_ENABLE		= 0x201E,
	MID_ALTERNATE_TIME_OFFSET_NAME			= 0x201F,
	MID_ALTERNATE_TIME_OFFSET_MAX_KEY		= 0x2020,
	MID_ALTERNATE_TIME_OFFSET_PROPERTIES		= 0x2021,
	MID_EXTERNAL_PORT_CONFIGURATION_ENABLED		= 0x3000,
	MID_HOLDOVER_UPGRADE_ENABLE			= 0x3002,
	MID_TRANSPARENT_CLOCK_DEFAULT_DATA_SET		= 0x4000,
	MID_PRIMARY_DOMAIN				= 0x4002,
	MID_TIME_STATUS_NP				= 0xC000,
	MID_GRANDMASTER_SETTINGS_NP			= 0xC001,
	MID_SUBSCRIBE_EVENTS_NP				= 0xC003,
	MID_SYNCHRONIZATION_UNCERTAIN_NP		= 0xC006,

	/* Port management ID values */
	MID_NULL_MANAGEMENT				= 0x0000,
	MID_CLOCK_DESCRIPTION				= 0x0001,
	MID_PORT_DATA_SET				= 0x2004,
	MID_LOG_ANNOUNCE_INTERVAL			= 0x2009,
	MID_ANNOUNCE_RECEIPT_TIMEOUT			= 0x200A,
	MID_LOG_SYNC_INTERVAL				= 0x200B,
	MID_VERSION_NUMBER				= 0x200C,
	MID_ENABLE_PORT					= 0x200D,
	MID_DISABLE_PORT				= 0x200E,
	MID_UNICAST_NEGOTIATION_ENABLE			= 0x2014,
	MID_UNICAST_MASTER_TABLE			= 0x2018,
	MID_UNICAST_MASTER_MAX_TABLE_SIZE		= 0x2019,
	MID_ACCEPTABLE_MASTER_TABLE_ENABLED		= 0x201B,
	MID_ALTERNATE_MASTER				= 0x201D,
	MID_MASTER_ONLY					= 0x3001,
	MID_EXT_PORT_CONFIG_PORT_DATA_SET		= 0x3003,
	MID_TRANSPARENT_CLOCK_PORT_DATA_SET		= 0x4001,
	MID_DELAY_MECHANISM				= 0x6000,
	MID_LOG_MIN_PDELAY_REQ_INTERVAL			= 0x6001,
	MID_PORT_DATA_SET_NP				= 0xC002,
	MID_PORT_PROPERTIES_NP				= 0xC004,
	MID_PORT_STATS_NP				= 0xC005,
};

struct clock_quality {
	__u8			clock_class;
	__u8			clock_accuracy;
	__be16			offset_scaled_log_variance;
} __attribute((packed));

struct clock_identity {
	__u8 id[8];
}  __attribute((packed));

struct port_identity {
	struct clock_identity	clock_identity;
	__be16			port_number;
}  __attribute((packed));

/* MID_DEFAULT_DATA_SET */
struct default_ds {
	__u8			flags;
	__u8			reserved1;
	__be16			number_ports;
	__u8			priority1;
	struct clock_quality	clock_quality;
	__u8			priority2;
	struct clock_identity	clock_identity;
	__u8			domain_number;
	__u8			reserved2;
} __attribute((packed));

/* MID_PORT_DATA_SET */
struct port_ds {
	struct port_identity	port_identity;
	__u8			port_state;
	__u8			log_min_delay_req_interval;
	__be64			peer_mean_path_delay;
	__u8			log_announce_interval;
	__u8			announce_receipt_timeout;
	__u8			log_sync_interval;
	__u8			delay_mechanism;
	__u8			log_min_pdelay_req_interval;
	__u8			version_number;
} __attribute((packed));

/* MID_CURRENT_DATA_SET */
struct current_ds {
	__be16			steps_removed;
	__be64			offset_from_master;
	__be64			mean_path_delay;
} __attribute((packed));

/* MID_TIME_PROPERTIES_DATA_SET */
struct time_properties_ds {
	__be16			current_utc_offset;
	__u8			flags;
	__u8			time_source;
} __attribute((packed));

/* MID_PARENT_DATA_SET */
struct parent_data_set {
	struct port_identity	parent_port_identity;
	__u8			parent_stats;
	__u8			reserved;
	__be16			observed_parent_offset_scaled_log_variance;
	__be32			observed_parent_clock_phase_change_rate;
	__u8			grandmaster_priority1;
	struct clock_quality	grandmaster_clock_quality;
	__u8			grandmaster_priority2;
	struct clock_identity	grandmaster_identity;
} __attribute((packed));

/* MID_PORT_PROPERTIES_NP */
struct port_properties_np {
	struct port_identity	port_identity;
	__u8			port_state;
	__u8			timestamping;
	__u8			iface_len;
	char			iface[0]; /* up to MAX_IFACE_LEN */
} __attribute((packed));

/** Defines the state of a port. */
enum port_state {
	PS_INITIALIZING = 1,
	PS_FAULTY,
	PS_DISABLED,
	PS_LISTENING,
	PS_PRE_MASTER,
	PS_MASTER,
	PS_PASSIVE,
	PS_UNCALIBRATED,
	PS_SLAVE,
	PS_GRAND_MASTER, /*non-standard extension*/
};

static inline void portid_set(struct port_identity *portid,
			      const struct clock_identity *clockid,
			      unsigned int port_number)
{
	memcpy(&portid->clock_identity, clockid, sizeof(*clockid));
	portid->port_number = __cpu_to_be16(port_number);
}

#define CLOCKID_BUFSIZE			64
#define PORTID_BUFSIZE			64

static inline void clockid_to_string(const struct clock_identity *clockid,
				     char buf[CLOCKID_BUFSIZE])
{
	const unsigned char *ptr = clockid->id;

	snprintf(buf, CLOCKID_BUFSIZE, "%02x%02x%02x.%02x%02x.%02x%02x%02x",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7]);
}

static inline void portid_to_string(const struct port_identity *portid,
				    char buf[PORTID_BUFSIZE])
{
	const unsigned char *ptr = portid->clock_identity.id;

	snprintf(buf, PORTID_BUFSIZE, "%02x%02x%02x.%02x%02x.%02x%02x%02x-%hu",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7],
		 ntohs(portid->port_number));
}

static inline bool portid_eq(const struct port_identity *a,
			     const struct port_identity *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static inline bool clockid_eq(const struct clock_identity *a,
			      const struct clock_identity *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

const char *port_state_to_string(enum port_state state);

struct ptpmon;

struct ptpmon *ptpmon_create(int domain_number, int transport_specific,
			     const char uds_local[UNIX_PATH_MAX],
			     const char uds_remote[UNIX_PATH_MAX]);
void ptpmon_destroy(struct ptpmon *ptpmon);
int ptpmon_open(struct ptpmon *ptpmon);
void ptpmon_close(struct ptpmon *ptpmon);
int ptpmon_query_port_mid(struct ptpmon *ptpmon,
			  const struct port_identity *target_port_identity,
			  enum ptp_management_id mid,
			  void *dest, size_t dest_len);
int ptpmon_query_clock_mid(struct ptpmon *ptpmon, enum ptp_management_id mid,
			   void *dest, size_t dest_len);
int ptpmon_query_port_mid_extra(struct ptpmon *ptpmon,
				const struct port_identity *target_port_identity,
				enum ptp_management_id mid,
				void *dest, size_t dest_len, size_t extra_len);
int ptpmon_query_clock_mid_extra(struct ptpmon *ptpmon,
				 enum ptp_management_id mid,
				 void *dest, size_t dest_len,
				 size_t extra_len);

#endif
