/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "argparser.h"
#include "common.h"
#include "management.h"
#include "ptpmon.h"
#include "rtnl.h"
#include "sysmon.h"

static const char *mid_to_string(enum isochron_management_id mid)
{
	switch (mid) {
	case ISOCHRON_MID_LOG:
		return "LOG";
	case ISOCHRON_MID_SYSMON_OFFSET:
		return "SYSMON_OFFSET";
	case ISOCHRON_MID_PTPMON_OFFSET:
		return "PTPMON_OFFSET";
	case ISOCHRON_MID_UTC_OFFSET:
		return "UTC_OFFSET";
	case ISOCHRON_MID_PORT_STATE:
		return "PORT_STATE";
	case ISOCHRON_MID_GM_CLOCK_IDENTITY:
		return "GM_CLOCK_IDENTITY";
	case ISOCHRON_MID_PACKET_COUNT:
		return "PACKET_COUNT";
	case ISOCHRON_MID_DESTINATION_MAC:
		return "DESTINATION_MAC";
	case ISOCHRON_MID_SOURCE_MAC:
		return "SOURCE_MAC";
	case ISOCHRON_MID_NODE_ROLE:
		return "NODE_ROLE";
	case ISOCHRON_MID_PACKET_SIZE:
		return "PACKET_SIZE";
	case ISOCHRON_MID_IF_NAME:
		return "IF_NAME";
	case ISOCHRON_MID_PRIORITY:
		return "PRIORITY";
	case ISOCHRON_MID_STATS_PORT:
		return "STATS_PORT";
	case ISOCHRON_MID_BASE_TIME:
		return "BASE_TIME";
	case ISOCHRON_MID_ADVANCE_TIME:
		return "ADVANCE_TIME";
	case ISOCHRON_MID_SHIFT_TIME:
		return "SHIFT_TIME";
	case ISOCHRON_MID_CYCLE_TIME:
		return "CYCLE_TIME";
	case ISOCHRON_MID_WINDOW_SIZE:
		return "WINDOW_SIZE";
	case ISOCHRON_MID_SYSMON_ENABLED:
		return "SYSMON_ENABLED";
	case ISOCHRON_MID_PTPMON_ENABLED:
		return "PTPMON_ENABLED";
	case ISOCHRON_MID_UDS:
		return "UDS";
	case ISOCHRON_MID_DOMAIN_NUMBER:
		return "DOMAIN_NUMBER";
	case ISOCHRON_MID_TRANSPORT_SPECIFIC:
		return "TRANSPORT_SPECIFIC";
	case ISOCHRON_MID_NUM_READINGS:
		return "NUM_READINGS";
	case ISOCHRON_MID_TS_ENABLED:
		return "TS_ENABLED";
	case ISOCHRON_MID_VID:
		return "VID";
	case ISOCHRON_MID_ETHERTYPE:
		return "ETHERTYPE";
	case ISOCHRON_MID_QUIET_ENABLED:
		return "QUIET_ENABLED";
	case ISOCHRON_MID_TAPRIO_ENABLED:
		return "TAPRIO_ENABLED";
	case ISOCHRON_MID_TXTIME_ENABLED:
		return "TXTIME_ENABLED";
	case ISOCHRON_MID_DEADLINE_ENABLED:
		return "DEADLINE_ENABLED";
	case ISOCHRON_MID_IP_DESTINATION:
		return "IP_DESTINATION";
	case ISOCHRON_MID_L2_ENABLED:
		return "L2_ENABLED";
	case ISOCHRON_MID_L4_ENABLED:
		return "L4_ENABLED";
	case ISOCHRON_MID_DATA_PORT:
		return "DATA_PORT";
	case ISOCHRON_MID_SCHED_FIFO_ENABLED:
		return "SCHED_FIFO_ENABLED";
	case ISOCHRON_MID_SCHED_RR_ENABLED:
		return "SCHED_RR_ENABLED";
	case ISOCHRON_MID_SCHED_PRIORITY:
		return "SCHED_PRIORITY";
	case ISOCHRON_MID_CPU_MASK:
		return "CPU_MASK";
	case ISOCHRON_MID_TEST_STATE:
		return "TEST_STATE";
	case ISOCHRON_MID_SYNC_MONITOR_ENABLED:
		return "SYNC_MONITOR_ENABLED";
	case ISOCHRON_MID_PORT_LINK_STATE:
		return "PORT_LINK_STATE";
	default:
		return "UNKNOWN";
	}
};

int isochron_send_tlv(struct sk *sock, enum isochron_management_action action,
		      enum isochron_management_id mid, size_t size)
{
	struct isochron_management_message *msg;
	unsigned char buf[BUFSIZ];
	struct isochron_tlv *tlv;
	ssize_t len;

	memset(buf, 0, sizeof(*msg) + sizeof(*tlv));

	msg = (struct isochron_management_message *)buf;
	msg->version = ISOCHRON_MANAGEMENT_VERSION;
	msg->action = action;
	msg->payload_length = __cpu_to_be32(sizeof(*tlv) + size);

	tlv = (struct isochron_tlv *)(msg + 1);
	tlv->tlv_type = __cpu_to_be16(ISOCHRON_TLV_MANAGEMENT);
	tlv->management_id = __cpu_to_be16(mid);
	tlv->length_field = __cpu_to_be32(size);

	len = sk_send(sock, buf, sizeof(*msg) + sizeof(*tlv));
	if (len < 0)
		return len;
	if (len == 0)
		return -ECONNRESET;
	return 0;
}

void isochron_send_empty_tlv(struct sk *sock, enum isochron_management_id mid)
{
	isochron_send_tlv(sock, ISOCHRON_RESPONSE, mid, 0);
}

int isochron_collect_rcv_log(struct sk *sock, struct isochron_log *rcv_log)
{
	struct isochron_management_message msg;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_GET, ISOCHRON_MID_LOG, 0);
	if (rc)
		return rc;

	len = sk_recv(sock, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	len = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION ||
	    msg.action != ISOCHRON_RESPONSE ||
	    __be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT ||
	    __be16_to_cpu(tlv.management_id) != ISOCHRON_MID_LOG) {
		fprintf(stderr, "Unexpected reply from isochron receiver\n");
		return -EBADMSG;
	}

	return isochron_log_recv(rcv_log, sock);
}

static void isochron_drain_sk(struct sk *sock, size_t len)
{
	unsigned char junk[BUFSIZ];

	while (len) {
		size_t count = min(len, (size_t)BUFSIZ);

		sk_recv(sock, junk, count, 0);
		len -= count;
	};
}

int isochron_query_mid(struct sk *sock, enum isochron_management_id mid,
		       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_GET, mid, 0);
	if (rc)
		return rc;

	len = sk_recv(sock, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Failed to query MID %s: unexpected message version %d in response\n",
			mid_to_string(mid), msg.version);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr,
			"Failed to query MID %s: unexpected action %d in response\n",
			mid_to_string(mid), msg.action);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		if (data_len == sizeof(tlv)) {
			fprintf(stderr,
				"Failed to query MID %s: received empty payload in response\n",
				mid_to_string(mid));
		} else {
			fprintf(stderr,
				"Failed to query MID %s: expected payload length %zu in response, got %zu\n",
				mid_to_string(mid), data_len + sizeof(tlv),
				payload_length);
		}
		isochron_drain_sk(sock, payload_length);
		return -EBADMSG;
	}

	len = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Failed to query MID %s: expected TLV length %zu in response, got %zu\n",
			mid_to_string(mid), data_len, tlv_length);
		isochron_drain_sk(sock, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Failed to query MID %s: unexpected TLV type %d in response\n",
			mid_to_string(mid), __be16_to_cpu(tlv.tlv_type));
		isochron_drain_sk(sock, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr,
			"Failed to query MID %s: response for unexpected MID %s\n",
			mid_to_string(mid),
			mid_to_string(__be16_to_cpu(tlv.management_id)));
		isochron_drain_sk(sock, tlv_length);
		return -EBADMSG;
	}

	if (data_len) {
		len = sk_recv(sock, data, data_len, 0);
		if (len <= 0)
			return len ? len : -ECONNRESET;
	}

	return 0;
}

int isochron_mgmt_tlv_set(struct sk *sock, struct isochron_tlv *tlv, void *priv,
			  enum isochron_management_id mid,
			  size_t struct_size, isochron_mgmt_tlv_set_cb_t cb)
{
	size_t tlv_len = __be32_to_cpu(tlv->length_field);
	int rc;

	if (tlv_len != struct_size) {
		fprintf(stderr,
			"Expected %zu bytes for SET of MID %s, got %zu\n",
			struct_size, mid_to_string(mid), tlv_len);
		isochron_send_empty_tlv(sock, mid);
		return 0;
	}

	rc = cb(priv, isochron_tlv_data(tlv));
	if (rc) {
		isochron_send_empty_tlv(sock, mid);
		return 0;
	}

	/* Echo back the TLV data as ack */
	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE, mid, struct_size);
	if (rc)
		return rc;

	sk_send(sock, isochron_tlv_data(tlv), struct_size);

	return 0;
}

static int isochron_update_mid(struct sk *sock, enum isochron_management_id mid,
			       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	unsigned char *tmp_buf;
	ssize_t len;
	int rc;

	tmp_buf = malloc(data_len);
	if (!tmp_buf)
		return -ENOMEM;

	rc = isochron_send_tlv(sock, ISOCHRON_SET, mid, data_len);
	if (rc) {
		free(tmp_buf);
		return rc;
	}

	len = sk_send(sock, data, data_len);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	len = sk_recv(sock, &msg, sizeof(msg), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected message version %d in response\n",
			mid_to_string(mid), msg.version);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected action %d in response\n",
			mid_to_string(mid), msg.action);
		free(tmp_buf);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		if (payload_length == sizeof(tlv)) {
			fprintf(stderr,
				"Failed to update MID %s: received empty payload in response\n",
				mid_to_string(mid));
		} else {
			fprintf(stderr,
				"Failed to update MID %s: expected payload length %zu in response, got %zu\n",
				mid_to_string(mid), data_len + sizeof(tlv),
				payload_length);
		}
		isochron_drain_sk(sock, payload_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Failed to update MID %s: expected TLV length %zu in response, got %zu\n",
			mid_to_string(mid), data_len, tlv_length);
		isochron_drain_sk(sock, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected TLV type %d in response\n",
			mid_to_string(mid), __be16_to_cpu(tlv.tlv_type));
		isochron_drain_sk(sock, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr,
			"Failed to update MID %s: response for unexpected MID %s\n",
			mid_to_string(mid),
			mid_to_string(__be16_to_cpu(tlv.management_id)));
		isochron_drain_sk(sock, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = sk_recv(sock, tmp_buf, data_len, 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (memcmp(tmp_buf, data, data_len)) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected reply contents\n",
			mid_to_string(mid));
		free(tmp_buf);
		return -EBADMSG;
	}

	free(tmp_buf);

	return 0;
}

int isochron_update_packet_count(struct sk *sock, long count)
{
	struct isochron_packet_count packet_count = {
		.count = __cpu_to_be64(count),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_PACKET_COUNT,
				   &packet_count, sizeof(packet_count));
}

int isochron_update_packet_size(struct sk *sock, int size)
{
	struct isochron_packet_size p = {
		.size = __cpu_to_be32(size),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_PACKET_SIZE,
				   &p, sizeof(p));
}

int isochron_update_destination_mac(struct sk *sock, unsigned char *addr)
{
	struct isochron_mac_addr mac = {};

	ether_addr_copy(mac.addr, addr);

	return isochron_update_mid(sock, ISOCHRON_MID_DESTINATION_MAC, &mac,
				   sizeof(mac));
}

int isochron_update_source_mac(struct sk *sock, unsigned char *addr)
{
	struct isochron_mac_addr mac = {};

	ether_addr_copy(mac.addr, addr);

	return isochron_update_mid(sock, ISOCHRON_MID_SOURCE_MAC, &mac,
				   sizeof(mac));
}

int isochron_update_node_role(struct sk *sock, enum isochron_role role)
{
	struct isochron_node_role r = {
		.role = __cpu_to_be32(role),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_NODE_ROLE, &r, sizeof(r));
}

int isochron_update_if_name(struct sk *sock, const char *if_name)
{
	struct isochron_if_name ifn = {};

	strcpy(ifn.name, if_name);

	return isochron_update_mid(sock, ISOCHRON_MID_IF_NAME,
				   &ifn, sizeof(ifn));
}

int isochron_update_priority(struct sk *sock, int priority)
{
	struct isochron_priority p = {
		.priority = __cpu_to_be32(priority),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_PRIORITY, &p, sizeof(p));
}

int isochron_update_stats_port(struct sk *sock, __u16 port)
{
	struct isochron_port p = {
		.port = __cpu_to_be16(port),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_STATS_PORT, &p, sizeof(p));
}

int isochron_update_base_time(struct sk *sock, __u64 base_time)
{
	struct isochron_time t = {
		.time = __cpu_to_be64(base_time),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_BASE_TIME, &t, sizeof(t));
}

int isochron_update_advance_time(struct sk *sock, __u64 advance_time)
{
	struct isochron_time t = {
		.time = __cpu_to_be64(advance_time),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_ADVANCE_TIME,
				   &t, sizeof(t));
}

int isochron_update_shift_time(struct sk *sock, __u64 shift_time)
{
	struct isochron_time t = {
		.time = __cpu_to_be64(shift_time),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SHIFT_TIME,
				   &t, sizeof(t));
}

int isochron_update_cycle_time(struct sk *sock, __u64 cycle_time)
{
	struct isochron_time t = {
		.time = __cpu_to_be64(cycle_time),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_CYCLE_TIME,
				   &t, sizeof(t));
}

int isochron_update_window_size(struct sk *sock, __u64 window_time)
{
	struct isochron_time t = {
		.time = __cpu_to_be64(window_time),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_WINDOW_SIZE,
				   &t, sizeof(t));
}

int isochron_update_domain_number(struct sk *sock, int domain_number)
{
	struct isochron_domain_number d = {
		.domain_number = domain_number,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_DOMAIN_NUMBER,
				   &d, sizeof(d));
}

int isochron_update_transport_specific(struct sk *sock, int transport_specific)
{
	struct isochron_transport_specific t = {
		.transport_specific = transport_specific,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_TRANSPORT_SPECIFIC,
				   &t, sizeof(t));
}

int isochron_update_uds(struct sk *sock, const char *uds_remote)
{
	struct isochron_uds u = {};

	strcpy(u.name, uds_remote);

	return isochron_update_mid(sock, ISOCHRON_MID_UDS, &u, sizeof(u));
}

int isochron_update_num_readings(struct sk *sock, int num_readings)
{
	struct isochron_num_readings n = {
		.num_readings = __cpu_to_be32(num_readings),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_NUM_READINGS,
				   &n, sizeof(n));
}

int isochron_update_sysmon_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SYSMON_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_ptpmon_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_PTPMON_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_ts_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_TS_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_vid(struct sk *sock, __u16 vid)
{
	struct isochron_vid v = {
		.vid = __cpu_to_be16(vid),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_VID, &v, sizeof(v));
}

int isochron_update_ethertype(struct sk *sock, __u16 ethertype)
{
	struct isochron_ethertype e = {
		.ethertype = __cpu_to_be16(ethertype),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_ETHERTYPE, &e, sizeof(e));
}

int isochron_update_quiet_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_QUIET_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_taprio_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_TAPRIO_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_txtime_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_TXTIME_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_deadline_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_DEADLINE_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_utc_offset(struct sk *sock, int offset)
{
	struct isochron_utc_offset u = {
		.offset = __cpu_to_be16(offset),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_UTC_OFFSET,
				   &u, sizeof(u));
}

int isochron_update_ip_destination(struct sk *sock, struct ip_address *addr)
{
	struct isochron_ip_address i;

	i.family = __cpu_to_be32(addr->family);
	memcpy(i.addr, &addr->addr6, 16);
	strcpy(i.bound_if_name, addr->bound_if_name);

	return isochron_update_mid(sock, ISOCHRON_MID_IP_DESTINATION,
				   &i, sizeof(i));
}

int isochron_update_l2_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_L2_ENABLED, &f, sizeof(f));
}

int isochron_update_l4_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_L4_ENABLED, &f, sizeof(f));
}

int isochron_update_data_port(struct sk *sock, __u16 port)
{
	struct isochron_port p = {
		.port = __cpu_to_be16(port),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_DATA_PORT, &p, sizeof(p));
}

int isochron_update_sched_fifo(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SCHED_FIFO_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_sched_rr(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SCHED_RR_ENABLED,
				   &f, sizeof(f));
}

int isochron_update_sched_priority(struct sk *sock, int priority)
{
	struct isochron_sched_priority p = {
		.sched_priority = __cpu_to_be32(priority),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SCHED_PRIORITY,
				   &p, sizeof(p));
}

int isochron_update_cpu_mask(struct sk *sock, unsigned long cpumask)
{
	struct isochron_cpu_mask c = {
		.cpu_mask = __cpu_to_be64(cpumask),
	};

	return isochron_update_mid(sock, ISOCHRON_MID_CPU_MASK, &c, sizeof(c));
}

int isochron_update_test_state(struct sk *sock, enum test_state state)
{
	struct isochron_test_state t = {
		.test_state = state,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_TEST_STATE, &t, sizeof(t));
}

int isochron_update_sync_monitor_enabled(struct sk *sock, bool enabled)
{
	struct isochron_feature_enabled f = {
		.enabled = enabled,
	};

	return isochron_update_mid(sock, ISOCHRON_MID_SYNC_MONITOR_ENABLED,
				   &f, sizeof(f));
}

static void isochron_tlv_next(struct isochron_tlv **tlv, size_t *len)
{
	size_t tlv_size_bytes;

	tlv_size_bytes = __be32_to_cpu((*tlv)->length_field) + sizeof(**tlv);
	*len += tlv_size_bytes;
	*tlv = (struct isochron_tlv *)((unsigned char *)tlv + tlv_size_bytes);
}

int isochron_mgmt_event(struct sk *sock, void *priv, isochron_tlv_cb_t get_cb,
			isochron_tlv_cb_t set_cb, bool *socket_closed)
{
	struct isochron_management_message msg;
	unsigned char buf[BUFSIZ];
	struct isochron_tlv *tlv;
	size_t parsed_len = 0;
	ssize_t len;
	int rc;

	*socket_closed = false;

	len = sk_recv(sock, &msg, sizeof(msg), 0);
	if (len <= 0) {
		*socket_closed = len == 0;
		return len;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr, "Expected management version %d, got %d\n",
			ISOCHRON_MANAGEMENT_VERSION, msg.version);
		return 0;
	}

	if (msg.action != ISOCHRON_GET && msg.action != ISOCHRON_SET) {
		fprintf(stderr, "Unexpected action %d\n", msg.action);
		return 0;
	}

	len = __be32_to_cpu(msg.payload_length);
	if (len >= BUFSIZ) {
		fprintf(stderr, "GET message too large at %zd, max %d\n", len, BUFSIZ);
		return 0;
	}

	len = sk_recv(sock, buf, len, 0);
	if (len <= 0) {
		*socket_closed = len == 0;
		return len;
	}

	tlv = (struct isochron_tlv *)buf;

	while (parsed_len < (size_t)len) {
		if (__be16_to_cpu(tlv->tlv_type) != ISOCHRON_TLV_MANAGEMENT)
			continue;

		switch (msg.action) {
		case ISOCHRON_GET:
			rc = get_cb(priv, tlv);
			if (rc)
				return rc;
			break;
		case ISOCHRON_SET:
			rc = set_cb(priv, tlv);
			if (rc)
				return rc;
			break;
		default:
			break;
		}

		isochron_tlv_next(&tlv, &parsed_len);
	}

	return 0;
}

int isochron_forward_log(struct sk *sock, struct isochron_log *log, size_t size)
{
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(log));
	if (rc)
		return 0;

	isochron_log_xmit(log, sock);
	isochron_log_teardown(log);
	return isochron_log_init(log, size);
}

int isochron_forward_sysmon_offset(struct sk *sock, struct sysmon *sysmon)
{
	__s64 sysmon_offset, sysmon_delay;
	struct isochron_sysmon_offset so;
	__u64 sysmon_ts;
	int rc;

	rc = sysmon_get_offset(sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc) {
		pr_err(rc, "Failed to read sysmon offset: %m\n");
		isochron_send_empty_tlv(sock, ISOCHRON_MID_SYSMON_OFFSET);
		return 0;
	}

	so.offset = __cpu_to_be64(sysmon_offset);
	so.time = __cpu_to_be64(sysmon_ts);
	so.delay = __cpu_to_be64(sysmon_delay);

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_SYSMON_OFFSET,
			       sizeof(so));
	if (rc)
		return 0;

	sk_send(sock, &so, sizeof(so));

	return 0;
}

int isochron_forward_ptpmon_offset(struct sk *sock, struct ptpmon *ptpmon)
{
	struct isochron_ptpmon_offset po;
	struct current_ds current_ds;
	__s64 ptpmon_offset;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon offset: %m\n");
		isochron_send_empty_tlv(sock, ISOCHRON_MID_PTPMON_OFFSET);
		return 0;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);
	po.offset = __cpu_to_be64(ptpmon_offset);

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PTPMON_OFFSET,
			       sizeof(po));
	if (rc)
		return 0;

	sk_send(sock, &po, sizeof(po));

	return 0;
}

int isochron_forward_utc_offset(struct sk *sock, struct ptpmon *ptpmon,
				int *utc_offset)
{
	struct time_properties_ds time_properties_ds;
	struct isochron_utc_offset utc;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds, sizeof(time_properties_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon UTC offset: %m\n");
		isochron_send_empty_tlv(sock, ISOCHRON_MID_UTC_OFFSET);
		return 0;
	}

	utc.offset = time_properties_ds.current_utc_offset;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_UTC_OFFSET, sizeof(utc));
	if (rc)
		return 0;

	sk_send(sock, &utc, sizeof(utc));

	*utc_offset = __be16_to_cpu(utc.offset);

	return 0;
}

int isochron_forward_port_state(struct sk *sock, struct ptpmon *ptpmon,
				const char *if_name, struct mnl_socket *rtnl)
{
	struct isochron_port_state state;
	enum port_state port_state;
	int rc;

	rc = ptpmon_query_port_state_by_name(ptpmon, if_name, rtnl,
					     &port_state);
	if (rc) {
		pr_err(rc, "Failed to read ptpmon port state: %m\n");
		isochron_send_empty_tlv(sock, ISOCHRON_MID_PORT_STATE);
		return 0;
	}

	state.state = port_state;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_STATE, sizeof(state));
	if (rc)
		return 0;

	sk_send(sock, &state, sizeof(state));

	return 0;
}

int isochron_forward_test_state(struct sk *sock, enum test_state state)
{
	struct isochron_test_state test_state = {
		.test_state = state,
	};
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_TEST_STATE,
			       sizeof(test_state));
	if (rc)
		return 0;

	sk_send(sock, &test_state, sizeof(test_state));

	return 0;
}

int isochron_forward_port_link_state(struct sk *sock, const char *if_name,
				     struct mnl_socket *rtnl)
{
	struct isochron_port_link_state s = {
		.link_state = PORT_LINK_STATE_UNKNOWN,
	};
	bool running;
	int rc;

	rc = rtnl_query_link_state(rtnl, if_name, &running);
	if (rc) {
		pr_err(rc, "Failed to query port %s link state: %m\n",
		       if_name);
	} else {
		s.link_state = running ? PORT_LINK_STATE_RUNNING :
					 PORT_LINK_STATE_DOWN;
	}

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_LINK_STATE, sizeof(s));
	if (rc)
		return 0;

	sk_send(sock, &s, sizeof(s));

	return 0;
}

int isochron_forward_gm_clock_identity(struct sk *sock, struct ptpmon *ptpmon)
{
	struct isochron_gm_clock_identity gm;
	struct parent_data_set parent_ds;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon GM clockID: %m\n");
		isochron_send_empty_tlv(sock, ISOCHRON_MID_GM_CLOCK_IDENTITY);
		return 0;
	}

	memcpy(&gm.clock_identity, &parent_ds.grandmaster_identity,
	       sizeof(gm.clock_identity));

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_GM_CLOCK_IDENTITY,
			       sizeof(gm));
	if (rc)
		return 0;

	sk_send(sock, &gm, sizeof(gm));

	return 0;
}

int isochron_collect_sync_stats(struct sk *sock, __s64 *sysmon_offset,
				__s64 *ptpmon_offset, int *utc_offset,
				enum port_state *port_state,
				struct clock_identity *gm_clkid)
{
	struct isochron_gm_clock_identity gm;
	struct isochron_sysmon_offset sysmon;
	struct isochron_ptpmon_offset ptpmon;
	struct isochron_port_state state;
	struct isochron_utc_offset utc;
	int rc;

	rc = isochron_query_mid(sock, ISOCHRON_MID_SYSMON_OFFSET, &sysmon,
				sizeof(sysmon));
	if (rc) {
		fprintf(stderr, "sysmon offset missing from mgmt reply\n");
		return rc;
	}

	rc = isochron_query_mid(sock, ISOCHRON_MID_PTPMON_OFFSET, &ptpmon,
				sizeof(ptpmon));
	if (rc) {
		fprintf(stderr, "ptpmon offset missing from mgmt reply\n");
		return rc;
	}

	rc = isochron_query_mid(sock, ISOCHRON_MID_UTC_OFFSET, &utc,
				sizeof(utc));
	if (rc) {
		fprintf(stderr, "UTC offset missing from mgmt reply\n");
		return rc;
	}

	rc = isochron_query_mid(sock, ISOCHRON_MID_PORT_STATE, &state,
				sizeof(state));
	if (rc) {
		fprintf(stderr, "port state missing from mgmt reply\n");
		return rc;
	}

	rc = isochron_query_mid(sock, ISOCHRON_MID_GM_CLOCK_IDENTITY, &gm,
				sizeof(gm));
	if (rc) {
		fprintf(stderr,
			"GM clock identity missing from mgmt reply: %d\n",
			rc);
		return rc;
	}

	*sysmon_offset = __be64_to_cpu(sysmon.offset);
	*ptpmon_offset = __be64_to_cpu(ptpmon.offset);
	*utc_offset = __be16_to_cpu(utc.offset);
	*port_state = state.state;
	memcpy(gm_clkid, &gm.clock_identity, sizeof(*gm_clkid));

	return 0;
}
