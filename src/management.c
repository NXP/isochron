/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "argparser.h"
#include "common.h"
#include "management.h"
#include "ptpmon.h"
#include "rtnl.h"
#include "sysmon.h"

struct isochron_mgmt_handler {
	const struct isochron_mgmt_ops *ops;
	struct isochron_error *error_table;
};

const char *mid_to_string(enum isochron_management_id mid)
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
	case ISOCHRON_MID_CURRENT_CLOCK_TAI:
		return "CURRENT_CLOCK_TAI";
	case ISOCHRON_MID_OPER_BASE_TIME:
		return "OPER_BASE_TIME";
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

	memset(buf, 0, sizeof(*msg) + sizeof(*tlv));

	msg = (struct isochron_management_message *)buf;
	msg->version = ISOCHRON_MANAGEMENT_VERSION;
	msg->action = action;
	msg->payload_length = __cpu_to_be32(sizeof(*tlv) + size);

	tlv = (struct isochron_tlv *)(msg + 1);
	tlv->tlv_type = __cpu_to_be16(ISOCHRON_TLV_MANAGEMENT);
	tlv->management_id = __cpu_to_be16(mid);
	tlv->length_field = __cpu_to_be32(size);

	return sk_send(sock, buf, sizeof(*msg) + sizeof(*tlv));
}

static void isochron_send_empty_tlv(struct sk *sock,
				    enum isochron_management_id mid)
{
	isochron_send_tlv(sock, ISOCHRON_RESPONSE, mid, 0);
}

int isochron_collect_rcv_log(struct sk *sock, struct isochron_log *rcv_log)
{
	struct isochron_management_message msg;
	struct isochron_tlv tlv;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_GET, ISOCHRON_MID_LOG, 0);
	if (rc)
		return rc;

	rc = sk_recv(sock, &msg, sizeof(msg), 0);
	if (rc) {
		sk_err(sock, rc,
		       "Failed to receive GET response message header for log: %m\n");
		return rc;
	}

	rc = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (rc) {
		sk_err(sock, rc,
		       "Failed to receive GET response TLV for log: %m\n");
		return rc;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION ||
	    msg.action != ISOCHRON_RESPONSE ||
	    __be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT ||
	    __be16_to_cpu(tlv.management_id) != ISOCHRON_MID_LOG) {
		fprintf(stderr, "Unexpected reply from isochron receiver\n");
		return -EBADMSG;
	}

	return isochron_log_recv(rcv_log, sock);
}

static int isochron_drain_sk(struct sk *sock, size_t len)
{
	unsigned char junk[BUFSIZ];
	int rc;

	while (len) {
		size_t count = min(len, (size_t)BUFSIZ);

		rc = sk_recv(sock, junk, count, 0);
		if (rc) {
			sk_err(sock, rc,
			       "Error while draining %zu bytes from socket: %m\n",
			       len);
			return rc;
		}
		len -= count;
	};

	return 0;
}

int isochron_query_mid_error(struct sk *sock, enum isochron_management_id mid,
			     struct isochron_error *err)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	__be32 rc_be;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_GET_ERROR, mid, 0);
	if (rc)
		return rc;

	rc = sk_recv(sock, &msg, sizeof(msg), 0);
	if (rc) {
		sk_err(sock, rc,
		       "Failed to receive GET_ERR response message header: %m\n");
		return rc;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Failed to get error for MID %s: unexpected message version %d in response\n",
			mid_to_string(mid), msg.version);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr,
			"Failed to get error for MID %s: unexpected action %d in response\n",
			mid_to_string(mid), msg.action);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length < sizeof(tlv)) {
		fprintf(stderr,
			"Failed to get error for MID %s: TLV header length %zu shorter than expected\n",
			mid_to_string(mid), payload_length);

		rc = isochron_drain_sk(sock, payload_length);
		if (rc)
			return rc;

		return -EBADMSG;
	}

	rc = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (rc) {
		sk_err(sock, rc, "Failed to receive GET_ERR response TLV: %m\n");
		return rc;
	}

	payload_length -= sizeof(tlv);

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length < sizeof(rc_be)) {
		fprintf(stderr,
			"Failed to get error for MID %s: expected TLV length at least %zu in response, got %zu\n",
			mid_to_string(mid), sizeof(rc_be), tlv_length);

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr,
			"Failed to get error for MID %s: unexpected TLV type %d in response\n",
			mid_to_string(mid), __be16_to_cpu(tlv.tlv_type));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr,
			"Failed to get error for MID %s: response for unexpected MID %s\n",
			mid_to_string(mid),
			mid_to_string(__be16_to_cpu(tlv.management_id)));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		return -EBADMSG;
	}

	rc = sk_recv(sock, &rc_be, sizeof(rc_be), 0);
	if (rc) {
		sk_err(sock, rc, "Failed to receive error code for MID %s: %m\n",
		       mid_to_string(mid));
		return rc;
	}

	err->rc = (int)__be32_to_cpu(rc_be);
	memset(err->extack, 0, ISOCHRON_EXTACK_SIZE);

	payload_length -= sizeof(rc_be);
	if (payload_length >= ISOCHRON_EXTACK_SIZE) {
		fprintf(stderr, "extack message too long, discarding\n");

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;
	}

	if (payload_length) {
		rc = sk_recv(sock, err->extack, payload_length, 0);
		if (rc) {
			sk_err(sock, rc,
			       "Failed to receive extack for MID %s: %m\n",
			       mid_to_string(mid));
			return rc;
		}
	}

	return 0;
}

static void isochron_print_mid_error(struct sk *sock,
				     enum isochron_management_id mid)
{
	struct isochron_error err;

	if (isochron_query_mid_error(sock, mid, &err))
		return;

	if (strlen(err.extack))
		fprintf(stderr, "Remote error %d: %s\n", err.rc, err.extack);
	else
		pr_err(err.rc, "Remote error %d: %m\n", err.rc);
}

int isochron_query_mid(struct sk *sock, enum isochron_management_id mid,
		       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_GET, mid, 0);
	if (rc) {
		sk_err(sock, rc, "Failed to send GET message for MID %s: %m\n",
		       mid_to_string(mid));
		return rc;
	}

	rc = sk_recv(sock, &msg, sizeof(msg), 0);
	if (rc) {
		sk_err(sock, rc,
		       "Failed to receive response message header for MID %s: %m\n",
		       mid_to_string(mid));
		return rc;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Failed to query MID %s: unexpected message version %d in response\n",
			mid_to_string(mid), msg.version);
		isochron_print_mid_error(sock, mid);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr,
			"Failed to query MID %s: unexpected action %d in response\n",
			mid_to_string(mid), msg.action);
		isochron_print_mid_error(sock, mid);
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

		rc = isochron_drain_sk(sock, payload_length);
		if (rc)
			return rc;

		isochron_print_mid_error(sock, mid);
		return -EBADMSG;
	}

	rc = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (rc) {
		sk_err(sock, rc, "Failed to receive TLV header for MID %s: %m\n",
		       mid_to_string(mid));
		return rc;
	}

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Failed to query MID %s: expected TLV length %zu in response, got %zu\n",
			mid_to_string(mid), data_len, tlv_length);

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		isochron_print_mid_error(sock, mid);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Failed to query MID %s: unexpected TLV type %d in response\n",
			mid_to_string(mid), __be16_to_cpu(tlv.tlv_type));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		isochron_print_mid_error(sock, mid);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr,
			"Failed to query MID %s: response for unexpected MID %s\n",
			mid_to_string(mid),
			mid_to_string(__be16_to_cpu(tlv.management_id)));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			return rc;

		isochron_print_mid_error(sock, mid);
		return -EBADMSG;
	}

	if (data_len) {
		rc = sk_recv(sock, data, data_len, 0);
		if (rc) {
			sk_err(sock, rc,
			       "Failed to receive management data for MID %s: %m\n",
			       mid_to_string(mid));
			return rc;
		}
	}

	return 0;
}

void mgmt_extack(char *extack, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(extack, ISOCHRON_EXTACK_SIZE - 1, fmt, ap);
	va_end(ap);

	/* Print to the local error output as well, for posterity */
	fprintf(stderr, "%s\n", extack);
}

static void isochron_mgmt_tlv_get(struct sk *sock, void *priv,
				  enum isochron_management_id mid,
				  const struct isochron_mgmt_ops *ops,
				  struct isochron_error *err)
{
	int rc;

	if (!ops->get) {
		mgmt_extack(err->extack, "Unhandled GET for MID %s",
			    mid_to_string(mid));
		err->rc = -EOPNOTSUPP;
		goto error;
	}

	*err->extack = 0;

	rc = ops->get(priv, err->extack);
	err->rc = rc;
	if (rc)
		goto error;

	return;
error:
	isochron_send_empty_tlv(sock, mid);
}

static void isochron_mgmt_tlv_set(struct sk *sock, struct isochron_tlv *tlv,
				  void *priv, enum isochron_management_id mid,
				  const struct isochron_mgmt_ops *ops,
				  struct isochron_error *err)
{
	size_t tlv_len = __be32_to_cpu(tlv->length_field);
	int rc;

	if (!ops->set) {
		mgmt_extack(err->extack, "Unhandled SET for MID %s",
			    mid_to_string(mid));
		err->rc = -EOPNOTSUPP;
		goto error;
	}

	if (tlv_len != ops->struct_size) {
		mgmt_extack(err->extack,
			    "Expected %zu bytes for SET of MID %s, got %zu",
			    ops->struct_size, mid_to_string(mid), tlv_len);
		err->rc = -EINVAL;
		goto error;
	}

	*err->extack = 0;

	rc = ops->set(priv, isochron_tlv_data(tlv), err->extack);
	err->rc = rc;
	if (rc)
		goto error;

	/* Echo back the TLV data as ack */
	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE, mid, ops->struct_size);
	if (rc) {
		mgmt_extack(err->extack, "Failed to send TLV response");
		err->rc = rc;
		goto error;
	}

	sk_send(sock, isochron_tlv_data(tlv), ops->struct_size);

	return;

error:
	isochron_send_empty_tlv(sock, mid);
}

static void isochron_forward_mgmt_err(struct sk *sock,
				      enum isochron_management_id mid,
				      const struct isochron_error *err)
{
	size_t len = strlen(err->extack);
	__be32 err_be;
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE, mid,
			       sizeof(__be32) + len);
	if (rc)
		goto error;

	err_be = __cpu_to_be32(err->rc);
	sk_send(sock, &err_be, sizeof(err_be));
	if (len)
		sk_send(sock, err->extack, len);

	return;

error:
	isochron_send_empty_tlv(sock, mid);
}

static int isochron_update_mid(struct sk *sock, enum isochron_management_id mid,
			       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	unsigned char *tmp_buf;
	int rc;

	tmp_buf = malloc(data_len);
	if (!tmp_buf)
		return -ENOMEM;

	rc = isochron_send_tlv(sock, ISOCHRON_SET, mid, data_len);
	if (rc)
		goto out;

	rc = sk_send(sock, data, data_len);
	if (rc)
		goto out;

	rc = sk_recv(sock, &msg, sizeof(msg), 0);
	if (rc)
		goto out;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected message version %d in response\n",
			mid_to_string(mid), msg.version);
		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected action %d in response\n",
			mid_to_string(mid), msg.action);
		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
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

		rc = isochron_drain_sk(sock, payload_length);
		if (rc)
			goto out;

		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

	rc = sk_recv(sock, &tlv, sizeof(tlv), 0);
	if (rc)
		goto out;

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Failed to update MID %s: expected TLV length %zu in response, got %zu\n",
			mid_to_string(mid), data_len, tlv_length);

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			goto out;

		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected TLV type %d in response\n",
			mid_to_string(mid), __be16_to_cpu(tlv.tlv_type));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			goto out;

		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr,
			"Failed to update MID %s: response for unexpected MID %s\n",
			mid_to_string(mid),
			mid_to_string(__be16_to_cpu(tlv.management_id)));

		rc = isochron_drain_sk(sock, tlv_length);
		if (rc)
			goto out;

		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

	rc = sk_recv(sock, tmp_buf, data_len, 0);
	if (rc)
		goto out;

	if (memcmp(tmp_buf, data, data_len)) {
		fprintf(stderr,
			"Failed to update MID %s: unexpected reply contents\n",
			mid_to_string(mid));
		isochron_print_mid_error(sock, mid);
		rc = -EBADMSG;
		goto out;
	}

out:
	free(tmp_buf);

	return rc;
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

int isochron_update_if_name(struct sk *sock, const char if_name[IFNAMSIZ])
{
	struct isochron_if_name ifn = {};
	int rc;

	rc = if_name_copy(ifn.name, if_name);
	if (rc) {
		fprintf(stderr, "Truncation while copying string\n");
		return rc;
	}

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

int isochron_update_uds(struct sk *sock, const char uds_remote[UNIX_PATH_MAX])
{
	struct isochron_uds u = {};
	int rc;

	rc = uds_copy(u.name, uds_remote);
	if (rc) {
		fprintf(stderr, "Truncation while copying string\n");
		return rc;
	}

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
	int rc;

	i.family = __cpu_to_be32(addr->family);
	memcpy(i.addr, &addr->addr6, 16);
	rc = if_name_copy(i.bound_if_name, addr->bound_if_name);
	if (rc) {
		fprintf(stderr, "Truncation while copying string\n");
		return rc;
	}

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

int isochron_mgmt_event(struct sk *sock, struct isochron_mgmt_handler *handler,
			void *priv)
{
	struct isochron_management_message msg;
	const struct isochron_mgmt_ops *ops;
	enum isochron_management_id mid;
	struct isochron_error *err;
	unsigned char buf[BUFSIZ];
	struct isochron_tlv *tlv;
	size_t parsed_len = 0;
	size_t len;
	int rc;

	rc = sk_recv(sock, &msg, sizeof(msg), 0);
	if (rc) {
		sk_err(sock, rc, "Failed to receive message header: %m\n");
		return rc;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr, "Expected management version %d, got %d\n",
			ISOCHRON_MANAGEMENT_VERSION, msg.version);
		return 0;
	}

	switch (msg.action) {
	case ISOCHRON_GET:
	case ISOCHRON_SET:
	case ISOCHRON_GET_ERROR:
		break;
	default:
		fprintf(stderr, "Unexpected action %d\n", msg.action);
		return 0;
	}

	len = __be32_to_cpu(msg.payload_length);
	if (len >= BUFSIZ) {
		fprintf(stderr, "GET message too large at %zd, max %d\n", len, BUFSIZ);
		return 0;
	}

	rc = sk_recv(sock, buf, len, 0);
	if (rc) {
		sk_err(sock, rc, "Failed to receive message body: %m\n");
		return rc;
	}

	tlv = (struct isochron_tlv *)buf;

	while (parsed_len < (size_t)len) {
		if (__be16_to_cpu(tlv->tlv_type) != ISOCHRON_TLV_MANAGEMENT)
			goto next;

		mid = __be16_to_cpu(tlv->management_id);
		if (mid < 0 || mid >= __ISOCHRON_MID_MAX) {
			fprintf(stderr, "Unrecognized MID %d\n", mid);
			isochron_send_empty_tlv(sock, mid);
			goto next;
		}

		ops = &handler->ops[mid];
		err = &handler->error_table[mid];

		switch (msg.action) {
		case ISOCHRON_GET:
			isochron_mgmt_tlv_get(sock, priv, mid, ops, err);
			break;
		case ISOCHRON_SET:
			isochron_mgmt_tlv_set(sock, tlv, priv, mid, ops, err);
			break;
		case ISOCHRON_GET_ERROR:
			isochron_forward_mgmt_err(sock, mid, err);
		default:
			break;
		}

next:
		isochron_tlv_next(&tlv, &parsed_len);
	}

	return 0;
}

int isochron_forward_log(struct sk *sock, struct isochron_log *log,
			 size_t size, char *extack)
{
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(log));
	if (rc)
		return rc;

	isochron_log_xmit(log, sock);
	isochron_log_teardown(log);
	return isochron_log_init(log, size);
}

int isochron_forward_sysmon_offset(struct sk *sock, struct sysmon *sysmon,
				   char *extack)
{
	__s64 sysmon_offset, sysmon_delay;
	struct isochron_sysmon_offset so;
	__u64 sysmon_ts;
	int rc;

	rc = sysmon_get_offset(sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc) {
		mgmt_extack(extack, "Failed to read sysmon offset: %m");
		return rc;
	}

	so.offset = __cpu_to_be64(sysmon_offset);
	so.time = __cpu_to_be64(sysmon_ts);
	so.delay = __cpu_to_be64(sysmon_delay);

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_SYSMON_OFFSET,
			       sizeof(so));
	if (rc)
		return rc;

	sk_send(sock, &so, sizeof(so));

	return 0;
}

int isochron_forward_ptpmon_offset(struct sk *sock, struct ptpmon *ptpmon,
				   char *extack)
{
	struct isochron_ptpmon_offset po;
	struct current_ds current_ds;
	__s64 ptpmon_offset;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		mgmt_extack(extack, "Failed to read ptpmon offset: %m");
		return rc;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);
	po.offset = __cpu_to_be64(ptpmon_offset);

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PTPMON_OFFSET,
			       sizeof(po));
	if (rc)
		return rc;

	sk_send(sock, &po, sizeof(po));

	return 0;
}

int isochron_forward_utc_offset(struct sk *sock, struct ptpmon *ptpmon,
				int *utc_offset, char *extack)
{
	struct time_properties_ds time_properties_ds;
	struct isochron_utc_offset utc;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds, sizeof(time_properties_ds));
	if (rc) {
		mgmt_extack(extack, "Failed to read ptpmon UTC offset: %m");
		return rc;
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
				const char *if_name, struct mnl_socket *rtnl,
				char *extack)
{
	struct isochron_port_state state;
	enum port_state port_state;
	int rc;

	rc = ptpmon_query_port_state_by_name(ptpmon, if_name, rtnl,
					     &port_state);
	if (rc) {
		mgmt_extack(extack, "Failed to read ptpmon port state: %m");
		return rc;
	}

	state.state = port_state;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_STATE, sizeof(state));
	if (rc)
		return rc;

	sk_send(sock, &state, sizeof(state));

	return 0;
}

int isochron_forward_test_state(struct sk *sock, enum test_state state,
				char *extack)
{
	struct isochron_test_state test_state = {
		.test_state = state,
	};
	int rc;

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_TEST_STATE,
			       sizeof(test_state));
	if (rc)
		return rc;

	sk_send(sock, &test_state, sizeof(test_state));

	return 0;
}

int isochron_forward_port_link_state(struct sk *sock, const char *if_name,
				     struct mnl_socket *rtnl, char *extack)
{
	struct isochron_port_link_state s = {
		.link_state = PORT_LINK_STATE_UNKNOWN,
	};
	bool running;
	int rc;

	rc = rtnl_query_link_state(rtnl, if_name, &running);
	if (rc) {
		mgmt_extack(extack, "Failed to query port %s link state",
			    if_name);
	} else {
		s.link_state = running ? PORT_LINK_STATE_RUNNING :
					 PORT_LINK_STATE_DOWN;
	}

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_LINK_STATE, sizeof(s));
	if (rc)
		return rc;

	sk_send(sock, &s, sizeof(s));

	return 0;
}

int isochron_forward_gm_clock_identity(struct sk *sock, struct ptpmon *ptpmon,
				       char *extack)
{
	struct isochron_gm_clock_identity gm;
	struct parent_data_set parent_ds;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		mgmt_extack(extack, "Failed to read ptpmon GM clockID: %m");
		return rc;
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

int isochron_forward_current_clock_tai(struct sk *sock, char *extack)
{
	struct isochron_time t = {};
	struct timespec now_ts;
	__s64 now;
	int rc;

	clock_gettime(CLOCK_TAI, &now_ts);
	now = timespec_to_ns(&now_ts);
	t.time = __cpu_to_be64(now);

	rc = isochron_send_tlv(sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_CURRENT_CLOCK_TAI,
			       sizeof(t));
	if (rc)
		return rc;

	sk_send(sock, &t, sizeof(t));

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

int isochron_query_current_clock_tai(struct sk *sock, __s64 *clock_tai)
{
	struct isochron_time t = {};
	int rc;

	rc = isochron_query_mid(sock, ISOCHRON_MID_CURRENT_CLOCK_TAI, &t,
				sizeof(t));
	if (rc) {
		fprintf(stderr, "Current CLOCK_TAI missing from mgmt reply\n");
		return rc;
	}

	*clock_tai = __be64_to_cpu(t.time);

	return 0;
}

int isochron_query_oper_base_time(struct sk *sock, __s64 *base_time)
{
	struct isochron_time t = {};
	int rc;

	rc = isochron_query_mid(sock, ISOCHRON_MID_OPER_BASE_TIME, &t,
				sizeof(t));
	if (rc) {
		fprintf(stderr, "OPER_BASE_TIME missing from mgmt reply\n");
		return rc;
	}

	*base_time = __be64_to_cpu(t.time);

	return 0;
}

struct isochron_mgmt_handler *
isochron_mgmt_handler_create(const struct isochron_mgmt_ops *ops)
{
	struct isochron_mgmt_handler *handler;
	struct isochron_error *error_table;

	handler = calloc(1, sizeof(*handler));
	if (!handler)
		return NULL;

	error_table = calloc(__ISOCHRON_MID_MAX, sizeof(*error_table));
	if (!error_table) {
		free(handler);
		return NULL;
	}

	handler->ops = ops;
	handler->error_table = error_table;

	return handler;
}

void isochron_mgmt_handler_destroy(struct isochron_mgmt_handler *handler)
{
	free(handler->error_table);
	free(handler);
}
