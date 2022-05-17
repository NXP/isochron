/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "management.h"
#include "ptpmon.h"
#include "sysmon.h"

int isochron_send_tlv(int fd, enum isochron_management_action action,
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

	len = write_exact(fd, buf, sizeof(*msg) + sizeof(*tlv));
	if (len < 0)
		return len;
	if (len == 0)
		return -ECONNRESET;
	return 0;
}

void isochron_send_empty_tlv(int fd, enum isochron_management_id mid)
{
	isochron_send_tlv(fd, ISOCHRON_RESPONSE, mid, 0);
}

int isochron_collect_rcv_log(int fd, struct isochron_log *rcv_log)
{
	struct isochron_management_message msg;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(fd, ISOCHRON_GET, ISOCHRON_MID_LOG, 0);
	if (rc)
		return rc;

	len = recv_exact(fd, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	len = recv_exact(fd, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION ||
	    msg.action != ISOCHRON_RESPONSE ||
	    __be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT ||
	    __be16_to_cpu(tlv.management_id) != ISOCHRON_MID_LOG) {
		fprintf(stderr, "Unexpected reply from isochron receiver\n");
		return -EBADMSG;
	}

	return isochron_log_recv(rcv_log, fd);
}

static void isochron_drain_fd(int fd, size_t len)
{
	unsigned char junk[BUFSIZ];

	while (len) {
		size_t count = min(len, (size_t)BUFSIZ);

		recv_exact(fd, junk, count, 0);
		len -= count;
	};
}

int isochron_query_mid(int fd, enum isochron_management_id mid,
		       void *data, size_t data_len)
{
	struct isochron_management_message msg;
	size_t payload_length, tlv_length;
	struct isochron_tlv tlv;
	ssize_t len;
	int rc;

	rc = isochron_send_tlv(fd, ISOCHRON_GET, mid, 0);
	if (rc)
		return rc;

	len = recv_exact(fd, &msg, sizeof(msg), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Unexpected message version %d from isochron receiver\n",
			msg.version);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr, "Unexpected action %d from isochron receiver\n",
			msg.action);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		fprintf(stderr,
			"Expected payload length %zu from isochron receiver, got %zu\n",
			data_len + sizeof(tlv), payload_length);
		isochron_drain_fd(fd, payload_length);
		return -EBADMSG;
	}

	len = recv_exact(fd, &tlv, sizeof(tlv), 0);
	if (len <= 0)
		return len ? len : -ECONNRESET;

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Expected TLV length %zu from isochron receiver, got %zu\n",
			data_len, tlv_length);
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Unexpected TLV type %d from isochron receiver\n",
			__be16_to_cpu(tlv.tlv_type));
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr, "Response for unexpected MID %d from isochron receiver\n",
			__be16_to_cpu(tlv.management_id));
		isochron_drain_fd(fd, tlv_length);
		return -EBADMSG;
	}

	if (data_len) {
		len = recv_exact(fd, data, data_len, 0);
		if (len <= 0)
			return len ? len : -ECONNRESET;
	}

	return 0;
}

int isochron_update_mid(int fd, enum isochron_management_id mid,
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

	rc = isochron_send_tlv(fd, ISOCHRON_SET, mid, data_len);
	if (rc) {
		free(tmp_buf);
		return rc;
	}

	len = write_exact(fd, data, data_len);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	len = recv_exact(fd, &msg, sizeof(msg), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (msg.version != ISOCHRON_MANAGEMENT_VERSION) {
		fprintf(stderr,
			"Unexpected message version %d from isochron receiver\n",
			msg.version);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (msg.action != ISOCHRON_RESPONSE) {
		fprintf(stderr, "Unexpected action %d from isochron receiver\n",
			msg.action);
		free(tmp_buf);
		return -EBADMSG;
	}

	payload_length = __be32_to_cpu(msg.payload_length);
	if (payload_length != data_len + sizeof(tlv)) {
		fprintf(stderr,
			"Expected payload length %zu from isochron receiver, got %zu\n",
			data_len + sizeof(tlv), payload_length);
		isochron_drain_fd(fd, payload_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = recv_exact(fd, &tlv, sizeof(tlv), 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	tlv_length = __be32_to_cpu(tlv.length_field);
	if (tlv_length != data_len) {
		fprintf(stderr,
			"Expected TLV length %zu from isochron receiver, got %zu\n",
			data_len, tlv_length);
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.tlv_type) != ISOCHRON_TLV_MANAGEMENT) {
		fprintf(stderr, "Unexpected TLV type %d from isochron receiver\n",
			__be16_to_cpu(tlv.tlv_type));
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	if (__be16_to_cpu(tlv.management_id) != mid) {
		fprintf(stderr, "Response for unexpected MID %d from isochron receiver\n",
			__be16_to_cpu(tlv.management_id));
		isochron_drain_fd(fd, tlv_length);
		free(tmp_buf);
		return -EBADMSG;
	}

	len = recv_exact(fd, tmp_buf, data_len, 0);
	if (len <= 0) {
		free(tmp_buf);
		return len ? len : -ECONNRESET;
	}

	if (memcmp(tmp_buf, data, data_len)) {
		fprintf(stderr,
			"Unexpected reply contents from isochron receiver\n");
		free(tmp_buf);
		return -EBADMSG;
	}

	free(tmp_buf);

	return 0;
}

static void isochron_tlv_next(struct isochron_tlv **tlv, size_t *len)
{
	size_t tlv_size_bytes;

	tlv_size_bytes = __be32_to_cpu((*tlv)->length_field) + sizeof(**tlv);
	*len += tlv_size_bytes;
	*tlv = (struct isochron_tlv *)((unsigned char *)tlv + tlv_size_bytes);
}

int isochron_mgmt_event(int fd, void *priv, isochron_tlv_cb_t get_cb,
			isochron_tlv_cb_t set_cb, bool *socket_closed)
{
	struct isochron_management_message msg;
	unsigned char buf[BUFSIZ];
	struct isochron_tlv *tlv;
	size_t parsed_len = 0;
	ssize_t len;
	int rc;

	*socket_closed = false;

	len = recv_exact(fd, &msg, sizeof(msg), 0);
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

	len = recv_exact(fd, buf, len, 0);
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

int isochron_forward_log(int fd, struct isochron_log *log, size_t size)
{
	int rc;

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(log));
	if (rc)
		return 0;

	isochron_log_xmit(log, fd);
	isochron_log_teardown(log);
	return isochron_log_init(log, size);
}

int isochron_forward_sysmon_offset(int fd, struct sysmon *sysmon)
{
	__s64 sysmon_offset, sysmon_delay;
	struct isochron_sysmon_offset so;
	__u64 sysmon_ts;
	int rc;

	rc = sysmon_get_offset(sysmon, &sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc) {
		pr_err(rc, "Failed to read sysmon offset: %m\n");
		isochron_send_empty_tlv(fd, ISOCHRON_MID_SYSMON_OFFSET);
		return 0;
	}

	so.offset = __cpu_to_be64(sysmon_offset);
	so.time = __cpu_to_be64(sysmon_ts);
	so.delay = __cpu_to_be64(sysmon_delay);

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_SYSMON_OFFSET,
			       sizeof(so));
	if (rc)
		return 0;

	write_exact(fd, &so, sizeof(so));

	return 0;
}

int isochron_forward_ptpmon_offset(int fd, struct ptpmon *ptpmon)
{
	struct isochron_ptpmon_offset po;
	struct current_ds current_ds;
	__s64 ptpmon_offset;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon offset: %m\n");
		isochron_send_empty_tlv(fd, ISOCHRON_MID_PTPMON_OFFSET);
		return 0;
	}

	ptpmon_offset = master_offset_from_current_ds(&current_ds);
	po.offset = __cpu_to_be64(ptpmon_offset);

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PTPMON_OFFSET,
			       sizeof(po));
	if (rc)
		return 0;

	write_exact(fd, &po, sizeof(po));

	return 0;
}

int isochron_forward_utc_offset(int fd, struct ptpmon *ptpmon, int *utc_offset)
{
	struct time_properties_ds time_properties_ds;
	struct isochron_utc_offset utc;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds, sizeof(time_properties_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon UTC offset: %m\n");
		isochron_send_empty_tlv(fd, ISOCHRON_MID_UTC_OFFSET);
		return 0;
	}

	utc.offset = time_properties_ds.current_utc_offset;

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_UTC_OFFSET, sizeof(utc));
	if (rc)
		return 0;

	write_exact(fd, &utc, sizeof(utc));

	*utc_offset = __be16_to_cpu(utc.offset);

	return 0;
}

int isochron_forward_port_state(int fd, struct ptpmon *ptpmon,
				const char *if_name, struct mnl_socket *rtnl)
{
	struct isochron_port_state state;
	enum port_state port_state;
	int rc;

	rc = ptpmon_query_port_state_by_name(ptpmon, if_name, rtnl,
					     &port_state);
	if (rc) {
		pr_err(rc, "Failed to read ptpmon port state: %m\n");
		isochron_send_empty_tlv(fd, ISOCHRON_MID_PORT_STATE);
		return 0;
	}

	state.state = port_state;

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_PORT_STATE, sizeof(state));
	if (rc)
		return 0;

	write_exact(fd, &state, sizeof(state));

	return 0;
}

int isochron_forward_gm_clock_identity(int fd, struct ptpmon *ptpmon)
{
	struct isochron_gm_clock_identity gm;
	struct parent_data_set parent_ds;
	int rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		pr_err(rc, "Failed to read ptpmon GM clockID: %m\n");
		isochron_send_empty_tlv(fd, ISOCHRON_MID_GM_CLOCK_IDENTITY);
		return 0;
	}

	memcpy(&gm.clock_identity, &parent_ds.grandmaster_identity,
	       sizeof(gm.clock_identity));

	rc = isochron_send_tlv(fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_GM_CLOCK_IDENTITY,
			       sizeof(gm));
	if (rc)
		return 0;

	write_exact(fd, &gm, sizeof(gm));

	return 0;
}
