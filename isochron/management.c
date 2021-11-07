/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"
#include "management.h"

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
