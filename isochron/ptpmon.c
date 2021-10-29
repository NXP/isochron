/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <poll.h>
#include <unistd.h>
#include "ptpmon.h"

#define ARRAY_SIZE(array) \
	(sizeof(array) / sizeof(*array))

/* Version definition for IEEE 1588-2019 */
#define PTP_MAJOR_VERSION	2
#define PTP_MINOR_VERSION	1
#define PTP_VERSION		(PTP_MINOR_VERSION << 4 | PTP_MAJOR_VERSION)

#define PTP_MSGSIZE		1500

#define UDS_FILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) /*0660*/

enum ptp_message_type {
	PTP_MSGTYPE_SYNC	= 0x0,
	PTP_MSGTYPE_DELAY_REQ	= 0x1,
	PTP_MSGTYPE_PDELAY_REQ	= 0x2,
	PTP_MSGTYPE_PDELAY_RESP	= 0x3,
	PTP_MSGTYPE_MANAGEMENT	= 0xd,
};

enum control_field {
	CTL_SYNC,
	CTL_DELAY_REQ,
	CTL_FOLLOW_UP,
	CTL_DELAY_RESP,
	CTL_MANAGEMENT,
	CTL_OTHER,
};

struct ptp_header {
	__u8			tsmt;  /* transportSpecific | messageType */
	__u8			ver;   /* reserved          | versionPTP  */
	__be16			message_length;
	__u8			domain_number;
	__u8			reserved1;
	__u8			flag_field[2];
	__be64			correction;
	__be32			reserved2;
	struct port_identity	source_port_identity;
	__be16			sequence_id;
	__u8			control;
	__u8			log_message_interval;
}  __attribute((packed));

enum management_action {
	GET,
	SET,
	RESPONSE,
	COMMAND,
	ACKNOWLEDGE,
};

enum ptp_tlv_type {
	TLV_MANAGEMENT					= 0x0001,
	TLV_MANAGEMENT_ERROR_STATUS			= 0x0002,
};

enum ptp_management_error_id {
	MID_RESPONSE_TOO_BIG				= 0x0001,
	MID_NO_SUCH_ID					= 0x0002,
	MID_WRONG_LENGTH				= 0x0003,
	MID_WRONG_VALUE					= 0x0004,
	MID_NOT_SETABLE					= 0x0005,
	MID_NOT_SUPPORTED				= 0x0006,
	MID_GENERAL_ERROR				= 0xFFFE,
};

struct management_error_status {
	__be16			type;
	__be16			length;
	__be16			error;
	__be16			id;
	__u8			reserved[4];
} __attribute((packed));

struct management_tlv_datum {
	__u8			val;
	__u8			reserved;
} __attribute((packed));

struct ptp_message {
	unsigned char buf[PTP_MSGSIZE];
	size_t len;
};

struct ptp_management_header {
	struct ptp_header	hdr;
	struct port_identity	target_port_identity;
	__u8			starting_boundary_hops;
	__u8			boundary_hops;
	__u8			flags; /* reserved | actionField */
	__u8			reserved;
} __attribute((packed));

struct ptp_tlv {
	__be16			tlv_type;
	__be16			length_field;
	__be16			management_id;
} __attribute((packed));

struct ptpmon {
	char uds_remote[UNIX_PATH_MAX];
	char uds_local[UNIX_PATH_MAX];
	struct port_identity port_identity;
	int transport_specific;
	int domain_number;
	int timeout;
	int fd;
	__u16 sequence_id;
	struct default_ds dds;
};

typedef int ptpmon_tlv_cb_t(void *priv, struct ptp_tlv *tlv, const void *tlv_data);

static const struct port_identity target_all_ports = {
	.clock_identity = {
		.id = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	},
	.port_number = 0xffff,
};

static const char *ps_str[] = {
	"NONE",
	"INITIALIZING",
	"FAULTY",
	"DISABLED",
	"LISTENING",
	"PRE_MASTER",
	"MASTER",
	"PASSIVE",
	"UNCALIBRATED",
	"SLAVE",
	"GRAND_MASTER",
};

const char *port_state_to_string(enum port_state state)
{
	return ps_str[state];
}

static void ptp_message_clear(struct ptp_message *msg)
{
	memset(&msg->buf, 0, PTP_MSGSIZE);
}

static struct ptp_header *ptp_message_header(struct ptp_message *msg)
{
	return (struct ptp_header *)msg->buf;
}

static struct ptp_management_header *ptp_management_header(struct ptp_message *msg)
{
	return (struct ptp_management_header *)msg->buf;
}

static void *ptp_management_suffix(struct ptp_message *msg)
{
	return ptp_management_header(msg) + 1;
}

static enum ptp_message_type ptp_message_type(struct ptp_message *msg)
{
	struct ptp_header *header = ptp_message_header(msg);

	return header->tsmt & 0x0f;
}

static enum management_action ptp_management_action(struct ptp_message *msg)
{
	struct ptp_management_header *mgmt = ptp_management_header(msg);

	return mgmt->flags & 0x0f;
}

static void *ptp_management_tlv_data(struct ptp_tlv *tlv)
{
	return tlv + 1;
}

static const char *mgt_err_code_to_string(enum ptp_management_error_id err)
{
	switch (err) {
	case MID_RESPONSE_TOO_BIG:
		return "response too big";
	case MID_NO_SUCH_ID:
		return "no such ID";
	case MID_WRONG_LENGTH:
		return "wrong length";
	case MID_WRONG_VALUE:
		return "wrong value";
	case MID_NOT_SETABLE:
		return "not settable";
	case MID_NOT_SUPPORTED:
		return "not supported";
	case MID_GENERAL_ERROR:
		return "general error";
	default:
		return "unknown";
	}
}

static int ptpmon_management_error(struct management_error_status *mgt)
{
	enum ptp_management_error_id err;
	enum ptp_management_id mid;

	mid = ntohs(mgt->id);
	err = ntohs(mgt->error);

	fprintf(stderr, "Server returned error code %d (%s) for MID %d\n",
		err, mgt_err_code_to_string(err), mid);

	return err;
}

static void *ptp_message_add_management_tlv(struct ptp_message *msg,
					    enum ptp_management_id mid,
					    size_t mid_size)
{
	struct ptp_header *header = ptp_message_header(msg);
	struct ptp_tlv *tlv = ptp_management_suffix(msg);

	if (msg->len + sizeof(*tlv) + mid_size >= PTP_MSGSIZE)
		return NULL;

	tlv->tlv_type = htons(TLV_MANAGEMENT);
	tlv->length_field = htons(2 + mid_size);
	tlv->management_id = htons(mid);
	msg->len += sizeof(*tlv) + mid_size;
	header->message_length = htons(msg->len);

	return ptp_management_tlv_data(tlv);
}

static int uds_send(int fd, const char *uds_remote, void *buf, int buflen)
{
	struct sockaddr_un sun;
	int cnt;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strncpy(sun.sun_path, uds_remote, sizeof(sun.sun_path) - 1);

	cnt = sendto(fd, buf, buflen, 0, (struct sockaddr *)&sun, sizeof(sun));
	if (cnt < 1)
		return -errno;

	return cnt;
}

static int uds_recv(int fd, const char *uds_remote, void *buf, int buflen)
{
	struct sockaddr_un sun;
	socklen_t len = sizeof(sun);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strncpy(sun.sun_path, uds_remote, sizeof(sun.sun_path) - 1);

	return recvfrom(fd, buf, buflen, 0, (struct sockaddr *)&sun, &len);
}

static int uds_poll(int fd, int timeout)
{
	struct pollfd pfd[1] = {
		[0] = {
			.fd = fd,
			.events = POLLIN | POLLPRI | POLLERR,
		},
	};
	int cnt;

	cnt = poll(pfd, ARRAY_SIZE(pfd), timeout);
	if (cnt < 0) {
		if (errno != EINTR) {
			fprintf(stderr, "poll returned %d: %s\n",
				errno, strerror(errno));
		}
		return -errno;
	}

	return cnt ? 0 : -ETIMEDOUT;
}

static int uds_bind(const char *uds_local)
{
	struct sockaddr_un sun;
	int fd, err;

	fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strncpy(sun.sun_path, uds_local, sizeof(sun.sun_path) - 1);

	unlink(uds_local);

	err = bind(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (err < 0) {
		close(fd);
		return -errno;
	}

	chmod(uds_local, UDS_FILEMODE);

	return fd;
}

static void uds_close(int fd)
{
	struct sockaddr_un sun;
	socklen_t len = sizeof(sun);
	int err;

	err = getsockname(fd, (struct sockaddr *)&sun, &len);
	if (err)
		return;

	if (sun.sun_family == AF_LOCAL)
		unlink(sun.sun_path);

	close(fd);
}

static int ptpmon_send(struct ptpmon *ptpmon, struct ptp_message *msg)
{
	int len;

	len = uds_send(ptpmon->fd, ptpmon->uds_remote, msg->buf, msg->len);

	return len < 0 ? len : 0;
}

static int ptpmon_recv(struct ptpmon *ptpmon, struct ptp_message *msg)
{
	int len;

	len = uds_poll(ptpmon->fd, ptpmon->timeout);
	if (len)
		return len;

	len = uds_recv(ptpmon->fd, ptpmon->uds_remote, msg->buf, PTP_MSGSIZE);
	if (len >= 0)
		msg->len = len;

	return len < 0 ? len : 0;
}

static void ptpmon_message_init(struct ptpmon *ptpmon, struct ptp_message *msg,
				enum management_action action,
				const struct port_identity *target_port_identity)
{
	struct ptp_management_header *mgmt = ptp_management_header(msg);
	struct ptp_header *header = ptp_message_header(msg);

	msg->len = sizeof(*mgmt);

	header->tsmt = PTP_MSGTYPE_MANAGEMENT | ptpmon->transport_specific;
	header->ver = PTP_VERSION;
	header->message_length = htons(msg->len);
	header->domain_number = ptpmon->domain_number;
	header->source_port_identity = ptpmon->port_identity;
	header->sequence_id = htons(ptpmon->sequence_id++);
	header->control = CTL_MANAGEMENT;
	header->log_message_interval = 0x7f;

	memcpy(&mgmt->target_port_identity, target_port_identity,
	       sizeof(*target_port_identity));
	mgmt->starting_boundary_hops = 0;
	mgmt->boundary_hops = 0;
	mgmt->flags = action;
}

static void ptp_management_tlv_next(struct ptp_tlv **tlv, size_t *len)
{
	size_t tlv_size_bytes = ntohs((*tlv)->length_field) + sizeof(**tlv);

	*len += tlv_size_bytes;
	*tlv = (struct ptp_tlv *)((unsigned char *)tlv + tlv_size_bytes);
}

struct ptpmon_tlv_parse_priv {
	enum ptp_management_id mid;
	void *dest;
	size_t dest_len;
};

static int ptpmon_copy_data_set(void *priv, struct ptp_tlv *tlv,
				const void *tlv_data)
{
	struct ptpmon_tlv_parse_priv *parse = priv;

	if (ntohs(tlv->management_id) != parse->mid) {
		fprintf(stderr, "unknown management id 0x%x, expected 0x%x\n",
			ntohs(tlv->management_id), parse->mid);
		return -EINVAL;
	}

	if (ntohs(tlv->length_field) != parse->dest_len + 2) {
		fprintf(stderr,
			"unexpected TLV length %d for management id %d, expected %zu\n",
			ntohs(tlv->length_field), parse->mid, parse->dest_len + 2);
		return -EINVAL;
	}

	memcpy(parse->dest, tlv_data, parse->dest_len);

	return 0;
}

static int ptp_management_message_for_each_tlv(struct ptp_message *msg,
					       ptpmon_tlv_cb_t cb, void *priv)
{
	size_t len = sizeof(struct ptp_management_header);
	struct ptp_tlv *tlv = ptp_management_suffix(msg);
	int err = -EBADMSG;

	while (len < msg->len) {
		switch (ntohs(tlv->tlv_type)) {
		case TLV_MANAGEMENT:
			err = cb(priv, tlv, ptp_management_tlv_data(tlv));
			if (err)
				return err;
			break;
		case TLV_MANAGEMENT_ERROR_STATUS:
			return ptpmon_management_error(ptp_management_tlv_data(tlv));
		default:
			printf("unknown TLV type %d\n", ntohs(tlv->tlv_type));
		}

		ptp_management_tlv_next(&tlv, &len);
	}

	return err;
}

static int ptp_message_parse_reply(struct ptp_message *msg, ptpmon_tlv_cb_t cb,
				   void *priv)
{
	enum ptp_message_type msgtype = ptp_message_type(msg);
	enum management_action action;

	if (msg->len < sizeof(struct ptp_management_header)) {
		fprintf(stderr, "Buffer too short to be a management message\n");
		return -EBADMSG;
	}

	if (msgtype != PTP_MSGTYPE_MANAGEMENT) {
		fprintf(stderr, "Expected MANAGEMENT PTP message, got 0x%x\n",
			msgtype);
		return -EBADMSG;
	}

	action = ptp_management_action(msg);
	if (action != RESPONSE) {
		printf("expected RESPONSE action, got %d\n", action);
		return -EBADMSG;
	}

	return ptp_management_message_for_each_tlv(msg, cb, priv);
}

int ptpmon_query_port_mid(struct ptpmon *ptpmon,
			  const struct port_identity *target_port_identity,
			  enum ptp_management_id mid,
			  void *dest, size_t dest_len)
{
	struct ptpmon_tlv_parse_priv parse = {
		.mid = mid,
		.dest = dest,
		.dest_len = dest_len,
	};
	struct ptp_message msg;
	int err;

	ptp_message_clear(&msg);

	ptpmon_message_init(ptpmon, &msg, GET, target_port_identity);

	if (!ptp_message_add_management_tlv(&msg, mid, dest_len))
		return -ERANGE;

	err = ptpmon_send(ptpmon, &msg);
	if (err)
		return err;

	err = ptpmon_recv(ptpmon, &msg);
	if (err)
		return err;

	return ptp_message_parse_reply(&msg, ptpmon_copy_data_set, &parse);
}

int ptpmon_query_clock_mid(struct ptpmon *ptpmon, enum ptp_management_id mid,
			   void *dest, size_t dest_len)
{
	return ptpmon_query_port_mid(ptpmon, &target_all_ports, mid, dest, dest_len);
}

int ptpmon_open(struct ptpmon *ptpmon)
{
	int fd;

	fd = uds_bind(ptpmon->uds_local);
	if (fd < 0)
		return fd;

	ptpmon->fd = fd;

	return 0;
}

void ptpmon_close(struct ptpmon *ptpmon)
{
	uds_close(ptpmon->fd);
}

struct ptpmon *ptpmon_create(int domain_number, int transport_specific,
			     int timeout, const char *uds_local,
			     const char *uds_remote)
{
	struct ptpmon *ptpmon;

	ptpmon = calloc(1, sizeof(*ptpmon));
	if (!ptpmon)
		return NULL;

	ptpmon->domain_number = domain_number;
	ptpmon->transport_specific = transport_specific;
	ptpmon->timeout = timeout;
	strncpy(ptpmon->uds_local, uds_local, UNIX_PATH_MAX);
	strncpy(ptpmon->uds_remote, uds_remote, UNIX_PATH_MAX);
	ptpmon->port_identity.port_number = htons(getpid());

	return ptpmon;
}

void ptpmon_destroy(struct ptpmon *ptpmon)
{
	free(ptpmon);
}
