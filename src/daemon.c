// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 NXP */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "management.h"
#include "ptpmon.h"
#include "send.h"
#include "sysmon.h"

struct isochron_daemon {
	long stats_port;
	char pid_filename[PATH_MAX];
	char log_filename[PATH_MAX];
	int stats_listenfd;
	int stats_fd;
	bool have_client;
	struct isochron_send *send;
	struct mnl_socket *rtnl;
	bool test_running;
};

static int signal_received;

static void sig_handler(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		signal_received = 1;
		break;
	default:
		break;
	}
}

static int prog_prepare_session(struct isochron_send *send)
{
	int rc;

	rc = isochron_send_interpret_args(send);
	if (rc)
		return rc;

	rc = isochron_send_init_data_fd(send);
	if (rc)
		goto err_init_data_fd;

	isochron_send_init_data_packet(send);

	send->timestamped = 0;
	send->send_tid_should_stop = false;
	send->send_tid_stopped = false;

	rc = isochron_log_init(&send->log, send->iterations *
			       sizeof(struct isochron_send_pkt_data));
	if (rc)
		goto err_log_init;

	rc = isochron_send_update_session_start_time(send);
	if (rc) {
		pr_err(rc, "Failed to update session start time: %m\n");
		goto err_update_session_start;
	}

	rc = isochron_send_start_threads(send);
	if (rc)
		goto err_start_threads;

	return 0;

err_start_threads:
err_update_session_start:
	isochron_log_teardown(&send->log);
err_log_init:
	isochron_send_teardown_data_fd(send);
err_init_data_fd:
	return rc;
}

static void isochron_teardown_sender(struct isochron_daemon *prog)
{
	struct isochron_send *send = prog->send;

	if (!send)
		return;

	if (prog->test_running) {
		isochron_send_stop_threads(send);
		isochron_log_teardown(&send->log);
		isochron_send_teardown_data_fd(send);
		prog->test_running = false;
	}

	if (send->ptpmon)
		isochron_send_teardown_ptpmon(send);
	if (prog->send->sysmon)
		isochron_send_teardown_sysmon(send);

	free(send);
	prog->send = NULL;
}

static void prog_close_client_stats_session(struct isochron_daemon *prog)
{
	isochron_teardown_sender(prog);
	close(prog->stats_fd);
	prog->have_client = false;
}

static int prog_client_connect_event(struct isochron_daemon *prog)
{
	char client_addr[INET6_ADDRSTRLEN];
	struct sockaddr_in addr;
	socklen_t addr_len;

	addr_len = sizeof(struct sockaddr_in);
	prog->stats_fd = accept(prog->stats_listenfd, (struct sockaddr *)&addr,
				&addr_len);
	if (prog->stats_fd < 0) {
		if (errno != EINTR)
			perror("accept failed");
		return -errno;
	}

	if (!inet_ntop(addr.sin_family, &addr.sin_addr.s_addr,
		       client_addr, addr_len)) {
		perror("inet_pton failed");
		prog_close_client_stats_session(prog);
		return -errno;
	}

	printf("Accepted connection from %s\n", client_addr);

	prog->have_client = true;

	return 0;
}

static int prog_update_role(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_node_role *r = ptr;
	struct isochron_send *send;

	if (__be32_to_cpu(r->role) != ISOCHRON_ROLE_SEND) {
		fprintf(stderr,
			"Unexpected node role %d\n", __be32_to_cpu(r->role));
		return -EINVAL;
	}

	send = calloc(1, sizeof(*send));
	if (!send) {
		fprintf(stderr, "failed to allocate memory for new sender\n");
		return -ENOMEM;
	}

	isochron_send_prepare_default_args(send);
	/* Suppress local log output to the filesystem */
	send->output_file[0] = 0;

	isochron_teardown_sender(prog);

	prog->send = send;

	return 0;
}

static int prog_update_utc_offset(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_utc_offset *u = ptr;
	int offset;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	offset = __be16_to_cpu(u->offset);
	isochron_fixup_kernel_utc_offset(offset);
	prog->send->utc_tai_offset = offset;

	return 0;
}

static int prog_update_packet_count(void *priv, void *ptr)
{
	struct isochron_packet_count *p = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->iterations = __be64_to_cpu(p->count);

	return 0;
}

static int prog_update_packet_size(void *priv, void *ptr)
{
	struct isochron_packet_size *p = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->tx_len = __be32_to_cpu(p->size);

	return 0;
}

static int prog_update_destination_mac(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_mac_addr *m = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	ether_addr_copy(prog->send->dest_mac, m->addr);

	return 0;
}

static int prog_update_source_mac(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_mac_addr *m = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	ether_addr_copy(prog->send->src_mac, m->addr);

	return 0;
}

static int prog_update_if_name(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_if_name *n = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	strcpy(prog->send->if_name, n->name);

	return 0;
}

static int prog_update_priority(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_priority *p = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->priority = __be32_to_cpu(p->priority);

	return 0;
}

static int prog_update_stats_port(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_port *p = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->stats_port = __be16_to_cpu(p->port);

	return 0;
}

static int prog_update_base_time(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->base_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_advance_time(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->advance_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_shift_time(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->shift_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_cycle_time(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->cycle_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_window_size(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->window_size = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_sysmon_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (f->enabled) {
		if (prog->send->sysmon) {
			fprintf(stderr, "sysmon already enabled\n");
			return -EINVAL;
		}

		return isochron_send_init_sysmon(prog->send);
	} else {
		if (!prog->send->sysmon) {
			fprintf(stderr, "sysmon not enabled\n");
			return -EINVAL;
		}

		isochron_send_teardown_sysmon(prog->send);
	}

	return 0;
}

static int prog_update_ptpmon_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (f->enabled) {
		if (prog->send->ptpmon) {
			fprintf(stderr, "ptpmon already enabled\n");
			return -EINVAL;
		}

		return isochron_send_init_ptpmon(prog->send);
	} else {
		if (!prog->send->ptpmon) {
			fprintf(stderr, "ptpmon not enabled\n");
			return -EINVAL;
		}

		isochron_send_teardown_ptpmon(prog->send);
	}

	return 0;
}

static int prog_update_uds(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_uds *u = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	strcpy(prog->send->uds_remote, u->name);

	return 0;
}

static int prog_update_domain_number(void *priv, void *ptr)
{
	struct isochron_domain_number *d = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->domain_number = d->domain_number;

	return 0;
}

static int prog_update_transport_specific(void *priv, void *ptr)
{
	struct isochron_transport_specific *t = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->transport_specific = t->transport_specific;

	return 0;
}

static int prog_update_num_readings(void *priv, void *ptr)
{
	struct isochron_num_readings *n = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->num_readings = __be32_to_cpu(n->num_readings);

	return 0;
}

static int prog_update_ts_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->do_ts = f->enabled;

	return 0;
}

static int prog_update_vid(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_vid *v = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->vid = __be16_to_cpu(v->vid);

	return 0;
}

static int prog_update_ethertype(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_ethertype *e = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->etype = (__s16)__be16_to_cpu(e->ethertype);

	return 0;
}

static int prog_update_quiet_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->quiet = f->enabled;

	return 0;
}

static int prog_update_taprio_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->taprio = f->enabled;

	return 0;
}

static int prog_update_txtime_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->txtime = f->enabled;

	return 0;
}

static int prog_update_deadline_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->deadline = f->enabled;

	return 0;
}

static int prog_update_ip_destination(void *priv, void *ptr)
{
	struct isochron_ip_address *i = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->ip_destination.family = __be32_to_cpu(i->family);
	memcpy(&prog->send->ip_destination.addr6, i->addr, 16);
	strcpy(prog->send->ip_destination.bound_if_name, i->bound_if_name);

	return 0;
}

static int prog_update_l2_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->l2 = f->enabled;

	return 0;
}

static int prog_update_l4_enabled(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->l4 = f->enabled;

	return 0;
}

static int prog_update_data_port(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_port *p = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->data_port = __be16_to_cpu(p->port);

	return 0;
}

static int prog_update_sched_fifo(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->sched_fifo = f->enabled;

	return 0;
}

static int prog_update_sched_rr(void *priv, void *ptr)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->sched_rr = f->enabled;

	return 0;
}

static int prog_update_sched_priority(void *priv, void *ptr)
{
	struct isochron_sched_priority *s = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->sched_priority = __be32_to_cpu(s->sched_priority);

	return 0;
}

static int prog_update_cpu_mask(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_cpu_mask *c = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->cpumask = __be64_to_cpu(c->cpu_mask);

	return 0;
}

static int prog_update_test_state(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_test_state *s = ptr;
	int rc;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (s->test_state == ISOCHRON_TEST_STATE_IDLE) {
		if (!prog->test_running) {
			fprintf(stderr, "Sender already idle\n");
			return -EINVAL;
		}

		isochron_send_stop_threads(prog->send);
		prog->test_running = false;
	} else if (s->test_state == ISOCHRON_TEST_STATE_RUNNING) {
		if (prog->test_running) {
			fprintf(stderr, "Sender already running a test\n");
			return -EINVAL;
		}

		rc = prog_prepare_session(prog->send);
		if (rc)
			return rc;

		prog->test_running = true;
	}

	return 0;
}

static int prog_update_sync_monitor_enabled(void *priv, void *ptr)
{
	struct isochron_daemon *prog = priv;
	struct isochron_feature_enabled *f = ptr;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	prog->send->omit_sync = !f->enabled;

	return 0;
}

static int prog_mgmt_tlv_set(void *priv, struct isochron_tlv *tlv)
{
	enum isochron_management_id mid = __be16_to_cpu(tlv->management_id);
	struct isochron_daemon *prog = priv;
	int fd = prog->stats_fd;

	switch (mid) {
	case ISOCHRON_MID_NODE_ROLE:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_node_role),
					     prog_update_role);
	case ISOCHRON_MID_UTC_OFFSET:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_utc_offset),
					     prog_update_utc_offset);
	case ISOCHRON_MID_PACKET_COUNT:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_packet_count),
					     prog_update_packet_count);
	case ISOCHRON_MID_PACKET_SIZE:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_packet_size),
					     prog_update_packet_size);
	case ISOCHRON_MID_DESTINATION_MAC:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_mac_addr),
					     prog_update_destination_mac);
	case ISOCHRON_MID_SOURCE_MAC:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_mac_addr),
					     prog_update_source_mac);
	case ISOCHRON_MID_IF_NAME:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_if_name),
					     prog_update_if_name);
	case ISOCHRON_MID_PRIORITY:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_priority),
					     prog_update_priority);
	case ISOCHRON_MID_STATS_PORT:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_port),
					     prog_update_stats_port);
	case ISOCHRON_MID_BASE_TIME:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_time),
					     prog_update_base_time);
	case ISOCHRON_MID_ADVANCE_TIME:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_time),
					     prog_update_advance_time);
	case ISOCHRON_MID_SHIFT_TIME:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_time),
					     prog_update_shift_time);
	case ISOCHRON_MID_CYCLE_TIME:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_time),
					     prog_update_cycle_time);
	case ISOCHRON_MID_WINDOW_SIZE:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_time),
					     prog_update_window_size);
	case ISOCHRON_MID_SYSMON_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_sysmon_enabled);
	case ISOCHRON_MID_PTPMON_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_ptpmon_enabled);
	case ISOCHRON_MID_UDS:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_uds),
					     prog_update_uds);
	case ISOCHRON_MID_DOMAIN_NUMBER:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_domain_number),
					     prog_update_domain_number);
	case ISOCHRON_MID_TRANSPORT_SPECIFIC:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_transport_specific),
					     prog_update_transport_specific);
	case ISOCHRON_MID_NUM_READINGS:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_num_readings),
					     prog_update_num_readings);
	case ISOCHRON_MID_TS_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_ts_enabled);
	case ISOCHRON_MID_VID:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_vid),
					     prog_update_vid);
	case ISOCHRON_MID_ETHERTYPE:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_ethertype),
					     prog_update_ethertype);
	case ISOCHRON_MID_QUIET_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_quiet_enabled);
	case ISOCHRON_MID_TAPRIO_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_taprio_enabled);
	case ISOCHRON_MID_TXTIME_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_txtime_enabled);
	case ISOCHRON_MID_DEADLINE_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_deadline_enabled);
	case ISOCHRON_MID_IP_DESTINATION:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_ip_address),
					     prog_update_ip_destination);
	case ISOCHRON_MID_L2_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_l2_enabled);
	case ISOCHRON_MID_L4_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_l4_enabled);
	case ISOCHRON_MID_DATA_PORT:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_port),
					     prog_update_data_port);
	case ISOCHRON_MID_SCHED_FIFO_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_sched_fifo);
	case ISOCHRON_MID_SCHED_RR_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_sched_rr);
	case ISOCHRON_MID_SCHED_PRIORITY:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_sched_priority),
					     prog_update_sched_priority);
	case ISOCHRON_MID_CPU_MASK:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_cpu_mask),
					     prog_update_cpu_mask);
	case ISOCHRON_MID_TEST_STATE:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_test_state),
					     prog_update_test_state);
	case ISOCHRON_MID_SYNC_MONITOR_ENABLED:
		return isochron_mgmt_tlv_set(fd, tlv, prog, mid,
					     sizeof(struct isochron_feature_enabled),
					     prog_update_sync_monitor_enabled);
	default:
		fprintf(stderr, "Unhandled SET for MID %d\n", mid);
		isochron_send_empty_tlv(prog->stats_fd, mid);
		return 0;
	}
}

static int prog_forward_isochron_log(struct isochron_daemon *prog)
{
	struct isochron_send *send = prog->send;
	int rc;

	if (!send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	rc = isochron_send_tlv(prog->stats_fd, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(&send->log));
	if (rc)
		return 0;

	isochron_log_xmit(&send->log, prog->stats_fd);
	isochron_log_teardown(&send->log);
	return isochron_log_init(&send->log, send->iterations *
				 sizeof(struct isochron_send_pkt_data));
}

static int prog_forward_sysmon_offset(struct isochron_daemon *prog)
{
	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (!prog->send->sysmon) {
		fprintf(stderr, "Sender sysmon not instantiated\n");
		return -EINVAL;
	}

	return isochron_forward_sysmon_offset(prog->stats_fd,
					      prog->send->sysmon);
}

static int prog_forward_ptpmon_offset(struct isochron_daemon *prog)
{
	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (!prog->send->ptpmon) {
		fprintf(stderr, "Sender ptpmon not instantiated\n");
		return -EINVAL;
	}

	return isochron_forward_ptpmon_offset(prog->stats_fd,
					      prog->send->ptpmon);
}

static int prog_forward_utc_offset(struct isochron_daemon *prog)
{
	int rc, utc_offset;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (!prog->send->ptpmon) {
		fprintf(stderr, "Sender ptpmon not instantiated\n");
		return -EINVAL;
	}

	rc = isochron_forward_utc_offset(prog->stats_fd, prog->send->ptpmon,
					 &utc_offset);
	if (rc)
		return rc;

	isochron_fixup_kernel_utc_offset(utc_offset);
	prog->send->utc_tai_offset = utc_offset;

	return 0;
}

static int prog_forward_port_state(struct isochron_daemon *prog)
{
	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (!prog->send->ptpmon) {
		fprintf(stderr, "Sender ptpmon not instantiated\n");
		return -EINVAL;
	}

	if (!strlen(prog->send->if_name)) {
		fprintf(stderr, "Sender interface not specified\n");
		return -EINVAL;
	}

	return isochron_forward_port_state(prog->stats_fd, prog->send->ptpmon,
					   prog->send->if_name, prog->rtnl);
}

static int prog_forward_gm_clock_identity(struct isochron_daemon *prog)
{
	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (!prog->send->ptpmon) {
		fprintf(stderr, "Sender ptpmon not instantiated\n");
		return -EINVAL;
	}

	return isochron_forward_gm_clock_identity(prog->stats_fd,
						  prog->send->ptpmon);
}

static int prog_forward_test_state(struct isochron_daemon *prog)
{
	enum test_state state;

	if (!prog->send) {
		fprintf(stderr, "Sender role not instantiated\n");
		return -EINVAL;
	}

	if (prog->send->send_tid_stopped)
		state = ISOCHRON_TEST_STATE_IDLE;
	else
		state = ISOCHRON_TEST_STATE_RUNNING;

	return isochron_forward_test_state(prog->stats_fd, state);
}

static int prog_mgmt_tlv_get(void *priv, struct isochron_tlv *tlv)
{
	enum isochron_management_id mid = __be16_to_cpu(tlv->management_id);
	struct isochron_daemon *prog = priv;

	switch (mid) {
	case ISOCHRON_MID_LOG:
		return prog_forward_isochron_log(prog);
	case ISOCHRON_MID_SYSMON_OFFSET:
		return prog_forward_sysmon_offset(prog);
	case ISOCHRON_MID_PTPMON_OFFSET:
		return prog_forward_ptpmon_offset(prog);
	case ISOCHRON_MID_UTC_OFFSET:
		return prog_forward_utc_offset(prog);
	case ISOCHRON_MID_PORT_STATE:
		return prog_forward_port_state(prog);
	case ISOCHRON_MID_GM_CLOCK_IDENTITY:
		return prog_forward_gm_clock_identity(prog);
	case ISOCHRON_MID_TEST_STATE:
		return prog_forward_test_state(prog);
	default:
		fprintf(stderr, "Unhandled GET for MID %d\n", mid);
		isochron_send_empty_tlv(prog->stats_fd, mid);
		return 0;
	}
}

static int prog_mgmt_loop(struct isochron_daemon __attribute__((unused)) *prog)
{
	struct pollfd pfd[1] = {
		[0] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
	};
	bool socket_closed;
	int rc = 0;
	int cnt;

	do {
		if (prog->have_client)
			pfd[0].fd = prog->stats_fd;
		else
			pfd[0].fd = prog->stats_listenfd;

		cnt = poll(pfd, ARRAY_SIZE(pfd), -1);
		if (cnt < 0) {
			if (errno == EINTR) {
				break;
			} else {
				perror("poll failed");
				rc = -errno;
				break;
			}
		} else if (!cnt) {
			printf("poll returned 0\n");
			break;
		}

		if (pfd[0].revents & (POLLIN | POLLERR | POLLPRI)) {
			if (prog->have_client) {
				rc = isochron_mgmt_event(prog->stats_fd, prog,
							 prog_mgmt_tlv_get,
							 prog_mgmt_tlv_set,
							 &socket_closed);
				if (socket_closed)
					prog_close_client_stats_session(prog);
				if (rc)
					break;
			} else {
				rc = prog_client_connect_event(prog);
				if (rc)
					break;
			}
		}

		if (signal_received)
			break;
	} while (1);

	if (prog->have_client)
		prog_close_client_stats_session(prog);

	return rc;
}

static int prog_init_stats_listenfd(struct isochron_daemon *prog)
{
	struct sockaddr_in serv_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(prog->stats_port),
		.sin_zero = {0},
	};
	int sockopt = 1;
	int fd, rc;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("listener: stats socket");
		return -errno;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));
	if (rc < 0) {
		perror("setsockopt: stats socket");
		goto out;
	}

	rc = bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (rc < 0) {
		perror("bind: stats socket");
		goto out;
	}

	rc = listen(fd, 1);
	if (rc < 0) {
		perror("listen: stats socket");
		goto out;
	}

	prog->stats_listenfd = fd;

	return 0;

out:
	close(fd);
	return -errno;
}

static void prog_teardown_stats_listenfd(struct isochron_daemon *prog)
{
	close(prog->stats_listenfd);
}

static int prog_redirect_output(struct isochron_daemon *prog)
{
	FILE *log_file;
	int dev_null;

	dev_null = open("/dev/null", O_RDONLY);
	if (dev_null < 0) {
		perror("open /dev/null");
		return -errno;
	}

	dup2(dev_null, STDIN_FILENO);

	if (!strlen(prog->log_filename)) {
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);
		return 0;
	}

	log_file = freopen(prog->log_filename, "w", stdout);
	if (!log_file) {
		perror("freopen");
		return -errno;
	}

	setlinebuf(log_file);

	dup2(STDOUT_FILENO, STDERR_FILENO);

	return 0;
}

static int prog_daemonize(struct isochron_daemon *prog)
{
	FILE *pid_file = NULL;
	pid_t pid;

	if (strlen(prog->pid_filename)) {
		pid_file = fopen(prog->pid_filename, "w");
		if (!pid_file) {
			perror("pid file open");
			goto err_pid_file_open;
		}
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto err_fork;
	}

	if (pid > 0) {
		/* Parent */
		if (pid_file) {
			fprintf(pid_file, "%d", pid);
			fclose(pid_file);
		}

		exit(EXIT_SUCCESS);
	}

	/* Child */
	if (setsid() < 0)
		return -errno;

	return prog_redirect_output(prog);

err_fork:
	if (pid_file)
		fclose(pid_file);
err_pid_file_open:
	return -errno;
}

static int prog_rtnl_open(struct isochron_daemon *prog)
{
	struct mnl_socket *nl;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		perror("mnl_socket_open");
		return -errno;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		mnl_socket_close(nl);
		return -errno;
	}

	prog->rtnl = nl;

	return 0;
}

static void prog_rtnl_close(struct isochron_daemon *prog)
{
	struct mnl_socket *nl = prog->rtnl;

	prog->rtnl = NULL;
	mnl_socket_close(nl);
}

static int prog_init(struct isochron_daemon *prog)
{
	int rc;

	rc = prog_rtnl_open(prog);
	if (rc)
		goto err_rtnl;

	rc = prog_init_stats_listenfd(prog);
	if (rc)
		goto err_statsfd;

	rc = prog_daemonize(prog);
	if (rc) {
		fprintf(stderr, "prog_daemonize returned %d\n", rc);
		goto err_daemonize;
	}

	rc = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rc < 0) {
		perror("mlockall failed");
		goto err_mlockall;
	}

	return 0;

err_mlockall:
err_daemonize:
	prog_teardown_stats_listenfd(prog);
err_statsfd:
	prog_rtnl_close(prog);
err_rtnl:
	return rc;
}

static void prog_teardown(struct isochron_daemon *prog)
{
	munlockall();
	prog_teardown_stats_listenfd(prog);
	prog_rtnl_close(prog);
}

static int prog_parse_args(int argc, char **argv, struct isochron_daemon *prog)
{
	bool help = false;
	struct prog_arg args[] = {
		{
			.short_opt = "-h",
			.long_opt = "--help",
			.type = PROG_ARG_HELP,
			.help_ptr = {
			        .ptr = &help,
			},
			.optional = true,
		}, {
			.short_opt = "-p",
			.long_opt = "--pid-file",
			.type = PROG_ARG_FILEPATH,
			.filepath = {
				.buf = prog->pid_filename,
				.size = PATH_MAX - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-l",
			.long_opt = "--log-file",
			.type = PROG_ARG_FILEPATH,
			.filepath = {
				.buf = prog->log_filename,
				.size = PATH_MAX - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-P",
			.long_opt = "--stats-port",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->stats_port,
			},
			.optional = true,
		},
	};
	int rc;

	rc = prog_parse_np_args(argc, argv, args, ARRAY_SIZE(args));

	/* Non-positional arguments left unconsumed */
	if (rc < 0) {
		pr_err(rc, "argument parsing failed: %m\n");
		return rc;
	} else if (rc < argc) {
		fprintf(stderr, "%d unconsumed arguments. First: %s\n",
			argc - rc, argv[rc]);
		prog_usage("isochron-rcv", args, ARRAY_SIZE(args));
		return -1;
	}

	if (help) {
		prog_usage("isochron-daemon", args, ARRAY_SIZE(args));
		return -1;
	}

	if (!prog->stats_port)
		prog->stats_port = ISOCHRON_STATS_PORT;

	return 0;
}

int isochron_daemon_main(int argc, char *argv[])
{
	struct isochron_daemon prog = {0};
	int rc;

	rc = isochron_handle_signals(sig_handler);
	if (rc)
		return rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_init(&prog);
	if (rc < 0)
		return rc;

	rc = prog_mgmt_loop(&prog);

	prog_teardown(&prog);

	return rc;
}
