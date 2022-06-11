// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 NXP */

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
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
#include "rtnl.h"
#include "send.h"
#include "sk.h"
#include "sysmon.h"

struct isochron_daemon {
	struct ip_address stats_addr;
	long stats_port;
	char pid_filename[PATH_MAX];
	char log_filename[PATH_MAX];
	struct isochron_mgmt_handler *mgmt_handler;
	struct sk *mgmt_listen_sock;
	struct sk *mgmt_sock;
	bool have_client;
	struct isochron_send *send;
	struct mnl_socket *rtnl;
	bool session_active;
};

static int prog_check_admin_state(struct isochron_daemon *prog)
{
	const char *if_name = prog->send->if_name;
	bool up;
	int rc;

	rc = rtnl_query_admin_state(prog->rtnl, if_name, &up);
	if (rc) {
		pr_err(rc, "Failed to query port %s admin state: %m\n",
		       if_name);
		return rc;
	}

	if (!up) {
		fprintf(stderr, "Interface %s is administratively down\n",
			if_name);
		return -ENETDOWN;
	}

	return 0;
}

static int prog_prepare_send_session(struct isochron_daemon *prog)
{
	struct isochron_send *send = prog->send;
	int rc;

	/* Hack to suppress local log output to the filesystem, since
	 * isochron_send_interpret_args() makes the default output_file
	 * isochron.dat, and this triggers a validation error when a sender
	 * session is restarted.
	 */
	send->output_file[0] = 0;

	rc = isochron_send_interpret_args(send);
	if (rc)
		return rc;

	rc = isochron_send_init_data_sock(send);
	if (rc)
		goto err_init_data_sock;

	isochron_send_init_data_packet(send);
	isochron_send_init_thread_state(send);

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

	prog->session_active = true;

	return 0;

err_start_threads:
err_update_session_start:
	isochron_log_teardown(&send->log);
err_log_init:
	isochron_send_teardown_data_sock(send);
err_init_data_sock:
	return rc;
}

static void prog_teardown_send_session(struct isochron_daemon *prog)
{
	struct isochron_send *send = prog->send;

	prog->session_active = false;
	isochron_send_stop_threads(send);
	isochron_log_teardown(&send->log);
	isochron_send_teardown_data_sock(send);
}

static void isochron_teardown_sender(struct isochron_daemon *prog)
{
	struct isochron_send *send = prog->send;

	if (!send)
		return;

	if (prog->session_active)
		prog_teardown_send_session(prog);

	if (send->ptpmon)
		isochron_send_teardown_ptpmon(send);
	if (send->sysmon)
		isochron_send_teardown_sysmon(send);

	free(send);
	prog->send = NULL;
}

static void prog_close_client_stats_session(struct isochron_daemon *prog)
{
	isochron_teardown_sender(prog);
	sk_close(prog->mgmt_sock);
	prog->have_client = false;
}

static int prog_client_connect_event(struct isochron_daemon *prog)
{
	int rc;

	rc = sk_accept(prog->mgmt_listen_sock, &prog->mgmt_sock);
	if (rc)
		return rc;

	prog->have_client = true;

	return 0;
}

static int prog_update_role(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_node_role *r = ptr;
	struct isochron_send *send;

	if (__be32_to_cpu(r->role) != ISOCHRON_ROLE_SEND) {
		mgmt_extack(extack, "Unexpected node role %d",
			    __be32_to_cpu(r->role));
		return -EINVAL;
	}

	send = calloc(1, sizeof(*send));
	if (!send) {
		mgmt_extack(extack,
			    "failed to allocate memory for new sender");
		return -ENOMEM;
	}

	isochron_send_prepare_default_args(send);

	isochron_teardown_sender(prog);

	prog->send = send;

	return 0;
}

static int prog_update_utc_offset(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_utc_offset *u = ptr;
	int offset;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	offset = __be16_to_cpu(u->offset);
	isochron_fixup_kernel_utc_offset(offset);
	prog->send->utc_tai_offset = offset;

	return 0;
}

static int prog_update_packet_count(void *priv, void *ptr, char *extack)
{
	struct isochron_packet_count *p = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->iterations = __be64_to_cpu(p->count);

	return 0;
}

static int prog_update_packet_size(void *priv, void *ptr, char *extack)
{
	struct isochron_packet_size *p = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->tx_len = __be32_to_cpu(p->size);

	return 0;
}

static int prog_update_destination_mac(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_mac_addr *m = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	ether_addr_copy(prog->send->dest_mac, m->addr);

	return 0;
}

static int prog_update_source_mac(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_mac_addr *m = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	ether_addr_copy(prog->send->src_mac, m->addr);

	return 0;
}

static int prog_update_if_name(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	struct isochron_if_name *n = ptr;
	int rc;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	rc = if_name_copy(send->if_name, n->name);
	if (rc) {
		mgmt_extack(extack, "Truncation while copying string");
		return rc;
	}

	return 0;
}

static int prog_update_priority(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_priority *p = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->priority = __be32_to_cpu(p->priority);

	return 0;
}

static int prog_update_stats_port(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_port *p = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->stats_port = __be16_to_cpu(p->port);

	return 0;
}

static int prog_update_base_time(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->base_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_advance_time(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->advance_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_shift_time(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->shift_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_cycle_time(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->cycle_time = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_window_size(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_time *t = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->window_size = (__s64)__be64_to_cpu(t->time);

	return 0;
}

static int prog_update_sysmon_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
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

static int prog_update_ptpmon_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (f->enabled) {
		if (prog->send->ptpmon) {
			mgmt_extack(extack, "ptpmon already enabled");
			return -EINVAL;
		}

		return isochron_send_init_ptpmon(prog->send);
	} else {
		if (!prog->send->ptpmon) {
			mgmt_extack(extack, "ptpmon not enabled");
			return -EINVAL;
		}

		isochron_send_teardown_ptpmon(prog->send);
	}

	return 0;
}

static int prog_update_uds(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	struct isochron_uds *u = ptr;
	int rc;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	rc = uds_copy(send->uds_remote, u->name);
	if (rc) {
		mgmt_extack(extack, "Truncation while copying string");
		return rc;
	}

	return 0;
}

static int prog_update_domain_number(void *priv, void *ptr, char *extack)
{
	struct isochron_domain_number *d = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->domain_number = d->domain_number;

	return 0;
}

static int prog_update_transport_specific(void *priv, void *ptr, char *extack)
{
	struct isochron_transport_specific *t = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->transport_specific = t->transport_specific;

	return 0;
}

static int prog_update_num_readings(void *priv, void *ptr, char *extack)
{
	struct isochron_num_readings *n = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->num_readings = __be32_to_cpu(n->num_readings);

	return 0;
}

static int prog_update_ts_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->do_ts = f->enabled;

	return 0;
}

static int prog_update_vid(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_vid *v = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->vid = __be16_to_cpu(v->vid);

	return 0;
}

static int prog_update_ethertype(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_ethertype *e = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->etype = (__s16)__be16_to_cpu(e->ethertype);

	return 0;
}

static int prog_update_quiet_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->quiet = f->enabled;

	return 0;
}

static int prog_update_taprio_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->taprio = f->enabled;

	return 0;
}

static int prog_update_txtime_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->txtime = f->enabled;

	return 0;
}

static int prog_update_deadline_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->deadline = f->enabled;

	return 0;
}

static int prog_update_ip_destination(void *priv, void *ptr, char *extack)
{
	struct isochron_ip_address *i = ptr;
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	int rc;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	send->ip_destination.family = __be32_to_cpu(i->family);
	rc = if_name_copy(send->ip_destination.bound_if_name,
			  i->bound_if_name);
	if (rc) {
		mgmt_extack(extack, "Truncation while copying string");
		return rc;
	}

	return 0;
}

static int prog_update_l2_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->l2 = f->enabled;

	return 0;
}

static int prog_update_l4_enabled(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->l4 = f->enabled;

	return 0;
}

static int prog_update_data_port(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_port *p = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->data_port = __be16_to_cpu(p->port);

	return 0;
}

static int prog_update_sched_fifo(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->sched_fifo = f->enabled;

	return 0;
}

static int prog_update_sched_rr(void *priv, void *ptr, char *extack)
{
	struct isochron_feature_enabled *f = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->sched_rr = f->enabled;

	return 0;
}

static int prog_update_sched_priority(void *priv, void *ptr, char *extack)
{
	struct isochron_sched_priority *s = ptr;
	struct isochron_daemon *prog = priv;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->sched_priority = __be32_to_cpu(s->sched_priority);

	return 0;
}

static int prog_update_cpu_mask(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_cpu_mask *c = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->cpumask = __be64_to_cpu(c->cpu_mask);

	return 0;
}

static int prog_update_test_state(void *priv, void *ptr, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_test_state *s = ptr;
	int rc;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (s->test_state == ISOCHRON_TEST_STATE_IDLE) {
		if (!prog->session_active) {
			mgmt_extack(extack, "Sender already idle");
			return -EINVAL;
		}

		prog_teardown_send_session(prog);
	} else if (s->test_state == ISOCHRON_TEST_STATE_RUNNING) {
		if (prog->session_active) {
			mgmt_extack(extack, "Sender already running a test");
			return -EINVAL;
		}

		rc = prog_check_admin_state(prog);
		if (rc)
			return rc;

		rc = prog_prepare_send_session(prog);
		if (rc)
			return rc;
	}

	return 0;
}

static int prog_update_sync_monitor_enabled(void *priv, void *ptr,
					    char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_feature_enabled *f = ptr;

	if (!prog->send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	prog->send->omit_sync = !f->enabled;

	return 0;
}

static int prog_forward_isochron_log(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	int rc;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!prog->session_active) {
		mgmt_extack(extack, "Log exists only while session is active");
		return -EINVAL;
	}

	rc = isochron_send_tlv(prog->mgmt_sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_LOG,
			       isochron_log_buf_tlv_size(&send->log));
	if (rc)
		return rc;

	isochron_log_xmit(&send->log, prog->mgmt_sock);
	isochron_log_teardown(&send->log);
	return isochron_log_init(&send->log, send->iterations *
				 sizeof(struct isochron_send_pkt_data));
}

static int prog_forward_sysmon_offset(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!send->sysmon) {
		mgmt_extack(extack, "Sender sysmon not instantiated");
		return -EINVAL;
	}

	return isochron_forward_sysmon_offset(prog->mgmt_sock,
					      send->sysmon, extack);
}

static int prog_forward_ptpmon_offset(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!send->ptpmon) {
		mgmt_extack(extack, "Sender ptpmon not instantiated");
		return -EINVAL;
	}

	return isochron_forward_ptpmon_offset(prog->mgmt_sock,
					      send->ptpmon, extack);
}

static int prog_forward_utc_offset(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	int rc, utc_offset;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!send->ptpmon) {
		mgmt_extack(extack, "Sender ptpmon not instantiated");
		return -EINVAL;
	}

	rc = isochron_forward_utc_offset(prog->mgmt_sock, send->ptpmon,
					 &utc_offset, extack);
	if (rc)
		return rc;

	isochron_fixup_kernel_utc_offset(utc_offset);
	prog->send->utc_tai_offset = utc_offset;

	return 0;
}

static int prog_forward_port_state(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!send->ptpmon) {
		mgmt_extack(extack, "Sender ptpmon not instantiated");
		return -EINVAL;
	}

	if (!strlen(send->if_name)) {
		mgmt_extack(extack, "Sender interface not specified");
		return -EINVAL;
	}

	return isochron_forward_port_state(prog->mgmt_sock, send->ptpmon,
					   send->if_name, prog->rtnl, extack);
}

static int prog_forward_port_link_state(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	return isochron_forward_port_link_state(prog->mgmt_sock, send->if_name,
						prog->rtnl, extack);
}

static int prog_forward_gm_clock_identity(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!send->ptpmon) {
		mgmt_extack(extack, "Sender ptpmon not instantiated");
		return -EINVAL;
	}

	return isochron_forward_gm_clock_identity(prog->mgmt_sock,
						  send->ptpmon, extack);
}

static int prog_forward_test_state(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	enum test_state test_state;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	if (!prog->session_active) {
		test_state = ISOCHRON_TEST_STATE_IDLE;
	} else if (send->tx_tstamp_tid_stopped) {
		test_state = ISOCHRON_TEST_STATE_IDLE;

		if (send->tx_timestamp_tid_rc) {
			mgmt_extack(extack, "TX timestamping thread failed");
			test_state = ISOCHRON_TEST_STATE_FAILED;
		}

		if (send->send_tid_rc) {
			mgmt_extack(extack, "Sender thread failed");
			test_state = ISOCHRON_TEST_STATE_FAILED;
		}
	} else {
		test_state = ISOCHRON_TEST_STATE_RUNNING;
	}

	return isochron_forward_test_state(prog->mgmt_sock, test_state, extack);
}

static int prog_forward_current_clock_tai(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;

	return isochron_forward_current_clock_tai(prog->mgmt_sock, extack);
}

static int prog_forward_oper_base_time(void *priv, char *extack)
{
	struct isochron_daemon *prog = priv;
	struct isochron_send *send = prog->send;
	struct isochron_time t = {};
	int rc;

	if (!send) {
		mgmt_extack(extack, "Sender role not instantiated");
		return -EINVAL;
	}

	t.time = __cpu_to_be64(send->oper_base_time);

	rc = isochron_send_tlv(prog->mgmt_sock, ISOCHRON_RESPONSE,
			       ISOCHRON_MID_OPER_BASE_TIME, sizeof(t));
	if (rc)
		return rc;

	sk_send(prog->mgmt_sock, &t, sizeof(t));

	return 0;
}

static const struct isochron_mgmt_ops daemon_mgmt_ops[__ISOCHRON_MID_MAX] = {
	[ISOCHRON_MID_LOG] = {
		.get = prog_forward_isochron_log,
	},
	[ISOCHRON_MID_SYSMON_OFFSET] = {
		.get = prog_forward_sysmon_offset,
	},
	[ISOCHRON_MID_PTPMON_OFFSET] = {
		.get = prog_forward_ptpmon_offset,
	},
	[ISOCHRON_MID_UTC_OFFSET] = {
		.get = prog_forward_utc_offset,
		.set = prog_update_utc_offset,
		.struct_size = sizeof(struct isochron_utc_offset),
	},
	[ISOCHRON_MID_PORT_STATE] = {
		.get = prog_forward_port_state,
	},
	[ISOCHRON_MID_PORT_LINK_STATE] = {
		.get = prog_forward_port_link_state,
	},
	[ISOCHRON_MID_GM_CLOCK_IDENTITY] = {
		.get = prog_forward_gm_clock_identity,
	},
	[ISOCHRON_MID_TEST_STATE] = {
		.get = prog_forward_test_state,
		.set = prog_update_test_state,
		.struct_size = sizeof(struct isochron_test_state),
	},
	[ISOCHRON_MID_CURRENT_CLOCK_TAI] = {
		.get = prog_forward_current_clock_tai,
	},
	[ISOCHRON_MID_OPER_BASE_TIME] = {
		.get = prog_forward_oper_base_time,
	},
	[ISOCHRON_MID_NODE_ROLE] = {
		.set = prog_update_role,
		.struct_size = sizeof(struct isochron_node_role),
	},
	[ISOCHRON_MID_PACKET_COUNT] = {
		.struct_size = sizeof(struct isochron_packet_count),
		.set = prog_update_packet_count,
	},
	[ISOCHRON_MID_PACKET_SIZE] = {
		.set = prog_update_packet_size,
		.struct_size = sizeof(struct isochron_packet_size),
	},
	[ISOCHRON_MID_DESTINATION_MAC] = {
		.set = prog_update_destination_mac,
		.struct_size = sizeof(struct isochron_mac_addr),
	},
	[ISOCHRON_MID_SOURCE_MAC] = {
		.set = prog_update_source_mac,
		.struct_size = sizeof(struct isochron_mac_addr),
	},
	[ISOCHRON_MID_IF_NAME] = {
		.set = prog_update_if_name,
		.struct_size = sizeof(struct isochron_if_name),
	},
	[ISOCHRON_MID_PRIORITY] = {
		.set = prog_update_priority,
		.struct_size = sizeof(struct isochron_priority),
	},
	[ISOCHRON_MID_STATS_PORT] = {
		.set = prog_update_stats_port,
		.struct_size = sizeof(struct isochron_port),
	},
	[ISOCHRON_MID_BASE_TIME] = {
		.set = prog_update_base_time,
		.struct_size = sizeof(struct isochron_time),
	},
	[ISOCHRON_MID_ADVANCE_TIME] = {
		.set = prog_update_advance_time,
		.struct_size = sizeof(struct isochron_time),
	},
	[ISOCHRON_MID_SHIFT_TIME] = {
		.set = prog_update_shift_time,
		.struct_size = sizeof(struct isochron_time),
	},
	[ISOCHRON_MID_CYCLE_TIME] = {
		.set = prog_update_cycle_time,
		.struct_size = sizeof(struct isochron_time),
	},
	[ISOCHRON_MID_WINDOW_SIZE] = {
		.set = prog_update_window_size,
		.struct_size = sizeof(struct isochron_time),
	},
	[ISOCHRON_MID_SYSMON_ENABLED] = {
		.set = prog_update_sysmon_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_PTPMON_ENABLED] = {
		.set = prog_update_ptpmon_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_UDS] = {
		.set = prog_update_uds,
		.struct_size = sizeof(struct isochron_uds),
	},
	[ISOCHRON_MID_DOMAIN_NUMBER] = {
		.set = prog_update_domain_number,
		.struct_size = sizeof(struct isochron_domain_number),
	},
	[ISOCHRON_MID_TRANSPORT_SPECIFIC] = {
		.set = prog_update_transport_specific,
		.struct_size = sizeof(struct isochron_transport_specific),
	},
	[ISOCHRON_MID_NUM_READINGS] = {
		.set = prog_update_num_readings,
		.struct_size = sizeof(struct isochron_num_readings),
	},
	[ISOCHRON_MID_TS_ENABLED] = {
		.set = prog_update_ts_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_VID] = {
		.set = prog_update_vid,
		.struct_size = sizeof(struct isochron_vid),
	},
	[ISOCHRON_MID_ETHERTYPE] = {
		.set = prog_update_ethertype,
		.struct_size = sizeof(struct isochron_ethertype),
	},
	[ISOCHRON_MID_QUIET_ENABLED] = {
		.set = prog_update_quiet_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_TAPRIO_ENABLED] = {
		.set = prog_update_taprio_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_TXTIME_ENABLED] = {
		.set = prog_update_txtime_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_DEADLINE_ENABLED] = {
		.set = prog_update_deadline_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_IP_DESTINATION] = {
		.set = prog_update_ip_destination,
		.struct_size = sizeof(struct isochron_ip_address),
	},
	[ISOCHRON_MID_L2_ENABLED] = {
		.set = prog_update_l2_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_L4_ENABLED] = {
		.set = prog_update_l4_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_DATA_PORT] = {
		.set = prog_update_data_port,
		.struct_size = sizeof(struct isochron_port),
	},
	[ISOCHRON_MID_SCHED_FIFO_ENABLED] = {
		.set = prog_update_sched_fifo,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_SCHED_RR_ENABLED] = {
		.set = prog_update_sched_rr,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
	[ISOCHRON_MID_SCHED_PRIORITY] = {
		.set = prog_update_sched_priority,
		.struct_size = sizeof(struct isochron_sched_priority),
	},
	[ISOCHRON_MID_CPU_MASK] = {
		.set = prog_update_cpu_mask,
		.struct_size = sizeof(struct isochron_cpu_mask),
	},
	[ISOCHRON_MID_SYNC_MONITOR_ENABLED] = {
		.set = prog_update_sync_monitor_enabled,
		.struct_size = sizeof(struct isochron_feature_enabled),
	},
};

static int prog_mgmt_loop(struct isochron_daemon *prog)
{
	struct pollfd pfd[1] = {
		[0] = {
			/* .fd to be filled in dynamically */
			.events = POLLIN | POLLERR | POLLPRI,
		},
	};
	int rc = 0;
	int cnt;

	do {
		if (prog->have_client)
			pfd[0].fd = sk_fd(prog->mgmt_sock);
		else
			pfd[0].fd = sk_fd(prog->mgmt_listen_sock);

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
				rc = isochron_mgmt_event(prog->mgmt_sock,
							 prog->mgmt_handler,
							 prog);
				if (sk_closed(prog->mgmt_sock))
					prog_close_client_stats_session(prog);
				else if (rc)
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

static int prog_init_mgmt_listen_sock(struct isochron_daemon *prog)
{
	int rc;

	prog->mgmt_handler = isochron_mgmt_handler_create(daemon_mgmt_ops);
	if (!prog->mgmt_handler)
		return -ENOMEM;

	rc = sk_listen_tcp(&prog->stats_addr, prog->stats_port, 1,
			   &prog->mgmt_listen_sock);
	if (rc)
		isochron_mgmt_handler_destroy(prog->mgmt_handler);

	return rc;
}

static void prog_teardown_mgmt_listen_sock(struct isochron_daemon *prog)
{
	sk_close(prog->mgmt_listen_sock);
	isochron_mgmt_handler_destroy(prog->mgmt_handler);
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
	close(dev_null);

	if (!strlen(prog->log_filename)) {
		/* Redirect stdout and stderr to /dev/null too */
		dup2(STDIN_FILENO, STDOUT_FILENO);
		dup2(STDIN_FILENO, STDERR_FILENO);
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

		prog_teardown_mgmt_listen_sock(prog);
		prog_rtnl_close(prog);
		exit(EXIT_SUCCESS);
	}

	if (pid_file)
		fclose(pid_file);

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

static int prog_init(struct isochron_daemon *prog)
{
	int rc;

	rc = prog_rtnl_open(prog);
	if (rc)
		goto err_rtnl;

	rc = prog_init_mgmt_listen_sock(prog);
	if (rc)
		goto err_mgmt_sock;

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
	prog_teardown_mgmt_listen_sock(prog);
err_mgmt_sock:
	prog_rtnl_close(prog);
err_rtnl:
	return rc;
}

static void prog_teardown(struct isochron_daemon *prog)
{
	munlockall();
	prog_teardown_mgmt_listen_sock(prog);
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
		}, {
			.short_opt = "-S",
			.long_opt = "--stats-address",
			.type = PROG_ARG_IP,
			.ip_ptr = {
			        .ptr = &prog->stats_addr,
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
