// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 NXP */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "management.h"
#include "send.h"
#include "sk.h"
#include "syncmon.h"

struct isochron_orch_node;

struct isochron_orch_node {
	enum isochron_role role;
	LIST_ENTRY(isochron_orch_node) list;
	char name[BUFSIZ];
	struct ip_address addr;
	unsigned long port;
	struct sk *mgmt_sock;
	long sync_threshold;
	bool collect_sync_stats;
	union {
		/* ISOCHRON_ROLE_SEND */
		struct {
			struct isochron_send *send;
			enum test_state test_state;
			char exec[BUFSIZ];
			__s64 oper_base_time;
			size_t num_rtt_measurements;
			__s64 rtt;
			__s64 max_rtt;
		};
		/* ISOCHRON_ROLE_RCV */
		struct {
			struct isochron_orch_node *sender;
		};
	};
};

struct isochron_orch {
	LIST_HEAD(nodes_head, isochron_orch_node) nodes;
	char input_filename[PATH_MAX];
	struct syncmon *syncmon;
};

static void isochron_node_rtt_init(struct isochron_orch_node *node)
{
	node->max_rtt = 0;
	node->num_rtt_measurements = 0;
}

static void isochron_node_rtt_before(struct isochron_orch_node *node)
{
	struct timespec now_ts;

	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	node->rtt = -timespec_to_ns(&now_ts);
}

static void isochron_node_rtt_after(struct isochron_orch_node *node)
{
	struct timespec now_ts;

	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	node->rtt += timespec_to_ns(&now_ts);
	node->num_rtt_measurements++;

	if (node->max_rtt < node->rtt)
		node->max_rtt = node->rtt;
}

static void isochron_node_rtt_finalize(struct isochron_orch_node *node)
{
	printf("Max TCP round trip time to node %s over %zu measurements is %lld ns\n",
	       node->name, node->num_rtt_measurements, node->max_rtt);
}

static int prog_query_test_state(struct isochron_orch_node *node,
				 enum test_state *state)
{
	struct isochron_test_state t;
	int rc;

	rc = isochron_query_mid(node->mgmt_sock, ISOCHRON_MID_TEST_STATE,
				&t, sizeof(t));
	if (rc) {
		fprintf(stderr, "Test state missing from node %s reply\n",
			node->name);
		return rc;
	}

	*state = t.test_state;

	return 0;
}

static bool prog_all_senders_stopped(void *priv)
{
	struct isochron_orch *prog = priv;
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		if (node->test_state != ISOCHRON_TEST_STATE_RUNNING)
			continue;

		rc = prog_query_test_state(node, &node->test_state);
		if (rc)
			return false;

		if (node->test_state == ISOCHRON_TEST_STATE_RUNNING)
			return false;
	}

	return true;
}

static struct isochron_orch_node *
prog_find_synchronized_sender(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		if (node->collect_sync_stats)
			return node;
	}

	return NULL;
}

static int prog_calculate_oper_base_times(struct isochron_orch *prog)
{
	struct isochron_orch_node *node, *ref, *tmp;
	struct isochron_orch_node **sorted_senders;
	struct isochron_send *send;
	size_t num_senders = 0;
	size_t i, j, k = 0;
	__s64 now;
	int rc;

	ref = prog_find_synchronized_sender(prog);
	if (!ref) {
		/* All senders are unsynchronized, use their base time as-is */
		LIST_FOREACH(node, &prog->nodes, list) {
			if (node->role != ISOCHRON_ROLE_SEND)
				continue;

			node->oper_base_time = node->send->base_time;
		}

		return 0;
	}

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		num_senders++;
	}

	sorted_senders = calloc(num_senders, sizeof(*sorted_senders));
	if (!sorted_senders) {
		rc = -ENOMEM;
		goto out;
	}

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		sorted_senders[k] = node;
		k++;
	}

	/* Sort the sender list by their original base times */
	for (i = 0; i < num_senders; i++) {
		for (j = i + 1; j < num_senders; j++) {
			if (sorted_senders[i]->send->base_time >
			    sorted_senders[j]->send->base_time) {
				tmp = sorted_senders[i];
				sorted_senders[i] = sorted_senders[j];
				sorted_senders[j] = tmp;
			}
		}
	}

	/* Since the nodes should be synchronized by now, it's enough to
	 * pick the current CLOCK_TAI of only one "reference" sender
	 */
	rc = isochron_query_current_clock_tai(ref->mgmt_sock, &now);
	if (rc)
		goto out_free_sorted_senders;

	/* The retrieved CLOCK_TAI value was taken half an RTT ago,
	 * update it with one full RTT to be on the safe side.
	 */
	now += ref->max_rtt;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		/* Adjust for the time it takes to update
		 * ISOCHRON_MID_BASE_TIME and ISOCHRON_MID_TEST_STATE
		 * for all senders
		 */
		now += 2 * node->max_rtt;
		/* Every node's PHC time is within +/- a margin of its PTP
		 * master, and its CLOCK_TAI is within +/- a margin of its PHC
		 * time. Furthermore, we don't really know the offset to the
		 * GM. So assume the worst case - a PTP linear topology - and
		 * account for twice the sync threshold for every node.
		 */
		if (node->send->sync_threshold)
			now += 2 * node->send->sync_threshold;
		else
			now += 2 * ref->send->sync_threshold;
	}

	now += TIME_MARGIN;

	/* Finally advance each sender's base time into the operational value
	 * in the common future, according to its own cycle time.
	 */
	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		send = node->send;
		/* Each sender takes its sweet time to ensure the first wakeup
		 * time is at least TIME_MARGIN into the future. We need to
		 * overcome that extra time and make sure the time we're
		 * passing it into the future by even more than that, to
		 * prevent the sender from auto-advancing it and make it use
		 * what we provided as-is.
		 */
		send->session_start = now;
		node->oper_base_time = isochron_send_first_base_time(send);
	}

	/* Produce equivalently sorted numbers by advancing the operational
	 * base times again such that the sort order by original base times
	 * (given by their position in the array) is preserved.
	 * Every node's oper base time needs to be higher than its previous
	 * element from the sorted list.
	 */
	for (i = 1; i < num_senders; i++) {
		node = sorted_senders[i];
		tmp = sorted_senders[i - 1];

		node->oper_base_time = future_base_time(node->oper_base_time,
							node->send->cycle_time,
							tmp->oper_base_time);
	}

out_free_sorted_senders:
	free(sorted_senders);
out:
	return rc;
}

static int prog_update_sender_base_times(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	rc = prog_calculate_oper_base_times(prog);
	if (rc)
		return rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		rc = isochron_update_base_time(node->mgmt_sock,
					       node->oper_base_time);
		if (rc) {
			fprintf(stderr,
				"failed to update base time for node %s\n",
				node->name);
			return rc;
		}
	}

	return 0;
}

static void prog_print_sender_base_times(struct isochron_orch *prog)
{
	char oper_base_time_buf[TIMESPEC_BUFSIZ];
	char cycle_time_buf[TIMESPEC_BUFSIZ];
	char base_time_buf[TIMESPEC_BUFSIZ];
	struct isochron_orch_node *node;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		ns_sprintf(oper_base_time_buf, node->oper_base_time);
		ns_sprintf(cycle_time_buf, node->send->cycle_time);
		ns_sprintf(base_time_buf, node->send->base_time);
		printf("Node %s: base time %s (operational %s), cycle time %s\n",
		       node->name, base_time_buf, oper_base_time_buf,
		       cycle_time_buf);
	}
}

static bool prog_validate_oper_base_time(struct isochron_orch_node *node)
{
	char their_oper_base_time_buf[TIMESPEC_BUFSIZ];
	char our_oper_base_time_buf[TIMESPEC_BUFSIZ];
	__s64 oper_base_time;
	int rc;

	if (node->oper_base_time == node->send->base_time)
		return true;

	/* Node had its base time auto-advanced by us, check if it
	 * actually used that for the test or if the margin was too low
	 */
	rc = isochron_query_oper_base_time(node->mgmt_sock, &oper_base_time);
	if (rc) {
		pr_err(rc, "Failed to read back node %s operational base time: %m\n",
		       node->name);
		return false;
	}

	if (oper_base_time == node->oper_base_time)
		return true;

	ns_sprintf(our_oper_base_time_buf, node->oper_base_time);
	ns_sprintf(their_oper_base_time_buf, oper_base_time);
	printf("Node %s had to advance our operational base time %s to %s, repeating test\n",
	       node->name, our_oper_base_time_buf, their_oper_base_time_buf);

	return false;
}

static bool prog_validate_test_exit_code(struct isochron_orch_node *node)
{
	struct isochron_error err;
	int rc;

	if (node->test_state != ISOCHRON_TEST_STATE_FAILED)
		return true;

	rc = isochron_query_mid_error(node->mgmt_sock, ISOCHRON_MID_TEST_STATE,
				      &err);
	if (rc) {
		pr_err(rc,
		       "Failed to retrieve test exit code for node %s: %m\n",
		       node->name);
		return false;
	}

	fprintf(stderr, "Node %s failed, repeating test: %s\n",
		node->name, err.extack);

	return false;
}

static bool prog_validate_test(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		if (!prog_validate_oper_base_time(node))
			return false;

		if (!prog_validate_test_exit_code(node))
			return false;
	}

	return true;
}

static int prog_start_senders(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	rc = prog_update_sender_base_times(prog);
	if (rc)
		return rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		rc = isochron_update_test_state(node->mgmt_sock,
						ISOCHRON_TEST_STATE_RUNNING);
		if (rc) {
			pr_err(rc, "Failed to start node %s: %m\n", node->name);
			return rc;
		}

		node->test_state = ISOCHRON_TEST_STATE_RUNNING;
	}

	prog_print_sender_base_times(prog);

	return 0;
}

static int prog_stop_senders(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		rc = isochron_update_test_state(node->mgmt_sock,
						ISOCHRON_TEST_STATE_IDLE);
		if (rc) {
			pr_err(rc, "Failed to stop node %s: %m\n", node->name);
			return rc;
		}
	}

	return 0;
}

static struct syncmon_node *
prog_add_syncmon_sender(struct syncmon *syncmon,
			struct isochron_orch_node *node)
{
	struct isochron_send *send = node->send;

	if (node->collect_sync_stats)
		return syncmon_add_remote_sender(syncmon, node->name,
						 node->mgmt_sock,
						 send->iterations,
						 send->cycle_time,
						 send->sync_threshold);
	else
		return syncmon_add_remote_sender_no_sync(syncmon, node->name,
							 node->mgmt_sock,
							 send->iterations,
							 send->cycle_time);
}

static struct syncmon_node *
prog_add_syncmon_receiver(struct syncmon *syncmon,
			  struct isochron_orch_node *node,
			  struct syncmon_node *pair)
{
	if (node->collect_sync_stats)
		return syncmon_add_remote_receiver(syncmon, node->name,
						   node->mgmt_sock, pair,
						   node->sync_threshold);
	else
		return syncmon_add_remote_receiver_no_sync(syncmon, node->name,
							   node->mgmt_sock,
							   pair);
}

static int prog_init_syncmon(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	struct syncmon *syncmon;
	struct syncmon_node *sn;

	syncmon = syncmon_create();
	if (!syncmon)
		return -ENOMEM;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_RCV)
			continue;

		sn = prog_add_syncmon_sender(syncmon, node->sender);
		if (!sn) {
			syncmon_destroy(syncmon);
			return -ENOMEM;
		}

		sn = prog_add_syncmon_receiver(syncmon, node, sn);
		if (!sn) {
			syncmon_destroy(syncmon);
			return -ENOMEM;
		}
	}

	prog->syncmon = syncmon;

	return 0;
}

static int prog_collect_logs(struct isochron_orch *prog)
{
	struct isochron_orch_node *node, *sender;
	struct isochron_log send_log, rcv_log;
	struct isochron_send *send;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role != ISOCHRON_ROLE_RCV)
			continue;

		sender = node->sender;
		send = sender->send;

		printf("Collecting stats from %s\n", sender->name);
		rc = isochron_collect_rcv_log(sender->mgmt_sock, &send_log);
		if (rc) {
			pr_err(rc, "Failed to collect sender stats: %m\n");
			return rc;
		}

		printf("Collecting stats from %s\n", node->name);
		rc = isochron_collect_rcv_log(node->mgmt_sock, &rcv_log);
		if (rc) {
			pr_err(rc, "Failed to collect receiver stats: %m\n");
			isochron_log_teardown(&send_log);
			return rc;
		}

		rc = isochron_log_save(send->output_file, &send_log,
				       &rcv_log, send->iterations,
				       send->tx_len, send->omit_sync,
				       send->do_ts, send->taprio,
				       send->txtime, send->deadline,
				       send->base_time, send->advance_time,
				       send->shift_time, send->cycle_time,
				       send->window_size);
		isochron_log_teardown(&send_log);
		isochron_log_teardown(&rcv_log);

		if (rc) {
			pr_err(rc, "Failed to save log: %m\n");
			return rc;
		}
	}

	return 0;
}

static int prog_run_test(struct isochron_orch *prog)
{
	bool sync_ok, test_valid;
	int rc;

	rc = prog_init_syncmon(prog);
	if (rc)
		return rc;

	do {
		/* Adapt sync check intervals to new realities */
		syncmon_init(prog->syncmon);

		rc = syncmon_wait_until_ok(prog->syncmon);
		if (rc) {
			pr_err(rc, "Failed to check sync status: %m\n");
			goto out;
		}

		rc = prog_start_senders(prog);
		if (rc)
			goto out;

		sync_ok = syncmon_monitor(prog->syncmon,
					  prog_all_senders_stopped,
					  prog);

		test_valid = prog_validate_test(prog);

		if (sync_ok && test_valid) {
			rc = prog_collect_logs(prog);
			if (rc)
				goto out;
		}

		rc = prog_stop_senders(prog);
		if (rc)
			goto out;

		if (signal_received) {
			rc = -EINTR;
			goto out;
		}
	} while (!sync_ok || !test_valid);

out:
	syncmon_destroy(prog->syncmon);

	return rc;
}

static int prog_marshall_data_to_receiver(struct isochron_orch_node *node)
{
	struct isochron_orch_node *sender = node->sender;

	return isochron_prepare_receiver(sender->send, node->mgmt_sock);
}

static int prog_marshall_data_to_sender(struct isochron_orch_node *node)
{
	struct isochron_send *send = node->send;
	const char *if_name = send->if_name;
	struct sk *sock = node->mgmt_sock;
	int rc;

	isochron_node_rtt_init(node);

	isochron_node_rtt_before(node);
	rc = isochron_update_node_role(sock, ISOCHRON_ROLE_SEND);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update role for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_if_name(sock, if_name);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update interface name for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_destination_mac(sock, send->dest_mac);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update MAC DA for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_source_mac(sock, send->src_mac);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update MAC SA for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_priority(sock, send->priority);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update priority for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_stats_port(sock, send->stats_port);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update stats port for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_advance_time(sock, send->advance_time);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update advance time for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_shift_time(sock, send->shift_time);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update shift time for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_cycle_time(sock, send->cycle_time);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update cycle time for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_window_size(sock, send->window_size);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update window size for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_domain_number(sock, send->domain_number);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update domain number for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_transport_specific(sock,
						send->transport_specific);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update transport specific for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_uds(sock, send->uds_remote);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update UDS for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_num_readings(sock, send->num_readings);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update number of readings for node %s\n",
			node->name);
		return rc;
	}

	if (!send->omit_sync) {
		isochron_node_rtt_before(node);
		rc = isochron_update_sysmon_enabled(sock, true);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr, "failed to enable sysmon for node %s\n",
				node->name);
			return rc;
		}

		isochron_node_rtt_before(node);
		rc = isochron_update_ptpmon_enabled(sock, true);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr, "failed to enable ptpmon for node %s\n",
				node->name);
			return rc;
		}
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_sync_monitor_enabled(sock, false);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr,
			"failed to disable local sync monitoring for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_packet_size(sock, send->tx_len);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update packet size for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_ts_enabled(sock, send->do_ts);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable timestamping for node %s\n",
			node->name);
		return rc;
	}

	if (send->vid >= 0) {
		isochron_node_rtt_before(node);
		rc = isochron_update_vid(sock, send->vid);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr,
				"failed to update VLAN ID for node %s\n",
				node->name);
			return rc;
		}
	}

	if (send->etype >= 0) {
		isochron_node_rtt_before(node);
		rc = isochron_update_ethertype(sock, send->etype);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr,
				"failed to update EtherType for node %s\n",
				node->name);
			return rc;
		}
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_quiet_enabled(sock, send->quiet);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to make node %s quiet\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_taprio_enabled(sock, send->taprio);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable taprio for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_txtime_enabled(sock, send->txtime);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable txtime for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_deadline_enabled(sock, send->deadline);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable deadline for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_packet_count(sock, send->iterations);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update packet count for node %s\n",
			node->name);
		return rc;
	}

	if (send->utc_tai_offset >= 0) {
		isochron_node_rtt_before(node);
		rc = isochron_update_utc_offset(sock, send->utc_tai_offset);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr,
				"failed to update UTC offset for node %s\n",
				node->name);
			return rc;
		}
	}

	if (send->ip_destination.family) {
		isochron_node_rtt_before(node);
		rc = isochron_update_ip_destination(sock,
						    &send->ip_destination);
		isochron_node_rtt_after(node);
		if (rc) {
			fprintf(stderr,
				"failed to update IP destination for node %s\n",
				node->name);
			return rc;
		}
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_l2_enabled(sock, send->l2);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable L2 transport for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_l4_enabled(sock, send->l4);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable L4 transport for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_data_port(sock, send->data_port);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to set data port for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_sched_fifo(sock, send->sched_fifo);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable SCHED_FIFO for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_sched_rr(sock, send->sched_rr);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to enable SCHED_RR for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_sched_priority(sock, send->sched_priority);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to update sched priority for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_before(node);
	rc = isochron_update_cpu_mask(sock, send->cpumask);
	isochron_node_rtt_after(node);
	if (rc) {
		fprintf(stderr, "failed to set CPU mask for node %s\n",
			node->name);
		return rc;
	}

	isochron_node_rtt_finalize(node);

	return 0;
}

static int prog_query_receiver_mac_address(struct isochron_orch_node *node)
{
	struct isochron_orch_node *sender = node->sender;
	struct isochron_mac_addr mac;
	char mac_buf[MACADDR_BUFSIZ];
	int rc;

	if (!sender->send->l2)
		return 0;

	if (!is_zero_ether_addr(sender->send->dest_mac))
		return 0;

	rc = isochron_query_mid(node->mgmt_sock, ISOCHRON_MID_DESTINATION_MAC,
				&mac, sizeof(mac));
	if (rc) {
		fprintf(stderr,
			"Destination MAC missing from node %s reply\n",
			node->name);
		return rc;
	}

	ether_addr_copy(sender->send->dest_mac, mac.addr);

	mac_addr_sprintf(mac_buf, sender->send->dest_mac);
	printf("Destination MAC address of %s is %s\n", node->name, mac_buf);

	return 0;
}

static int prog_drain_receiver_log(struct isochron_orch_node *node)
{
	struct isochron_log rcv_log;
	int rc;

	rc = isochron_collect_rcv_log(node->mgmt_sock, &rcv_log);
	if (rc)
		return rc;

	isochron_log_teardown(&rcv_log);

	return 0;
}

static int prog_marshall_data_from_receiver(struct isochron_orch_node *node)
{
	int rc;

	rc = prog_query_receiver_mac_address(node);
	if (rc)
		return rc;

	rc = prog_drain_receiver_log(node);
	if (rc)
		return rc;

	return 0;
}

static int prog_marshall_data_from_nodes(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role == ISOCHRON_ROLE_RCV) {
			rc = prog_marshall_data_from_receiver(node);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static int prog_marshall_data_to_nodes(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		if (node->role == ISOCHRON_ROLE_SEND) {
			rc = prog_marshall_data_to_sender(node);
			if (rc)
				return rc;
		} else if (node->role == ISOCHRON_ROLE_RCV) {
			rc = prog_marshall_data_to_receiver(node);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static int prog_open_node_connection(struct isochron_orch_node *node)
{
	int rc;

	if (!node->port)
		node->port = ISOCHRON_STATS_PORT;

	if (node->addr.family != AF_INET && node->addr.family != AF_INET6) {
		fprintf(stderr, "Node %s missing a \"host\" property\n",
			node->name);
		return -EINVAL;
	}

	rc = sk_connect_tcp(&node->addr, node->port, &node->mgmt_sock);
	if (rc) {
		fprintf(stderr, "Failed to connect to node %s: %m\n",
			node->name);
		return rc;
	}

	printf("Connected to node %s\n", node->name);

	return 0;
}

static int prog_validate_node(struct isochron_orch_node *node)
{
	if (!strlen(node->exec)) {
		fprintf(stderr, "exec line missing from node %s\n", node->name);
		return -EINVAL;
	}

	return 0;
}

static int prog_init_sender_nodes(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		rc = prog_validate_node(node);
		if (rc)
			return rc;

		node->collect_sync_stats = !node->send->omit_sync;
		node->sync_threshold = node->send->sync_threshold;
	}

	return 0;
}

static int prog_init_receiver_nodes(struct isochron_orch *prog)
{
	struct isochron_orch_node *node, *rcv_node, *tmp;
	struct isochron_send *send;
	int rc;

	LIST_FOREACH_SAFE(node, &prog->nodes, list, tmp) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		send = node->send;

		if (!send->stats_srv.family)
			continue;

		rcv_node = calloc(sizeof(*rcv_node), 1);
		if (!rcv_node)
			return -ENOMEM;

		rc = snprintf(rcv_node->name, BUFSIZ, "%s's receiver",
			      node->name);
		if (rc >= BUFSIZ) {
			fprintf(stderr,
				"Truncation while parsing node \"%s\"'s name\n",
				node->name);
			free(rcv_node);
			return -EINVAL;
		}

		rcv_node->addr = send->stats_srv;
		rcv_node->port = send->stats_port;
		rcv_node->collect_sync_stats = !send->omit_sync &&
					       !send->omit_remote_sync;
		rcv_node->sync_threshold = send->sync_threshold;
		rcv_node->role = ISOCHRON_ROLE_RCV;
		rcv_node->sender = node;
		LIST_INSERT_HEAD(&prog->nodes, rcv_node, list);
	}

	return 0;
}

static void prog_close_node_connection(struct isochron_orch_node *node)
{
	if (!node->mgmt_sock)
		return;

	sk_close(node->mgmt_sock);
}

static int prog_open_node_connections(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

	LIST_FOREACH(node, &prog->nodes, list) {
		rc = prog_open_node_connection(node);
		if (rc)
			return rc;
	}

	return 0;
}

static void prog_teardown(struct isochron_orch *prog)
{
	struct isochron_orch_node *node, *tmp;

	LIST_FOREACH_SAFE(node, &prog->nodes, list, tmp) {
		prog_close_node_connection(node);
		if (node->role == ISOCHRON_ROLE_SEND)
			free(node->send);
		LIST_REMOVE(node, list);
		free(node);
	}
}

static int prog_exec_node_argparser(struct isochron_orch_node *node,
				    int argc, char **argv,
				    const char *value)
{
	const struct isochron_prog *prog;
	int rc;

	rc = isochron_parse_args(&argc, &argv, &prog);
	if (rc)
		return rc;

	if (prog->main == isochron_send_main) {
		rc = isochron_send_parse_args(argc, argv, node->send);
	} else {
		fprintf(stderr,
			"Unsupported exec line \"%s\" for node %s\n",
			value, node->name);
		rc = -EINVAL;
	}

	return rc;
}

static int prog_parse_exec_line(struct isochron_orch_node *node,
				const char *value)
{
	size_t i, len = strlen(value);
	bool curr_char_is_quote;
	int argc = 0, k = 0;
	char last_quote = 0;
	char prev = 0;
	char **argv;
	int rc;

	for (i = 0; i < len; i++) {
		curr_char_is_quote = (value[i] == '\'' || value[i] == '"');

		if (last_quote && value[i] == last_quote)
			/* unquote */
			last_quote = 0;
		else if (curr_char_is_quote)
			/* quote and remember starting character */
			last_quote = value[i];

		if (curr_char_is_quote || (!last_quote && isspace(value[i])))
			node->exec[i] = 0;
		else
			node->exec[i] = value[i];

		if (node->exec[i] && !prev)
			argc++;

		prev = node->exec[i];
	}

	node->exec[len] = 0;

	argv = calloc(argc, sizeof(char *));
	if (!argv) {
		fprintf(stderr, "low memory\n");
		return -ENOMEM;
	}

	prev = 0;

	for (i = 0; i < len; i++) {
		if (node->exec[i] && !prev)
			argv[k++] = &node->exec[i];

		prev = node->exec[i];
	}

	rc = prog_exec_node_argparser(node, argc, argv, value);

	free(argv);

	return rc;
}

static int prog_parse_key_value(struct isochron_orch_node *node,
				const char *key, const char *value)
{
	int rc;

	if (strcmp(key, "host") == 0) {
		rc = ip_addr_from_string(value, &node->addr);
		if (rc) {
			fprintf(stderr, "Invalid IP address \"%s\" for host %s\n",
				value, node->name);
			return rc;
		}
	} else if (strcmp(key, "port") == 0) {
		errno = 0;
		node->port = strtoul(value, NULL, 0);
		if (errno) {
			fprintf(stderr, "Invalid port \"%s\" for host %s\n",
				value, node->name);
			return -errno;
		}
	} else if (strcmp(key, "exec") == 0) {
		rc = prog_parse_exec_line(node, value);
		if (rc)
			return rc;
	} else {
		fprintf(stderr, "Unrecognized key %s\n", key);
	}

	return 0;
}

static int prog_parse_input_file_linewise(struct isochron_orch *prog,
					  char *buf)
{
	struct isochron_orch_node *curr_node = NULL;
	char *end, *equal, *key, *value;
	char *line = strtok(buf, "\n");
	struct isochron_send *send;
	size_t len;
	int rc = 0;

	LIST_INIT(&prog->nodes);

	while (line) {
		line = string_trim_comments(line);
		line = string_trim_whitespaces(line);

		len = strlen(line);
		if (!len)
			goto next;

		if (len >= BUFSIZ) {
			fprintf(stderr, "Line too long: \"%s\"\n", line);
			rc = -EINVAL;
			break;
		}

		end = line + len - 1;

		if (*line == '[') {
			if (*end != ']') {
				fprintf(stderr,
					"Unterminated section header on line: \"%s\"\n",
					buf);
				rc = -EINVAL;
				break;
			}

			curr_node = calloc(sizeof(*curr_node), 1);
			if (!curr_node) {
				rc = -ENOMEM;
				break;
			}

			send = calloc(sizeof(*send), 1);
			if (!send) {
				free(curr_node);
				rc = -ENOMEM;
				break;
			}

			memcpy(curr_node->name, line + 1, len - 2);
			LIST_INSERT_HEAD(&prog->nodes, curr_node, list);
			curr_node->role = ISOCHRON_ROLE_SEND;
			curr_node->send = send;
			goto next;
		}

		if (!curr_node) {
			fprintf(stderr, "Unexpected line \"%s\" belonging to no section\n",
				buf);
			rc = -EINVAL;
			break;
		}

		equal = line;
		strsep(&equal, "=");
		if (!equal) {
			fprintf(stderr,
				"Invalid format for line \"%s\", expected \"<key> = <value>\"\n",
				line);
			rc = -EINVAL;
			break;
		}

		key = string_trim_whitespaces(line);
		value = string_trim_whitespaces(equal);

		rc = prog_parse_key_value(curr_node, key, value);
		if (rc)
			break;

next:
		line = strtok(NULL, "\n");
	}

	return rc;
}

static int prog_parse_input_file(struct isochron_orch *prog)
{
	struct stat sb;
	int rc, fd;
	char *buf;

	fd = open(prog->input_filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		rc = -errno;
		goto err_open;
	}

	rc = fstat(fd, &sb);
	if (rc) {
		perror("fstat");
		rc = -errno;
		goto err_fstat;
	}

	/* Allow multi-line statements by mmapping the entire file
	 * and replacing escape sequences first
	 */
	buf = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		rc = -errno;
		goto err_mmap;
	}

	string_replace_escape_sequences(buf);

	rc = prog_parse_input_file_linewise(prog, buf);

	munmap(buf, sb.st_size);

err_mmap:
err_fstat:
	close(fd);
err_open:
	return rc;
}

static int prog_parse_args(int argc, char **argv, struct isochron_orch *prog)
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
			.short_opt = "-F",
			.long_opt = "--input-file",
			.type = PROG_ARG_FILEPATH,
			.filepath = {
				.buf = prog->input_filename,
				.size = PATH_MAX - 1,
			},
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
		prog_usage("isochron-orchestrate", args, ARRAY_SIZE(args));
		return -1;
	}

	return 0;
}

int isochron_orchestrate_main(int argc, char *argv[])
{
	struct isochron_orch prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		return rc;

	rc = prog_parse_input_file(&prog);
	if (rc)
		goto out;

	rc = prog_init_sender_nodes(&prog);
	if (rc)
		goto out;

	rc = prog_init_receiver_nodes(&prog);
	if (rc)
		goto out;

	rc = prog_open_node_connections(&prog);
	if (rc)
		goto out;

	rc = prog_marshall_data_from_nodes(&prog);
	if (rc)
		goto out;

	rc = prog_marshall_data_to_nodes(&prog);
	if (rc)
		goto out;

	rc = prog_run_test(&prog);

out:
	prog_teardown(&prog);

	return rc;
}
