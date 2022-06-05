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

#define SYNC_CHECKS_TO_GO 3

struct isochron_orch_node;

struct isochron_orch_node {
	enum isochron_role role;
	LIST_ENTRY(isochron_orch_node) list;
	char name[BUFSIZ];
	struct ip_address addr;
	unsigned long port;
	struct sk *mgmt_sock;
	long sync_threshold;
	struct clock_identity gm_clkid;
	enum port_link_state link_state;
	enum port_state port_state;
	bool collect_sync_stats;
	__s64 ptpmon_offset;
	__s64 sysmon_offset;
	union {
		/* ISOCHRON_ROLE_SEND */
		struct {
			struct isochron_send *send;
			enum test_state test_state;
			char exec[BUFSIZ];
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
};

static int prog_query_link_state(struct isochron_orch_node *node)
{
	struct isochron_port_link_state s;
	enum port_link_state link_state;
	int rc;

	rc = isochron_query_mid(node->mgmt_sock, ISOCHRON_MID_PORT_LINK_STATE,
				&s, sizeof(s));
	if (rc) {
		fprintf(stderr,
			"Port link state missing from node %s reply\n",
			node->name);
		return rc;
	}

	link_state = s.link_state;

	if (node->link_state == link_state)
		return 0;

	node->link_state = link_state;
	if (node->link_state == PORT_LINK_STATE_RUNNING)
		printf("Link state of node %s is running\n", node->name);
	if (node->link_state == PORT_LINK_STATE_DOWN)
		printf("Link state of node %s is down\n", node->name);

	return 0;
}

static bool prog_sync_ok(struct isochron_orch *prog)
{
	bool port_transient_state, any_port_transient_state = false;
	bool ptpmon_sync_done, all_ptpmon_sync_done = true;
	bool sysmon_sync_done, all_sysmon_sync_done = true;
	struct isochron_orch_node *first_node = NULL;
	struct isochron_orch_node *node, *sender;
	char now_buf[TIMESPEC_BUFSIZ];
	enum port_state port_state;
	bool any_link_down = false;
	struct timespec now_ts;
	bool same_gm = true;
	int utc_offset;
	__s64 now;
	int rc;

	clock_gettime(CLOCK_TAI, &now_ts);
	now = timespec_to_ns(&now_ts);
	ns_sprintf(now_buf, now);

	LIST_FOREACH(node, &prog->nodes, list) {
		rc = prog_query_link_state(node);
		if (rc)
			return false;

		if (node->link_state != PORT_LINK_STATE_RUNNING)
			any_link_down = true;

		if (!node->collect_sync_stats)
			continue;

		rc = isochron_collect_sync_stats(node->mgmt_sock,
						 &node->sysmon_offset,
						 &node->ptpmon_offset,
						 &utc_offset,
						 &port_state,
						 &node->gm_clkid);
		if (rc)
			return false;

		if (port_state != node->port_state) {
			printf("Node %s port changed state to %s\n",
			       node->name, port_state_to_string(port_state));
			node->port_state = port_state;
		}

		if (!first_node) {
			first_node = node;
		} else if (!clockid_eq(&node->gm_clkid, &first_node->gm_clkid)) {
			char node1_gm[CLOCKID_BUFSIZE];
			char node2_gm[CLOCKID_BUFSIZE];

			clockid_to_string(&node->gm_clkid, node1_gm);
			clockid_to_string(&first_node->gm_clkid, node2_gm);

			printf("Nodes not synchronized to the same grandmaster, %s has %s, %s has %s\n",
			       node->name, node1_gm, first_node->name, node2_gm);
			same_gm = false;
		}

		node->sysmon_offset += NSEC_PER_SEC * utc_offset;

		port_transient_state = port_state != PS_MASTER &&
				       port_state != PS_SLAVE;

		ptpmon_sync_done = !!(llabs(node->ptpmon_offset) <= node->sync_threshold);
		sysmon_sync_done = !!(llabs(node->sysmon_offset) <= node->sync_threshold);

		if (port_transient_state)
			any_port_transient_state = true;
		if (!ptpmon_sync_done)
			all_ptpmon_sync_done = false;
		if (!sysmon_sync_done)
			all_sysmon_sync_done = false;
	}

	LIST_FOREACH(node, &prog->nodes, list) {
		/* Iterate through receivers so we can use the node->sender
		 * backpointer to catch both the sender and receiver in the
		 * same print line.
		 */
		if (node->role != ISOCHRON_ROLE_RCV)
			continue;

		sender = node->sender;

		if (node->collect_sync_stats && sender->collect_sync_stats) {
			printf("isochron[%s]: %s ptpmon %10lld sysmon %10lld receiver ptpmon %10lld sysmon %10lld\n",
			       now_buf, sender->name, sender->ptpmon_offset, sender->sysmon_offset,
			       node->ptpmon_offset, node->sysmon_offset);
		} else if (sender->collect_sync_stats) {
			/* In case --omit-remote-sync is used */
			printf("isochron[%s]: %s ptpmon %10lld sysmon %10lld\n",
			       now_buf, sender->name, sender->ptpmon_offset, sender->sysmon_offset);
		}
	}

	return !any_link_down && !any_port_transient_state && same_gm &&
	       all_ptpmon_sync_done && all_sysmon_sync_done;
}

static int prog_wait_until_sync_ok(struct isochron_orch *prog)
{
	int sync_checks_to_go = SYNC_CHECKS_TO_GO;

	while (1) {
		if (signal_received)
			return -EINTR;

		if (prog_sync_ok(prog))
			sync_checks_to_go--;

		if (!sync_checks_to_go)
			break;

		sleep(1);
	}

	return 0;
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

static bool prog_all_senders_stopped(struct isochron_orch *prog)
{
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

static bool prog_monitor_sync(struct isochron_orch *prog)
{
	int sync_checks_to_go = SYNC_CHECKS_TO_GO;

	while (!prog_all_senders_stopped(prog)) {
		if (signal_received)
			return false;

		if (!prog_sync_ok(prog))
			sync_checks_to_go--;

		if (!sync_checks_to_go) {
			fprintf(stderr,
				"Sync lost during the test, repeating\n");
			return false;
		}

		sleep(1);
	}

	return true;
}

static int prog_start_senders(struct isochron_orch *prog)
{
	struct isochron_orch_node *node;
	int rc;

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

static int prog_run_test(struct isochron_orch *prog)
{
	bool sync_ok;
	int rc;

	rc = prog_wait_until_sync_ok(prog);
	if (rc) {
		pr_err(rc, "Failed to check sync status: %m\n");
		return rc;
	}

	do {
		rc = prog_start_senders(prog);
		if (rc)
			return rc;

		sync_ok = prog_monitor_sync(prog);

		rc = prog_stop_senders(prog);
		if (rc)
			return rc;

		if (signal_received) {
			rc = -EINTR;
			break;
		}
	} while (!sync_ok);

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

	rc = isochron_update_node_role(sock, ISOCHRON_ROLE_SEND);
	if (rc) {
		fprintf(stderr, "failed to update role for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_if_name(sock, if_name);
	if (rc) {
		fprintf(stderr, "failed to update interface name for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_destination_mac(sock, send->dest_mac);
	if (rc) {
		fprintf(stderr, "failed to update MAC DA for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_source_mac(sock, send->src_mac);
	if (rc) {
		fprintf(stderr, "failed to update MAC SA for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_priority(sock, send->priority);
	if (rc) {
		fprintf(stderr, "failed to update priority for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_stats_port(sock, send->stats_port);
	if (rc) {
		fprintf(stderr, "failed to update stats port for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_base_time(sock, send->base_time);
	if (rc) {
		fprintf(stderr, "failed to update base time for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_advance_time(sock, send->advance_time);
	if (rc) {
		fprintf(stderr, "failed to update advance time for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_shift_time(sock, send->shift_time);
	if (rc) {
		fprintf(stderr, "failed to update shift time for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_cycle_time(sock, send->cycle_time);
	if (rc) {
		fprintf(stderr, "failed to update cycle time for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_window_size(sock, send->window_size);
	if (rc) {
		fprintf(stderr, "failed to update window size for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_domain_number(sock, send->domain_number);
	if (rc) {
		fprintf(stderr, "failed to update domain number for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_transport_specific(sock,
						send->transport_specific);
	if (rc) {
		fprintf(stderr, "failed to update transport specific for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_uds(sock, send->uds_remote);
	if (rc) {
		fprintf(stderr, "failed to update UDS for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_num_readings(sock, send->num_readings);
	if (rc) {
		fprintf(stderr, "failed to update number of readings for node %s\n",
			node->name);
		return rc;
	}

	if (!send->omit_sync) {
		rc = isochron_update_sysmon_enabled(sock, true);
		if (rc) {
			fprintf(stderr, "failed to enable sysmon for node %s\n",
				node->name);
			return rc;
		}

		rc = isochron_update_ptpmon_enabled(sock, true);
		if (rc) {
			fprintf(stderr, "failed to enable ptpmon for node %s\n",
				node->name);
			return rc;
		}
	}

	rc = isochron_update_sync_monitor_enabled(sock, false);
	if (rc) {
		fprintf(stderr,
			"failed to disable local sync monitoring for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_packet_size(sock, send->tx_len);
	if (rc) {
		fprintf(stderr, "failed to update packet size for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_ts_enabled(sock, send->do_ts);
	if (rc) {
		fprintf(stderr, "failed to enable timestamping for node %s\n",
			node->name);
		return rc;
	}

	if (send->vid >= 0) {
		rc = isochron_update_vid(sock, send->vid);
		if (rc) {
			fprintf(stderr,
				"failed to update VLAN ID for node %s\n",
				node->name);
			return rc;
		}
	}

	if (send->etype >= 0) {
		rc = isochron_update_ethertype(sock, send->etype);
		if (rc) {
			fprintf(stderr,
				"failed to update EtherType for node %s\n",
				node->name);
			return rc;
		}
	}

	rc = isochron_update_quiet_enabled(sock, send->quiet);
	if (rc) {
		fprintf(stderr, "failed to make node %s quiet\n",
			node->name);
		return rc;
	}

	rc = isochron_update_taprio_enabled(sock, send->taprio);
	if (rc) {
		fprintf(stderr, "failed to enable taprio for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_txtime_enabled(sock, send->txtime);
	if (rc) {
		fprintf(stderr, "failed to enable txtime for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_deadline_enabled(sock, send->deadline);
	if (rc) {
		fprintf(stderr, "failed to enable deadline for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_packet_count(sock, send->iterations);
	if (rc) {
		fprintf(stderr, "failed to update packet count for node %s\n",
			node->name);
		return rc;
	}

	if (send->utc_tai_offset >= 0) {
		rc = isochron_update_utc_offset(sock, send->utc_tai_offset);
		if (rc) {
			fprintf(stderr,
				"failed to update UTC offset for node %s\n",
				node->name);
			return rc;
		}
	}

	if (send->ip_destination.family) {
		rc = isochron_update_ip_destination(sock,
						    &send->ip_destination);
		if (rc) {
			fprintf(stderr,
				"failed to update IP destination for node %s\n",
				node->name);
			return rc;
		}
	}

	rc = isochron_update_l2_enabled(sock, send->l2);
	if (rc) {
		fprintf(stderr, "failed to enable L2 transport for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_l4_enabled(sock, send->l4);
	if (rc) {
		fprintf(stderr, "failed to enable L4 transport for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_data_port(sock, send->data_port);
	if (rc) {
		fprintf(stderr, "failed to set data port for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_sched_fifo(sock, send->sched_fifo);
	if (rc) {
		fprintf(stderr, "failed to enable SCHED_FIFO for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_sched_rr(sock, send->sched_rr);
	if (rc) {
		fprintf(stderr, "failed to enable SCHED_RR for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_sched_priority(sock, send->sched_priority);
	if (rc) {
		fprintf(stderr, "failed to update sched priority for node %s\n",
			node->name);
		return rc;
	}

	rc = isochron_update_cpu_mask(sock, send->cpumask);
	if (rc) {
		fprintf(stderr, "failed to set CPU mask for node %s\n",
			node->name);
		return rc;
	}

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
	if (rc)
		goto out;

	rc = prog_collect_logs(&prog);

out:
	prog_teardown(&prog);

	return rc;
}
