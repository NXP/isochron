/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#include <errno.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <time.h>

#include "common.h"
#include "isochron.h"
#include "management.h"
#include "rtnl.h"
#include "syncmon.h"

#define NUM_SYNC_CHECKS	 3

struct syncmon_node {
	bool remote;
	union {
		/* remote */
		struct {
			struct sk *mgmt_sock;
		};
		/* local */
		struct {
			struct mnl_socket *rtnl;
			const char *if_name;
			struct ptpmon *ptpmon;
			struct sysmon *sysmon;
		};
	};
	const char *name;
	enum isochron_role role;
	struct syncmon_node *pair;
	size_t num_pkts;
	__s64 cycle_time;
	__s64 sync_threshold;
	bool collect_sync_stats;
	bool gm_warned;
	bool ptpmon_sync_done;
	bool sysmon_sync_done;
	bool transient_port_state;
	struct clock_identity gm_clkid;
	enum port_link_state link_state;
	enum port_state port_state;
	__s64 ptpmon_offset;
	__s64 sysmon_offset;
	LIST_ENTRY(syncmon_node) list;
};

struct syncmon {
	struct timespec ts;
	size_t num_checks;
	__s64 monitor_interval;
	__s64 initial_interval;
	bool same_gm;
	LIST_HEAD(nodes_head, syncmon_node) nodes;
};

static const struct clock_identity clockid_zero;

static int syncmon_node_query_link_state_remote(struct syncmon_node *node,
						enum port_link_state *link_state)
{
	struct isochron_port_link_state s;
	int rc;

	rc = isochron_query_mid(node->mgmt_sock, ISOCHRON_MID_PORT_LINK_STATE,
				&s, sizeof(s));
	if (rc) {
		fprintf(stderr,
			"Port link state missing from node %s reply\n",
			node->name);
		return rc;
	}

	*link_state = s.link_state;

	return 0;
}

static int syncmon_node_query_link_state_local(struct syncmon_node *node,
					       enum port_link_state *link_state)
{
	bool running;
	int rc;

	rc = rtnl_query_link_state(node->rtnl, node->if_name, &running);
	if (rc) {
		pr_err(rc, "Failed to query port %s link state: %m\n",
		       node->if_name);
		return rc;
	}

	*link_state = running ? PORT_LINK_STATE_RUNNING : PORT_LINK_STATE_DOWN;

	return 0;
}

static int syncmon_node_update_link_state(struct syncmon_node *node)
{
	enum port_link_state link_state;
	int rc;

	if (node->remote)
		rc = syncmon_node_query_link_state_remote(node, &link_state);
	else
		rc = syncmon_node_query_link_state_local(node, &link_state);
	if (rc)
		return rc;

	if (node->link_state == link_state)
		return 0;

	node->link_state = link_state;
	if (node->link_state == PORT_LINK_STATE_RUNNING)
		printf("Link state of node %s is running\n", node->name);
	if (node->link_state == PORT_LINK_STATE_DOWN)
		printf("Link state of node %s is down\n", node->name);

	return 0;
}

static int syncmon_node_query_sync_local(struct syncmon_node *node,
					 __s64 *sysmon_offset,
					 __s64 *ptpmon_offset, int *utc_offset,
					 enum port_state *port_state,
					 struct clock_identity *gm_clkid)
{
	struct time_properties_ds time_properties_ds;
	struct parent_data_set parent_ds;
	struct current_ds current_ds;
	__s64 sysmon_delay;
	__u64 sysmon_ts;
	int rc;

	rc = ptpmon_query_port_state_by_name(node->ptpmon, node->if_name,
					     node->rtnl, port_state);
	if (rc) {
		pr_err(rc, "ptpmon failed to query port state: %m\n");
		return rc;
	}

	rc = ptpmon_query_clock_mid(node->ptpmon, MID_PARENT_DATA_SET,
				    &parent_ds, sizeof(parent_ds));
	if (rc) {
		pr_err(rc, "ptpmon failed to query grandmaster clock id: %m\n");
		return rc;
	}

	rc = ptpmon_query_clock_mid(node->ptpmon, MID_CURRENT_DATA_SET,
				    &current_ds, sizeof(current_ds));
	if (rc) {
		pr_err(rc, "ptpmon failed to query CURRENT_DATA_SET: %m\n");
		return rc;
	}

	rc = ptpmon_query_clock_mid(node->ptpmon, MID_TIME_PROPERTIES_DATA_SET,
				    &time_properties_ds,
				    sizeof(time_properties_ds));
	if (rc) {
		pr_err(rc, "ptpmon failed to query TIME_PROPERTIES_DATA_SET: %m\n");
		return rc;
	}

	rc = sysmon_get_offset(node->sysmon, sysmon_offset, &sysmon_ts,
			       &sysmon_delay);
	if (rc) {
		pr_err(rc, "Failed to query current sysmon offset: %m\n");
		return rc;
	}

	*ptpmon_offset = master_offset_from_current_ds(&current_ds);
	*utc_offset = __be16_to_cpu(time_properties_ds.current_utc_offset);
	*gm_clkid = parent_ds.grandmaster_identity;

	return 0;
}

static int syncmon_node_query_sync_remote(struct syncmon_node *node,
					  __s64 *sysmon_offset,
					  __s64 *ptpmon_offset, int *utc_offset,
					  enum port_state *port_state,
					  struct clock_identity *gm_clkid)
{
	return isochron_collect_sync_stats(node->mgmt_sock, sysmon_offset,
					   ptpmon_offset, utc_offset,
					   port_state, gm_clkid);
}

static void syncmon_warn_different_grandmasters(struct syncmon_node *node1,
						struct syncmon_node *node2)
{
	char node1_gm[CLOCKID_BUFSIZE];
	char node2_gm[CLOCKID_BUFSIZE];

	if (clockid_eq(&node1->gm_clkid, &clockid_zero) ||
	    clockid_eq(&node2->gm_clkid, &clockid_zero))
		return;

	if (node1->gm_warned && node2->gm_warned)
		return;

	clockid_to_string(&node1->gm_clkid, node1_gm);
	clockid_to_string(&node2->gm_clkid, node2_gm);

	printf("Nodes not synchronized to the same grandmaster, %s has %s, %s has %s\n",
	       node1->name, node1_gm, node2->name, node2_gm);

	node1->gm_warned = true;
	node2->gm_warned = true;
}

static void syncmon_compare_node_grandmasters(struct syncmon *syncmon)
{
	struct syncmon_node *node1, *node2;

	syncmon->same_gm = true;

	LIST_FOREACH(node1, &syncmon->nodes, list) {
		if (!node1->collect_sync_stats)
			continue;

		LIST_FOREACH(node2, &syncmon->nodes, list) {
			if (!node2->collect_sync_stats)
				continue;

			if (node1 == node2)
				continue;

			if (!clockid_eq(&node1->gm_clkid, &node2->gm_clkid)) {
				syncmon->same_gm = false;
				syncmon_warn_different_grandmasters(node1, node2);
				break;
			}
		}
	}
}

static int syncmon_node_update_sync(struct syncmon *syncmon,
				    struct syncmon_node *node)
{
	struct clock_identity gm_clkid;
	enum port_state port_state;
	int utc_offset;
	int rc;

	if (node->remote)
		rc = syncmon_node_query_sync_remote(node, &node->sysmon_offset,
						    &node->ptpmon_offset,
						    &utc_offset, &port_state,
						    &gm_clkid);
	else
		rc = syncmon_node_query_sync_local(node, &node->sysmon_offset,
						   &node->ptpmon_offset,
						   &utc_offset, &port_state,
						   &gm_clkid);
	if (rc)
		return rc;

	node->sysmon_offset += NSEC_PER_SEC * utc_offset;

	node->transient_port_state = port_state != PS_MASTER &&
				     port_state != PS_SLAVE;

	node->ptpmon_sync_done = !!(llabs(node->ptpmon_offset) <= node->sync_threshold);
	node->sysmon_sync_done = !!(llabs(node->sysmon_offset) <= node->sync_threshold);

	if (port_state != node->port_state) {
		printf("Node %s port changed state to %s\n",
		       node->name, port_state_to_string(port_state));
		node->port_state = port_state;
	}

	if (!clockid_eq(&gm_clkid, &node->gm_clkid)) {
		char gm[CLOCKID_BUFSIZE];

		clockid_to_string(&gm_clkid, gm);

		printf("Node %s changed GM to %s\n", node->name, gm);
		node->gm_clkid = gm_clkid;
		node->gm_warned = false;
		syncmon_compare_node_grandmasters(syncmon);
	}

	return 0;
}

static void syncmon_next(struct syncmon *syncmon, __s64 interval)
{
	__s64 next = timespec_to_ns(&syncmon->ts) + interval;

	syncmon->ts = ns_to_timespec(next);
	clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &syncmon->ts, NULL);
}

static bool syncmon_all_nodes_within_3x_threshold(struct syncmon *syncmon)
{
	struct syncmon_node *node;

	LIST_FOREACH(node, &syncmon->nodes, list) {
		if (!node->collect_sync_stats)
			continue;

		if (node->transient_port_state)
			return false;

		if (llabs(node->ptpmon_offset) > 3 * node->sync_threshold)
			return false;

		if (llabs(node->sysmon_offset) > 3 * node->sync_threshold)
			return false;
	}

	return true;
}

static void syncmon_print_sync_stats_double(struct syncmon_node *send,
					    struct syncmon_node *rcv)
{
	char now_buf[TIMESPEC_BUFSIZ];
	struct timespec now_ts;
	__s64 now;

	clock_gettime(CLOCK_TAI, &now_ts);
	now = timespec_to_ns(&now_ts);
	ns_sprintf(now_buf, now);

	printf("isochron[%s]: %s ptpmon %10lld sysmon %10lld receiver ptpmon %10lld sysmon %10lld\n",
	       now_buf, send->name, send->ptpmon_offset, send->sysmon_offset,
	       rcv->ptpmon_offset, rcv->sysmon_offset);
}

static void syncmon_print_sync_stats_single(struct syncmon_node *send)
{
	char now_buf[TIMESPEC_BUFSIZ];
	struct timespec now_ts;
	__s64 now;

	clock_gettime(CLOCK_TAI, &now_ts);
	now = timespec_to_ns(&now_ts);
	ns_sprintf(now_buf, now);

	/* In case --omit-remote-sync is used */
	printf("isochron[%s]: %s ptpmon %10lld sysmon %10lld\n",
	       now_buf, send->name, send->ptpmon_offset, send->sysmon_offset);
}

static bool syncmon_sync_ok(struct syncmon *syncmon)
{
	bool any_port_transient_state = false;
	bool all_ptpmon_sync_done = true;
	bool all_sysmon_sync_done = true;
	bool any_link_down = false;
	struct syncmon_node *node;
	int rc;

	LIST_FOREACH(node, &syncmon->nodes, list) {
		rc = syncmon_node_update_link_state(node);
		if (rc)
			return false;

		if (node->link_state != PORT_LINK_STATE_RUNNING)
			any_link_down = true;

		if (!node->collect_sync_stats)
			continue;

		rc = syncmon_node_update_sync(syncmon, node);
		if (rc)
			return false;

		if (node->transient_port_state)
			any_port_transient_state = true;
		if (!node->ptpmon_sync_done)
			all_ptpmon_sync_done = false;
		if (!node->sysmon_sync_done)
			all_sysmon_sync_done = false;
	}

	LIST_FOREACH(node, &syncmon->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		if (!node->collect_sync_stats)
			continue;

		if (node->pair && node->pair->collect_sync_stats)
			syncmon_print_sync_stats_double(node, node->pair);
		else
			syncmon_print_sync_stats_single(node);
	}

	return !any_link_down && !any_port_transient_state &&
	       syncmon->same_gm && all_ptpmon_sync_done && all_sysmon_sync_done;
}

static void syncmon_init_num_checks(struct syncmon *syncmon)
{
	bool have_sync_stats = false;
	struct syncmon_node *node;

	LIST_FOREACH(node, &syncmon->nodes, list) {
		if (node->collect_sync_stats) {
			have_sync_stats = true;
			break;
		}
	}

	/* No point for checking link state more than once if
	 * we don't have a ptpmon.
	 */
	syncmon->num_checks = have_sync_stats ? NUM_SYNC_CHECKS : 1;
	/* Bypass GM check if we won't have ptpmon */
	if (!have_sync_stats)
		syncmon->same_gm = true;
}

static void syncmon_init_initial_interval(struct syncmon *syncmon)
{
	/* Accelerate initial sync checks if we're already in sync. */
	if (syncmon_sync_ok(syncmon))
		syncmon->initial_interval = NSEC_PER_SEC / 10;
	else if (syncmon_all_nodes_within_3x_threshold(syncmon))
		syncmon->initial_interval = NSEC_PER_SEC / 2;
	else
		syncmon->initial_interval = NSEC_PER_SEC;
}

static void syncmon_init_monitor_interval(struct syncmon *syncmon)
{
	__s64 duration, shortest_duration = INT64_MAX;
	struct syncmon_node *node;

	LIST_FOREACH(node, &syncmon->nodes, list) {
		if (node->role != ISOCHRON_ROLE_SEND)
			continue;

		duration = node->num_pkts * node->cycle_time;
		if (shortest_duration > duration)
			shortest_duration = duration;
	}

	/* Make sure that short tests have sync checks frequent enough to
	 * actually detect a sync loss and have the time to stop it.
	 */
	syncmon->monitor_interval = shortest_duration / syncmon->num_checks;
	if (syncmon->monitor_interval > NSEC_PER_SEC)
		syncmon->monitor_interval = NSEC_PER_SEC;
}

void syncmon_init(struct syncmon *syncmon)
{
	syncmon_init_num_checks(syncmon);
	syncmon_init_initial_interval(syncmon);
	syncmon_init_monitor_interval(syncmon);
}

static void syncmon_init_ts(struct syncmon *syncmon)
{
	clock_gettime(CLOCK_MONOTONIC, &syncmon->ts);
}

int syncmon_wait_until_ok(struct syncmon *syncmon)
{
	int sync_checks_to_go = syncmon->num_checks;

	syncmon_init_ts(syncmon);

	while (1) {
		if (signal_received)
			return -EINTR;

		if (syncmon_sync_ok(syncmon))
			sync_checks_to_go--;

		if (!sync_checks_to_go)
			break;

		syncmon_next(syncmon, syncmon->initial_interval);
	}

	return 0;
}

bool syncmon_monitor(struct syncmon *syncmon, syncmon_stop_fn_t stop,
		     void *priv)
{
	int sync_checks_to_go = syncmon->num_checks;

	syncmon_init_ts(syncmon);

	while (!stop(priv)) {
		if (signal_received)
			return false;

		if (!syncmon_sync_ok(syncmon))
			sync_checks_to_go--;

		if (!sync_checks_to_go) {
			fprintf(stderr,
				"Sync lost during the test, repeating\n");
			return false;
		}

		syncmon_next(syncmon, syncmon->monitor_interval);
	}

	return true;
}

struct syncmon_node *
syncmon_add_local_sender_no_sync(struct syncmon *syncmon, const char *name,
				 struct mnl_socket *rtnl, const char *if_name,
				 size_t num_pkts, __s64 cycle_time)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->role = ISOCHRON_ROLE_SEND;
	node->name = name;
	node->rtnl = rtnl;
	node->if_name = if_name;
	node->num_pkts = num_pkts;
	node->cycle_time = cycle_time;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon_node *syncmon_add_local_sender(struct syncmon *syncmon,
					      const char *name,
					      struct mnl_socket *rtnl,
					      const char *if_name,
					      size_t num_pkts, __s64 cycle_time,
					      struct ptpmon *ptpmon,
					      struct sysmon *sysmon,
					      __s64 sync_threshold)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->role = ISOCHRON_ROLE_SEND;
	node->name = name;
	node->rtnl = rtnl;
	node->if_name = if_name;
	node->num_pkts = num_pkts;
	node->cycle_time = cycle_time;
	node->ptpmon = ptpmon;
	node->sysmon = sysmon;
	node->sync_threshold = sync_threshold;
	node->collect_sync_stats = true;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon_node *
syncmon_add_remote_sender_no_sync(struct syncmon *syncmon, const char *name,
				  struct sk *mgmt_sock, size_t num_pkts,
				  __s64 cycle_time)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->remote = true;
	node->role = ISOCHRON_ROLE_SEND;
	node->name = name;
	node->mgmt_sock = mgmt_sock;
	node->num_pkts = num_pkts;
	node->cycle_time = cycle_time;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon_node *syncmon_add_remote_sender(struct syncmon *syncmon,
					       const char *name,
					       struct sk *mgmt_sock,
					       size_t num_pkts,
					       __s64 cycle_time,
					       __s64 sync_threshold)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->remote = true;
	node->role = ISOCHRON_ROLE_SEND;
	node->name = name;
	node->mgmt_sock = mgmt_sock;
	node->num_pkts = num_pkts;
	node->cycle_time = cycle_time;
	node->sync_threshold = sync_threshold;
	node->collect_sync_stats = true;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon_node *
syncmon_add_remote_receiver_no_sync(struct syncmon *syncmon, const char *name,
				    struct sk *mgmt_sock,
				    struct syncmon_node *pair)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->remote = true;
	node->role = ISOCHRON_ROLE_RCV;
	node->name = name;
	node->mgmt_sock = mgmt_sock;
	node->pair = pair;
	pair->pair = node;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon_node *syncmon_add_remote_receiver(struct syncmon *syncmon,
						 const char *name,
						 struct sk *mgmt_sock,
						 struct syncmon_node *pair,
						 __s64 sync_threshold)
{
	struct syncmon_node *node;

	node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->remote = true;
	node->role = ISOCHRON_ROLE_RCV;
	node->name = name;
	node->mgmt_sock = mgmt_sock;
	node->pair = pair;
	pair->pair = node;
	node->sync_threshold = sync_threshold;
	node->collect_sync_stats = true;
	LIST_INSERT_HEAD(&syncmon->nodes, node, list);

	return node;
}

struct syncmon *syncmon_create(void)
{
	struct syncmon *syncmon;

	syncmon = calloc(1, sizeof(*syncmon));
	if (!syncmon)
		return NULL;

	LIST_INIT(&syncmon->nodes);

	return syncmon;
}

void syncmon_destroy(struct syncmon *syncmon)
{
	struct syncmon_node *node, *tmp;

	LIST_FOREACH_SAFE(node, &syncmon->nodes, list, tmp) {
		LIST_REMOVE(node, list);
		free(node);
	}

	free(syncmon);
}
