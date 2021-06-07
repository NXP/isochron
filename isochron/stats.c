// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 NXP Semiconductors */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "isochron.h"

#define BUF_SIZ		10000
#define MAX_NUM_LINES	10000

enum fsm_state {
	STATE_UNKNOWN,
	STATE_SEQID,
	STATE_GATE,
	STATE_WAKEUP,
	STATE_TX,
	STATE_RX,
	STATE_ARRIVAL,
};

struct prog_data {
	struct isochron_log send_log;
	struct isochron_log rcv_log;
	enum fsm_state state;
	bool txtime;
	bool taprio;
	bool quiet;
	__s64 advance_time;
	__s64 shift_time;
	__s64 cycle_time;
	__s64 window_size;
};

static int isochron_parse_word(struct prog_data *prog, char *word,
			       struct isochron_send_pkt_data *send_pkt,
			       struct isochron_rcv_pkt_data *rcv_pkt)
{
	int rc;

	switch (prog->state) {
	case STATE_UNKNOWN:
		if (strcmp(word, "seqid") == 0) {
			prog->state = STATE_SEQID;
		} else if (strcmp(word, "gate") == 0) {
			prog->state = STATE_GATE;
		} else if (strcmp(word, "wakeup") == 0) {
			prog->state = STATE_WAKEUP;
		} else if (strcmp(word, "tx") == 0) {
			prog->state = STATE_TX;
		} else if (strcmp(word, "rx") == 0) {
			prog->state = STATE_RX;
		} else if (strcmp(word, "arrival") == 0) {
			prog->state = STATE_ARRIVAL;
		} else {
			fprintf(stderr, "Unknown token \"%s\"\n", word);
			return -1;
		}

		break;
	case STATE_SEQID:
		send_pkt->seqid = strtol(word, NULL, 0);
		if (errno) {
			fprintf(stderr,
				"could not read seqid from string \"%s\": %s\n",
				word, strerror(errno));
			return -errno;
		}
		rcv_pkt->seqid = send_pkt->seqid;
		prog->state = STATE_UNKNOWN;
		break;
	case STATE_GATE:
		rc = get_time_from_string(CLOCK_TAI, &send_pkt->tx_time, word);
		if (rc) {
			fprintf(stderr,
				"could not read gate from string \"%s\": %s\n",
				word, strerror(rc));
			return rc;
		}
		rcv_pkt->tx_time = send_pkt->tx_time;
		prog->state = STATE_UNKNOWN;
		break;
	case STATE_WAKEUP:
		rc = get_time_from_string(CLOCK_TAI, &send_pkt->wakeup, word);
		if (rc) {
			fprintf(stderr,
				"could not read wakeup from string \"%s\": %s\n",
				word, strerror(rc));
			return rc;
		}
		prog->state = STATE_UNKNOWN;
		break;
	case STATE_TX:
		rc = get_time_from_string(CLOCK_TAI, &send_pkt->hwts, word);
		if (rc) {
			fprintf(stderr,
				"could not read tx from string \"%s\": %s\n",
				word, strerror(rc));
			return rc;
		}
		prog->state = STATE_UNKNOWN;
		break;
	case STATE_RX:
		rc = get_time_from_string(CLOCK_TAI, &rcv_pkt->hwts, word);
		if (rc) {
			fprintf(stderr,
				"could not read rx from string \"%s\": %s\n",
				word, strerror(rc));
			return rc;
		}
		prog->state = STATE_UNKNOWN;
		break;
	case STATE_ARRIVAL:
		rc = get_time_from_string(CLOCK_TAI, &rcv_pkt->arrival, word);
		if (rc) {
			fprintf(stderr,
				"could not read arrival from string \"%s\": %s\n",
				word, strerror(rc));
			return rc;
		}
		prog->state = STATE_UNKNOWN;
		break;
	default:
		fprintf(stderr, "invalid state %d\n", prog->state);
		return -1;
	}

	return 0;
}

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
{
	struct prog_arg args[] = {
		{
			.short_opt = "-a",
			.long_opt = "--advance-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->advance_time,
			},
			.optional = true,
		}, {
			.short_opt = "-c",
			.long_opt = "--cycle-time",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->cycle_time,
			},
			.optional = true,
		}, {
			.short_opt = "-w",
			.long_opt = "--window-size",
			.type = PROG_ARG_TIME,
			.time = {
				.clkid = CLOCK_TAI,
				.ns = &prog->window_size,
			},
			.optional = true,
		}, {
			.short_opt = "-q",
			.long_opt = "--quiet",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->quiet,
			},
			.optional = true,
		}, {
			.short_opt = "-Q",
			.long_opt = "--taprio",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->taprio,
			},
			.optional = true,
		}, {
			.short_opt = "-x",
			.long_opt = "--txtime",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->txtime,
			},
			.optional = true,
		},
	};
	int rc;

	rc = prog_parse_np_args(argc, argv, args, ARRAY_SIZE(args));

	/* Non-positional arguments left unconsumed */
	if (rc < 0) {
		fprintf(stderr, "Parsing returned %d: %s\n",
			-rc, strerror(-rc));
		return rc;
	} else if (rc < argc) {
		fprintf(stderr, "%d unconsumed arguments. First: %s\n",
			argc - rc, argv[rc]);
		prog_usage("isochron-send", args, ARRAY_SIZE(args));
		return -1;
	}

	if (prog->txtime && prog->taprio) {
		fprintf(stderr,
			"Cannot enable txtime and taprio mode at the same time\n");
		return -EINVAL;
	}

	if (!prog->advance_time)
		prog->advance_time = prog->cycle_time - prog->window_size;

	return 0;
}

int isochron_stats_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	char buf[BUF_SIZ] = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc < 0)
		goto out_parse_args_failed;

	rc = isochron_log_init(&prog.send_log, MAX_NUM_LINES *
			       sizeof(struct isochron_send_pkt_data));
	if (rc)
		goto out_send_log_failed;

	rc = isochron_log_init(&prog.rcv_log, MAX_NUM_LINES *
			       sizeof(struct isochron_rcv_pkt_data));
	if (rc)
		goto out_rcv_log_failed;

	while (fgets(buf, BUF_SIZ, stdin)) {
		struct isochron_send_pkt_data send_pkt = {0};
		struct isochron_rcv_pkt_data rcv_pkt = {0};
		char *p = strtok(buf, " \n");

		while (p) {
			rc = isochron_parse_word(&prog, p, &send_pkt, &rcv_pkt);
			if (rc)
				break;

			p = strtok(NULL, " \n");
		}

		isochron_log_data(&prog.send_log, &send_pkt,
				  sizeof(send_pkt));
		isochron_log_data(&prog.rcv_log, &rcv_pkt,
				  sizeof(rcv_pkt));
	}

	isochron_print_stats(&prog.send_log, &prog.rcv_log, true, prog.quiet,
			     prog.taprio, prog.txtime, prog.advance_time);

	isochron_log_teardown(&prog.rcv_log);
out_rcv_log_failed:
	isochron_log_teardown(&prog.send_log);
out_send_log_failed:
out_parse_args_failed:
	return rc;
}
