// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 NXP */
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "log.h"

struct prog_data {
	struct isochron_log send_log;
	struct isochron_log rcv_log;
	long packet_count;
	long frame_size;
	bool omit_sync;
	bool do_ts;
	bool txtime;
	bool taprio;
	bool deadline;
	__s64 base_time;
	__s64 advance_time;
	__s64 shift_time;
	__s64 cycle_time;
	__s64 window_size;
	bool quiet;
	long start;
	long stop;
	char input_file[PATH_MAX];
};

static int prog_parse_args(int argc, char **argv, struct prog_data *prog)
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
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->input_file,
				.size = PATH_MAX - 1,
			},
		}, {
			.short_opt = "-q",
			.long_opt = "--quiet",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->quiet,
			},
			.optional = true,
		}, {
			.short_opt = "-s",
			.long_opt = "--start",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->start,
			},
			.optional = true,
		}, {
			.short_opt = "-S",
			.long_opt = "--stop",
			.type = PROG_ARG_LONG,
			.long_ptr = {
				.ptr = &prog->stop,
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
		prog_usage("isochron-report", args, ARRAY_SIZE(args));
		return -1;
	}

	if (help) {
		prog_usage("isochron-report", args, ARRAY_SIZE(args));
		return -1;
	}

	return 0;
}

int isochron_report_main(int argc, char *argv[])
{
	struct prog_data prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc)
		return rc;

	rc = isochron_log_load(prog.input_file, &prog.send_log, &prog.rcv_log,
			       &prog.packet_count, &prog.frame_size,
			       &prog.omit_sync, &prog.do_ts, &prog.taprio,
			       &prog.txtime, &prog.deadline, &prog.base_time,
			       &prog.advance_time, &prog.shift_time,
			       &prog.cycle_time, &prog.window_size);
	if (rc)
		return rc;

	if (!prog.start)
		prog.start = 1;
	if (!prog.stop)
		prog.stop = prog.packet_count;

	isochron_print_stats(&prog.send_log, &prog.rcv_log, prog.start,
			     prog.stop, prog.omit_sync, prog.quiet, prog.taprio,
			     prog.txtime, prog.cycle_time, prog.advance_time);

	isochron_log_teardown(&prog.send_log);
	isochron_log_teardown(&prog.rcv_log);

	return 0;
}
