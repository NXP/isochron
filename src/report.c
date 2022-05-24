// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 NXP */
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include "argparser.h"
#include "common.h"
#include "isochron.h"
#include "log.h"

struct isochron_report {
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
	bool summary;
	unsigned long start;
	unsigned long stop;
	char input_file[PATH_MAX];
	char printf_fmt[ISOCHRON_LOG_PRINTF_BUF_SIZE];
	char printf_args[ISOCHRON_LOG_PRINTF_MAX_NUM_ARGS];
};

static int prog_parse_args(int argc, char **argv, struct isochron_report *prog)
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
				.buf = prog->input_file,
				.size = PATH_MAX - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-m",
			.long_opt = "--summary",
			.type = PROG_ARG_BOOL,
			.boolean_ptr = {
			        .ptr = &prog->summary,
			},
			.optional = true,
		}, {
			.short_opt = "-s",
			.long_opt = "--start",
			.type = PROG_ARG_UNSIGNED,
			.unsigned_ptr = {
				.ptr = &prog->start,
			},
			.optional = true,
		}, {
			.short_opt = "-S",
			.long_opt = "--stop",
			.type = PROG_ARG_UNSIGNED,
			.unsigned_ptr = {
				.ptr = &prog->stop,
			},
			.optional = true,
		}, {
			.short_opt = "-f",
			.long_opt = "--printf-format",
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->printf_fmt,
				.size = ISOCHRON_LOG_PRINTF_BUF_SIZE - 1,
			},
			.optional = true,
		}, {
			.short_opt = "-a",
			.long_opt = "--printf-args",
			.type = PROG_ARG_STRING,
			.string = {
				.buf = prog->printf_args,
				.size = ISOCHRON_LOG_PRINTF_MAX_NUM_ARGS - 1,
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
		prog_usage("isochron-report", args, ARRAY_SIZE(args));
		return -1;
	}

	if (help) {
		prog_usage("isochron-report", args, ARRAY_SIZE(args));
		return -1;
	}

	if (!strlen(prog->input_file))
		sprintf(prog->input_file, "isochron.dat");

	return 0;
}

int isochron_report_main(int argc, char *argv[])
{
	struct isochron_report prog = {0};
	int rc;

	rc = prog_parse_args(argc, argv, &prog);
	if (rc)
		return rc;

	/* Replacing the escape sequences does not need to be done per packet,
	 * so do it once before passing the printf format specifier to the log.
	 */
	rc = string_replace_escape_sequences(prog.printf_fmt);
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

	rc = isochron_print_stats(&prog.send_log, &prog.rcv_log,
				  prog.printf_fmt, prog.printf_args,
				  prog.start, prog.stop, prog.summary,
				  prog.omit_sync, prog.taprio,
				  prog.txtime, prog.base_time,
				  prog.advance_time, prog.shift_time,
				  prog.cycle_time, prog.window_size);

	isochron_log_teardown(&prog.send_log);
	isochron_log_teardown(&prog.rcv_log);

	return 0;
}
