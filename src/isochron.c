// SPDX-License-Identifier: GPL-2.0
/* Copyright 2020 NXP */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "common.h"
#include "isochron.h"

static const struct isochron_prog progs[] = {
	{
		.prog_name = "isochron-daemon",
		.prog_func = "daemon",
		.main = isochron_daemon_main,
	}, {
		.prog_name = "isochron-orchestrate",
		.prog_func = "orchestrate",
		.main = isochron_orchestrate_main,
	}, {
		.prog_name = "isochron-send",
		.prog_func = "send",
		.main = isochron_send_main,
	}, {
		.prog_name = "isochron-rcv",
		.prog_func = "rcv",
		.main = isochron_rcv_main,
	}, {
		.prog_name = "isochron-report",
		.prog_func = "report",
		.main = isochron_report_main,
	},
};

bool signal_received;

static void isochron_signal_handler(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		signal_received = true;
		break;
	default:
		break;
	}
}

static void isochron_usage(void)
{
	size_t i;

	fprintf(stderr, "isochron usage:\n");

	for (i = 0; i < ARRAY_SIZE(progs); i++)
		fprintf(stderr, "isochron %s ...\n", progs[i].prog_func);

	fprintf(stderr, "Run ");

	for (i = 0; i < ARRAY_SIZE(progs); i++)
		fprintf(stderr, "\"isochron %s --help\", ", progs[i].prog_func);

	fprintf(stderr, "for more details.\n");
}

int isochron_parse_args(int *argc, char ***argv,
			const struct isochron_prog **prog)
{
	char *prog_name;
	char *prog_func;
	size_t i;

	if (*argc < 2) {
		isochron_usage();
		return -EINVAL;
	}

	/* First try to match on program name */
	prog_name = *argv[0];
	(*argv)++;
	(*argc)--;

	for (i = 0; i < ARRAY_SIZE(progs); i++) {
		if (strcmp(prog_name, progs[i].prog_name) == 0) {
			*prog = &progs[i];
			return 0;
		}
	}

	/* Next try to match on function name */
	prog_func = (*argv)[0];
	(*argv)++;
	(*argc)--;

	if (!strcmp(prog_func, "-V") || !strcmp(prog_func, "--version")) {
		fprintf(stderr, "%s\n", VERSION);
		return -EINVAL;
	}

	if (!strcmp(prog_func, "-h") || !strcmp(prog_func, "--help")) {
		isochron_usage();
		return -EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(progs); i++) {
		if (strcmp(prog_func, progs[i].prog_func) == 0) {
			*prog = &progs[i];
			return 0;
		}
	}

	fprintf(stderr, "%s: unknown function %s, expected one of ",
		prog_name, prog_func);

	for (i = 0; i < ARRAY_SIZE(progs); i++)
		fprintf(stderr, "\"%s\", ", progs[i].prog_func);

	fprintf(stderr, "\n");

	return -EINVAL;
}

static int isochron_handle_signals(void (*handler)(int signo))
{
	struct sigaction sa;
	int rc;

	sa.sa_handler = handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	rc = sigaction(SIGTERM, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGTERM");
		return -errno;
	}

	rc = sigaction(SIGINT, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGINT");
		return -errno;
	}

	rc = sigaction(SIGPIPE, &sa, NULL);
	if (rc < 0) {
		perror("can't catch SIGPIPE");
		return -errno;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	const struct isochron_prog *prog;
	int rc;

	rc = isochron_handle_signals(isochron_signal_handler);
	if (rc)
		return rc;

	rc = isochron_parse_args(&argc, &argv, &prog);
	if (rc)
		return -rc;

	return prog->main(argc, argv);
}
