/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2021 NXP */
#ifndef _ISOCHRON_H
#define _ISOCHRON_H

#include <stdbool.h>

typedef int isochron_prog_main_func_t(int argc, char *argv[]);

struct isochron_prog {
	const char *prog_name;
	const char *prog_func;
	isochron_prog_main_func_t *main;
};

int isochron_daemon_main(int argc, char *argv[]);
int isochron_orchestrate_main(int argc, char *argv[]);
int isochron_send_main(int argc, char *argv[]);
int isochron_rcv_main(int argc, char *argv[]);
int isochron_report_main(int argc, char *argv[]);

int isochron_parse_args(int *argc, char ***argv,
			const struct isochron_prog **prog);

extern bool signal_received;

#endif
