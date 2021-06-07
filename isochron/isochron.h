/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2021 NXP Semiconductors */
#ifndef _ISOCHRON_H
#define _ISOCHRON_H

int isochron_send_main(int argc, char *argv[]);
int isochron_rcv_main(int argc, char *argv[]);
void isochron_print_stats(struct isochron_log *send_log,
			  struct isochron_log *rcv_log,
			  bool omit_sync, bool quiet, bool taprio, bool txtime,
			  __s64 advance_time);

#endif
