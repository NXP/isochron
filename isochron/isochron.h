/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020-2021 NXP */
#ifndef _ISOCHRON_H
#define _ISOCHRON_H

#include <stdbool.h>

int isochron_send_main(int argc, char *argv[]);
int isochron_rcv_main(int argc, char *argv[]);
int isochron_report_main(int argc, char *argv[]);

#endif
