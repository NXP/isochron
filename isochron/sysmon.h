/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2021 NXP */
#ifndef _SYSMON_H
#define _SYSMON_H

#include <linux/types.h>

struct sysmon;

struct sysmon *sysmon_create(const char *iface, int num_readings);
void sysmon_destroy(struct sysmon *sysmon);
int sysmon_get_offset(struct sysmon *sysmon, __s64 *offset, __u64 *ts,
		      __s64 *delay);
void sysmon_print_method(struct sysmon *sysmon);

#endif
