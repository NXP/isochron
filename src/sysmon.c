// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 * Copyright 2021 NXP
 */
/* This file contains code snippets from the linuxptp project
 */
#define _GNU_SOURCE	/* for asprintf() */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/ethtool.h>
#include <linux/ptp_clock.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "missing.h"
#include "sk.h"
#include "sysmon.h"

#define NSEC_PER_SEC 1000000000LL

enum sysoff_method {
	SYSOFF_RUN_TIME_MISSING = -1,
	SYSOFF_PRECISE,
	SYSOFF_EXTENDED,
	SYSOFF_BASIC,
	SYSOFF_LAST,
};

struct sysmon {
	clockid_t clkid;
	char *name;
	int phc_index;
	int num_readings;
	enum sysoff_method sysoff_method;
};

static __s64 pct_to_ns(struct ptp_clock_time *t)
{
	return t->sec * NSEC_PER_SEC + t->nsec;
}

static clockid_t phc_open(const char *iface, int *phc_index)
{
	struct sk_ts_info ts_info;
	char phc_device[19];
	struct timespec ts;
	clockid_t clkid;
	int fd;

	/* check if device is a valid ethernet device */
	if (sk_get_ts_info(iface, &ts_info) || !ts_info.valid) {
		fprintf(stderr, "unknown clock %s: %m\n", iface);
		return CLOCK_INVALID;
	}

	if (ts_info.phc_index < 0) {
		fprintf(stderr, "interface %s does not have a PHC\n", iface);
		return CLOCK_INVALID;
	}

	snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d", ts_info.phc_index);

	fd = open(phc_device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "cannot open %s: %m\n", phc_device);
		return CLOCK_INVALID;
	}

	clkid = FD_TO_CLOCKID(fd);
	/* check if clkid is valid */
	if (clock_gettime(clkid, &ts)) {
		close(fd);
		return CLOCK_INVALID;
	}

	*phc_index = ts_info.phc_index;
	return clkid;
}

static void phc_close(clockid_t clkid)
{
	close(CLOCKID_TO_FD(clkid));
}

static int sysoff_precise(int fd, __s64 *result, __u64 *ts)
{
	struct ptp_sys_offset_precise pso;
	memset(&pso, 0, sizeof(pso));
	if (ioctl(fd, PTP_SYS_OFFSET_PRECISE, &pso))
		return SYSOFF_RUN_TIME_MISSING;

	*result = pct_to_ns(&pso.sys_realtime) - pct_to_ns(&pso.device);
	*ts = pct_to_ns(&pso.sys_realtime);
	return SYSOFF_PRECISE;
}

static __s64 sysoff_estimate(struct ptp_clock_time *pct, int extended,
			     int n_samples, __u64 *ts, __s64 *delay)
{
	__s64 shortest_interval, best_timestamp, best_offset;
	__s64 interval, timestamp, offset;
	__s64 t1, t2, tp;
	int i = 0;

	if (extended) {
		t1 = pct_to_ns(&pct[3*i]);
		tp = pct_to_ns(&pct[3*i+1]);
		t2 = pct_to_ns(&pct[3*i+2]);
	} else {
		t1 = pct_to_ns(&pct[2*i]);
		tp = pct_to_ns(&pct[2*i+1]);
		t2 = pct_to_ns(&pct[2*i+2]);
	}
	shortest_interval = t2 - t1;
	best_timestamp = (t2 + t1) / 2;
	best_offset = best_timestamp - tp;

	for (i = 1; i < n_samples; i++) {
		if (extended) {
			t1 = pct_to_ns(&pct[3*i]);
			tp = pct_to_ns(&pct[3*i+1]);
			t2 = pct_to_ns(&pct[3*i+2]);
		} else {
			t1 = pct_to_ns(&pct[2*i]);
			tp = pct_to_ns(&pct[2*i+1]);
			t2 = pct_to_ns(&pct[2*i+2]);
		}
		interval = t2 - t1;
		timestamp = (t2 + t1) / 2;
		offset = timestamp - tp;
		if (interval < shortest_interval) {
			shortest_interval = interval;
			best_timestamp = timestamp;
			best_offset = offset;
		}
	}
	*ts = best_timestamp;
	*delay = shortest_interval;
	return best_offset;
}

static int sysoff_extended(int fd, int n_samples, __s64 *result, __u64 *ts,
			   __s64 *delay)
{
	struct ptp_sys_offset_extended pso;
	memset(&pso, 0, sizeof(pso));
	pso.n_samples = n_samples;
	if (ioctl(fd, PTP_SYS_OFFSET_EXTENDED, &pso))
		return SYSOFF_RUN_TIME_MISSING;

	*result = sysoff_estimate(&pso.ts[0][0], 1, n_samples, ts, delay);
	return SYSOFF_EXTENDED;
}

static int sysoff_basic(int fd, int n_samples, __s64 *result, __u64 *ts,
			__s64 *delay)
{
	struct ptp_sys_offset pso;
	memset(&pso, 0, sizeof(pso));
	pso.n_samples = n_samples;
	if (ioctl(fd, PTP_SYS_OFFSET, &pso))
		return SYSOFF_RUN_TIME_MISSING;

	*result = sysoff_estimate(pso.ts, 0, n_samples, ts, delay);
	return SYSOFF_BASIC;
}

/**
 * Measure the offset between a PHC and the system time.
 * @param fd         An open file descriptor to a PHC device.
 * @param method     A non-negative SYSOFF_ value returned by sysoff_probe().
 * @param n_samples  The number of consecutive readings to make.
 * @param result     The estimated offset in nanoseconds.
 * @param ts         The system time corresponding to the 'result'.
 * @param delay      The delay in reading of the clock in nanoseconds.
 * @return  One of the SYSOFF_ enumeration values.
 */
static int sysoff_measure(int fd, enum sysoff_method method, int n_samples,
			  __s64 *result, __u64 *ts, __s64 *delay)
{
	switch (method) {
	case SYSOFF_PRECISE:
		*delay = 0;
		return sysoff_precise(fd, result, ts);
	case SYSOFF_EXTENDED:
		return sysoff_extended(fd, n_samples, result, ts, delay);
	case SYSOFF_BASIC:
		return sysoff_basic(fd, n_samples, result, ts, delay);
	default:
		return SYSOFF_RUN_TIME_MISSING;
	}
}

/**
 * Check to see if a PTP_SYS_OFFSET ioctl is supported.
 * @param fd  An open file descriptor to a PHC device.
 * @return  One of the SYSOFF_ enumeration values.
 */
static enum sysoff_method sysoff_probe(int fd, int n_samples)
{
	__s64 junk, delay;
	__u64 ts;
	int i;

	if (n_samples > PTP_MAX_SAMPLES) {
		fprintf(stderr, "warning: %d exceeds kernel max readings %d\n",
			n_samples, PTP_MAX_SAMPLES);
		fprintf(stderr, "falling back to clock_gettime method\n");
		return SYSOFF_RUN_TIME_MISSING;
	}

	for (i = 0; i < SYSOFF_LAST; i++) {
		if (sysoff_measure(fd, i, n_samples, &junk, &ts, &delay) < 0)
			continue;
		return i;
	}

	return SYSOFF_RUN_TIME_MISSING;
}

static int read_phc(clockid_t clkid, clockid_t sysclk, int readings,
		    __s64 *offset, __u64 *ts, __s64 *delay)
{
	__s64 interval, best_interval = INT64_MAX;
	struct timespec t_dst1, t_dst2, t_src;
	int i;

	/* Pick the quickest clkid reading. */
	for (i = 0; i < readings; i++) {
		if (clock_gettime(sysclk, &t_dst1) ||
		    clock_gettime(clkid, &t_src) ||
		    clock_gettime(sysclk, &t_dst2)) {
			fprintf(stderr, "failed to read clock: %m\n");
			return 0;
		}

		interval = (t_dst2.tv_sec - t_dst1.tv_sec) * NSEC_PER_SEC +
			    t_dst2.tv_nsec - t_dst1.tv_nsec;

		if (best_interval > interval) {
			best_interval = interval;
			*offset = (t_dst1.tv_sec - t_src.tv_sec) * NSEC_PER_SEC +
				   t_dst1.tv_nsec - t_src.tv_nsec + interval / 2;
			*ts = t_dst2.tv_sec * NSEC_PER_SEC + t_dst2.tv_nsec;
		}
	}
	*delay = best_interval;

	return 1;
}

int sysmon_get_offset(struct sysmon *sysmon, __s64 *offset, __u64 *ts,
		      __s64 *delay)
{
	if (sysmon->sysoff_method != SYSOFF_RUN_TIME_MISSING) {
		if (sysoff_measure(CLOCKID_TO_FD(sysmon->clkid),
				   sysmon->sysoff_method, sysmon->num_readings,
				   offset, ts, delay) < 0)
			return -1;
	} else {
		if (!read_phc(sysmon->clkid, CLOCK_REALTIME,
			      sysmon->num_readings, offset, ts, delay))
			return -1;
	}

	return 0;
}

void sysmon_print_method(struct sysmon *sysmon)
{
	switch (sysmon->sysoff_method) {
	case SYSOFF_BASIC:
		printf("Using PTP_SYS_OFFSET for measuring the offset from %s to CLOCK_REALTIME\n",
		       sysmon->name);
		break;
	case SYSOFF_EXTENDED:
		printf("Using PTP_SYS_OFFSET_EXTENDED for measuring the offset from %s to CLOCK_REALTIME\n",
		       sysmon->name);
		break;
	case SYSOFF_PRECISE:
		printf("Using PTP_SYS_OFFSET_PRECISE for measuring the offset from %s to CLOCK_REALTIME\n",
		       sysmon->name);
		break;
	default:
		break;
	}
}

struct sysmon *sysmon_create(const char *iface, int num_readings)
{
	struct sysmon *sysmon;
	int phc_index = -1;
	clockid_t clkid;
	int err;

	sysmon = calloc(1, sizeof(*sysmon));
	if (!sysmon)
		return NULL;

	clkid = phc_open(iface, &phc_index);
	if (clkid == CLOCK_INVALID) {
		free(sysmon);
		return NULL;
	}

	sysmon->clkid = clkid;
	sysmon->phc_index = phc_index;
	sysmon->num_readings = num_readings;
	sysmon->sysoff_method = sysoff_probe(CLOCKID_TO_FD(clkid),
					     num_readings);

	err = asprintf(&sysmon->name, "/dev/ptp%d", phc_index);
	if (err < 0) {
		phc_close(clkid);
		free(sysmon);
		return NULL;
	}

	return sysmon;
}

void sysmon_destroy(struct sysmon *sysmon)
{
	phc_close(sysmon->clkid);
	free(sysmon->name);
	free(sysmon);
}
