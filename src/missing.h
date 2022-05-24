// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 * Copyright 2021 NXP
 */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 */
#ifndef _MISSING_H
#define _MISSING_H

#ifndef PTP_MAX_SAMPLES
#define PTP_MAX_SAMPLES 25 /* Maximum allowed offset measurement samples. */
#endif /* PTP_MAX_SAMPLES */

#ifndef PTP_SYS_OFFSET

#define PTP_SYS_OFFSET     _IOW(PTP_CLK_MAGIC, 5, struct ptp_sys_offset)

struct ptp_sys_offset {
	unsigned int n_samples; /* Desired number of measurements. */
	unsigned int rsv[3];    /* Reserved for future use. */
	/*
	 * Array of interleaved system/phc time stamps. The kernel
	 * will provide 2*n_samples + 1 time stamps, with the last
	 * one as a system time stamp.
	 */
	struct ptp_clock_time ts[2 * PTP_MAX_SAMPLES + 1];
};

#endif /* PTP_SYS_OFFSET */

#ifndef PTP_SYS_OFFSET_PRECISE

#define PTP_SYS_OFFSET_PRECISE \
	_IOWR(PTP_CLK_MAGIC, 8, struct ptp_sys_offset_precise)

struct ptp_sys_offset_precise {
	struct ptp_clock_time device;
	struct ptp_clock_time sys_realtime;
	struct ptp_clock_time sys_monoraw;
	unsigned int rsv[4];    /* Reserved for future use. */
};

#endif /* PTP_SYS_OFFSET_PRECISE */

#ifndef PTP_SYS_OFFSET_EXTENDED

#define PTP_SYS_OFFSET_EXTENDED \
	_IOWR(PTP_CLK_MAGIC, 9, struct ptp_sys_offset_extended)

struct ptp_sys_offset_extended {
	unsigned int n_samples; /* Desired number of measurements. */
	unsigned int rsv[3];    /* Reserved for future use. */
	/*
	 * Array of [system, phc, system] time stamps. The kernel will provide
	 * 3*n_samples time stamps.
	 */
	struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
};

#endif /* PTP_SYS_OFFSET_EXTENDED */

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#endif
