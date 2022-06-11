// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019 NXP */
/* This file contains code snippets from:
 * - The Linux kernel
 * - The linuxptp project
 */
#include <time.h>
#include <netinet/ether.h>
#include <linux/sockios.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
/* For va_start and va_end */
#include <stdarg.h>
#include "common.h"
#include "rtnl.h"

void pr_err(int rc, const char *fmt, ...)
{
	va_list ap;

	errno = -rc;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

ssize_t read_exact(int fd, void *buf, size_t count)
{
	size_t total_read = 0;
	ssize_t ret;

	do {
		ret = read(fd, buf + total_read, count - total_read);
		if (ret <= 0)
			return ret;
		total_read += ret;
	} while (total_read != count);

	return total_read;
}

ssize_t write_exact(int fd, const void *buf, size_t count)
{
	size_t written = 0;
	ssize_t ret;

	do {
		ret = write(fd, buf + written, count - written);
		if (ret <= 0)
			return ret;
		written += ret;
	} while (written != count);

	return written;
}

void mac_addr_sprintf(char *buf, unsigned char *addr)
{
	snprintf(buf, MACADDR_BUFSIZ, "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

__s64 timespec_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

struct timespec ns_to_timespec(__s64 ns)
{
	return (struct timespec) {
		.tv_sec = ns / NSEC_PER_SEC,
		.tv_nsec = llabs(ns) % NSEC_PER_SEC,
	};
}

void ns_sprintf(char *buf, __s64 ns)
{
	struct timespec ts = ns_to_timespec(ns);

	snprintf(buf, TIMESPEC_BUFSIZ, "%ld.%09ld", ts.tv_sec, ts.tv_nsec);
}

static const char * const trace_marker_paths[] = {
	"/sys/kernel/debug/tracing/trace_marker",
	"/debug/tracing/trace_marker",
	"/debugfs/tracing/trace_marker",
};

int trace_mark_open(void)
{
	unsigned int i;
	int fd;

	for (i = 0; i < ARRAY_SIZE(trace_marker_paths); i++) {
		fd = open(trace_marker_paths[i], O_WRONLY);
		if (fd < 0)
			continue;

		return fd;
	}

	return -1;
}

void trace_mark_close(int fd)
{
	close(fd);
}

int set_utc_tai_offset(int offset)
{
	struct timex tx;

	memset(&tx, 0, sizeof(tx));

	tx.modes = ADJ_TAI;
	tx.constant = offset;

	return adjtimex(&tx);
}

int get_utc_tai_offset(void)
{
	struct timex tx;

	memset(&tx, 0, sizeof(tx));

	adjtimex(&tx);
	return tx.tai;
}

void isochron_fixup_kernel_utc_offset(int ptp_utc_offset)
{
	int kernel_offset = get_utc_tai_offset();

	if (ptp_utc_offset == kernel_offset)
		return;

	printf("Kernel UTC-TAI offset of %d seems out of date, updating it to %d\n",
	       kernel_offset, ptp_utc_offset);

	set_utc_tai_offset(ptp_utc_offset);
}

static void ptpmon_print_tried_ports(const char *real_ifname,
				     char **tried_ports,
				     int tries)
{
	int i;

	fprintf(stderr, "Interface %s not found amount %d ports reported by ptp4l: ",
		real_ifname, tries);

	for (i = 0; i < tries; i++)
		fprintf(stderr, "%s", tried_ports[i]);

	fprintf(stderr, "\n");
}

static void ptpmon_free_tried_ports(char **tried_ports, int tries)
{
	int i;

	for (i = 0; i < tries; i++)
		free(tried_ports[i]);

	free(tried_ports);
}

int ptpmon_query_port_state_by_name(struct ptpmon *ptpmon, const char *iface,
				    struct mnl_socket *rtnl,
				    enum port_state *port_state)
{
	struct default_ds default_ds;
	char real_ifname[IFNAMSIZ];
	char **tried_ports, *dup;
	int portnum, num_ports;
	int tries = 0;
	int rc;

	rc = vlan_resolve_real_dev(rtnl, iface, real_ifname);
	if (rc)
		return rc;

	rc = ptpmon_query_clock_mid(ptpmon, MID_DEFAULT_DATA_SET,
				    &default_ds, sizeof(default_ds));
	if (rc) {
		pr_err(rc, "Failed to query DEFAULT_DATA_SET: %m\n");
		return rc;
	}

	num_ports = __be16_to_cpu(default_ds.number_ports);

	tried_ports = calloc(num_ports, sizeof(char *));
	if (!tried_ports) {
		printf("Failed to allocate memory for port names\n");
		return -ENOMEM;
	}

	for (portnum = 1; portnum <= num_ports; portnum++) {
		__u8 buf[sizeof(struct port_properties_np) + MAX_IFACE_LEN] = {0};
		struct port_properties_np *port_properties_np;
		char real_port_ifname[IFNAMSIZ];
		struct port_identity portid;

		portid_set(&portid, &default_ds.clock_identity, portnum);

		rc = ptpmon_query_port_mid_extra(ptpmon, &portid,
						 MID_PORT_PROPERTIES_NP, buf,
						 sizeof(struct port_properties_np),
						 MAX_IFACE_LEN);
		if (rc) {
			ptpmon_free_tried_ports(tried_ports, tries);
			return rc;
		}

		port_properties_np = (struct port_properties_np *)buf;

		rc = vlan_resolve_real_dev(rtnl, port_properties_np->iface,
					   real_port_ifname);
		if (rc)
			goto out;

		if (strcmp(real_port_ifname, real_ifname)) {
			/* Skipping ptp4l port, save the name for later to
			 * inform the user in case we found nothing.
			 */
			dup = strdup(real_port_ifname);
			if (!dup) {
				rc = -ENOMEM;
				goto out;
			}
			tried_ports[tries++] = dup;
			continue;
		}

		*port_state = port_properties_np->port_state;
		rc = 0;
		goto out;
	}

	/* Nothing found */
	rc = -ENODEV;

	ptpmon_print_tried_ports(real_ifname, tried_ports, tries);
out:
	ptpmon_free_tried_ports(tried_ports, tries);
	return rc;
}

int if_name_copy(char dest[IFNAMSIZ], const char src[IFNAMSIZ])
{
	char buf[IFNAMSIZ + 1];

	memcpy(buf, src, IFNAMSIZ);
	buf[IFNAMSIZ] = 0;

	if (strlen(buf) == IFNAMSIZ)
		return -EINVAL;

	strcpy(dest, buf);

	return 0;
}

int uds_copy(char dest[UNIX_PATH_MAX], const char src[UNIX_PATH_MAX])
{
	char buf[UNIX_PATH_MAX + 1];

	memcpy(buf, src, UNIX_PATH_MAX);
	buf[UNIX_PATH_MAX] = 0;

	if (strlen(buf) == UNIX_PATH_MAX)
		return -EINVAL;

	strcpy(dest, buf);

	return 0;
}
