/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2019-2021 NXP */
#ifndef _ISOCHRON_ARGPARSER_H
#define _ISOCHRON_ARGPARSER_H

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/types.h>
#include <stdbool.h>
#include <time.h>

struct ip_address {
	int family;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
	char bound_if_name[IFNAMSIZ];
};

enum prog_arg_type {
	PROG_ARG_MAC_ADDR,
	PROG_ARG_UNSIGNED,
	PROG_ARG_LONG,
	PROG_ARG_TIME,
	PROG_ARG_STRING,
	PROG_ARG_IFNAME,
	PROG_ARG_FILEPATH,
	PROG_ARG_BOOL,
	PROG_ARG_IP,
	PROG_ARG_HELP,
};

struct prog_arg_filepath {
	char *buf;
	size_t size;
};

struct prog_arg_ifname {
	char *buf;
	size_t size;
};

struct prog_arg_string {
	char *buf;
	size_t size;
};

struct prog_arg_time {
	clockid_t clkid;
	__s64 *ns;
};

struct prog_arg_unsigned {
	unsigned long *ptr;
};

struct prog_arg_long {
	long *ptr;
};

struct prog_arg_mac_addr {
	unsigned char *buf;
};

struct prog_arg_boolean {
	bool *ptr;
};

struct prog_arg_ip {
	struct ip_address *ptr;
};

struct prog_arg_help {
	bool *ptr;
};

struct prog_arg {
	const char *short_opt;
	const char *long_opt;
	bool optional;
	enum prog_arg_type type;
	union {
		struct prog_arg_string string;
		struct prog_arg_ifname ifname;
		struct prog_arg_filepath filepath;
		struct prog_arg_time time;
		struct prog_arg_unsigned unsigned_ptr;
		struct prog_arg_long long_ptr;
		struct prog_arg_mac_addr mac;
		struct prog_arg_boolean boolean_ptr;
		struct prog_arg_ip ip_ptr;
		struct prog_arg_help help_ptr;
	};
};

int prog_parse_np_args(int argc, char **argv,
		       struct prog_arg *prog_args,
		       int prog_args_size);
void prog_usage(const char *prog_name, struct prog_arg *prog_args,
		int prog_args_size);

int string_replace_escape_sequences(char *str);
char *string_trim_whitespaces(char *str);
char *string_trim_comments(char *str);
int ip_addr_from_string(const char *string, struct ip_address *ip);

#endif
