// SPDX-License-Identifier: GPL-2.0
/* Copyright 2019-2021 NXP */
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argparser.h"
#include "common.h"

int string_replace_escape_sequences(char *str)
{
	char *end_ptr = str + strlen(str);
	char code, replacement;
	const char *p = str;
	char *backslash;

	while ((backslash = strchr(p, '\\')) != NULL) {
		if (backslash + 1 >= end_ptr) {
			fprintf(stderr,
				"Illegal backslash placement at the end of the printf format\n");
			return -EINVAL;
		}

		code = *(backslash + 1);
		switch (code) {
		case 'a': /* alert (beep) */
			replacement = '\a';
			break;
		case '\\': /* backslash */
			replacement = '\\';
			break;
		case 'b': /* backspace */
			replacement = '\b';
			break;
		case 'r': /* carriage return */
			replacement = '\r';
			break;
		case '"': /* double quote */
			replacement = '"';
			break;
		case 'f': /* formfeed */
			replacement = '\f';
			break;
		case 't': /* horizontal tab */
			replacement = '\t';
			break;
		case 'n': /* newline */
			replacement = '\n';
			break;
		case '0': /* null character */
			replacement = '\0';
			break;
		case '\'': /* single quote */
			replacement = '\'';
			break;
		case 'v': /* vertical tab */
			replacement = '\v';
			break;
		case '?': /* question mark */
			replacement = '\?';
			break;
		case '\n': /* line continuation */
			replacement = ' ';
			break;
		default:
			fprintf(stderr,
				"Unrecognized escape sequence %c\n", code);
			return -EINVAL;
		}

		*backslash = replacement;
		memmove(backslash + 1, backslash + 2,
			end_ptr - (backslash + 2));

		p = backslash + 1;
		end_ptr--;
	}

	*end_ptr = '\0';

	return 0;
}

char *string_trim_whitespaces(char *str)
{
	size_t len;
	char *end;

	/* Trim leading space */
	while (isspace(*str))
		str++;

	/* All spaces? */
	len = strlen(str);
	if (!len)
		return str;

	/* Trim trailing space */
	end = str + len - 1;
	while (end > str && isspace(*end))
		end--;

	/* Write new null terminator */
	*(end + 1) = 0;
	return str;
}

char *string_trim_comments(char *str)
{
	char *pound, *single_quote, *double_quote, *first_quote, *next_quote;
	char *substr = str;

	while (strlen(substr)) {
		pound = strchr(substr, '#');
		if (!pound)
			break;

		single_quote = strchr(substr, '\'');
		double_quote = strchr(substr, '"');

		if (!single_quote && !double_quote) {
			/* We have a comment and no quotes,
			 * strip the rest of the line
			 */
			*pound = 0;
			break;
		} else if (single_quote && !double_quote) {
			first_quote = single_quote;
		} else if (!single_quote && double_quote) {
			first_quote = double_quote;
		} else {
			/* We have both kinds of quotes, choose the first one */
			if (single_quote - substr < double_quote - substr)
				first_quote = single_quote;
			else
				first_quote = double_quote;
		}

		next_quote = strchr(first_quote + 1, *first_quote);
		if (!next_quote) {
			fprintf(stderr, "Unterminated quoted string: \"%s\"\n",
				str);
			*pound = 0;
			break;
		}

		/* Continue the search after the closing quote */
		substr = next_quote + 1;
	}

	return str;
}

static int mac_addr_from_string(unsigned char *to, char *from)
{
	unsigned long byte;
	char *p = from;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		byte = strtoul(p, &p, 16);
		to[i] = (unsigned char)byte;
		if (i == (ETH_ALEN - 1) && *p != 0)
			/* 6 bytes processed but more are present */
			return -EFBIG;
		else if (i != (ETH_ALEN - 1) && *p == ':')
			p++;
	}

	return 0;
}

int ip_addr_from_string(const char *string, struct ip_address *ip)
{
	char *percent, *if_name;
	size_t len;
	int rc;

	percent = strchr(string, '%');
	if (percent) {
		if_name = percent + 1;
		len = strlen(if_name);
		if (!len || len >= IFNAMSIZ) {
			fprintf(stderr, "Invalid interface name %s\n",
				if_name);
			return -EINVAL;
		}

		*percent = 0;
		strcpy(ip->bound_if_name, if_name);
	}

	rc = inet_pton(AF_INET6, string, &ip->addr6);
	if (rc > 0) {
		ip->family = AF_INET6;
	} else {
		rc = inet_pton(AF_INET, string, &ip->addr);
		if (rc > 0) {
			ip->family = AF_INET;
		} else {
			fprintf(stderr, "IP address %s not in known format\n",
			        string);
			return -1;
		}
	}

	return 0;
}

static int get_time_from_string(clockid_t clkid, __s64 *to, char *from)
{
	struct timespec now_ts = {0};
	__kernel_time_t sec;
	int relative = 0;
	long nsec = 0;
	__s64 now = 0;
	int size;

	if (from[0] == '+') {
		relative = 1;
		from++;
	}

	errno = 0;
	sec = strtol(from, &from, 0);
	if (errno) {
		perror("Failed to read seconds");
		return -EINVAL;
	}
	if (from[0] == '.') {
		char nsec_buf[] = "000000000";
		int i;

		/* The format is "sec.nsec" */
		from++;
		if (strlen(from) > 9) {
			fprintf(stderr,
				"Nanosecond format too long, would truncate: %s\n",
				from);
			return -ERANGE;
		}
		size = sprintf(nsec_buf, "%s", from);
		for (i = size; i < 9; i++)
			nsec_buf[i] = '0';

		errno = 0;
		/* Force base 10 here, since leading zeroes will make
		 * strtol think this is an octal number.
		 */
		nsec = strtol(nsec_buf, NULL, 10);
		if (errno) {
			perror("Failed to extract ns info");
			return -EINVAL;
		}
	} else {
		/* The format is "nsec" */
		nsec = sec;
		sec = 0;
	}

	if (relative) {
		clock_gettime(clkid, &now_ts);
		now = timespec_to_ns(&now_ts);
	}

	*to = sec * NSEC_PER_SEC + nsec;
	*to += now;

	return 0;
}

static const char * const prog_arg_type_str[] = {
	[PROG_ARG_MAC_ADDR] = "MAC address",
	[PROG_ARG_UNSIGNED] = "Unsigned integer",
	[PROG_ARG_LONG] = "Long integer",
	[PROG_ARG_TIME] = "Time in sec.nsec format",
	[PROG_ARG_FILEPATH] = "File path",
	[PROG_ARG_IFNAME] = "Network interface",
	[PROG_ARG_STRING] = "String",
	[PROG_ARG_BOOL] = "Boolean",
	[PROG_ARG_IP] = "IP address",
	[PROG_ARG_HELP] = "Help text",
};

static int required_args[] = {
	[PROG_ARG_MAC_ADDR] = 1,
	[PROG_ARG_UNSIGNED] = 1,
	[PROG_ARG_LONG] = 1,
	[PROG_ARG_TIME] = 1,
	[PROG_ARG_FILEPATH] = 1,
	[PROG_ARG_IFNAME] = 1,
	[PROG_ARG_STRING] = 1,
	[PROG_ARG_BOOL] = 0,
	[PROG_ARG_IP] = 1,
	[PROG_ARG_HELP] = 0,
};

void prog_usage(const char *prog_name, struct prog_arg *prog_args,
		int prog_args_size)
{
	int i;

	fprintf(stderr, "%s usage:\n", prog_name);

	for (i = 0; i < prog_args_size; i++)
		fprintf(stderr, "%s|%s: %s%s\n",
			prog_args[i].short_opt, prog_args[i].long_opt,
			prog_arg_type_str[prog_args[i].type],
			prog_args[i].optional ? " (optional)" : "");
}

static int prog_parse_one_arg(char *val, const struct prog_arg *match)
{
	struct prog_arg_filepath filepath;
	struct prog_arg_ifname ifname;
	struct prog_arg_string string;
	unsigned long *unsigned_ptr;
	struct prog_arg_time time;
	struct ip_address *ip_ptr;
	bool *boolean_ptr;
	long *long_ptr;
	bool *help_ptr;
	int rc;

	switch (match->type) {
	case PROG_ARG_MAC_ADDR:
		rc = mac_addr_from_string(match->mac.buf, val);
		if (rc < 0) {
			pr_err(rc, "Could not read %s: %m\n", match->long_opt);
			return rc;
		}
		break;
	case PROG_ARG_UNSIGNED:
		unsigned_ptr = match->unsigned_ptr.ptr;

		errno = 0;
		*unsigned_ptr = strtoul(val, NULL, 0);
		if (errno) {
			pr_err(-errno, "Could not read %s: %m\n", match->long_opt);
			return -1;
		}
		break;
	case PROG_ARG_LONG:
		long_ptr = match->long_ptr.ptr;

		errno = 0;
		*long_ptr = strtol(val, NULL, 0);
		if (errno) {
			pr_err(-errno, "Could not read %s: %m\n", match->long_opt);
			return -1;
		}
		break;
	case PROG_ARG_IP:
		ip_ptr = match->ip_ptr.ptr;

		rc = ip_addr_from_string(val, ip_ptr);
		if (rc)
			return rc;

		break;
	case PROG_ARG_TIME:
		time = match->time;

		rc = get_time_from_string(time.clkid, time.ns, val);
		if (rc < 0) {
			pr_err(rc, "Could not read base time: %m\n");
			return -1;
		}
		break;
	case PROG_ARG_BOOL:
		boolean_ptr = match->boolean_ptr.ptr;

		*boolean_ptr = true;
		break;
	case PROG_ARG_FILEPATH:
		filepath = match->filepath;

		if (strlen(val) >= filepath.size) {
			fprintf(stderr,
				"File path \"%s\" too large, please limit to %zu bytes\n",
				val, filepath.size);
			return -ERANGE;
		}

		strcpy(filepath.buf, val);
		break;
	case PROG_ARG_IFNAME:
		ifname = match->ifname;

		if (strlen(val) >= ifname.size) {
			fprintf(stderr,
				"Interface name \"%s\" too large, please limit to %zu bytes\n",
				val, ifname.size);
			return -ERANGE;
		}

		strcpy(ifname.buf, val);
		break;
	case PROG_ARG_STRING:
		string = match->string;

		if (strlen(val) >= string.size) {
			fprintf(stderr,
				"String \"%s\" too large, please limit to %zu bytes\n",
				val, string.size);
			return -ERANGE;
		}

		strcpy(string.buf, val);
		break;
	case PROG_ARG_HELP:
		help_ptr = match->help_ptr.ptr;

		*help_ptr = true;
		break;
	default:
		fprintf(stderr, "Unknown argument type %d\n",
			match->type);
		return -EINVAL;
	}

	return 0;
}

/* Parse non-positional arguments and return the number of
 * arguments consumed. Return on first positional argument
 * found.
 */
int prog_parse_np_args(int argc, char **argv, struct prog_arg *prog_args,
		       int prog_args_size)
{
	bool help_requested = false;
	int rc, i, parsed = 0;
	bool *parsed_arr;

	parsed_arr = calloc(sizeof(bool), prog_args_size);
	if (!parsed_arr)
		return -ENOMEM;

	while (argc) {
		char *arg = argv[0], *val = NULL;
		char *equals = NULL;

		equals = strchr(arg, '=');
		if (equals) {
			*equals = 0;
			val = equals + 1;
		} else if (argc >= 2) {
			val = argv[1];
		}

		for (i = 0; i < prog_args_size; i++) {
			if (strcmp(arg, prog_args[i].short_opt) &&
			    strcmp(arg, prog_args[i].long_opt))
				continue;

			/* Consume argument specifier */
			parsed++;
			argc--;
			argv++;

			if (!val && argc < required_args[prog_args[i].type]) {
				fprintf(stderr, "Value expected after %s\n",
					arg);
				free(parsed_arr);
				return -EINVAL;
			}

			rc = prog_parse_one_arg(val, &prog_args[i]);
			if (rc) {
				free(parsed_arr);
				return rc;
			}

			if (prog_args[i].type == PROG_ARG_HELP)
				help_requested = true;

			/* Consume actual argument value, unless it was
			 * separated from the argument string by an "=" sign,
			 * case in which it's really the same string
			 */
			if (!equals) {
				parsed += required_args[prog_args[i].type];
				argc -= required_args[prog_args[i].type];
				argv += required_args[prog_args[i].type];
			}
			parsed_arr[i] = true;

			/* Success, stop searching */
			break;
		}
		if (i == prog_args_size) {
			fprintf(stderr, "Unrecognized option %s\n", arg);
			free(parsed_arr);
			return -EINVAL;
		}
	}

	for (i = 0; i < prog_args_size; i++) {
		/* Mandatory arguments are only mandatory if the user doesn't
		 * specify --help.
		 */
		if (!prog_args[i].optional && !parsed_arr[i] &&
		    !help_requested) {
			fprintf(stderr, "Please specify %s\n",
				prog_args[i].long_opt);
			free(parsed_arr);
			return -EINVAL;
		}
	}

	free(parsed_arr);

	return parsed;
}
