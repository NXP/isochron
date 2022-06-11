/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include "common.h"
#include "sk.h"

struct sk_addr {
	union {
		struct sockaddr_ll l2;
		struct sockaddr_in udp4;
		struct sockaddr_in6 udp6;
	} u;
	size_t sockaddr_size;
};

struct sk_msg {
	struct iovec iov;
	struct msghdr msghdr;
	struct cmsghdr *last_cmsg;
	char *msg_control;
};

struct sk {
	int family;
	int fd;
	struct sk_addr *sa;
	bool closed;
};

static int __sk_bind_ipv4(int fd, const struct in_addr *a, int port)
{
	struct sockaddr_in s = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};

	memcpy(&s.sin_addr, a, sizeof(*a));

	return bind(fd, (struct sockaddr *)&s, sizeof(s));
}

static int sk_bind_ipv4_any(int fd, int port)
{
	struct in_addr a = {
		.s_addr = htonl(INADDR_ANY),
	};

	return __sk_bind_ipv4(fd, &a, port);
}

static int sk_bind_ipv4(int fd, const struct ip_address *ip, int port)
{
	if (ip->family != AF_INET)
		return sk_bind_ipv4_any(fd, port);

	return __sk_bind_ipv4(fd, &ip->addr, port);
}

static int __sk_bind_ipv6(int fd, const struct in6_addr *a, int port)
{
	struct sockaddr_in6 s = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
	};

	memcpy(&s.sin6_addr, a, sizeof(*a));

	return bind(fd, (struct sockaddr *)&s, sizeof(s));
}

static int sk_bind_ipv6_any(int fd, int port)
{
	struct in6_addr a = in6addr_any;

	return __sk_bind_ipv6(fd, &a, port);
}

static int sk_bind_ipv6(int fd, const struct ip_address *ip, int port)
{
	if (ip->family != AF_INET6)
		return sk_bind_ipv6_any(fd, port);

	return __sk_bind_ipv6(fd, &ip->addr6, port);
}

int sk_listen_tcp(const struct ip_address *ip, int port, int backlog,
		  struct sk **listen_sock)
{
	bool ipv4_fallback = false;
	int sockopt = 1;
	int fd, rc;

	*listen_sock = calloc(1, sizeof(struct sk));
	if (!(*listen_sock))
		return -ENOMEM;

	fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		/* Linux kernel is dual stack and allows IPv4-mapped IPv6
		 * addresses, but it may be compiled with CONFIG_IPV6=n, case
		 * in which we need to explicitly fall back to PF_INET sockets.
		 */
		fd = socket(PF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			perror("Failed to create IPv6 or IPv4 socket");
			goto out;
		}
		ipv4_fallback = true;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));
	if (rc < 0) {
		perror("Failed to setsockopt(SO_REUSEADDR)");
		goto out_close;
	}

	if (strlen(ip->bound_if_name)) {
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				ip->bound_if_name, IFNAMSIZ - 1);
		if (rc < 0) {
			fprintf(stderr,
				"Failed to bind socket to device %s: %m\n",
				ip->bound_if_name);
			goto out_close;
		}
	}

	if (ipv4_fallback)
		rc = sk_bind_ipv4(fd, ip, port);
	else
		rc = sk_bind_ipv6(fd, ip, port);
	if (rc < 0) {
		fprintf(stderr, "Failed to bind to TCP port %d: %m\n", port);
		goto out_close;
	}

	rc = listen(fd, backlog);
	if (rc < 0) {
		fprintf(stderr, "Failed to listen on TCP port %d: %m\n", port);
		goto out_close;
	}

	(*listen_sock)->fd = fd;
	(*listen_sock)->family = ipv4_fallback ? PF_INET : PF_INET6;

	return 0;
out_close:
	close(fd);
out:
	free(*listen_sock);
	*listen_sock = NULL;
	return -errno;
}

static int sk_accept_ipv6(const struct sk *listen_sock, struct sk *sock,
			  char *client_addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 sa;
	int fd;

	fd = accept(listen_sock->fd, (struct sockaddr *)&sa, &addr_len);
	if (fd < 0) {
		if (errno != EINTR)
			perror("Failed to accept connection from socket");
		return -errno;
	}

	if (!inet_ntop(AF_INET6, &sa.sin6_addr, client_addr,
	    INET6_ADDRSTRLEN)) {
		perror("Failed to convert IPv6 address to text");
		close(fd);
		return -errno;
	}

	sock->family = PF_INET6;
	sock->fd = fd;

	return 0;
}

static int sk_accept_ipv4(const struct sk *listen_sock, struct sk *sock,
			  char *client_addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in sa;
	int fd;

	fd = accept(listen_sock->fd, (struct sockaddr *)&sa, &addr_len);
	if (fd < 0) {
		if (errno != EINTR)
			perror("Failed to accept connection from socket");
		return -errno;
	}

	if (!inet_ntop(AF_INET, &sa.sin_addr.s_addr, client_addr,
	    INET_ADDRSTRLEN)) {
		perror("Failed to convert IPv4 address to text");
		close(fd);
		return -errno;
	}

	sock->family = PF_INET6;
	sock->fd = fd;

	return 0;
}

int sk_accept(const struct sk *listen_sock, struct sk **sock)
{
	char client_addr[INET6_ADDRSTRLEN];
	int rc;

	if (listen_sock->family != PF_INET && listen_sock->family != PF_INET6)
		return -EINVAL;

	*sock = calloc(1, sizeof(struct sk));
	if (!(*sock))
		return -ENOMEM;

	if (listen_sock->family == PF_INET6)
		rc = sk_accept_ipv6(listen_sock, *sock, client_addr);
	else
		rc = sk_accept_ipv4(listen_sock, *sock, client_addr);
	if (rc) {
		free(*sock);
		return rc;
	}

	printf("Accepted connection from %s\n", client_addr);

	return 0;
}

int sk_connect_tcp(const struct ip_address *ip, int port, struct sk **sock)
{
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	struct sockaddr *sa;
	int fd, size, rc;

	if (ip->family == AF_INET) {
		sa = (struct sockaddr *)&sa4;
		sa4.sin_addr = ip->addr;
		sa4.sin_port = htons(port);
		sa4.sin_family = AF_INET;
		size = sizeof(struct sockaddr_in);
	} else if (ip->family == AF_INET6) {
		sa = (struct sockaddr *)&sa6;
		sa6.sin6_addr = ip->addr6;
		sa6.sin6_port = htons(port);
		sa6.sin6_family = AF_INET6;
		size = sizeof(struct sockaddr_in6);
	} else {
		return -EINVAL;
	}

	*sock = calloc(1, sizeof(struct sk));
	if (!(*sock))
		return -ENOMEM;

	fd = socket(ip->family, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("Failed to create TCP socket");
		goto err;
	}

	if (strlen(ip->bound_if_name)) {
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				ip->bound_if_name, IFNAMSIZ - 1);
		if (rc < 0) {
			fprintf(stderr,
				"Failed to bind TCP socket to device %s: %m\n",
				ip->bound_if_name);
			goto err_close;
		}
	}

	rc = connect(fd, sa, size);
	if (rc < 0) {
		fprintf(stderr, "Failed to connect to TCP port %d: %m\n",
			port);
		goto err_close;
	}

	(*sock)->fd = fd;
	(*sock)->family = ip->family;

	return 0;

err_close:
	close(fd);
err:
	free(*sock);
	*sock = NULL;
	return -errno;
}

static void sk_addr_destroy(struct sk_addr *sa)
{
	free(sa);
}

void sk_close(struct sk *sock)
{
	if (sock->sa)
		sk_addr_destroy(sock->sa);
	close(sock->fd);
	free(sock);
}

int sk_recv(struct sk *sock, void *buf, size_t len, int flags)
{
	size_t received = 0;
	ssize_t ret;

	do {
		ret = recv(sock->fd, buf + received, len - received, flags);
		if (ret <= 0) {
			sock->closed = ret == 0;
			return ret ? -errno : -ECONNRESET;
		}
		received += ret;
	} while (received != len);

	return 0;
}

int sk_send(struct sk *sock, const void *buf, size_t count)
{
	size_t sent = 0;
	ssize_t ret;

	do {
		ret = send(sock->fd, buf + sent, count - sent, 0);
		if (ret <= 0) {
			sock->closed = ret == 0;
			return ret ? -errno : -ECONNRESET;
		}
		sent += ret;
	} while (sent != count);

	return 0;
}

int sk_fd(const struct sk *sock)
{
	return sock->fd;
}

bool sk_closed(const struct sk *sock)
{
	return sock->closed;
}

static struct sk_addr *sk_addr_create_l2(const unsigned char addr[ETH_ALEN],
					 __u16 ethertype, const char *if_name)
{
	int ifindex = if_nametoindex(if_name);
	struct sk_addr *sa;

	if (!ifindex) {
		fprintf(stderr, "Could not determine ifindex of %s\n", if_name);
		return NULL;
	}

	sa = calloc(1, sizeof(struct sk_addr));
	if (!sa)
		return NULL;

	sa->u.l2.sll_protocol = __cpu_to_be16(ethertype);
	sa->u.l2.sll_ifindex = ifindex;
	sa->u.l2.sll_halen = ETH_ALEN;
	sa->u.l2.sll_family = AF_PACKET;
	ether_addr_copy(sa->u.l2.sll_addr, addr);
	sa->sockaddr_size = sizeof(struct sockaddr_ll);

	return sa;
}

static struct sk_addr *sk_addr_create_udp(const struct ip_address *ip, int port)
{
	struct sk_addr *sa;

	sa = calloc(1, sizeof(struct sk_addr));
	if (!sa)
		return NULL;

	if (ip->family == AF_INET) {
		sa->u.udp4.sin_addr = ip->addr;
		sa->u.udp4.sin_port = htons(port);
		sa->u.udp4.sin_family = AF_INET;
		sa->sockaddr_size = sizeof(struct sockaddr_in);
	} else {
		sa->u.udp6.sin6_addr = ip->addr6;
		sa->u.udp6.sin6_port = htons(port);
		sa->u.udp6.sin6_family = AF_INET6;
		sa->sockaddr_size = sizeof(struct sockaddr_in6);
	}

	return sa;
}

struct sk_msg *sk_msg_create(const struct sk *sock, void *buf, size_t len,
			     size_t cmsg_len)
{
	struct sk_addr *sa = sock->sa;
	struct sk_msg *msg;

	if (!sa)
		return NULL;

	msg = calloc(1, sizeof(struct sk_msg));
	if (!msg)
		return NULL;

	if (cmsg_len) {
		msg->msg_control = calloc(1, cmsg_len);
		if (!msg->msg_control) {
			free(msg);
			return NULL;
		}
	}

	msg->iov.iov_base = buf;
	msg->iov.iov_len = len;

	msg->msghdr.msg_name = (struct sockaddr *)&sa->u;
	msg->msghdr.msg_namelen = sa->sockaddr_size;
	msg->msghdr.msg_iov = &msg->iov;
	msg->msghdr.msg_iovlen = 1;
	msg->msghdr.msg_control = msg->msg_control;

	return msg;
}

void sk_msg_destroy(struct sk_msg *msg)
{
	if (msg->msg_control)
		free(msg->msg_control);
	free(msg);
}

struct cmsghdr *sk_msg_add_cmsg(struct sk_msg *msg, int level, int type,
				size_t len)
{
	struct cmsghdr *cmsg;

	msg->msghdr.msg_controllen += len;

	if (msg->last_cmsg)
		cmsg = CMSG_NXTHDR(&msg->msghdr, msg->last_cmsg);
	else
		cmsg = CMSG_FIRSTHDR(&msg->msghdr);

	cmsg->cmsg_level = level;
	cmsg->cmsg_type = type;
	cmsg->cmsg_len = len;
	msg->last_cmsg = cmsg;

	return cmsg;
}

int sk_sendmsg(struct sk *sock, const struct sk_msg *msg, int flags)
{
	return sendmsg(sock->fd, &msg->msghdr, flags);
}

int sk_bind_l2(const unsigned char addr[ETH_ALEN], __u16 ethertype,
	       const char *if_name, struct sk **sock)
{
	struct sk_addr *sa;
	int fd, rc;

	*sock = calloc(1, sizeof(struct sk));
	if (!(*sock))
		return -ENOMEM;

	sa = sk_addr_create_l2(addr, ethertype, if_name);
	if (!sa)
		goto out_free_sock;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ethertype));
	if (fd < 0) {
		perror("Failed to create PF_PACKET socket");
		goto out_free_sa;
	}

	/* Bind to device */
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ - 1);
	if (rc < 0) {
		fprintf(stderr, "Failed to bind L2 socket to device %s: %m",
			if_name);
		goto out_close;
	}

	rc = bind(fd, (struct sockaddr *)&sa->u.l2, sa->sockaddr_size);
	if (rc)
		goto out_close;

	(*sock)->fd = fd;
	(*sock)->family = PF_PACKET;
	(*sock)->sa = sa;

	return 0;

out_close:
	close(fd);
out_free_sa:
	free(sa);
out_free_sock:
	free(*sock);
	*sock = NULL;
	return -errno;
}

int sk_udp(const struct ip_address *dest, int port, struct sk **sock)
{
	bool ipv4_fallback = false;
	struct sk_addr *sa;
	int fd, rc;

	*sock = calloc(1, sizeof(struct sk));
	if (!(*sock))
		return -ENOMEM;

	sa = sk_addr_create_udp(dest, port);
	if (!sa) {
		errno = -ENOMEM;
		goto out_free_sock;
	}

	if (dest->family) {
		fd = socket(dest->family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0) {
			perror("Failed to create UDP socket");
			goto out_free_sa;
		}
	} else {
		fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0) {
			fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (fd < 0) {
				perror("Failed to create IPv6 or IPv4 UDP socket");
				goto out_free_sa;
			}
			ipv4_fallback = true;
		}
	}

	if (strlen(dest->bound_if_name)) {
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				dest->bound_if_name, IFNAMSIZ - 1);
		if (rc < 0) {
			fprintf(stderr,
				"Failed to bind socket to device %s: %m\n",
				dest->bound_if_name);
			goto out_close;
		}
	}

	(*sock)->fd = fd;
	(*sock)->family = dest->family ? : ipv4_fallback ? PF_INET : PF_INET6;
	(*sock)->sa = sa;

	return 0;
out_close:
	close(fd);
out_free_sa:
	free(sa);
out_free_sock:
	free(*sock);
	*sock = NULL;
	return -errno;
}

int sk_bind_udp(const struct ip_address *dest, int port, struct sk **sock)
{
	int rc;

	rc = sk_udp(dest, port, sock);
	if (rc)
		return rc;

	if ((*sock)->family == AF_INET)
		rc = sk_bind_ipv4((*sock)->fd, dest, port);
	else
		rc = sk_bind_ipv6((*sock)->fd, dest, port);
	if (rc) {
		fprintf(stderr, "Failed to bind to UDP port %d: %m\n", port);
		sk_close(*sock);
		*sock = NULL;
	}

	return rc;
}

static void init_ifreq(struct ifreq *ifreq, struct hwtstamp_config *cfg,
		       const char if_name[IFNAMSIZ])
{
	memset(ifreq, 0, sizeof(*ifreq));
	memset(cfg, 0, sizeof(*cfg));

	strcpy(ifreq->ifr_name, if_name);

	ifreq->ifr_data = (void *) cfg;
}

static int hwts_init(int fd, const char if_name[IFNAMSIZ], int rx_filter,
		     int tx_type)
{
	struct hwtstamp_config cfg;
	struct ifreq ifreq;
	int rc;

	init_ifreq(&ifreq, &cfg, if_name);

	cfg.tx_type   = tx_type;
	cfg.rx_filter = rx_filter;
	rc = ioctl(fd, SIOCSHWTSTAMP, &ifreq);
	if (rc < 0) {
		perror("ioctl SIOCSHWTSTAMP failed");
		return -errno;
	}

	if (cfg.tx_type != tx_type)
		fprintf(stderr, "tx_type   %d not %d\n",
			cfg.tx_type, tx_type);
	if (cfg.rx_filter != rx_filter)
		fprintf(stderr, "rx_filter %d not %d\n",
			cfg.rx_filter, rx_filter);
	if (cfg.tx_type != tx_type || cfg.rx_filter != rx_filter)
		fprintf(stderr,
			"The current filter does not match the required\n");

	return 0;
}

int sk_timestamping_init(struct sk *sock, const char if_name[IFNAMSIZ], bool on)
{
	int rc, filter, flags, tx_type;
	int fd = sock->fd;

	if (strlen(if_name) >= IFNAMSIZ) {
		fprintf(stderr, "Interface name %s too long\n", if_name);
		return -EINVAL;
	}

	flags = SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_TX_SCHED |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE |
		SOF_TIMESTAMPING_OPT_TX_SWHW |
		SOF_TIMESTAMPING_OPT_ID;

	filter = HWTSTAMP_FILTER_ALL;

	if (on)
		tx_type = HWTSTAMP_TX_ON;
	else
		tx_type = HWTSTAMP_TX_OFF;

	rc = hwts_init(fd, if_name, filter, tx_type);
	if (rc)
		return rc;

	rc = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING,
			&flags, sizeof(flags));
	if (rc < 0) {
		perror("ioctl SO_TIMESTAMPING failed");
		return -1;
	}

	flags = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_SELECT_ERR_QUEUE,
			&flags, sizeof(flags));
	if (rc < 0) {
		perror("SO_SELECT_ERR_QUEUE failed");
		return rc;
	}

	return 0;
}

int sk_recvmsg(struct sk *sock, void *buf, int buflen,
	       struct isochron_timestamp *tstamp, int flags, int timeout)
{
	struct iovec iov = { buf, buflen };
	struct timespec *ts;
	struct cmsghdr *cm;
	struct msghdr msg;
	char control[256];
	int fd = sock->fd;
	ssize_t len;
	int rc = 0;

	memset(control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	if (flags == MSG_ERRQUEUE) {
		struct pollfd pfd = { fd, POLLPRI, 0 };

		rc = poll(&pfd, 1, timeout);
		if (rc == 0) {
			return 0;
		} else if (rc < 0) {
			perror("poll for tx timestamp failed");
			return rc;
		} else if (!(pfd.revents & POLLPRI)) {
			fprintf(stderr, "poll woke up on non ERR event\n");
			return -1;
		}
		/* On success a positive number is returned */
	}

	len = recvmsg(fd, &msg, flags);
	/* Suppress "Interrupted system call" message */
	if (len < 1 && errno != EINTR)
		perror("recvmsg failed");

	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm)) {
		int level = cm->cmsg_level;
		int type  = cm->cmsg_type;

		if (level == SOL_SOCKET && type == SCM_TIMESTAMPING) {
			struct scm_timestamping *tss;

			if (cm->cmsg_len < sizeof(*ts) * 3) {
				fprintf(stderr, "short SO_TIMESTAMPING message\n");
				return -1;
			}

			tss = (struct scm_timestamping *)CMSG_DATA(cm);

			if (tstamp) {
				tstamp->sw = tss->ts[0];
				tstamp->hw = tss->ts[2];
			}
		} else if ((level == SOL_PACKET && type == PACKET_TX_TIMESTAMP) ||
			   (level == SOL_IP && type == IP_RECVERR) ||
			   (level == SOL_IPV6 && type == IPV6_RECVERR)) {
			struct sock_extended_err *sock_err;
			char txtime_buf[TIMESPEC_BUFSIZ];
			__u64 txtime;

			sock_err = (struct sock_extended_err *)CMSG_DATA(cm);
			if (!sock_err)
				continue;

			switch (sock_err->ee_origin) {
			case SO_EE_ORIGIN_TIMESTAMPING:
				if (!tstamp)
					break;

				tstamp->tskey = sock_err->ee_data;
				tstamp->tstype = sock_err->ee_info;
				break;
			case SO_EE_ORIGIN_TXTIME:
				txtime = ((__u64)sock_err->ee_data << 32) +
					 sock_err->ee_info;

				if (tstamp)
					tstamp->txtime = ns_to_timespec(txtime);

				ns_sprintf(txtime_buf, txtime);

				switch (sock_err->ee_code) {
				case SO_EE_CODE_TXTIME_INVALID_PARAM:
					fprintf(stderr,
						"packet with txtime %s dropped due to invalid params\n",
						txtime_buf);
					break;
				case SO_EE_CODE_TXTIME_MISSED:
					fprintf(stderr,
						"packet with txtime %s dropped due to missed deadline\n",
						txtime_buf);
					break;
				default:
					return -1;
				}
				break;
			default:
				pr_err(-sock_err->ee_errno,
				       "unknown socket error %d, origin %d code %d: %m\n",
				       sock_err->ee_errno, sock_err->ee_origin,
				       sock_err->ee_code);
				break;
			}
		} else {
			fprintf(stderr, "unknown cmsg level %d type %d\n",
				level, type);
		}
	}

	return len;
}

int sk_get_ts_info(const char name[IFNAMSIZ], struct sk_ts_info *sk_info)
{
	struct ethtool_ts_info info;
	struct ifreq ifr;
	int fd, err;

	if (strlen(name) >= IFNAMSIZ) {
		fprintf(stderr, "Interface name %s too long\n", name);
		return -EINVAL;
	}

	memset(sk_info, 0, sizeof(struct sk_ts_info));

	memset(&ifr, 0, sizeof(ifr));
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_GET_TS_INFO;
	strcpy(ifr.ifr_name, name);
	ifr.ifr_data = (char *) &info;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket failed: %m\n");
		return -errno;
	}

	err = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	if (err < 0) {
		fprintf(stderr, "ioctl SIOCETHTOOL failed: %m\n");
		return -errno;
	}

	/* copy the necessary data to sk_info */
	sk_info->valid = true;
	sk_info->phc_index = info.phc_index;
	sk_info->so_timestamping = info.so_timestamping;
	sk_info->tx_types = info.tx_types;
	sk_info->rx_filters = info.rx_filters;

	return 0;
}

int sk_validate_ts_info(const char if_name[IFNAMSIZ])
{
	struct sk_ts_info ts_info;
	int rc;

	/* check if device is a valid ethernet device */
	rc = sk_get_ts_info(if_name, &ts_info);
	if (rc)
		return rc;

	if (!ts_info.valid)
		return -EINVAL;

	if (!(ts_info.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE)) {
		fprintf(stderr,
			"Driver not capable of SOF_TIMESTAMPING_TX_HARDWARE, continuing anyway\n");
	}

	if (!(ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE)) {
		fprintf(stderr,
			"Driver not capable of SOF_TIMESTAMPING_RX_HARDWARE, continuing anyway\n");
	}

	if (!(ts_info.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE)) {
		fprintf(stderr,
			"Driver not capable of SOF_TIMESTAMPING_TX_SOFTWARE, continuing anyway\n");
	}

	if (!(ts_info.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE)) {
		fprintf(stderr,
			"Driver not capable of SOF_TIMESTAMPING_RX_SOFTWARE, continuing anyway\n");
	}

	if (!(ts_info.so_timestamping & SOF_TIMESTAMPING_SOFTWARE)) {
		fprintf(stderr,
			"Driver not capable of SOF_TIMESTAMPING_SOFTWARE, continuing anyway\n");
	}

	return 0;
}

int sk_get_ether_addr(const char if_name[IFNAMSIZ], unsigned char *addr)
{
	struct ifreq if_mac;
	int fd, rc;

	if (strlen(if_name) >= IFNAMSIZ) {
		fprintf(stderr, "Interface name %s too long\n", if_name);
		return -EINVAL;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("Failed to open socket");
		return -errno;
	}

	memset(&if_mac, 0, sizeof(struct ifreq));
	strcpy(if_mac.ifr_name, if_name);

	rc = ioctl(fd, SIOCGIFHWADDR, &if_mac);
	close(fd);

	if (rc < 0) {
		perror("SIOCGIFHWADDR");
		return -errno;
	}

	ether_addr_copy(addr, (unsigned char *)if_mac.ifr_hwaddr.sa_data);

	return 0;
}
