/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include "common.h"
#include "sk.h"

struct sk {
	int family;
	int fd;
};

static int sk_bind_ipv4_any(int fd, int port)
{
	struct sockaddr_in s = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(port),
	};

	return bind(fd, (struct sockaddr *)&s, sizeof(s));
}

static int sk_bind_ipv6_any(int fd, int port)
{
	struct sockaddr_in6 s = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_any,
		.sin6_port = htons(port),
	};

	return bind(fd, (struct sockaddr *)&s, sizeof(s));
}

int sk_listen_tcp_any(int port, int backlog, struct sk **listen_sock)
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
			free(*listen_sock);
			return -errno;
		}
		ipv4_fallback = true;
	}

	/* Allow the socket to be reused, in case the connection
	 * is closed prematurely
	 */
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int));
	if (rc < 0) {
		perror("Failed to setsockopt(SO_REUSEADDR)");
		goto out;
	}

	if (ipv4_fallback)
		rc = sk_bind_ipv4_any(fd, port);
	else
		rc = sk_bind_ipv6_any(fd, port);
	if (rc < 0) {
		fprintf(stderr, "Failed to bind to TCP port %d: %m", port);
		goto out;
	}

	rc = listen(fd, backlog);
	if (rc < 0) {
		fprintf(stderr, "Failed to listen on TCP port %d: %m", port);
		goto out;
	}

	(*listen_sock)->fd = fd;
	(*listen_sock)->family = ipv4_fallback ? PF_INET : PF_INET6;

	return 0;
out:
	close(fd);
	free(*listen_sock);
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
			perror("Failed to setsockopt(SO_BINDTODEVICE)");
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
	return -errno;
}

void sk_close(struct sk *sock)
{
	close(sock->fd);
	free(sock);
}

ssize_t sk_recv(const struct sk *sock, void *buf, size_t len, int flags)
{
	size_t received = 0;
	ssize_t ret;

	do {
		ret = recv(sock->fd, buf + received, len - received, flags);
		if (ret <= 0)
			return ret;
		received += ret;
	} while (received != len);

	return received;
}

ssize_t sk_send(const struct sk *sock, const void *buf, size_t count)
{
	return write_exact(sock->fd, buf, count);
}

int sk_fd(const struct sk *sock)
{
	return sock->fd;
}
