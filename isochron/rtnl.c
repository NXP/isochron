// SPDX-License-Identifier: GPL-2.0
/* Copyright 2022 NXP */
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <string.h>
#include "common.h"

struct vlan_info {
	const char *kind;
	__u32 link_ifindex;
};

struct ifname_info {
	const char *ifname;
};

struct ifindex_info {
	int ifindex;
};

static int rtnl_parse_vlan_linkinfo(const struct nlattr *attr, void *data)
{
	__u16 type = mnl_attr_get_type(attr);
	struct vlan_info *v = data;

	/* skip unsupported attributes */
	if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_INFO_KIND:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		v->kind = mnl_attr_get_str(attr);
		break;
	}

	return MNL_CB_OK;
}

static int rtnl_parse_vlan_attr(const struct nlattr *attr, void *data)
{
	struct vlan_info *v = data;

	/* skip unsupported attributes */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (mnl_attr_get_type(attr)) {
	case IFLA_LINK:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}

		v->link_ifindex = mnl_attr_get_u32(attr);
		break;
	case IFLA_LINKINFO:
		mnl_attr_parse_nested(attr, rtnl_parse_vlan_linkinfo, v);

		break;
	}

	return MNL_CB_OK;
}

static int rtnl_parse_vlan_nlh(const struct nlmsghdr *nlh, void *data)
{
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
	struct vlan_info *v = data;

	mnl_attr_parse(nlh, sizeof(*ifm), rtnl_parse_vlan_attr, v);

	return MNL_CB_STOP;
}

static int rtnl_parse_ifname_attr(const struct nlattr *attr, void *data)
{
	struct ifname_info *i = data;

	/* skip unsupported attributes */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (mnl_attr_get_type(attr)) {
	case IFLA_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}

		i->ifname = mnl_attr_get_str(attr);
		break;
	}

	return MNL_CB_OK;
}

static int rtnl_parse_ifname_nlh(const struct nlmsghdr *nlh, void *data)
{
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
	struct ifname_info *i = data;

	mnl_attr_parse(nlh, sizeof(*ifm), rtnl_parse_ifname_attr, i);

	return MNL_CB_STOP;
}

static int rtnl_parse_ifindex_nlh(const struct nlmsghdr *nlh, void *data)
{
	struct ifinfomsg *ifm = mnl_nlmsg_get_payload(nlh);
	struct ifindex_info *i = data;

	i->ifindex = ifm->ifi_index;

	return MNL_CB_STOP;
}

static int rtnl_getlink_by_ifname(struct mnl_socket *rtnl, const char *ifname,
				  mnl_cb_t cb, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;
	__u32 seq, portid;
	int rc;

	portid = mnl_socket_get_portid(rtnl);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;

	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq = time(NULL);

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_change = 0;
	ifm->ifi_flags = 0;

	mnl_attr_put_str(nlh, IFLA_IFNAME, ifname);

	if (mnl_socket_sendto(rtnl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return -errno;
	}

	rc = mnl_socket_recvfrom(rtnl, buf, sizeof(buf));
	if (rc < 0) {
		perror("mnl_socket_recvfrom");
		return -errno;
	}

	rc = mnl_cb_run(buf, rc, seq, portid, cb, data);
	if (rc < 0) {
		perror("mnl_cb_run");
		return -errno;
	}

	return 0;
}

static int rtnl_getlink_by_ifindex(struct mnl_socket *rtnl, int ifindex,
				   mnl_cb_t cb, void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct ifinfomsg *ifm;
	struct nlmsghdr *nlh;
	__u32 seq, portid;
	int rc;

	portid = mnl_socket_get_portid(rtnl);

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;

	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq = time(NULL);

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = ifindex;
	ifm->ifi_change = 0;
	ifm->ifi_flags = 0;

	if (mnl_socket_sendto(rtnl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		return -errno;
	}

	rc = mnl_socket_recvfrom(rtnl, buf, sizeof(buf));
	if (rc < 0) {
		perror("mnl_socket_recvfrom");
		return -errno;
	}

	rc = mnl_cb_run(buf, rc, seq, portid, cb, data);
	if (rc < 0) {
		perror("mnl_cb_run");
		return -errno;
	}

	return 0;
}

static int rtnl_fill_vlan_info(struct mnl_socket *rtnl, int ifindex,
			       struct vlan_info *v)
{
	return rtnl_getlink_by_ifindex(rtnl, ifindex, rtnl_parse_vlan_nlh, v);
}

static int rtnl_fill_ifindex_name(struct mnl_socket *rtnl, int ifindex,
				  struct ifname_info *i)
{
	return rtnl_getlink_by_ifindex(rtnl, ifindex, rtnl_parse_ifname_nlh, i);
}

static int rtnl_fill_ifname_ifindex(struct mnl_socket *rtnl, const char *ifname,
				    struct ifindex_info *i)
{
	return rtnl_getlink_by_ifname(rtnl, ifname, rtnl_parse_ifindex_nlh, i);
}

int vlan_resolve_real_dev(struct mnl_socket *rtnl, const char *vlan_ifname,
			  char *real_ifname)
{
	struct ifindex_info ifindex = {};
	struct ifname_info ifname = {};
	struct vlan_info v = {};
	int rc;

	rc = rtnl_fill_ifname_ifindex(rtnl, vlan_ifname, &ifindex);
	if (rc)
		return rc;

	do {
		rc = rtnl_fill_vlan_info(rtnl, ifindex.ifindex, &v);
		if (rc)
			return rc;

		if (!v.kind || strcmp(v.kind, "vlan"))
			break;

		ifindex.ifindex = v.link_ifindex;
	} while (true);

	rc = rtnl_fill_ifindex_name(rtnl, ifindex.ifindex, &ifname);
	if (rc)
		return rc;

	strcpy(real_ifname, ifname.ifname);

	return 0;
}
