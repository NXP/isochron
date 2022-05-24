/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _RTNL_H
#define _RTNL_H

int vlan_resolve_real_dev(struct mnl_socket *rtnl, const char *vlan_ifname,
			  char *real_ifname);

#endif
