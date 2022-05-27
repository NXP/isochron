/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 NXP */
#ifndef _RTNL_H
#define _RTNL_H

int vlan_resolve_real_dev(struct mnl_socket *rtnl, const char *vlan_ifname,
			  char *real_ifname);
int rtnl_query_admin_state(struct mnl_socket *rtnl, const char *if_name,
			   bool *up);
int rtnl_query_link_state(struct mnl_socket *rtnl, const char *if_name,
			  bool *running);

#endif
