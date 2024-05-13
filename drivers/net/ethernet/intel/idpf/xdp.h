/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_XDP_H_
#define _IDPF_XDP_H_

#include <linux/types.h>

struct bpf_prog;
struct idpf_vport;
struct net_device;
struct netdev_bpf;

int idpf_xdp_rxq_info_init_all(const struct idpf_vport *vport);
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport);
void idpf_copy_xdp_prog_to_qs(const struct idpf_vport *vport,
			      struct bpf_prog *xdp_prog);

int idpf_vport_xdpq_get(const struct idpf_vport *vport);
void idpf_vport_xdpq_put(const struct idpf_vport *vport);

int idpf_xdp(struct net_device *dev, struct netdev_bpf *xdp);

#endif /* _IDPF_XDP_H_ */
