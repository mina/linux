/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef _IDPF_XSK_H_
#define _IDPF_XSK_H_

#include <linux/types.h>

enum virtchnl2_queue_type;
struct idpf_buf_queue;
struct idpf_rx_queue;
struct idpf_tx_queue;
struct idpf_vport;
struct netdev_bpf;

void idpf_xsk_setup_queue(const struct idpf_vport *vport, void *q,
			  enum virtchnl2_queue_type type);
void idpf_xsk_clear_queue(void *q, enum virtchnl2_queue_type type);

int idpf_xsk_bufs_init(struct idpf_buf_queue *bufq);
void idpf_xsk_buf_rel(struct idpf_buf_queue *bufq);
void idpf_xsk_clean_xdpq(struct idpf_tx_queue *xdpq);

int idpf_clean_rx_irq_zc(struct idpf_rx_queue *rxq, u32 budget);
bool idpf_xsk_xmit(struct idpf_tx_queue *xsksq);

int idpf_xsk_pool_setup(struct idpf_vport *vport, struct netdev_bpf *xdp);

#endif /* !_IDPF_XSK_H_ */
