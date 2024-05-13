// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xdp.h>

#include "idpf.h"
#include "idpf_virtchnl.h"
#include "xdp.h"

static int idpf_rxq_for_each(const struct idpf_vport *vport,
			     int (*fn)(struct idpf_rx_queue *rxq, void *arg),
			     void *arg)
{
	bool splitq = idpf_is_queue_model_split(vport->rxq_model);

	for (u32 i = 0; i < vport->num_rxq_grp; i++) {
		const struct idpf_rxq_group *rx_qgrp = &vport->rxq_grps[i];
		u32 num_rxq;

		if (splitq)
			num_rxq = rx_qgrp->splitq.num_rxq_sets;
		else
			num_rxq = rx_qgrp->singleq.num_rxq;

		for (u32 j = 0; j < num_rxq; j++) {
			struct idpf_rx_queue *q;
			int err;

			if (splitq)
				q = &rx_qgrp->splitq.rxq_sets[j]->rxq;
			else
				q = rx_qgrp->singleq.rxqs[j];

			err = fn(q, arg);
			if (err)
				return err;
		}
	}

	return 0;
}

/**
 * __idpf_xdp_rxq_info_init - Setup XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are setup
 * @arg: flag indicating if the HW works in split queue mode
 *
 * Return: 0 on success, negative on failure.
 */
static int __idpf_xdp_rxq_info_init(struct idpf_rx_queue *rxq, void *arg)
{
	const struct idpf_vport *vport = rxq->q_vector->vport;
	bool split = idpf_is_queue_model_split(vport->rxq_model);
	const struct page_pool *pp;
	int err;

	err = __xdp_rxq_info_reg(&rxq->xdp_rxq, vport->netdev, rxq->idx,
				 rxq->q_vector->napi.napi_id,
				 rxq->rx_buf_size);
	if (err)
		return err;

	pp = split ? rxq->bufq_sets[0].bufq.pp : rxq->pp;
	xdp_rxq_info_attach_page_pool(&rxq->xdp_rxq, pp);

	if (!split)
		return 0;

	rxq->xdpqs = &vport->txqs[vport->xdp_txq_offset];
	rxq->num_xdp_txq = vport->num_xdp_txq;

	return 0;
}

/**
 * idpf_xdp_rxq_info_init_all - initialize RxQ info for all Rx queues in vport
 * @vport: vport to setup the info
 *
 * Return: 0 on success, negative on failure.
 */
int idpf_xdp_rxq_info_init_all(const struct idpf_vport *vport)
{
	return idpf_rxq_for_each(vport, __idpf_xdp_rxq_info_init, NULL);
}

/**
 * __idpf_xdp_rxq_info_deinit - Deinit XDP RxQ info for a given Rx queue
 * @rxq: Rx queue for which the resources are destroyed
 * @arg: flag indicating if the HW works in split queue mode
 *
 * Return: always 0.
 */
static int __idpf_xdp_rxq_info_deinit(struct idpf_rx_queue *rxq, void *arg)
{
	if (idpf_is_queue_model_split((size_t)arg)) {
		rxq->xdpqs = NULL;
		rxq->num_xdp_txq = 0;
	}

	xdp_rxq_info_detach_mem_model(&rxq->xdp_rxq);
	xdp_rxq_info_unreg(&rxq->xdp_rxq);

	return 0;
}

/**
 * idpf_xdp_rxq_info_deinit_all - deinit RxQ info for all Rx queues in vport
 * @vport: vport to setup the info
 */
void idpf_xdp_rxq_info_deinit_all(const struct idpf_vport *vport)
{
	idpf_rxq_for_each(vport, __idpf_xdp_rxq_info_deinit,
			  (void *)(size_t)vport->rxq_model);
}

static int idpf_xdp_rxq_assign_prog(struct idpf_rx_queue *rxq, void *arg)
{
	struct mutex *lock = &rxq->q_vector->vport->adapter->vport_ctrl_lock;
	struct bpf_prog *prog = arg;
	struct bpf_prog *old;

	if (prog)
		bpf_prog_inc(prog);

	old = rcu_replace_pointer(rxq->xdp_prog, prog, lockdep_is_held(lock));
	if (old)
		bpf_prog_put(old);

	return 0;
}

/**
 * idpf_copy_xdp_prog_to_qs - set pointers to xdp program for each Rx queue
 * @vport: vport to setup XDP for
 * @xdp_prog: XDP program that should be copied to all Rx queues
 */
void idpf_copy_xdp_prog_to_qs(const struct idpf_vport *vport,
			      struct bpf_prog *xdp_prog)
{
	idpf_rxq_for_each(vport, idpf_xdp_rxq_assign_prog, xdp_prog);
}

int idpf_vport_xdpq_get(const struct idpf_vport *vport)
{
	struct libeth_xdpsq_timer **timers __free(kvfree) = NULL;
	struct net_device *dev;
	u32 sqs;

	if (!idpf_xdp_is_prog_ena(vport))
		return 0;

	timers = kvcalloc(vport->num_xdp_txq, sizeof(*timers), GFP_KERNEL);
	if (!timers)
		return -ENOMEM;

	for (u32 i = 0; i < vport->num_xdp_txq; i++) {
		timers[i] = kzalloc_node(sizeof(*timers[i]), GFP_KERNEL,
					 cpu_to_mem(i));
		if (!timers[i]) {
			for (int j = i - 1; j >= 0; j--)
				kfree(timers[j]);

			return -ENOMEM;
		}
	}

	dev = vport->netdev;
	sqs = vport->xdp_txq_offset;

	libeth_xdpsq_get_start();

	for (u32 i = sqs; i < vport->num_txq; i++) {
		struct idpf_tx_queue *xdpq = vport->txqs[i];

		xdpq->complq = xdpq->txq_grp->complq;

		idpf_queue_clear(FLOW_SCH_EN, xdpq);
		idpf_queue_clear(FLOW_SCH_EN, xdpq->complq);
		idpf_queue_set(NOIRQ, xdpq);
		idpf_queue_set(XDP, xdpq);
		idpf_queue_set(XDP, xdpq->complq);

		xdpq->timer = timers[i - sqs];
		libeth_xdpsq_get(&xdpq->xdp_lock, dev, vport->xdpq_share);

		xdpq->pending = 0;
		xdpq->xdp_tx = 0;
		xdpq->thresh = libeth_xdp_queue_threshold(xdpq->desc_count);
	}

	libeth_xdpsq_get_end();

	return 0;
}

void idpf_vport_xdpq_put(const struct idpf_vport *vport)
{
	struct net_device *dev;
	u32 sqs;

	if (!idpf_xdp_is_prog_ena(vport))
		return;

	dev = vport->netdev;
	sqs = vport->xdp_txq_offset;

	libeth_xdpsq_get_start();

	for (u32 i = sqs; i < vport->num_txq; i++) {
		struct idpf_tx_queue *xdpq = vport->txqs[i];

		if (!idpf_queue_has_clear(XDP, xdpq))
			continue;

		libeth_xdpsq_put(&xdpq->xdp_lock, dev);

		kfree(xdpq->timer);
		idpf_queue_clear(NOIRQ, xdpq);
	}

	libeth_xdpsq_get_end();
}

/**
 * idpf_xdp_reconfig_queues - reconfigure queues after the XDP setup
 * @vport: vport to load or unload XDP for
 */
static int idpf_xdp_reconfig_queues(struct idpf_vport *vport)
{
	int err;

	err = idpf_vport_adjust_qs(vport);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not adjust queue number for XDP\n");
		return err;
	}
	idpf_vport_calc_num_q_desc(vport);

	err = idpf_vport_queues_alloc(vport);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not allocate queues for XDP\n");
		return err;
	}

	err = idpf_send_add_queues_msg(vport, vport->num_txq,
				       vport->num_complq,
				       vport->num_rxq, vport->num_bufq);
	if (err) {
		netdev_err(vport->netdev,
			   "Could not add queues for XDP, VC message sent failed\n");
		return err;
	}

	idpf_vport_alloc_vec_indexes(vport);

	return 0;
}

/**
 * idpf_xdp_setup_prog - Add or remove XDP eBPF program
 * @vport: vport to setup XDP for
 * @xdp: XDP program and extack
 */
static int
idpf_xdp_setup_prog(struct idpf_vport *vport, struct netdev_bpf *xdp)
{
	struct idpf_netdev_priv *np = netdev_priv(vport->netdev);
	struct bpf_prog *prog = xdp->prog;
	struct xdp_attachment_info *info;
	bool needs_reconfig, vport_is_up;
	u16 idx = vport->idx;
	int err;

	vport_is_up = np->state == __IDPF_VPORT_UP;

	info = &vport->adapter->vport_config[idx]->user_config.xdp;
	needs_reconfig = !!info->prog != !!prog;

	if (!needs_reconfig) {
		idpf_copy_xdp_prog_to_qs(vport, prog);
		xdp_attachment_setup(info, xdp);

		return 0;
	}

	if (!vport_is_up) {
		idpf_send_delete_queues_msg(vport);
	} else {
		set_bit(IDPF_VPORT_DEL_QUEUES, vport->flags);
		idpf_vport_stop(vport);
	}

	idpf_deinit_rss(vport);
	xdp_attachment_setup(info, xdp);

	err = idpf_xdp_reconfig_queues(vport);
	if (err) {
		NL_SET_ERR_MSG_MOD(xdp->extack,
				   "Could not reconfigure the queues after XDP setup");
		return err;
	}

	if (vport_is_up) {
		err = idpf_vport_open(vport, false);
		if (err) {
			NL_SET_ERR_MSG_MOD(xdp->extack,
					   "Could not reopen the vport after XDP setup");
			return err;
		}
	}

	return 0;
}

/**
 * idpf_xdp - implements XDP handler
 * @dev: netdevice
 * @xdp: XDP command
 */
int idpf_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	struct idpf_vport *vport;
	int ret;

	idpf_vport_ctrl_lock(dev);
	vport = idpf_netdev_to_vport(dev);

	if (!idpf_is_queue_model_split(vport->txq_model))
		goto notsupp;

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		ret = idpf_xdp_setup_prog(vport, xdp);
		break;
	default:
notsupp:
		ret = -EOPNOTSUPP;
		break;
	}

	idpf_vport_ctrl_unlock(dev);

	return ret;
}
