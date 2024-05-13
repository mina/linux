// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

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

static void idpf_xdp_tx_timer(struct work_struct *work);

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
		libeth_xdpsq_init_timer(xdpq->timer, xdpq, &xdpq->xdp_lock,
					idpf_xdp_tx_timer);

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

		libeth_xdpsq_deinit_timer(xdpq->timer);
		libeth_xdpsq_put(&xdpq->xdp_lock, dev);

		kfree(xdpq->timer);
		idpf_queue_clear(NOIRQ, xdpq);
	}

	libeth_xdpsq_get_end();
}

static int
idpf_xdp_parse_compl_desc(const struct idpf_splitq_4b_tx_compl_desc *desc,
			  bool gen)
{
	u32 val;

#ifdef __LIBETH_WORD_ACCESS
	val = *(const u32 *)desc;
#else
	val = ((u32)le16_to_cpu(desc->q_head_compl_tag.q_head) << 16) |
	      le16_to_cpu(desc->qid_comptype_gen);
#endif
	if (!!(val & IDPF_TXD_COMPLQ_GEN_M) != gen)
		return -ENODATA;

	if (unlikely((val & GENMASK(IDPF_TXD_COMPLQ_GEN_S - 1, 0)) !=
		     FIELD_PREP(IDPF_TXD_COMPLQ_COMPL_TYPE_M,
				IDPF_TXD_COMPLT_RS)))
		return -EINVAL;

	return upper_16_bits(val);
}

static u32 idpf_xdpsq_poll(struct idpf_tx_queue *xdpsq, u32 budget)
{
	struct idpf_compl_queue *cq = xdpsq->complq;
	u32 tx_ntc = xdpsq->next_to_clean;
	u32 tx_cnt = xdpsq->desc_count;
	u32 ntc = cq->next_to_clean;
	u32 cnt = cq->desc_count;
	u32 done_frames;
	bool gen;

	gen = idpf_queue_has(GEN_CHK, cq);

	for (done_frames = 0; done_frames < budget; ) {
		int ret;

		ret = idpf_xdp_parse_compl_desc(&cq->comp_4b[ntc], gen);
		if (ret >= 0) {
			done_frames = ret > tx_ntc ? ret - tx_ntc :
						     ret + tx_cnt - tx_ntc;
			goto next;
		}

		switch (ret) {
		case -ENODATA:
			goto out;
		case -EINVAL:
			break;
		}

next:
		if (unlikely(++ntc == cnt)) {
			ntc = 0;
			gen = !gen;
			idpf_queue_change(GEN_CHK, cq);
		}
	}

out:
	cq->next_to_clean = ntc;

	return done_frames;
}

/**
 * idpf_clean_xdp_irq - Reclaim a batch of TX resources from completed XDP_TX
 * @_xdpq: XDP Tx queue
 * @budget: maximum number of descriptors to clean
 *
 * Returns number of cleaned descriptors.
 */
static u32 idpf_clean_xdp_irq(void *_xdpq, u32 budget)
{
	struct libeth_xdpsq_napi_stats ss = { };
	struct idpf_tx_queue *xdpq = _xdpq;
	u32 tx_ntc = xdpq->next_to_clean;
	u32 tx_cnt = xdpq->desc_count;
	struct xdp_frame_bulk bq;
	struct libeth_cq_pp cp = {
		.dev	= xdpq->dev,
		.bq	= &bq,
		.xss	= &ss,
		.napi	= true,
	};
	u32 done_frames;

	done_frames = idpf_xdpsq_poll(xdpq, budget);
	if (unlikely(!done_frames))
		return 0;

	xdp_frame_bulk_init(&bq);

	for (u32 i = 0; likely(i < done_frames); i++) {
		libeth_xdp_complete_tx(&xdpq->tx_buf[tx_ntc], &cp);

		if (unlikely(++tx_ntc == tx_cnt))
			tx_ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);

	xdpq->next_to_clean = tx_ntc;
	xdpq->pending -= done_frames;
	xdpq->xdp_tx -= cp.xdp_tx;

	libeth_xdpsq_napi_stats_add(&xdpq->xstats, &ss);

	return done_frames;
}

static u32 idpf_xdp_tx_prep(void *_xdpq, struct libeth_xdpsq *sq)
{
	struct idpf_tx_queue *xdpq = _xdpq;
	u32 free;

	libeth_xdpsq_lock(&xdpq->xdp_lock);

	free = xdpq->desc_count - xdpq->pending;
	if (unlikely(free < xdpq->thresh))
		free += idpf_clean_xdp_irq(xdpq, NAPI_POLL_WEIGHT);

	*sq = (struct libeth_xdpsq){
		.sqes		= xdpq->tx_buf,
		.descs		= xdpq->desc_ring,
		.count		= xdpq->desc_count,
		.lock		= &xdpq->xdp_lock,
		.ntu		= &xdpq->next_to_use,
		.pending	= &xdpq->pending,
		.xdp_tx		= &xdpq->xdp_tx,
	};

	return free;
}

LIBETH_XDP_DEFINE_START();
LIBETH_XDP_DEFINE_TIMER(static idpf_xdp_tx_timer, idpf_clean_xdp_irq);
LIBETH_XDP_DEFINE_FLUSH_TX(idpf_xdp_tx_flush_bulk, idpf_xdp_tx_prep,
			   idpf_xdp_tx_xmit);
LIBETH_XDP_DEFINE_FLUSH_XMIT(static idpf_xdp_xmit_flush_bulk, idpf_xdp_tx_prep,
			     idpf_xdp_tx_xmit);
LIBETH_XDP_DEFINE_END();

/**
 * idpf_xdp_xmit - submit packets to xdp ring for transmission
 * @dev: netdev
 * @n: number of xdp frames to be transmitted
 * @frames: xdp frames to be transmitted
 * @flags: transmit flags
 *
 * Return: number of frames successfully sent or -errno on error.
 */
int idpf_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
		  u32 flags)
{
	const struct idpf_netdev_priv *np = netdev_priv(dev);
	const struct idpf_vport *vport = np->vport;

	if (unlikely(!netif_carrier_ok(dev) || !vport->link_up))
		return -ENETDOWN;

	return libeth_xdp_xmit_do_bulk(dev, n, frames, flags,
				       &vport->txqs[vport->xdp_txq_offset],
				       vport->num_xdp_txq,
				       idpf_xdp_xmit_flush_bulk,
				       idpf_xdp_tx_finalize);
}

static int idpf_xdpmo_rx_hash(const struct xdp_md *ctx, u32 *hash,
			      enum xdp_rss_hash_type *rss_type)
{
	const struct libeth_xdp_buff *xdp = (typeof(xdp))ctx;
	const struct idpf_rx_queue *rxq;
	struct idpf_xdp_rx_desc desc;
	struct libeth_rx_pt pt;

	rxq = libeth_xdp_buff_to_rq(xdp, typeof(*rxq), xdp_rxq);

	idpf_xdp_get_qw0(&desc, xdp->desc);

	pt = rxq->rx_ptype_lkup[idpf_xdp_rx_pt(&desc)];
	if (!libeth_rx_pt_has_hash(rxq->xdp_rxq.dev, pt))
		return -ENODATA;

	idpf_xdp_get_qw2(&desc, xdp->desc);

	return libeth_xdpmo_rx_hash(hash, rss_type, idpf_xdp_rx_hash(&desc),
				    pt);
}

static const struct xdp_metadata_ops idpf_xdpmo = {
	.xmo_rx_hash		= idpf_xdpmo_rx_hash,
};

void idpf_xdp_set_features(const struct idpf_vport *vport)
{
	if (!idpf_is_queue_model_split(vport->rxq_model))
		return;

	libeth_xdp_set_features_noredir(vport->netdev, &idpf_xdpmo);
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

	libeth_xdp_set_redirect(vport->netdev, prog);

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
