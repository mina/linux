// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xdp.h>

#include "priv.h"

/* XDPSQ sharing */

DEFINE_STATIC_KEY_FALSE(libeth_xdpsq_share);
EXPORT_SYMBOL_NS_GPL(libeth_xdpsq_share, LIBETH_XDP);

void __libeth_xdpsq_get(struct libeth_xdpsq_lock *lock,
			const struct net_device *dev)
{
	bool warn;

	spin_lock_init(&lock->lock);
	lock->share = true;

	warn = !static_key_enabled(&libeth_xdpsq_share);
	static_branch_inc_cpuslocked(&libeth_xdpsq_share);

	if (warn && net_ratelimit())
		netdev_warn(dev, "XDPSQ sharing enabled, possible XDP Tx slowdown\n");
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdpsq_get, LIBETH_XDP);

void __libeth_xdpsq_put(struct libeth_xdpsq_lock *lock,
			const struct net_device *dev)
{
	static_branch_dec_cpuslocked(&libeth_xdpsq_share);

	if (!static_key_enabled(&libeth_xdpsq_share) && net_ratelimit())
		netdev_notice(dev, "XDPSQ sharing disabled\n");

	lock->share = false;
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdpsq_put, LIBETH_XDP);

void __libeth_xdpsq_lock(struct libeth_xdpsq_lock *lock)
{
	spin_lock(&lock->lock);
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdpsq_lock, LIBETH_XDP);

void __libeth_xdpsq_unlock(struct libeth_xdpsq_lock *lock)
{
	spin_unlock(&lock->lock);
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdpsq_unlock, LIBETH_XDP);

/* XDPSQ clean-up timers */

void libeth_xdpsq_init_timer(struct libeth_xdpsq_timer *timer, void *xdpsq,
			     struct libeth_xdpsq_lock *lock,
			     void (*poll)(struct work_struct *work))
{
	timer->xdpsq = xdpsq;
	timer->lock = lock;

	INIT_DELAYED_WORK(&timer->dwork, poll);
}
EXPORT_SYMBOL_NS_GPL(libeth_xdpsq_init_timer, LIBETH_XDP);

/* ``XDP_TX`` bulking */

static void __cold
libeth_xdp_tx_return_one(const struct libeth_xdp_tx_frame *frm)
{
	if (frm->len_fl & LIBETH_XDP_TX_MULTI)
		libeth_xdp_return_frags(frm->data + frm->soff, true);

	libeth_xdp_return_va(frm->data, true);
}

static void __cold
libeth_xdp_tx_return_bulk(const struct libeth_xdp_tx_frame *bq, u32 count)
{
	for (u32 i = 0; i < count; i++) {
		const struct libeth_xdp_tx_frame *frm = &bq[i];

		if (!(frm->len_fl & LIBETH_XDP_TX_FIRST))
			continue;

		libeth_xdp_tx_return_one(frm);
	}
}

static void __cold libeth_trace_xdp_exception(const struct net_device *dev,
					      const struct bpf_prog *prog,
					      u32 act)
{
	trace_xdp_exception(dev, prog, act);
}

void __cold libeth_xdp_tx_exception(struct libeth_xdp_tx_bulk *bq, u32 sent,
				    u32 flags)
{
	const struct libeth_xdp_tx_frame *pos = &bq->bulk[sent];
	u32 left = bq->count - sent;

	if (!(flags & LIBETH_XDP_TX_NDO))
		libeth_trace_xdp_exception(bq->dev, bq->prog, XDP_TX);

	if (!(flags & LIBETH_XDP_TX_DROP)) {
		memmove(bq->bulk, pos, left * sizeof(*bq->bulk));
		bq->count = left;

		return;
	}

	if (flags & LIBETH_XDP_TX_XSK)
		libeth_xsk_tx_return_bulk(pos, left);
	else if (!(flags & LIBETH_XDP_TX_NDO))
		libeth_xdp_tx_return_bulk(pos, left);
	else
		libeth_xdp_xmit_return_bulk(pos, left, bq->dev);

	bq->count = 0;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_tx_exception, LIBETH_XDP);

/* .ndo_xdp_xmit() implementation */

u32 __cold libeth_xdp_xmit_return_bulk(const struct libeth_xdp_tx_frame *bq,
				       u32 count, const struct net_device *dev)
{
	u32 n = 0;

	for (u32 i = 0; i < count; i++) {
		const struct libeth_xdp_tx_frame *frm = &bq[i];
		dma_addr_t dma;

		if (frm->flags & LIBETH_XDP_TX_FIRST)
			dma = *libeth_xdp_xmit_frame_dma(frm->xdpf);
		else
			dma = dma_unmap_addr(frm, dma);

		dma_unmap_page(dev->dev.parent, dma, dma_unmap_len(frm, len),
			       DMA_TO_DEVICE);

		/* Actual xdp_frames are freed by the core */
		n += !!(frm->flags & LIBETH_XDP_TX_FIRST);
	}

	return n;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_xmit_return_bulk, LIBETH_XDP);

/* Rx polling path */

void libeth_xdp_load_stash(struct libeth_xdp_buff *dst,
			   const struct libeth_xdp_buff_stash *src)
{
	dst->data = src->data;
	dst->base.data_end = src->data + src->len;
	dst->base.data_meta = src->data;
	dst->base.data_hard_start = src->data - src->headroom;

	dst->base.frame_sz = src->frame_sz;
	dst->base.flags = src->flags;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_load_stash, LIBETH_XDP);

void libeth_xdp_save_stash(struct libeth_xdp_buff_stash *dst,
			   const struct libeth_xdp_buff *src)
{
	dst->data = src->data;
	dst->headroom = src->data - src->base.data_hard_start;
	dst->len = src->base.data_end - src->data;

	dst->frame_sz = src->base.frame_sz;
	dst->flags = src->base.flags;

	WARN_ON_ONCE(dst->flags != src->base.flags);
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_save_stash, LIBETH_XDP);

void __libeth_xdp_return_stash(struct libeth_xdp_buff_stash *stash)
{
	LIBETH_XDP_ONSTACK_BUFF(xdp);

	libeth_xdp_load_stash(xdp, stash);
	libeth_xdp_return_buff_slow(xdp);

	stash->data = NULL;
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdp_return_stash, LIBETH_XDP);

void __cold libeth_xdp_return_buff_slow(struct libeth_xdp_buff *xdp)
{
	libeth_xdp_return_buff(xdp);
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_return_buff_slow, LIBETH_XDP);

bool libeth_xdp_buff_add_frag(struct libeth_xdp_buff *xdp,
			      const struct libeth_fqe *fqe,
			      u32 len)
{
	struct page *page = fqe->page;

	if (!xdp_buff_add_frag(&xdp->base, page,
			       fqe->offset + page->pp->p.offset,
			       len, fqe->truesize))
		goto recycle;

	return true;

recycle:
	libeth_rx_recycle_slow(page);
	libeth_xdp_return_buff_slow(xdp);

	return false;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_buff_add_frag, LIBETH_XDP);

u32 __cold libeth_xdp_prog_exception(const struct libeth_xdp_tx_bulk *bq,
				     struct libeth_xdp_buff *xdp,
				     enum xdp_action act, int ret)
{
	if (act > XDP_REDIRECT)
		bpf_warn_invalid_xdp_action(bq->dev, bq->prog, act);

	libeth_trace_xdp_exception(bq->dev, bq->prog, act);

	if (xdp->base.rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL)
		return libeth_xsk_prog_exception(xdp, act, ret);

	libeth_xdp_return_buff_slow(xdp);

	return LIBETH_XDP_DROP;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_prog_exception, LIBETH_XDP);

/* Tx buffer completion */

static void libeth_xdp_put_page_bulk(struct page *page,
				     struct xdp_frame_bulk *bq)
{
	if (unlikely(bq->count == XDP_BULK_QUEUE_SIZE))
		xdp_flush_frame_bulk(bq);

	bq->q[bq->count++] = page;
}

void libeth_xdp_return_buff_bulk(const struct skb_shared_info *sinfo,
				 struct xdp_frame_bulk *bq, bool frags)
{
	if (!frags)
		goto head;

	for (u32 i = 0; i < sinfo->nr_frags; i++)
		libeth_xdp_put_page_bulk(skb_frag_page(&sinfo->frags[i]), bq);

head:
	libeth_xdp_put_page_bulk(virt_to_page(sinfo), bq);
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_return_buff_bulk, LIBETH_XDP);

/* Misc */

u32 libeth_xdp_queue_threshold(u32 count)
{
	u32 quarter, low, high;

	if (likely(is_power_of_2(count)))
		return count >> 2;

	quarter = DIV_ROUND_CLOSEST(count, 4);
	low = rounddown_pow_of_two(quarter);
	high = roundup_pow_of_two(quarter);

	return high - quarter <= quarter - low ? high : low;
}
EXPORT_SYMBOL_NS_GPL(libeth_xdp_queue_threshold, LIBETH_XDP);

void __libeth_xdp_set_features(struct net_device *dev,
			       const struct xdp_metadata_ops *xmo,
			       u32 zc_segs,
			       const struct xsk_tx_metadata_ops *tmo)
{
	xdp_set_features_flag(dev,
			      NETDEV_XDP_ACT_BASIC |
			      NETDEV_XDP_ACT_REDIRECT |
			      NETDEV_XDP_ACT_NDO_XMIT |
			      (zc_segs ? NETDEV_XDP_ACT_XSK_ZEROCOPY : 0) |
			      NETDEV_XDP_ACT_RX_SG |
			      NETDEV_XDP_ACT_NDO_XMIT_SG);
	dev->xdp_metadata_ops = xmo;

	tmo = tmo == libeth_xsktmo ? &libeth_xsktmo_slow : tmo;

	dev->xdp_zc_max_segs = zc_segs ? : 1;
	dev->xsk_tx_metadata_ops = zc_segs ? tmo : NULL;
}
EXPORT_SYMBOL_NS_GPL(__libeth_xdp_set_features, LIBETH_XDP);

/* Module */

static const struct libeth_xdp_ops xdp_ops __initconst = {
	.bulk	= libeth_xdp_return_buff_bulk,
	.xsk	= libeth_xsk_buff_free_slow,
};

static int __init libeth_xdp_module_init(void)
{
	libeth_attach_xdp(&xdp_ops);

	return 0;
}
module_init(libeth_xdp_module_init);

static void __exit libeth_xdp_module_exit(void)
{
	libeth_detach_xdp();
}
module_exit(libeth_xdp_module_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Common Ethernet library - XDP infra");
MODULE_IMPORT_NS(LIBETH);
MODULE_LICENSE("GPL");
