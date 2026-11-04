/*
 * Copyright (C) 2017 Netronome Systems, Inc.
 *
 * This software is dual licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree or the BSD 2-Clause License provided below.  You have the
 * option to license this software under the complete terms of either license.
 *
 * The BSD 2-Clause License:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net_tstamp.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/gro.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/net_shaper.h>
#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>
#include <net/netmem.h>
#include <net/page_pool/helpers.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/psp.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/switchdev.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/xdp.h>
#include <net/xdp_sock_drv.h>
#include <linux/ethtool_netlink.h>

#include "netdevsim.h"

MODULE_IMPORT_NS("NETDEV_INTERNAL");

#define NSIM_RING_SIZE		256
#define NSIM_HW_GRO_TIMEOUT_NS	(25 * NSEC_PER_MSEC)

static void nsim_irq_noop(struct irq_data *data)
{
}

static int nsim_irq_set_affinity(struct irq_data *data,
				 const struct cpumask *dest, bool force)
{
	irq_data_update_effective_affinity(data, dest);
	return IRQ_SET_MASK_OK;
}

static struct irq_chip nsim_irq_chip = {
	.name			= "netdevsim",
	.irq_startup		= NULL,
	.irq_shutdown		= nsim_irq_noop,
	.irq_enable		= nsim_irq_noop,
	.irq_disable		= nsim_irq_noop,
	.irq_ack		= nsim_irq_noop,
	.irq_mask		= nsim_irq_noop,
	.irq_unmask		= nsim_irq_noop,
	.irq_set_affinity	= nsim_irq_set_affinity,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static irqreturn_t nsim_irq_handler(int irq, void *data)
{
	return IRQ_HANDLED;
}

static void nsim_napi_csd_fn(void *info)
{
	struct nsim_rq *rq = info;

	__napi_schedule_irqoff(&rq->napi);
}

static void nsim_schedule_rq_napi(struct netdevsim *ns, int rxq_idx,
				  struct nsim_rq *rq)
{
	int target_cpu = -1;

	if (!napi_schedule_prep(&rq->napi))
		return;

	if (rq->irq >= 0) {
		struct irq_data *irqd = irq_get_irq_data(rq->irq);

		if (irqd) {
			const struct cpumask *mask;
			unsigned int weight;

			mask = irq_data_get_affinity_mask(irqd);
			weight = cpumask_weight_and(mask, cpu_online_mask);
			if (weight == 1)
				target_cpu = cpumask_first_and(mask,
							       cpu_online_mask);
		}
	}

	if (target_cpu >= 0 && target_cpu < nr_cpu_ids &&
	    target_cpu != raw_smp_processor_id() && cpu_online(target_cpu)) {
		if (!smp_call_function_single_async(target_cpu, &rq->csd))
			return;
	}

	__napi_schedule(&rq->napi);
}

static int nsim_xmo_rx_timestamp(const struct xdp_md *ctx, u64 *timestamp)
{
	const struct xdp_buff *xdp = (const struct xdp_buff *)ctx;
	struct nsim_rq *rq = container_of(xdp->rxq, struct nsim_rq, xdp_rxq);

	*timestamp = rq->cur_rx_tstamp ?: ktime_get_real_ns();
	return 0;
}

static int nsim_xmo_rx_hash(const struct xdp_md *ctx, u32 *hash,
			    enum xdp_rss_hash_type *rss_type)
{
	const struct xdp_buff *xdp = (const struct xdp_buff *)ctx;
	struct nsim_rq *rq = container_of(xdp->rxq, struct nsim_rq, xdp_rxq);

	*hash = rq->cur_rx_hash ?: 1;
	*rss_type = rq->cur_rx_hash_type ?: XDP_RSS_TYPE_L4_IPV4_TCP;
	return 0;
}

static const struct xdp_metadata_ops nsim_xdp_metadata_ops = {
	.xmo_rx_timestamp	= nsim_xmo_rx_timestamp,
	.xmo_rx_hash		= nsim_xmo_rx_hash,
};

static enum xdp_rss_hash_type nsim_skb_xdp_rss_type(struct sk_buff *skb)
{
	struct ethhdr eth_buf, *eth;
	unsigned int off = ETH_HLEN;
	__be16 proto;

	eth = skb_header_pointer(skb, 0, sizeof(eth_buf), &eth_buf);
	if (!eth)
		return XDP_RSS_TYPE_NONE;
	proto = eth->h_proto;

	while (eth_type_vlan(proto)) {
		struct vlan_hdr vhdr, *vp;

		vp = skb_header_pointer(skb, off, sizeof(vhdr), &vhdr);
		if (!vp)
			return XDP_RSS_TYPE_NONE;
		proto = vp->h_vlan_encapsulated_proto;
		off += sizeof(vhdr);
	}

	if (proto == htons(ETH_P_IP)) {
		struct iphdr iph_buf, *iph;

		iph = skb_header_pointer(skb, off, sizeof(iph_buf), &iph_buf);
		if (!iph)
			return XDP_RSS_TYPE_L3_IPV4;
		if (iph->protocol == IPPROTO_TCP)
			return XDP_RSS_TYPE_L4_IPV4_TCP;
		if (iph->protocol == IPPROTO_UDP)
			return XDP_RSS_TYPE_L4_IPV4_UDP;
		return XDP_RSS_TYPE_L3_IPV4;
	}

	if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6h_buf, *ip6h;

		ip6h = skb_header_pointer(skb, off, sizeof(ip6h_buf), &ip6h_buf);
		if (!ip6h)
			return XDP_RSS_TYPE_L3_IPV6;
		if (ip6h->nexthdr == IPPROTO_TCP)
			return XDP_RSS_TYPE_L4_IPV6_TCP;
		if (ip6h->nexthdr == IPPROTO_UDP)
			return XDP_RSS_TYPE_L4_IPV6_UDP;
		return XDP_RSS_TYPE_L3_IPV6;
	}

	return XDP_RSS_TYPE_NONE;
}

static bool nsim_skb_has_net_iov(const struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);

	return shinfo->nr_frags && skb_frag_is_net_iov(&shinfo->frags[0]);
}

static struct sk_buff *nsim_devmem_tx_copy(struct sk_buff *skb,
					   struct net_device *dev)
{
	struct sk_buff *nskb;
	unsigned int headlen;
	int i, err;

	nskb = __netdev_alloc_skb(dev, skb->len, GFP_ATOMIC);
	if (!nskb)
		return NULL;

	skb_copy_header(nskb, skb);
	nskb->unreadable = 0;
	headlen = skb_headlen(skb);
	if (headlen)
		skb_put_data(nskb, skb->data, headlen);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int fsize = skb_frag_size(frag);
		unsigned int foff = skb_frag_off(frag);
		void *dst = skb_put(nskb, fsize);

		if (skb_frag_is_net_iov(frag)) {
			struct net_iov *niov = skb_frag_net_iov(frag);

			err = net_iov_copy_to_buf(niov, foff, dst, fsize);
			if (err) {
				dev_kfree_skb_any(nskb);
				return NULL;
			}
		} else {
			memcpy(dst, skb_frag_address(frag), fsize);
		}
	}

	skb_reset_mac_header(nskb);
	skb_set_network_header(nskb, skb_network_offset(skb));
	if (skb_transport_header_was_set(skb))
		skb_set_transport_header(nskb, skb_transport_offset(skb));
	nskb->ip_summed = skb->ip_summed;
	nskb->csum_start = skb->csum_start - skb_headroom(skb) +
			   skb_headroom(nskb);
	nskb->csum_offset = skb->csum_offset;

	if (skb_is_gso(skb)) {
		skb_shinfo(nskb)->gso_size = skb_shinfo(skb)->gso_size;
		skb_shinfo(nskb)->gso_type = skb_shinfo(skb)->gso_type;
		skb_shinfo(nskb)->gso_segs = skb_shinfo(skb)->gso_segs;
	}

	return nskb;
}

static unsigned int nsim_skb_header_len(struct sk_buff *skb,
					unsigned int hds_thresh)
{
	struct ethhdr *eth;
	__be16 proto;
	unsigned int off = ETH_HLEN;
	unsigned int hdr_len = ETH_HLEN;

	if (skb->len < ETH_HLEN)
		return skb->len;

	eth = (struct ethhdr *)skb->data;
	proto = eth->h_proto;

	if (eth_type_vlan(proto) && skb->len >= off + sizeof(struct vlan_hdr)) {
		struct vlan_hdr vhdr, *vp;

		vp = skb_header_pointer(skb, off, sizeof(vhdr), &vhdr);
		if (vp) {
			proto = vp->h_vlan_encapsulated_proto;
			off += sizeof(vhdr);
			hdr_len = off;
		}
	}

	if (proto == htons(ETH_P_IP) && skb->len >= off + sizeof(struct iphdr)) {
		struct iphdr iph_buf, *iph;

		iph = skb_header_pointer(skb, off, sizeof(iph_buf), &iph_buf);
		if (iph && iph->ihl >= 5) {
			unsigned int ihl = iph->ihl * 4;

			hdr_len = off + ihl;
			if (iph->protocol == IPPROTO_TCP &&
			    skb->len >= hdr_len + sizeof(struct tcphdr)) {
				struct tcphdr th_buf, *th;

				th = skb_header_pointer(skb, hdr_len,
							sizeof(th_buf), &th_buf);
				if (th && th->doff >= 5)
					hdr_len += th->doff * 4;
			} else if (iph->protocol == IPPROTO_UDP &&
				   skb->len >= hdr_len + sizeof(struct udphdr)) {
				hdr_len += sizeof(struct udphdr);
			}
		}
	} else if (proto == htons(ETH_P_IPV6) &&
		   skb->len >= off + sizeof(struct ipv6hdr)) {
		struct ipv6hdr ip6h_buf, *ip6h;

		ip6h = skb_header_pointer(skb, off, sizeof(ip6h_buf), &ip6h_buf);
		if (ip6h) {
			u8 nexthdr = ip6h->nexthdr;
			__be16 frag_off;
			int l4_off;

			l4_off = ipv6_skip_exthdr(skb, off + sizeof(*ip6h),
						  &nexthdr, &frag_off);
			if (l4_off >= 0) {
				hdr_len = l4_off;
				if (nexthdr == IPPROTO_TCP &&
				    skb->len >= hdr_len + sizeof(struct tcphdr)) {
					struct tcphdr th_buf, *th;

					th = skb_header_pointer(skb, hdr_len,
								sizeof(th_buf),
								&th_buf);
					if (th && th->doff >= 5)
						hdr_len += th->doff * 4;
				} else if (nexthdr == IPPROTO_UDP &&
					   skb->len >= hdr_len + sizeof(struct udphdr)) {
					hdr_len += sizeof(struct udphdr);
				}
			}
		}
	}

	hdr_len = min(hdr_len, skb->len);
	if (skb->len <= hds_thresh)
		return skb->len;
	return hdr_len;
}

static struct sk_buff *nsim_page_pool_copy_rx(struct netdevsim *ns,
					      struct nsim_rq *rq,
					      struct sk_buff *skb)
{
	bool unreadable = page_pool_is_unreadable(rq->page_pool);
	u8 hds_cfg = READ_ONCE(ns->netdev->cfg->hds_config);
	u32 hds_thresh = READ_ONCE(ns->netdev->cfg->hds_thresh);
	unsigned int hdr_len, payload_len, copied = 0;
	struct sk_buff *nskb;
	int frag_idx = 0;

	if (!unreadable && hds_cfg == ETHTOOL_TCP_DATA_SPLIT_DISABLED)
		hdr_len = 0;
	else
		hdr_len = nsim_skb_header_len(skb, hds_thresh);

	payload_len = skb->len - hdr_len;

	nskb = __netdev_alloc_skb(ns->netdev, max(hdr_len, 64U), GFP_ATOMIC);
	if (!nskb)
		return NULL;
	skb_mark_for_recycle(nskb);

	if (hdr_len)
		skb_copy_bits(skb, 0, skb_put(nskb, hdr_len), hdr_len);

	while (copied < payload_len && frag_idx < MAX_SKB_FRAGS) {
		unsigned int chunk_max = PAGE_SIZE << rq->page_pool->p.order;
		unsigned int todo = min(payload_len - copied, chunk_max);
		netmem_ref netmem;

		netmem = page_pool_dev_alloc_netmems(rq->page_pool);
		if (!netmem) {
			WRITE_ONCE(rq->alloc_fail, rq->alloc_fail + 1);
			dev_kfree_skb_any(nskb);
			return NULL;
		}

		if (netmem_is_net_iov(netmem)) {
			struct net_iov *niov = netmem_to_net_iov(netmem);
			void *tmp = kmalloc(todo, GFP_ATOMIC);
			int err;

			if (!tmp) {
				page_pool_put_full_netmem(rq->page_pool, netmem,
							  true);
				dev_kfree_skb_any(nskb);
				return NULL;
			}
			skb_copy_bits(skb, hdr_len + copied, tmp, todo);
			err = net_iov_copy_from_buf(niov, 0, tmp, todo);
			kfree(tmp);
			if (err) {
				page_pool_put_full_netmem(rq->page_pool, netmem,
							  true);
				dev_kfree_skb_any(nskb);
				return NULL;
			}
		} else {
			struct page *page = netmem_to_page(netmem);

			skb_copy_bits(skb, hdr_len + copied,
				      page_address(page), todo);
		}

		skb_add_rx_frag_netmem(nskb, frag_idx++, netmem, 0, todo,
				       chunk_max);
		copied += todo;
	}

	if (copied < payload_len) {
		dev_kfree_skb_any(nskb);
		return NULL;
	}

	return nskb;
}

static void nsim_tx_csum_complete(struct sk_buff *skb)
{
	bool is_udp;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return;

	is_udp = (skb->csum_offset == offsetof(struct udphdr, check));
	if (skb_checksum_help(skb))
		return;

	if (is_udp) {
		__sum16 *csum = (__sum16 *)(skb_checksum_start(skb) +
					    skb->csum_offset);

		if (!*csum)
			*csum = CSUM_MANGLED_0;
	}
}

static bool nsim_rx_csum_valid(struct sk_buff *skb)
{
	__be16 proto = skb->protocol;
	unsigned int off = 0;

	while (eth_type_vlan(proto)) {
		const struct vlan_hdr *vh;

		if (!pskb_may_pull(skb, off + sizeof(*vh)))
			return false;
		vh = (const struct vlan_hdr *)(skb->data + off);
		proto = vh->h_vlan_encapsulated_proto;
		off += sizeof(*vh);
	}

	if (proto == htons(ETH_P_IP)) {
		const struct iphdr *iph;
		unsigned int ihl, tot_len, l4_off, l4_len;
		__wsum csum;

		if (!pskb_may_pull(skb, off + sizeof(*iph)))
			return false;
		iph = (const struct iphdr *)(skb->data + off);
		if (iph->version != 4 || iph->ihl < 5)
			return false;
		ihl = iph->ihl * 4;
		if (!pskb_may_pull(skb, off + ihl))
			return false;
		iph = (const struct iphdr *)(skb->data + off);
		if (ip_fast_csum((const u8 *)iph, iph->ihl) != 0)
			return false;
		if (ip_is_fragment(iph))
			return false;

		tot_len = ntohs(iph->tot_len);
		if (tot_len < ihl || off + tot_len > skb->len)
			return false;
		l4_off = off + ihl;
		l4_len = tot_len - ihl;

		if (iph->protocol == IPPROTO_TCP) {
			if (l4_len < sizeof(struct tcphdr))
				return false;
			csum = skb_checksum(skb, l4_off, l4_len, 0);
			return csum_tcpudp_magic(iph->saddr, iph->daddr,
						 l4_len, IPPROTO_TCP, csum) == 0;
		}
		if (iph->protocol == IPPROTO_UDP) {
			const struct udphdr *uh;

			if (l4_len < sizeof(struct udphdr) ||
			    !pskb_may_pull(skb, l4_off + sizeof(struct udphdr)))
				return false;
			uh = (const struct udphdr *)(skb->data + l4_off);
			if (!uh->check)
				return false;
			iph = (const struct iphdr *)(skb->data + off);
			csum = skb_checksum(skb, l4_off, l4_len, 0);
			return csum_tcpudp_magic(iph->saddr, iph->daddr,
						 l4_len, IPPROTO_UDP, csum) == 0;
		}
		return false;
	}

	if (proto == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h;
		unsigned int payload_len, l4_off;
		u8 nexthdr;
		__wsum csum;

		if (!pskb_may_pull(skb, off + sizeof(*ip6h)))
			return false;
		ip6h = (const struct ipv6hdr *)(skb->data + off);
		if (ip6h->version != 6)
			return false;
		payload_len = ntohs(ip6h->payload_len);
		l4_off = off + sizeof(*ip6h);
		if (l4_off + payload_len > skb->len)
			return false;
		nexthdr = ip6h->nexthdr;

		if (nexthdr == IPPROTO_TCP) {
			if (payload_len < sizeof(struct tcphdr))
				return false;
			csum = skb_checksum(skb, l4_off, payload_len, 0);
			return csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       payload_len, IPPROTO_TCP,
					       csum) == 0;
		}
		if (nexthdr == IPPROTO_UDP) {
			const struct udphdr *uh;

			if (payload_len < sizeof(struct udphdr) ||
			    !pskb_may_pull(skb, l4_off + sizeof(struct udphdr)))
				return false;
			uh = (const struct udphdr *)(skb->data + l4_off);
			if (!uh->check)
				return false;
			ip6h = (const struct ipv6hdr *)(skb->data + off);
			csum = skb_checksum(skb, l4_off, payload_len, 0);
			return csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					       payload_len, IPPROTO_UDP,
					       csum) == 0;
		}
		return false;
	}

	return false;
}

static bool nsim_rx_vlan_process(struct netdevsim *ns, struct sk_buff *skb)
{
	struct net_device *dev = ns->netdev;
	struct vlan_ethhdr *veth;
	__be16 vlan_proto;
	u16 tci, vid;

	if (skb_vlan_tag_present(skb)) {
		vlan_proto = skb->vlan_proto;
		vid = skb_vlan_tag_get_id(skb);
		if (!(dev->flags & IFF_PROMISC) && vid != 0) {
			if (vlan_proto == htons(ETH_P_8021Q) &&
			    (dev->features & NETIF_F_HW_VLAN_CTAG_FILTER) &&
			    !test_bit(vid, ns->vlan.ctag))
				return false;
			if (vlan_proto == htons(ETH_P_8021AD) &&
			    (dev->features & NETIF_F_HW_VLAN_STAG_FILTER) &&
			    !test_bit(vid, ns->vlan.stag))
				return false;
		}
		if ((vlan_proto == htons(ETH_P_8021Q) &&
		     !(dev->features & NETIF_F_HW_VLAN_CTAG_RX)) ||
		    (vlan_proto == htons(ETH_P_8021AD) &&
		     !(dev->features & NETIF_F_HW_VLAN_STAG_RX))) {
			if (!__vlan_hwaccel_push_inside(skb))
				return false;
		}
		return true;
	}

	if (skb->len < VLAN_ETH_HLEN || !pskb_may_pull(skb, VLAN_ETH_HLEN))
		return true;

	veth = (struct vlan_ethhdr *)skb->data;
	vlan_proto = veth->h_vlan_proto;
	if (vlan_proto != htons(ETH_P_8021Q) &&
	    vlan_proto != htons(ETH_P_8021AD))
		return true;

	tci = ntohs(veth->h_vlan_TCI);
	vid = tci & VLAN_VID_MASK;

	if (!(dev->flags & IFF_PROMISC) && vid != 0) {
		if (vlan_proto == htons(ETH_P_8021Q) &&
		    (dev->features & NETIF_F_HW_VLAN_CTAG_FILTER) &&
		    !test_bit(vid, ns->vlan.ctag))
			return false;
		if (vlan_proto == htons(ETH_P_8021AD) &&
		    (dev->features & NETIF_F_HW_VLAN_STAG_FILTER) &&
		    !test_bit(vid, ns->vlan.stag))
			return false;
	}

	if ((vlan_proto == htons(ETH_P_8021Q) &&
	     (dev->features & NETIF_F_HW_VLAN_CTAG_RX)) ||
	    (vlan_proto == htons(ETH_P_8021AD) &&
	     (dev->features & NETIF_F_HW_VLAN_STAG_RX))) {
		memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
		__skb_pull(skb, VLAN_HLEN);
		__vlan_hwaccel_put_tag(skb, vlan_proto, tci);
	}

	return true;
}

static void nsim_xdp_get_buff(struct xdp_buff *xdp)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	int i;

	get_page(virt_to_page(xdp->data));
	if (likely(!xdp_buff_has_frags(xdp)))
		return;

	for (i = 0; i < sinfo->nr_frags; i++)
		netmem_inc_ref(skb_frag_netmem(&sinfo->frags[i]));
}

static netdev_tx_t nsim_start_xmit(struct sk_buff *skb, struct net_device *dev);

static struct sk_buff *nsim_run_xdp(struct netdevsim *ns, struct nsim_rq *rq,
				    struct sk_buff *skb, bool *xmitted)
{
	struct bpf_prog *xdp_prog = READ_ONCE(ns->xdp.prog);
	struct xsk_buff_pool *xsk_pool = READ_ONCE(rq->xsk_pool);
	void *orig_data, *orig_data_end;
	struct xdp_buff xdp;
	u32 frame_sz, act, metalen;
	int off;

	skb_prepare_for_gro(skb);

	if (likely(!xdp_prog))
		return skb;

	if (xsk_pool && !skb_is_nonlinear(skb) &&
	    skb->len <= xsk_pool_get_rx_frame_size(xsk_pool)) {
		struct xdp_buff *xsk_xdp = xsk_buff_alloc(xsk_pool);

		if (xsk_xdp) {
			skb_copy_bits(skb, 0, xsk_xdp->data, skb->len);
			xsk_xdp->data_end = xsk_xdp->data + skb->len;

			rcu_read_lock();
			act = bpf_prog_run_xdp(xdp_prog, xsk_xdp);
			switch (act) {
			case XDP_PASS:
				rcu_read_unlock();
				xsk_buff_free(xsk_xdp);
				return skb;
			case XDP_REDIRECT:
				if (!xdp_do_redirect(ns->netdev, xsk_xdp,
						     xdp_prog)) {
					rcu_read_unlock();
					*xmitted = true;
					consume_skb(skb);
					return NULL;
				}
				rcu_read_unlock();
				xsk_buff_free(xsk_xdp);
				kfree_skb(skb);
				return NULL;
			case XDP_TX:
				rcu_read_unlock();
				xsk_buff_free(xsk_xdp);
				nsim_start_xmit(skb, ns->netdev);
				return NULL;
			default:
				bpf_warn_invalid_xdp_action(ns->netdev,
							    xdp_prog, act);
				fallthrough;
			case XDP_ABORTED:
			case XDP_DROP:
				rcu_read_unlock();
				xsk_buff_free(xsk_xdp);
				kfree_skb(skb);
				return NULL;
			}
		}
	}

	if (!rq->page_pool || page_pool_is_unreadable(rq->page_pool))
		return skb;

	skb_prepare_for_gro(skb);
	if (skb_shared(skb) || skb_head_is_locked(skb) ||
	    skb_is_nonlinear(skb) ||
	    skb_headroom(skb) < XDP_PACKET_HEADROOM) {
		if (skb_pp_cow_data(rq->page_pool, &skb, XDP_PACKET_HEADROOM))
			return NULL;
	}

	frame_sz = skb_end_pointer(skb) - skb->head +
		   SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	xdp_init_buff(&xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(&xdp, skb->head, skb_headroom(skb),
			 skb_headlen(skb), true);
	if (skb_shinfo(skb)->nr_frags) {
		skb_shinfo(skb)->xdp_frags_size = skb->data_len;
		xdp_buff_set_frags_flag(&xdp);
	} else {
		xdp_buff_clear_frags_flag(&xdp);
	}

	orig_data = xdp.data;
	orig_data_end = xdp.data_end;

	rcu_read_lock();
	act = bpf_prog_run_xdp(xdp_prog, &xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX: {
		struct xdp_frame *xdpf;

		WRITE_ONCE(rq->rx_packets, rq->rx_packets + 1);
		WRITE_ONCE(rq->rx_bytes, rq->rx_bytes + skb->len);
		dev_sw_netstats_rx_add(ns->netdev, skb->len);
		nsim_xdp_get_buff(&xdp);
		consume_skb(skb);
		xdpf = xdp_convert_buff_to_frame(&xdp);
		if (unlikely(!xdpf)) {
			xdp_return_buff(&xdp);
			rcu_read_unlock();
			return NULL;
		}
		skb = xdp_build_skb_from_frame(xdpf, ns->netdev);
		rcu_read_unlock();
		if (skb) {
			__skb_push(skb, ETH_HLEN);
			nsim_start_xmit(skb, ns->netdev);
		}
		return NULL;
	}
	case XDP_REDIRECT:
		WRITE_ONCE(rq->rx_packets, rq->rx_packets + 1);
		WRITE_ONCE(rq->rx_bytes, rq->rx_bytes + skb->len);
		dev_sw_netstats_rx_add(ns->netdev, skb->len);
		nsim_xdp_get_buff(&xdp);
		consume_skb(skb);
		if (xdp_do_redirect(ns->netdev, &xdp, xdp_prog))
			xdp_return_buff(&xdp);
		else
			*xmitted = true;
		rcu_read_unlock();
		return NULL;
	default:
		bpf_warn_invalid_xdp_action(ns->netdev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(ns->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		WRITE_ONCE(rq->rx_packets, rq->rx_packets + 1);
		WRITE_ONCE(rq->rx_bytes, rq->rx_bytes + skb->len);
		dev_sw_netstats_rx_add(ns->netdev, skb->len);
		rcu_read_unlock();
		kfree_skb(skb);
		return NULL;
	}
	rcu_read_unlock();

	off = orig_data - xdp.data;
	if (off > 0)
		__skb_push(skb, off);
	else if (off < 0)
		__skb_pull(skb, -off);

	skb_reset_mac_header(skb);
	skb->len -= skb->data_len;
	if (xdp_buff_has_frags(&xdp)) {
		skb->data_len = skb_shinfo(skb)->xdp_frags_size;
		skb->len += skb->data_len;
	} else {
		skb->data_len = 0;
	}

	off = xdp.data_end - orig_data_end;
	if (off != 0) {
		skb_set_tail_pointer(skb, xdp.data_end - xdp.data);
		skb->len += off;
	}

	metalen = xdp.data - xdp.data_meta;
	if (metalen)
		skb_metadata_set(skb, metalen);

	return skb;
}

static void nsim_drain_hw_gro_rx_list(struct netdevsim *ns, struct nsim_rq *rq)
{
	struct net_device *dev = ns->netdev;
	struct sk_buff *skb, *tmp;
	LIST_HEAD(list);

	list_splice_init(&rq->hw_gro.rx_list, &list);
	rq->hw_gro.rx_count = 0;

	list_for_each_entry_safe(skb, tmp, &list, list) {
		unsigned int pkts = max_t(u16, 1, skb_shinfo(skb)->gso_segs);
		unsigned int len = skb->len;

		skb_list_del_init(skb);
		WRITE_ONCE(rq->rx_packets, rq->rx_packets + pkts);
		WRITE_ONCE(rq->rx_bytes, rq->rx_bytes + len);
		dev_sw_netstats_rx_add(dev, len);

		if (dev->features & NETIF_F_GRO)
			napi_gro_receive(&rq->napi, skb);
		else
			netif_receive_skb(skb);
	}
}

static int nsim_rcv(struct nsim_rq *rq, int budget)
{
	struct net_device *dev = rq->napi.dev;
	struct netdevsim *ns = netdev_priv(dev);
	bool xdp_xmitted = false;
	struct sk_buff *skb;
	int i;

	if (xchg(&rq->gro_flush_pending, false)) {
		gro_flush(&rq->hw_gro, false);
		nsim_drain_hw_gro_rx_list(ns, rq);
	}

	for (i = 0; i < budget; i++) {
		bool use_pp_rx, valid_csum;
		unsigned int len;

		skb = skb_dequeue(&rq->skb_queue);
		if (!skb)
			break;

		/* Probe page_pool allocation for fault injection tests (pp_alloc_fail.py) */
		if (rq->page_pool &&
		    !page_pool_is_unreadable(rq->page_pool)) {
			struct page *probe_page;

			probe_page = page_pool_dev_alloc_pages(rq->page_pool);
			if (!probe_page)
				WRITE_ONCE(rq->alloc_fail, rq->alloc_fail + 1);
			else
				page_pool_put_full_page(rq->page_pool,
							probe_page, true);
		}

		if (!nsim_rx_vlan_process(ns, skb)) {
			kfree_skb(skb);
			continue;
		}

		rq->cur_rx_tstamp = ktime_get_real_ns();
		rq->cur_rx_hash = skb_get_hash_raw(skb);
		rq->cur_rx_hash_type = nsim_skb_xdp_rss_type(skb);

		if (ns->hwtstamp_cfg.rx_filter == HWTSTAMP_FILTER_ALL)
			skb_hwtstamps(skb)->hwtstamp =
				ns_to_ktime(rq->cur_rx_tstamp);

		skb = nsim_run_xdp(ns, rq, skb, &xdp_xmitted);
		if (!skb)
			continue;

		use_pp_rx = rq->page_pool &&
			    page_pool_is_unreadable(rq->page_pool);
		if (use_pp_rx && skb_frags_readable(skb)) {
			struct sk_buff *pp_skb;

			pp_skb = nsim_page_pool_copy_rx(ns, rq, skb);
			consume_skb(skb);
			if (!pp_skb)
				continue;
			skb = pp_skb;
		}

		len = skb->len;
		nsim_mac_record_frame(ns, skb, len, -1, false);
		nsim_dev_hwstats_record(dev, len, false);

		skb->dev = dev;
		skb->protocol = eth_type_trans(skb, dev);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			if (!skb_is_gso(skb))
				skb->ip_summed = (dev->features & NETIF_F_RXCSUM) ?
						 CHECKSUM_UNNECESSARY : CHECKSUM_NONE;
		} else if (skb_frags_readable(skb)) {
			valid_csum = (dev->features & NETIF_F_RXCSUM) &&
				     nsim_rx_csum_valid(skb);
			skb->ip_summed = valid_csum ? CHECKSUM_UNNECESSARY :
						      CHECKSUM_NONE;
		} else if (dev->features & NETIF_F_RXCSUM) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}

		if ((dev->features & NETIF_F_GRO_HW) &&
		    !skb_has_extensions(skb) &&
		    skb_frags_readable(skb)) {
			gro_receive_skb(&rq->hw_gro, skb);
			nsim_drain_hw_gro_rx_list(ns, rq);
			if (rq->hw_gro.bitmask)
				hrtimer_start(&rq->gro_timer,
					      ns_to_ktime(NSIM_HW_GRO_TIMEOUT_NS),
					      HRTIMER_MODE_REL_PINNED);
			else
				hrtimer_try_to_cancel(&rq->gro_timer);
		} else {
			if (rq->hw_gro.bitmask) {
				gro_flush(&rq->hw_gro, false);
				nsim_drain_hw_gro_rx_list(ns, rq);
			}
			WRITE_ONCE(rq->rx_packets, rq->rx_packets + 1);
			WRITE_ONCE(rq->rx_bytes, rq->rx_bytes + len);
			dev_sw_netstats_rx_add(dev, len);
			if (skb_is_gso(skb) || skb_shared(skb) ||
			    skb_unclone(skb, GFP_ATOMIC)) {
				if (rq->napi.gro.bitmask ||
				    rq->napi.gro.rx_count)
					gro_flush_normal(&rq->napi.gro, false);
				netif_receive_skb(skb);
			} else {
				napi_gro_receive(&rq->napi, skb);
			}
		}
	}

	if (xdp_xmitted)
		xdp_do_flush();

	return i;
}

static void nsim_xsk_tx(struct netdevsim *ns, struct nsim_rq *rq)
{
	struct xsk_buff_pool *pool = READ_ONCE(rq->xsk_pool);
	struct xdp_desc desc;
	u32 sent = 0;

	if (likely(!pool))
		return;

	while (sent < 64 && xsk_tx_peek_desc(pool, &desc)) {
		void *data = xsk_buff_raw_get_data(pool, desc.addr);
		struct sk_buff *skb;

		skb = __netdev_alloc_skb(ns->netdev, desc.len, GFP_ATOMIC);
		if (skb) {
			skb_put_data(skb, data, desc.len);
			skb_reset_mac_header(skb);
			nsim_start_xmit(skb, ns->netdev);
		}
		sent++;
	}
	if (sent) {
		xsk_tx_release(pool);
		xsk_tx_completed(pool, sent);
	}
}

static int nsim_poll(struct napi_struct *napi, int budget)
{
	struct nsim_rq *rq = container_of(napi, struct nsim_rq, napi);
	struct netdevsim *ns = netdev_priv(napi->dev);
	int done;

	if (unlikely(!budget)) {
		if (ns->txq)
			WRITE_ONCE(ns->txq[0].netpoll_polled, true);
		if (netif_queue_stopped(napi->dev))
			netif_tx_wake_all_queues(napi->dev);
		return 0;
	}

	nsim_xsk_tx(ns, rq);
	done = nsim_rcv(rq, budget);
	if (done < budget) {
		if (napi_complete_done(napi, done) &&
		    !skb_queue_empty(&rq->skb_queue))
			nsim_schedule_rq_napi(ns, rq->xdp_rxq.queue_index, rq);
	}

	return done;
}

static enum hrtimer_restart nsim_napi_timer_fn(struct hrtimer *timer)
{
	struct nsim_rq *rq = container_of(timer, struct nsim_rq, napi_timer);
	struct netdevsim *ns = netdev_priv(rq->napi.dev);
	int rxq_idx = rq->xdp_rxq.queue_index;

	nsim_schedule_rq_napi(ns, rxq_idx, rq);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart nsim_gro_timer_fn(struct hrtimer *timer)
{
	struct nsim_rq *rq = container_of(timer, struct nsim_rq, gro_timer);
	struct netdevsim *ns = netdev_priv(rq->napi.dev);

	WRITE_ONCE(rq->gro_flush_pending, true);
	nsim_schedule_rq_napi(ns, rq->xdp_rxq.queue_index, rq);
	return HRTIMER_NORESTART;
}

static int nsim_create_page_pool(struct net_device *dev, struct page_pool **p,
				 struct napi_struct *napi, int idx,
				 unsigned int order)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct page_pool_params params = {
		.order = order,
		.pool_size = NSIM_RING_SIZE,
		.max_len = PAGE_SIZE << order,
		.nid = NUMA_NO_NODE,
		.dev = &ns->nsim_bus_dev->dev,
		.napi = napi,
		.dma_dir = DMA_FROM_DEVICE,
		.netdev = dev,
		.queue_idx = idx,
	};
	struct page_pool *pool;

	if (dev->cfg->hds_config != ETHTOOL_TCP_DATA_SPLIT_DISABLED)
		params.flags |= PP_FLAG_ALLOW_UNREADABLE_NETMEM;
	if (ns->nsim_bus_dev->dev.dma_mask && PP_DMA_INDEX_BITS)
		params.flags |= PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV;

	pool = page_pool_create(&params);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	*p = pool;
	return 0;
}

static struct nsim_rq *nsim_queue_alloc(struct net_device *dev)
{
	struct nsim_rq *rq;

	rq = kzalloc_obj(*rq, GFP_KERNEL_ACCOUNT);
	if (!rq)
		return NULL;

	skb_queue_head_init(&rq->skb_queue);
	hrtimer_setup(&rq->napi_timer, nsim_napi_timer_fn, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_PINNED);
	hrtimer_setup(&rq->gro_timer, nsim_gro_timer_fn, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL_PINNED);
	spin_lock_init(&rq->gro_lock);
	gro_init(&rq->hw_gro);
	rq->hw_gro.hw_mode = true;
	rq->hw_gro.max_flows = 64;
	INIT_CSD(&rq->csd, nsim_napi_csd_fn, rq);
	rq->irq = -EINVAL;
	return rq;
}

static void nsim_free_irq(struct nsim_rq *rq)
{
	if (rq->irq < 0)
		return;

	netif_napi_set_irq_locked(&rq->napi, -1);
	free_irq(rq->irq, rq);
	irq_free_desc(rq->irq);
	rq->irq = -EINVAL;
}

static void nsim_queue_free(struct net_device *dev, struct nsim_rq *rq)
{
	hrtimer_cancel(&rq->napi_timer);
	hrtimer_cancel(&rq->gro_timer);
	gro_cleanup(&rq->hw_gro);
	nsim_free_irq(rq);
	skb_queue_purge_reason(&rq->skb_queue, SKB_DROP_REASON_QUEUE_PURGE);
	kfree(rq);
}

static void nsim_init_irq(struct nsim_rq *rq, int idx)
{
	unsigned int max_cpus;

	if (rq->irq >= 0) {
		netif_napi_set_irq_locked(&rq->napi, rq->irq);
		return;
	}

	rq->irq = irq_alloc_desc(NUMA_NO_NODE);
	if (rq->irq < 0)
		return;

	irq_set_chip_and_handler(rq->irq, &nsim_irq_chip, handle_simple_irq);
	irq_clear_status_flags(rq->irq, IRQ_NOREQUEST | IRQ_NOAUTOEN);
	if (request_irq(rq->irq, nsim_irq_handler, 0, "netdevsim", rq)) {
		irq_free_desc(rq->irq);
		rq->irq = -EINVAL;
		return;
	}
	max_cpus = num_online_cpus() > 2 ? num_online_cpus() - 2 : 1U;
	irq_set_affinity(rq->irq, cpumask_of(idx % max_cpus));
	netif_napi_set_irq_locked(&rq->napi, rq->irq);
}

static int nsim_init_napi(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	struct nsim_rq *rq;
	int err, i;

	for (i = 0; i < dev->num_rx_queues; i++) {
		rq = ns->rq[i];

		netif_napi_add_config_locked(dev, &rq->napi, nsim_poll, i);
		nsim_init_irq(rq, i);
	}

	for (i = 0; i < dev->num_rx_queues; i++) {
		rq = ns->rq[i];

		err = nsim_create_page_pool(dev, &rq->page_pool, &rq->napi,
					    i, 0);
		if (err)
			goto err_pp_destroy;

		err = xdp_rxq_info_reg(&rq->xdp_rxq, dev, i, rq->napi.napi_id);
		if (err) {
			page_pool_destroy(rq->page_pool);
			rq->page_pool = NULL;
			goto err_pp_destroy;
		}
		err = xdp_rxq_info_reg_mem_model(&rq->xdp_rxq,
						 MEM_TYPE_PAGE_POOL,
						 rq->page_pool);
		if (err) {
			xdp_rxq_info_unreg(&rq->xdp_rxq);
			page_pool_destroy(rq->page_pool);
			rq->page_pool = NULL;
			goto err_pp_destroy;
		}
	}

	return 0;

err_pp_destroy:
	while (i--) {
		xdp_rxq_info_unreg(&ns->rq[i]->xdp_rxq);
		page_pool_destroy(ns->rq[i]->page_pool);
		ns->rq[i]->page_pool = NULL;
	}
	for (i = 0; i < dev->num_rx_queues; i++) {
		nsim_free_irq(ns->rq[i]);
		__netif_napi_del_locked(&ns->rq[i]->napi);
	}
	return err;
}

static void nsim_enable_napi(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	int i;

	for (i = 0; i < dev->num_rx_queues; i++) {
		struct nsim_rq *rq = ns->rq[i];

		netif_queue_set_napi(dev, i, NETDEV_QUEUE_TYPE_RX, &rq->napi);
		napi_enable_locked(&rq->napi);
	}
}

static int nsim_open(struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;
	int err;

	netdev_assert_locked(dev);

	err = nsim_init_napi(ns);
	if (err)
		return err;

	nsim_enable_napi(ns);

	peer = rtnl_dereference(ns->peer);
	if (peer && netif_running(peer->netdev)) {
		nsim_update_carrier(ns);
		nsim_update_carrier(peer);
	} else {
		nsim_update_carrier(ns);
	}

	return 0;
}

static void nsim_del_napi(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	int i;

	for (i = 0; i < dev->num_rx_queues; i++) {
		struct nsim_rq *rq = ns->rq[i];

		napi_disable_locked(&rq->napi);
		hrtimer_cancel(&rq->napi_timer);
		hrtimer_cancel(&rq->gro_timer);
		gro_cleanup(&rq->hw_gro);
		netif_napi_set_irq_locked(&rq->napi, -1);
		__netif_napi_del_locked(&rq->napi);
	}
	synchronize_rcu();
	for (i = 0; i < dev->num_rx_queues; i++) {
		if (xdp_rxq_info_is_reg(&ns->rq[i]->xdp_rxq))
			xdp_rxq_info_unreg(&ns->rq[i]->xdp_rxq);
		page_pool_destroy(ns->rq[i]->page_pool);
		ns->rq[i]->page_pool = NULL;
	}
}

static int nsim_stop(struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;

	netdev_assert_locked(dev);

	netif_carrier_off(dev);
	peer = rtnl_dereference(ns->peer);
	if (peer)
		nsim_update_carrier(peer);

	nsim_del_napi(ns);

	return 0;
}

static int nsim_forward_skb(struct net_device *peer_dev, struct sk_buff *skb,
			    struct nsim_rq *rq, int rxq_idx,
			    u32 rss_hash, enum pkt_hash_types rss_type,
			    struct skb_ext *psp_ext)
{
	struct netdevsim *peer_ns = netdev_priv(peer_dev);
	u32 coal_usecs;
	u64 delay_ns;
	int ret;

	if (skb_queue_len(&rq->skb_queue) >= 65536) {
		if (psp_ext)
			__skb_ext_put(psp_ext);
		dev_kfree_skb_any(skb);
		return NET_RX_DROP;
	}

	ret = __dev_forward_skb(peer_dev, skb);
	if (ret) {
		if (psp_ext)
			__skb_ext_put(psp_ext);
		return ret;
	}
	skb_push(skb, ETH_HLEN);

	nsim_psp_handle_ext(skb, psp_ext);

	if (rss_type != PKT_HASH_TYPE_NONE)
		skb_set_hash(skb, rss_hash, rss_type);
	skb_record_rx_queue(skb, rxq_idx);
	skb_queue_tail(&rq->skb_queue, skb);

	coal_usecs = READ_ONCE(peer_ns->ethtool.coalesce.rx_coalesce_usecs);
	delay_ns = (u64)coal_usecs * NSEC_PER_USEC;
	if (READ_ONCE(peer_dev->gro_flush_timeout)) {
		delay_ns = max3((u64)delay_ns,
				(u64)READ_ONCE(peer_dev->gro_flush_timeout),
				(u64)(2 * NSEC_PER_MSEC));
		hrtimer_start(&rq->napi_timer, ns_to_ktime(delay_ns),
			      HRTIMER_MODE_REL_PINNED);
	} else if (delay_ns > 0) {
		if (!hrtimer_active(&rq->napi_timer))
			hrtimer_start(&rq->napi_timer, ns_to_ktime(delay_ns),
				      HRTIMER_MODE_REL_PINNED);
	} else {
		nsim_schedule_rq_napi(peer_ns, rxq_idx, rq);
	}

	return NET_RX_SUCCESS;
}

static netdev_tx_t nsim_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct skb_ext *psp_ext = NULL;
	struct net_device *peer_dev;
	unsigned int len = skb->len;
	struct netdevsim *peer_ns;
	struct nsim_rq *rq;
	u32 rss_hash = 0;
	enum pkt_hash_types rss_type = PKT_HASH_TYPE_NONE;
	u16 txq_idx;
	bool use_pp_rx;
	bool was_gso;
	unsigned int gso_segs;
	int rxq;
	int dr = SKB_DROP_REASON_NOT_SPECIFIED;

	if (unlikely(netpoll_tx_running(dev) &&
		     READ_ONCE(ns->ethtool.ring.tx_pending) == 1 &&
		     ns->txq && !xchg(&ns->txq[0].netpoll_polled, false)))
		return NETDEV_TX_BUSY;

	rcu_read_lock();
	if (dev->features & NETIF_F_LOOPBACK) {
		peer_ns = ns;
		peer_dev = dev;
	} else {
		peer_ns = rcu_dereference(ns->peer);
		if (!peer_ns)
			goto out_drop_free;
		peer_dev = peer_ns->netdev;
	}
	if (!netif_running(peer_dev))
		goto out_drop_free;

	if (skb_vlan_tag_present(skb) && READ_ONCE(peer_ns->xdp.prog)) {
		skb = __vlan_hwaccel_push_inside(skb);
		if (unlikely(!skb))
			goto out_drop_cnt;
		len = skb->len;
	}

	if (nsim_skb_has_net_iov(skb)) {
		struct sk_buff *copied = nsim_devmem_tx_copy(skb, dev);

		consume_skb(skb);
		if (!copied)
			goto out_drop_cnt;
		skb = copied;
	}

	txq_idx = skb_get_queue_mapping(skb);
	if (txq_idx >= dev->num_tx_queues)
		txq_idx = 0;

	was_gso = skb_is_gso(skb);
	gso_segs = was_gso ? max_t(unsigned int, 1, skb_shinfo(skb)->gso_segs) : 1;

	skb = nsim_ipsec_tx(ns, skb, peer_ns != ns);
	if (!skb)
		goto out_drop_cnt;

	if (skb->next) {
		struct sk_buff *curr, *next;
		unsigned int pkts = 0, bytes = 0;

		skb_list_walk_safe(skb, curr, next) {
			unsigned int slen = curr->len;

			skb_mark_not_on_list(curr);
			rxq = nsim_select_rxq(peer_ns, curr, &rss_hash, &rss_type);
			if (rxq < 0) {
				dev_kfree_skb_any(curr);
				continue;
			}
			rq = peer_ns->rq[rxq];
			nsim_tx_csum_complete(curr);
			nsim_mac_record_frame(ns, curr, slen, txq_idx, true);
			nsim_dev_hwstats_record(dev, slen, true);
			if (unlikely(nsim_forward_skb(peer_dev, curr, rq, rxq,
						      rss_hash, rss_type, NULL) ==
				     NET_RX_DROP)) {
				u64_stats_update_begin(&ns->syncp);
				u64_stats_inc(&ns->tx_dropped);
				u64_stats_update_end(&ns->syncp);
			} else {
				pkts++;
				bytes += slen;
			}
		}
		if (pkts) {
			dev_sw_netstats_tx_add(dev, pkts, bytes);
			if (ns->txq) {
				WRITE_ONCE(ns->txq[txq_idx].packets,
					   ns->txq[txq_idx].packets + pkts);
				WRITE_ONCE(ns->txq[txq_idx].bytes,
					   ns->txq[txq_idx].bytes + bytes);
				WRITE_ONCE(ns->txq[txq_idx].hw_gso_packets,
					   ns->txq[txq_idx].hw_gso_packets + 1);
				WRITE_ONCE(ns->txq[txq_idx].hw_gso_wire_packets,
					   ns->txq[txq_idx].hw_gso_wire_packets +
					   pkts);
			}
		}
		rcu_read_unlock();
		return NETDEV_TX_OK;
	}

	dr = nsim_do_psp(skb, ns, peer_ns, &psp_ext);
	if (dr)
		goto out_drop_free;
	len = skb->len;

	rxq = nsim_select_rxq(peer_ns, skb, &rss_hash, &rss_type);
	if (rxq < 0) {
		if (psp_ext)
			__skb_ext_put(psp_ext);
		goto out_drop_free;
	}
	rq = peer_ns->rq[rxq];

	use_pp_rx = rq->page_pool &&
		    page_pool_is_unreadable(rq->page_pool);

	if (skb_is_nonlinear(skb) && !was_gso &&
	    (use_pp_rx || (peer_dev->features & NETIF_F_GRO_HW) ||
	     READ_ONCE(peer_ns->xdp.prog))) {
		if (skb_linearize(skb)) {
			if (psp_ext)
				__skb_ext_put(psp_ext);
			goto out_drop_free;
		}
	}

	if ((skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) &&
	    ns->hwtstamp_cfg.tx_type == HWTSTAMP_TX_ON) {
		struct skb_shared_hwtstamps hwtstamps = {
			.hwtstamp = ktime_get_real(),
		};

		skb_tstamp_tx(skb, &hwtstamps);
	}

	if (was_gso && !psp_ext &&
	    (use_pp_rx || (peer_dev->features & NETIF_F_GRO_HW) ||
	     (skb_shinfo(skb)->gso_type &
	      (SKB_GSO_PARTIAL | SKB_GSO_UDP_L4 | SKB_GSO_UDP_TUNNEL |
	       SKB_GSO_UDP_TUNNEL_CSUM | SKB_GSO_GRE | SKB_GSO_GRE_CSUM |
	       SKB_GSO_IPXIP4 | SKB_GSO_IPXIP6)))) {
		struct sk_buff *segs, *curr, *next;
		unsigned int pkts = 0, bytes = 0;

		if (skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) {
			if (skb_shinfo(skb)->gso_type &
			    SKB_GSO_UDP_TUNNEL_CSUM) {
				skb_shinfo(skb)->gso_type &=
					~SKB_GSO_UDP_TUNNEL_CSUM;
				skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL;
			}
			if (skb_shinfo(skb)->gso_type & SKB_GSO_GRE_CSUM) {
				skb_shinfo(skb)->gso_type &= ~SKB_GSO_GRE_CSUM;
				skb_shinfo(skb)->gso_type |= SKB_GSO_GRE;
			}
		}
		segs = skb_gso_segment(skb, 0);
		if (IS_ERR_OR_NULL(segs)) {
			if (psp_ext)
				__skb_ext_put(psp_ext);
			goto out_drop_free;
		}
		consume_skb(skb);

		skb_list_walk_safe(segs, curr, next) {
			unsigned int slen = curr->len;

			skb_mark_not_on_list(curr);
			if (psp_ext)
				refcount_inc(&psp_ext->refcnt);
			nsim_tx_csum_complete(curr);
			nsim_mac_record_frame(ns, curr, slen, txq_idx, true);
			nsim_dev_hwstats_record(dev, slen, true);
			if (unlikely(nsim_forward_skb(peer_dev, curr, rq, rxq,
						      rss_hash, rss_type,
						      psp_ext) ==
				     NET_RX_DROP)) {
				u64_stats_update_begin(&ns->syncp);
				u64_stats_inc(&ns->tx_dropped);
				u64_stats_update_end(&ns->syncp);
			} else {
				pkts++;
				bytes += slen;
			}
		}
		if (psp_ext)
			__skb_ext_put(psp_ext);

		if (pkts) {
			dev_sw_netstats_tx_add(dev, pkts, bytes);
			if (ns->txq) {
				WRITE_ONCE(ns->txq[txq_idx].packets,
					   ns->txq[txq_idx].packets + pkts);
				WRITE_ONCE(ns->txq[txq_idx].bytes,
					   ns->txq[txq_idx].bytes + bytes);
				WRITE_ONCE(ns->txq[txq_idx].hw_gso_packets,
					   ns->txq[txq_idx].hw_gso_packets + 1);
				WRITE_ONCE(ns->txq[txq_idx].hw_gso_wire_packets,
					   ns->txq[txq_idx].hw_gso_wire_packets +
					   pkts);
			}
		}
		rcu_read_unlock();
		return NETDEV_TX_OK;
	}

	if (!was_gso)
		nsim_tx_csum_complete(skb);

	nsim_mac_record_frame(ns, skb, len, txq_idx, true);
	nsim_dev_hwstats_record(dev, len, true);

	if (unlikely(nsim_forward_skb(peer_dev, skb, rq, rxq,
				      rss_hash, rss_type, psp_ext) == NET_RX_DROP))
		goto out_drop_cnt;

	rcu_read_unlock();
	dev_sw_netstats_tx_add(dev, gso_segs, len);
	if (ns->txq) {
		WRITE_ONCE(ns->txq[txq_idx].packets,
			   ns->txq[txq_idx].packets + gso_segs);
		WRITE_ONCE(ns->txq[txq_idx].bytes,
			   ns->txq[txq_idx].bytes + len);
		if (was_gso) {
			WRITE_ONCE(ns->txq[txq_idx].hw_gso_packets,
				   ns->txq[txq_idx].hw_gso_packets + 1);
			WRITE_ONCE(ns->txq[txq_idx].hw_gso_wire_packets,
				   ns->txq[txq_idx].hw_gso_wire_packets +
				   gso_segs);
		}
	}
	return NETDEV_TX_OK;

out_drop_free:
	kfree_skb_reason(skb, dr);
out_drop_cnt:
	rcu_read_unlock();
	u64_stats_update_begin(&ns->syncp);
	u64_stats_inc(&ns->tx_dropped);
	u64_stats_update_end(&ns->syncp);
	return NETDEV_TX_OK;
}

static netdev_tx_t nsim_start_xmit_vf(struct sk_buff *skb,
				      struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	unsigned int len = skb->len;
	unsigned int vf_id;

	if (ns->nsim_dev_port &&
	    ns->nsim_dev_port->port_index >= NSIM_DEV_VF_PORT_INDEX_BASE) {
		vf_id = ns->nsim_dev_port->port_index -
			NSIM_DEV_VF_PORT_INDEX_BASE;
		if (vf_id < ns->nsim_dev->nsim_bus_dev->num_vfs) {
			struct net_device *vf_dev =
				READ_ONCE(ns->nsim_dev->vf_netdevs[vf_id]);

			if (vf_dev &&
			    __dev_forward_skb(vf_dev, skb) == NET_RX_SUCCESS) {
				netif_receive_skb(skb);
				dev_sw_netstats_tx_add(dev, 1, len);
				dev_sw_netstats_rx_add(vf_dev, len);
				return NETDEV_TX_OK;
			}
			u64_stats_update_begin(&ns->syncp);
			u64_stats_inc(&ns->tx_dropped);
			u64_stats_update_end(&ns->syncp);
			return NETDEV_TX_OK;
		}
	}

	dev_kfree_skb(skb);
	u64_stats_update_begin(&ns->syncp);
	u64_stats_inc(&ns->tx_dropped);
	u64_stats_update_end(&ns->syncp);
	return NETDEV_TX_OK;
}

static int nsim_set_rx_mode(struct net_device *dev,
			    struct netdev_hw_addr_list *uc,
			    struct netdev_hw_addr_list *mc)
{
	return 0;
}

static int nsim_change_mtu(struct net_device *dev, int new_mtu)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->xdp.prog && !ns->xdp.prog->aux->xdp_has_frags &&
	    new_mtu > NSIM_XDP_MAX_MTU)
		return -EBUSY;

	WRITE_ONCE(dev->mtu, new_mtu);

	return 0;
}

static void
nsim_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct netdevsim *ns = netdev_priv(dev);
	u64 rx_pkts = ns->base_rx_packets;
	u64 rx_bytes = ns->base_rx_bytes;
	u64 tx_pkts = 0;
	u64 tx_bytes = 0;
	unsigned int i;

	rcu_read_lock();
	for (i = 0; i < dev->num_rx_queues; i++) {
		if (ns->rq && ns->rq[i]) {
			rx_pkts += READ_ONCE(ns->rq[i]->rx_packets);
			rx_bytes += READ_ONCE(ns->rq[i]->rx_bytes);
		}
	}
	for (i = 0; i < dev->num_tx_queues; i++) {
		if (ns->txq) {
			tx_pkts += READ_ONCE(ns->txq[i].packets);
			tx_bytes += READ_ONCE(ns->txq[i].bytes);
		}
	}
	stats->rx_packets = rx_pkts;
	stats->rx_bytes = rx_bytes;
	stats->tx_packets = tx_pkts;
	stats->tx_bytes = tx_bytes;
	stats->tx_dropped = u64_stats_read(&ns->tx_dropped);
	rcu_read_unlock();
}

static int
nsim_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
		       void *cb_priv)
{
	return nsim_bpf_setup_tc_block_cb(type, type_data, cb_priv);
}

static int nsim_set_vf_mac(struct net_device *dev, int vf, u8 *mac)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev) || is_multicast_ether_addr(mac))
		return -EINVAL;
	memcpy(nsim_dev->vfconfigs[vf].vf_mac, mac, ETH_ALEN);

	return 0;
}

static int nsim_set_vf_vlan(struct net_device *dev, int vf,
			    u16 vlan, u8 qos, __be16 vlan_proto)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev) || vlan > 4095 || qos > 7)
		return -EINVAL;

	nsim_dev->vfconfigs[vf].vlan = vlan;
	nsim_dev->vfconfigs[vf].qos = qos;
	nsim_dev->vfconfigs[vf].vlan_proto = vlan_proto;

	return 0;
}

static int nsim_set_vf_rate(struct net_device *dev, int vf, int min, int max)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (nsim_esw_mode_is_switchdev(ns->nsim_dev)) {
		pr_err("Not supported in switchdev mode.Please use devlink API.\n");
		return -EOPNOTSUPP;
	}

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;

	nsim_dev->vfconfigs[vf].min_tx_rate = min;
	nsim_dev->vfconfigs[vf].max_tx_rate = max;

	return 0;
}

static int nsim_set_vf_spoofchk(struct net_device *dev, int vf, bool val)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;
	nsim_dev->vfconfigs[vf].spoofchk_enabled = val;

	return 0;
}

static int nsim_set_vf_rss_query_en(struct net_device *dev, int vf, bool val)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;
	nsim_dev->vfconfigs[vf].rss_query_enabled = val;

	return 0;
}

static int nsim_set_vf_trust(struct net_device *dev, int vf, bool val)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;
	nsim_dev->vfconfigs[vf].trusted = val;

	return 0;
}

static int
nsim_get_vf_config(struct net_device *dev, int vf, struct ifla_vf_info *ivi)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;

	ivi->vf = vf;
	ivi->linkstate = nsim_dev->vfconfigs[vf].link_state;
	ivi->min_tx_rate = nsim_dev->vfconfigs[vf].min_tx_rate;
	ivi->max_tx_rate = nsim_dev->vfconfigs[vf].max_tx_rate;
	ivi->vlan = nsim_dev->vfconfigs[vf].vlan;
	ivi->vlan_proto = nsim_dev->vfconfigs[vf].vlan_proto;
	ivi->qos = nsim_dev->vfconfigs[vf].qos;
	memcpy(&ivi->mac, nsim_dev->vfconfigs[vf].vf_mac, ETH_ALEN);
	ivi->spoofchk = nsim_dev->vfconfigs[vf].spoofchk_enabled;
	ivi->trusted = nsim_dev->vfconfigs[vf].trusted;
	ivi->rss_query_en = nsim_dev->vfconfigs[vf].rss_query_enabled;

	return 0;
}

static int nsim_set_vf_link_state(struct net_device *dev, int vf, int state)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_dev *nsim_dev = ns->nsim_dev;

	if (vf >= nsim_dev_get_vfs(nsim_dev))
		return -EINVAL;

	switch (state) {
	case IFLA_VF_LINK_STATE_AUTO:
	case IFLA_VF_LINK_STATE_ENABLE:
	case IFLA_VF_LINK_STATE_DISABLE:
		break;
	default:
		return -EINVAL;
	}

	nsim_dev->vfconfigs[vf].link_state = state;

	return 0;
}

static void nsim_taprio_stats(struct tc_taprio_qopt_stats *stats)
{
	stats->window_drops = 0;
	stats->tx_overruns = 0;
}

static int nsim_setup_tc_taprio(struct net_device *dev,
				struct tc_taprio_qopt_offload *offload)
{
	int err = 0;

	switch (offload->cmd) {
	case TAPRIO_CMD_REPLACE:
	case TAPRIO_CMD_DESTROY:
		break;
	case TAPRIO_CMD_STATS:
		nsim_taprio_stats(&offload->stats);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static LIST_HEAD(nsim_block_cb_list);

static int
nsim_ndo_setup_tc(struct net_device *dev, enum tc_setup_type type,
		  void *type_data)
{
	struct netdevsim *ns = netdev_priv(dev);

	switch (type) {
	case TC_SETUP_QDISC_TAPRIO:
		return nsim_setup_tc_taprio(dev, type_data);
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple(type_data,
						  &nsim_block_cb_list,
						  nsim_setup_tc_block_cb,
						  ns, ns, true);
	case TC_QUERY_CAPS:
	case TC_SETUP_QDISC_MQPRIO:
		return nsim_setup_tc(dev, type, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static int
nsim_set_features(struct net_device *dev, netdev_features_t features)
{
	struct netdevsim *ns = netdev_priv(dev);

	if ((dev->features & NETIF_F_HW_TC) > (features & NETIF_F_HW_TC))
		return nsim_bpf_disable_tc(ns);

	return 0;
}

static netdev_features_t nsim_fix_features(struct net_device *dev,
					   netdev_features_t features)
{
	struct netdevsim *ns = netdev_priv(dev);
	unsigned int i;

	if (ns->xdp_hw.prog)
		features &= ~NETIF_F_GRO_HW;

	for (i = 0; i < dev->num_rx_queues; i++) {
		if (ns->rq && ns->rq[i] && ns->rq[i]->page_pool &&
		    page_pool_is_unreadable(ns->rq[i]->page_pool)) {
			features &= ~NETIF_F_GRO_HW;
			break;
		}
	}

	return features;
}

static int nsim_get_iflink(const struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;
	int iflink;

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	iflink = peer ? READ_ONCE(peer->netdev->ifindex) :
			READ_ONCE(dev->ifindex);
	rcu_read_unlock();

	return iflink;
}

static int nsim_vlan_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct netdevsim *ns = netdev_priv(dev);

	switch (ntohs(proto)) {
	case ETH_P_8021Q:
		set_bit(vid, ns->vlan.ctag);
		break;
	case ETH_P_8021AD:
		set_bit(vid, ns->vlan.stag);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int nsim_vlan_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct netdevsim *ns = netdev_priv(dev);

	switch (ntohs(proto)) {
	case ETH_P_8021Q:
		clear_bit(vid, ns->vlan.ctag);
		break;
	case ETH_P_8021AD:
		clear_bit(vid, ns->vlan.stag);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int nsim_hwtstamp_get(struct net_device *dev,
			     struct kernel_hwtstamp_config *cfg)
{
	struct netdevsim *ns = netdev_priv(dev);

	*cfg = ns->hwtstamp_cfg;
	return 0;
}

static int nsim_hwtstamp_set(struct net_device *dev,
			     struct kernel_hwtstamp_config *cfg,
			     struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	switch (cfg->tx_type) {
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
		break;
	default:
		return -ERANGE;
	}

	switch (cfg->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
	case HWTSTAMP_FILTER_ALL:
		break;
	default:
		cfg->rx_filter = HWTSTAMP_FILTER_ALL;
		break;
	}

	ns->hwtstamp_cfg = *cfg;
	return 0;
}

static int nsim_ndo_xdp_xmit(struct net_device *dev, int n,
			     struct xdp_frame **frames, u32 flags)
{
	int i, nxmit = 0;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];
		struct sk_buff *skb;

		skb = xdp_build_skb_from_frame(xdpf, dev);
		if (!skb)
			break;
		__skb_push(skb, ETH_HLEN);
		nsim_start_xmit(skb, dev);
		nxmit++;
	}
	return nxmit;
}

static int nsim_xsk_wakeup(struct net_device *dev, u32 qid, u32 flags)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (qid >= dev->real_num_rx_queues)
		return -EINVAL;

	nsim_schedule_rq_napi(ns, qid, ns->rq[qid]);
	return 0;
}

static int nsim_shaper_set(struct net_shaper_binding *binding,
			   const struct net_shaper *shaper,
			   struct netlink_ext_ack *extack)
{
	return 0;
}

static int nsim_shaper_del(struct net_shaper_binding *binding,
			   const struct net_shaper_handle *handle,
			   struct netlink_ext_ack *extack)
{
	return 0;
}

static int nsim_shaper_group(struct net_shaper_binding *binding,
			     int leaves_count,
			     const struct net_shaper *leaves,
			     const struct net_shaper *root,
			     struct netlink_ext_ack *extack)
{
	return 0;
}

static void nsim_shaper_cap(struct net_shaper_binding *binding,
			    enum net_shaper_scope scope,
			    unsigned long *flags)
{
	*flags = ULONG_MAX;
}

static const struct net_shaper_ops nsim_shaper_ops = {
	.set			= nsim_shaper_set,
	.delete			= nsim_shaper_del,
	.group			= nsim_shaper_group,
	.capabilities		= nsim_shaper_cap,
};

static const struct net_device_ops nsim_netdev_ops = {
	.ndo_open		= nsim_open,
	.ndo_stop		= nsim_stop,
	.ndo_start_xmit		= nsim_start_xmit,
	.ndo_set_rx_mode_async	= nsim_set_rx_mode,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= nsim_change_mtu,
	.ndo_get_stats64	= nsim_get_stats64,
	.ndo_set_vf_mac		= nsim_set_vf_mac,
	.ndo_set_vf_vlan	= nsim_set_vf_vlan,
	.ndo_set_vf_rate	= nsim_set_vf_rate,
	.ndo_set_vf_spoofchk	= nsim_set_vf_spoofchk,
	.ndo_set_vf_trust	= nsim_set_vf_trust,
	.ndo_get_vf_config	= nsim_get_vf_config,
	.ndo_set_vf_link_state	= nsim_set_vf_link_state,
	.ndo_set_vf_rss_query_en = nsim_set_vf_rss_query_en,
	.ndo_setup_tc		= nsim_ndo_setup_tc,
	.ndo_set_features	= nsim_set_features,
	.ndo_fix_features	= nsim_fix_features,
	.ndo_vlan_rx_add_vid	= nsim_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= nsim_vlan_rx_kill_vid,
	.ndo_hwtstamp_get	= nsim_hwtstamp_get,
	.ndo_hwtstamp_set	= nsim_hwtstamp_set,
	.ndo_bpf		= nsim_bpf,
	.ndo_xdp_xmit		= nsim_ndo_xdp_xmit,
	.ndo_xsk_wakeup		= nsim_xsk_wakeup,
	.ndo_get_iflink		= nsim_get_iflink,
	.net_shaper_ops		= &nsim_shaper_ops,
};

static const struct net_device_ops nsim_vf_netdev_ops = {
	.ndo_start_xmit		= nsim_start_xmit_vf,
	.ndo_set_rx_mode_async	= nsim_set_rx_mode,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= nsim_change_mtu,
	.ndo_setup_tc		= nsim_ndo_setup_tc,
	.ndo_set_features	= nsim_set_features,
	.ndo_vlan_rx_add_vid	= nsim_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= nsim_vlan_rx_kill_vid,
};

/* We don't have true per-queue stats, yet, so do some randomikos
 * pretending data got cleanly Roach'd across all queues.
 */
static void nsim_get_queue_stats_rx(struct net_device *dev, int idx,
				    struct netdev_queue_stats_rx *stats)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_rq *rq = ns->rq[idx];

	stats->packets = READ_ONCE(rq->rx_packets);
	stats->bytes = READ_ONCE(rq->rx_bytes);
	stats->alloc_fail = READ_ONCE(rq->alloc_fail);
	stats->hw_gro_packets = READ_ONCE(rq->hw_gro.hw_gro_packets);
	stats->hw_gro_wire_packets = READ_ONCE(rq->hw_gro.hw_gro_wire_packets);
}

static void nsim_get_queue_stats_tx(struct net_device *dev, int idx,
				    struct netdev_queue_stats_tx *stats)
{
	struct netdevsim *ns = netdev_priv(dev);

	stats->packets = READ_ONCE(ns->txq[idx].packets);
	stats->bytes = READ_ONCE(ns->txq[idx].bytes);
	stats->hw_gso_packets = READ_ONCE(ns->txq[idx].hw_gso_packets);
	stats->hw_gso_wire_packets = READ_ONCE(ns->txq[idx].hw_gso_wire_packets);
}

static void nsim_get_base_stats(struct net_device *dev,
				struct netdev_queue_stats_rx *rx,
				struct netdev_queue_stats_tx *tx)
{
	struct netdevsim *ns = netdev_priv(dev);
	unsigned int i;

	rx->packets = ns->base_rx_packets;
	rx->bytes = ns->base_rx_bytes;
	rx->alloc_fail = ns->base_rx_alloc_fail;
	rx->hw_gro_packets = ns->base_rx_hw_gro_packets;
	rx->hw_gro_wire_packets = ns->base_rx_hw_gro_wire_packets;

	for (i = dev->real_num_rx_queues; i < dev->num_rx_queues; i++) {
		struct nsim_rq *rq = ns->rq[i];

		rx->packets += READ_ONCE(rq->rx_packets);
		rx->bytes += READ_ONCE(rq->rx_bytes);
		rx->alloc_fail += READ_ONCE(rq->alloc_fail);
		rx->hw_gro_packets += READ_ONCE(rq->hw_gro.hw_gro_packets);
		rx->hw_gro_wire_packets +=
			READ_ONCE(rq->hw_gro.hw_gro_wire_packets);
	}

	tx->packets = 0;
	tx->bytes = 0;
	tx->hw_gso_packets = 0;
	tx->hw_gso_wire_packets = 0;

	for (i = dev->real_num_tx_queues; i < dev->num_tx_queues; i++) {
		tx->packets += READ_ONCE(ns->txq[i].packets);
		tx->bytes += READ_ONCE(ns->txq[i].bytes);
		tx->hw_gso_packets += READ_ONCE(ns->txq[i].hw_gso_packets);
		tx->hw_gso_wire_packets +=
			READ_ONCE(ns->txq[i].hw_gso_wire_packets);
	}
}

static const struct netdev_stat_ops nsim_stat_ops = {
	.get_queue_stats_rx	= nsim_get_queue_stats_rx,
	.get_queue_stats_tx	= nsim_get_queue_stats_tx,
	.get_base_stats		= nsim_get_base_stats,
};

struct nsim_queue_mem {
	struct nsim_rq *rq;
	struct page_pool *pp;
};

static int nsim_queue_mem_alloc(struct net_device *dev,
				struct netdev_queue_config *qcfg,
				void *per_queue_mem, int idx)
{
	unsigned int order = qcfg->rx_page_size ?
			     get_order(qcfg->rx_page_size) : 0;
	struct nsim_queue_mem *qmem = per_queue_mem;
	struct netdevsim *ns = netdev_priv(dev);
	int err;

	if (ns->rq_reset_mode > 3)
		return -EINVAL;

	if (netif_rxq_has_unreadable_mp(dev, idx) &&
	    dev->cfg->hds_config == ETHTOOL_TCP_DATA_SPLIT_DISABLED)
		return -EINVAL;

	if (ns->rq_reset_mode == 1) {
		if (!netif_running(ns->netdev))
			return -ENETDOWN;
		return nsim_create_page_pool(dev, &qmem->pp,
					     &ns->rq[idx]->napi, idx, order);
	}

	qmem->rq = nsim_queue_alloc(dev);
	if (!qmem->rq)
		return -ENOMEM;

	err = nsim_create_page_pool(dev, &qmem->rq->page_pool, &qmem->rq->napi,
				    idx, order);
	if (err)
		goto err_free;

	if (!ns->rq_reset_mode) {
		netif_napi_add_config_locked(dev, &qmem->rq->napi, nsim_poll,
					     idx);
		nsim_init_irq(qmem->rq, idx);
	}

	return 0;

err_free:
	nsim_queue_free(dev, qmem->rq);
	return err;
}

static void nsim_queue_mem_free(struct net_device *dev, void *per_queue_mem)
{
	struct nsim_queue_mem *qmem = per_queue_mem;
	struct netdevsim *ns = netdev_priv(dev);

	page_pool_destroy(qmem->pp);
	if (qmem->rq) {
		struct page_pool *pp = qmem->rq->page_pool;

		if (xdp_rxq_info_is_reg(&qmem->rq->xdp_rxq))
			xdp_rxq_info_unreg(&qmem->rq->xdp_rxq);
		if (!ns->rq_reset_mode) {
			nsim_free_irq(qmem->rq);
			netif_napi_del_locked(&qmem->rq->napi);
		}
		nsim_queue_free(dev, qmem->rq);
		page_pool_destroy(pp);
	}
}

static int nsim_queue_start(struct net_device *dev,
			    struct netdev_queue_config *qcfg,
			    void *per_queue_mem, int idx)
{
	struct nsim_queue_mem *qmem = per_queue_mem;
	struct netdevsim *ns = netdev_priv(dev);
	int err;

	netdev_assert_locked(dev);

	if (ns->rq_reset_mode == 1) {
		ns->rq[idx]->page_pool = qmem->pp;
		napi_enable_locked(&ns->rq[idx]->napi);
		return 0;
	}

	if (ns->rq_reset_mode == 2) {
		nsim_free_irq(ns->rq[idx]);
		netif_napi_del_locked(&ns->rq[idx]->napi);
		netif_napi_add_config_locked(dev, &qmem->rq->napi, nsim_poll,
					     idx);
		nsim_init_irq(qmem->rq, idx);
	} else if (ns->rq_reset_mode == 3) {
		netif_napi_add_config_locked(dev, &qmem->rq->napi, nsim_poll,
					     idx);
		nsim_init_irq(qmem->rq, idx);
		nsim_free_irq(ns->rq[idx]);
		netif_napi_del_locked(&ns->rq[idx]->napi);
	}

	qmem->rq->rx_packets = ns->rq[idx]->rx_packets;
	qmem->rq->rx_bytes = ns->rq[idx]->rx_bytes;
	qmem->rq->alloc_fail = ns->rq[idx]->alloc_fail;
	qmem->rq->hw_gro.hw_gro_packets = ns->rq[idx]->hw_gro.hw_gro_packets;
	qmem->rq->hw_gro.hw_gro_wire_packets =
		ns->rq[idx]->hw_gro.hw_gro_wire_packets;
	qmem->rq->xsk_pool = ns->rq[idx]->xsk_pool;
	ns->rq[idx] = qmem->rq;

	err = xdp_rxq_info_reg(&ns->rq[idx]->xdp_rxq, dev, idx,
			       ns->rq[idx]->napi.napi_id);
	if (!err) {
		if (ns->rq[idx]->xsk_pool)
			xsk_pool_set_rxq_info(ns->rq[idx]->xsk_pool,
					      &ns->rq[idx]->xdp_rxq);
		else
			WARN_ON(xdp_rxq_info_reg_mem_model(&ns->rq[idx]->xdp_rxq,
							   MEM_TYPE_PAGE_POOL,
							   ns->rq[idx]->page_pool));
	}

	netif_queue_set_napi(dev, idx, NETDEV_QUEUE_TYPE_RX, &ns->rq[idx]->napi);
	napi_enable_locked(&ns->rq[idx]->napi);

	return 0;
}

static int nsim_queue_stop(struct net_device *dev, void *per_queue_mem, int idx)
{
	struct nsim_queue_mem *qmem = per_queue_mem;
	struct netdevsim *ns = netdev_priv(dev);

	netdev_assert_locked(dev);

	napi_disable_locked(&ns->rq[idx]->napi);

	if (ns->rq_reset_mode == 1) {
		qmem->pp = ns->rq[idx]->page_pool;
		page_pool_disable_direct_recycling(qmem->pp);
	} else {
		qmem->rq = ns->rq[idx];
	}

	return 0;
}

static void
nsim_default_qcfg(struct net_device *dev, struct netdev_queue_config *qcfg)
{
	qcfg->rx_page_size = PAGE_SIZE;
}

static int
nsim_validate_qcfg(struct net_device *dev, struct netdev_queue_config *qcfg,
		   struct netlink_ext_ack *extack)
{
	if (!is_power_of_2(qcfg->rx_page_size) ||
	    qcfg->rx_page_size < PAGE_SIZE ||
	    qcfg->rx_page_size > (PAGE_SIZE << 2)) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid rx page size");
		return -EINVAL;
	}
	return 0;
}

static struct device *
nsim_queue_get_dma_dev(struct net_device *dev, int idx)
{
	struct netdevsim *ns = netdev_priv(dev);

	return &ns->nsim_bus_dev->dev;
}

static const struct netdev_queue_mgmt_ops nsim_queue_mgmt_ops = {
	.ndo_queue_mem_size	= sizeof(struct nsim_queue_mem),
	.ndo_queue_mem_alloc	= nsim_queue_mem_alloc,
	.ndo_queue_mem_free	= nsim_queue_mem_free,
	.ndo_queue_start	= nsim_queue_start,
	.ndo_queue_stop		= nsim_queue_stop,
	.ndo_default_qcfg	= nsim_default_qcfg,
	.ndo_validate_qcfg	= nsim_validate_qcfg,
	.ndo_queue_get_dma_dev	= nsim_queue_get_dma_dev,
	.supported_params	= QCFG_RX_PAGE_SIZE,
};

static ssize_t
nsim_qreset_write(struct file *file, const char __user *data,
		  size_t count, loff_t *ppos)
{
	struct netdevsim *ns = file->private_data;
	unsigned int queue, mode;
	char buf[32];
	ssize_t ret;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, data, count))
		return -EFAULT;
	buf[count] = '\0';

	ret = sscanf(buf, "%u %u", &queue, &mode);
	if (ret != 2)
		return -EINVAL;

	netdev_lock(ns->netdev);
	if (queue >= ns->netdev->real_num_rx_queues) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	ns->rq_reset_mode = mode;
	ret = netdev_rx_queue_restart(ns->netdev, queue);
	ns->rq_reset_mode = 0;
	if (ret)
		goto exit_unlock;

	ret = count;
exit_unlock:
	netdev_unlock(ns->netdev);
	return ret;
}

static const struct file_operations nsim_qreset_fops = {
	.open = simple_open,
	.write = nsim_qreset_write,
	.owner = THIS_MODULE,
};

static ssize_t
nsim_pp_hold_read(struct file *file, char __user *data,
		  size_t count, loff_t *ppos)
{
	struct netdevsim *ns = file->private_data;
	char buf[3] = "n\n";

	if (ns->page)
		buf[0] = 'y';

	return simple_read_from_buffer(data, count, ppos, buf, 2);
}

static ssize_t
nsim_pp_hold_write(struct file *file, const char __user *data,
		   size_t count, loff_t *ppos)
{
	struct netdevsim *ns = file->private_data;
	ssize_t ret;
	bool val;

	ret = kstrtobool_from_user(data, count, &val);
	if (ret)
		return ret;

	rtnl_lock();
	netdev_lock(ns->netdev);
	ret = count;
	if (val == !!ns->page)
		goto exit;

	if (!netif_running(ns->netdev) && val) {
		ret = -ENETDOWN;
	} else if (val && (!ns->rq ||
			   page_pool_is_unreadable(ns->rq[0]->page_pool))) {
		ret = -EOPNOTSUPP;
	} else if (val) {
		ns->page = page_pool_dev_alloc_pages(ns->rq[0]->page_pool);
		if (!ns->page)
			ret = -ENOMEM;
	} else {
		page_pool_put_full_page(pp_page_to_nmdesc(ns->page)->pp,
					ns->page, false);
		ns->page = NULL;
	}

exit:
	netdev_unlock(ns->netdev);
	rtnl_unlock();
	return ret;
}

static const struct file_operations nsim_pp_hold_fops = {
	.open = simple_open,
	.read = nsim_pp_hold_read,
	.write = nsim_pp_hold_write,
	.llseek = generic_file_llseek,
	.owner = THIS_MODULE,
};

static int nsim_vlan_show(struct seq_file *s, void *data)
{
	struct netdevsim *ns = s->private;
	int vid;

	for_each_set_bit(vid, ns->vlan.ctag, VLAN_N_VID)
		seq_printf(s, "ctag %d\n", vid);
	for_each_set_bit(vid, ns->vlan.stag, VLAN_N_VID)
		seq_printf(s, "stag %d\n", vid);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(nsim_vlan);

static void nsim_setup(struct net_device *dev)
{
	ether_setup(dev);
	eth_hw_addr_random(dev);

	dev->tx_queue_len = 0;
	dev->flags |= IFF_BROADCAST | IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE |
			   IFF_NO_QUEUE;
	dev->features |= NETIF_F_HIGHDMA |
			 NETIF_F_SG |
			 NETIF_F_FRAGLIST |
			 NETIF_F_HW_CSUM |
			 NETIF_F_RXCSUM |
			 NETIF_F_RXHASH |
			 NETIF_F_GSO_SOFTWARE |
			 NETIF_F_GSO_ROBUST |
			 NETIF_F_GSO_PARTIAL |
			 NETIF_F_TSO_MANGLEID |
			 NETIF_F_GSO_UDP_TUNNEL |
			 NETIF_F_GSO_UDP_TUNNEL_CSUM |
			 NETIF_F_GSO_GRE |
			 NETIF_F_GSO_GRE_CSUM |
			 NETIF_F_GSO_IPXIP4 |
			 NETIF_F_GSO_IPXIP6 |
			 NETIF_F_NTUPLE |
			 NETIF_F_HW_VLAN_CTAG_TX |
			 NETIF_F_HW_VLAN_CTAG_RX |
			 NETIF_F_HW_VLAN_STAG_TX |
			 NETIF_F_HW_VLAN_STAG_RX |
			 NETIF_F_HW_VLAN_CTAG_FILTER |
			 NETIF_F_HW_VLAN_STAG_FILTER;
	dev->hw_features |= NETIF_F_HW_TC |
			    NETIF_F_SG |
			    NETIF_F_FRAGLIST |
			    NETIF_F_HW_CSUM |
			    NETIF_F_RXCSUM |
			    NETIF_F_RXHASH |
			    NETIF_F_LRO |
			    NETIF_F_GRO_HW |
			    NETIF_F_GRO_FRAGLIST |
			    NETIF_F_GSO_SOFTWARE |
			    NETIF_F_GSO_ROBUST |
			    NETIF_F_GSO_PARTIAL |
			    NETIF_F_TSO_MANGLEID |
			    NETIF_F_GSO_UDP_TUNNEL |
			    NETIF_F_GSO_UDP_TUNNEL_CSUM |
			    NETIF_F_GSO_GRE |
			    NETIF_F_GSO_GRE_CSUM |
			    NETIF_F_GSO_IPXIP4 |
			    NETIF_F_GSO_IPXIP6 |
			    NETIF_F_LOOPBACK |
			    NETIF_F_NTUPLE |
			    NETIF_F_HW_VLAN_CTAG_TX |
			    NETIF_F_HW_VLAN_CTAG_RX |
			    NETIF_F_HW_VLAN_STAG_TX |
			    NETIF_F_HW_VLAN_STAG_RX |
			    NETIF_F_HW_VLAN_CTAG_FILTER |
			    NETIF_F_HW_VLAN_STAG_FILTER;
	dev->vlan_features |= dev->features &
			      ~(NETIF_F_HW_VLAN_CTAG_TX |
				NETIF_F_HW_VLAN_CTAG_RX |
				NETIF_F_HW_VLAN_STAG_TX |
				NETIF_F_HW_VLAN_STAG_RX |
				NETIF_F_HW_VLAN_CTAG_FILTER |
				NETIF_F_HW_VLAN_STAG_FILTER);
	dev->hw_enc_features |= dev->features;
	dev->gso_partial_features |= NETIF_F_GSO_GRE |
				     NETIF_F_GSO_GRE_CSUM |
				     NETIF_F_GSO_IPXIP4 |
				     NETIF_F_GSO_IPXIP6 |
				     NETIF_F_GSO_UDP_TUNNEL |
				     NETIF_F_GSO_UDP_TUNNEL_CSUM;
	dev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	dev->max_mtu = ETH_MAX_MTU;
	netif_set_tso_max_size(dev, 262144);
	dev->xdp_features = NETDEV_XDP_ACT_BASIC |
			    NETDEV_XDP_ACT_REDIRECT |
			    NETDEV_XDP_ACT_NDO_XMIT |
			    NETDEV_XDP_ACT_XSK_ZEROCOPY |
			    NETDEV_XDP_ACT_RX_SG |
			    NETDEV_XDP_ACT_NDO_XMIT_SG |
			    NETDEV_XDP_ACT_HW_OFFLOAD;
	dev->xdp_zc_max_segs = MAX_SKB_FRAGS;
	dev->xdp_metadata_ops = &nsim_xdp_metadata_ops;
}

static int nsim_queue_init(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	int i;

	ns->rq = kcalloc(dev->num_rx_queues, sizeof(*ns->rq),
			 GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!ns->rq)
		return -ENOMEM;

	ns->txq = kcalloc(dev->num_tx_queues, sizeof(*ns->txq),
			  GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!ns->txq) {
		kfree(ns->rq);
		return -ENOMEM;
	}

	for (i = 0; i < dev->num_rx_queues; i++) {
		ns->rq[i] = nsim_queue_alloc(dev);
		if (!ns->rq[i])
			goto err_free_prev;
	}

	return 0;

err_free_prev:
	while (i--)
		nsim_queue_free(dev, ns->rq[i]);
	kfree(ns->txq);
	kfree(ns->rq);
	return -ENOMEM;
}

static void nsim_queue_uninit(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	int i;

	for (i = 0; i < dev->num_rx_queues; i++)
		nsim_queue_free(dev, ns->rq[i]);

	kfree(ns->txq);
	kfree(ns->rq);
	ns->rq = NULL;
	ns->txq = NULL;
}

static int nsim_init_netdevsim(struct netdevsim *ns)
{
	struct mock_phc *phc;
	int err;

	phc = mock_phc_create(&ns->nsim_bus_dev->dev);
	if (IS_ERR(phc))
		return PTR_ERR(phc);

	ns->phc = phc;
	ns->netdev->netdev_ops = &nsim_netdev_ops;
	ns->netdev->stat_ops = &nsim_stat_ops;
	ns->netdev->queue_mgmt_ops = &nsim_queue_mgmt_ops;
	ns->netdev->max_mtu = ETH_MAX_MTU;
	if (ns->nsim_bus_dev->dev.dma_mask)
		ns->netdev->netmem_tx = NETMEM_TX_DMA;
	netdev_lockdep_set_classes(ns->netdev);

	err = nsim_udp_tunnels_info_create(ns->nsim_dev, ns->netdev);
	if (err)
		goto err_phc_destroy;

	rtnl_lock();
	err = nsim_bpf_init(ns);
	if (err)
		goto err_utn_destroy;

	nsim_macsec_init(ns);
	nsim_ipsec_init(ns);

	err = register_netdevice(ns->netdev);
	if (err)
		goto err_ipsec_teardown;
	rtnl_unlock();

	err = nsim_psp_init(ns);
	if (err)
		goto err_unreg_netdev;

	return 0;

err_unreg_netdev:
	unregister_netdev(ns->netdev);
	rtnl_lock();
err_ipsec_teardown:
	nsim_ipsec_teardown(ns);
	nsim_macsec_teardown(ns);
	nsim_bpf_uninit(ns);
err_utn_destroy:
	rtnl_unlock();
	nsim_udp_tunnels_info_destroy(ns->netdev);
err_phc_destroy:
	mock_phc_destroy(ns->phc);
	return err;
}

static int nsim_init_netdevsim_vf(struct netdevsim *ns)
{
	int err;

	ns->netdev->netdev_ops = &nsim_vf_netdev_ops;
	ns->netdev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;
	rtnl_lock();
	err = register_netdevice(ns->netdev);
	rtnl_unlock();
	return err;
}

struct netdevsim *
nsim_create(struct nsim_dev *nsim_dev, struct nsim_dev_port *nsim_dev_port,
	    u8 perm_addr[ETH_ALEN])
{
	const char *ifname = (nsim_dev_port && nsim_dev_port->ifname[0]) ?
			     nsim_dev_port->ifname : "eth%d";
	unsigned char name_assign_type =
		(nsim_dev_port && nsim_dev_port->ifname[0]) ?
		NET_NAME_PREDICTABLE : NET_NAME_UNKNOWN;
	struct net_device *dev;
	struct netdevsim *ns;
	int err;

	dev = alloc_netdev_mq(sizeof(*ns), ifname, name_assign_type, nsim_setup,
			      nsim_dev->nsim_bus_dev->num_queues);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	if (perm_addr) {
		memcpy(dev->perm_addr, perm_addr, ETH_ALEN);
		eth_hw_addr_set(dev, perm_addr);
	}

	dev_net_set(dev, nsim_dev_net(nsim_dev));
	ns = netdev_priv(dev);
	ns->netdev = dev;
	u64_stats_init(&ns->syncp);
	spin_lock_init(&ns->stats_lock);
	ns->nsim_dev = nsim_dev;
	ns->nsim_dev_port = nsim_dev_port;
	ns->nsim_bus_dev = nsim_dev->nsim_bus_dev;
	SET_NETDEV_DEV(dev, &ns->nsim_bus_dev->dev);
	SET_NETDEV_DEVLINK_PORT(dev, &nsim_dev_port->devlink_port);
	nsim_ethtool_init(ns);
	if (nsim_dev_port_is_pf(nsim_dev_port)) {
		err = nsim_queue_init(ns);
		if (err)
			goto err_ethtool_fini;
		err = nsim_init_netdevsim(ns);
		if (err)
			goto err_queue_uninit;
	} else {
		err = nsim_init_netdevsim_vf(ns);
		if (err)
			goto err_ethtool_fini;
	}

	ns->pp_dfs = debugfs_create_file("pp_hold", 0600, nsim_dev_port->ddir,
					 ns, &nsim_pp_hold_fops);
	ns->qr_dfs = debugfs_create_file("queue_reset", 0200,
					 nsim_dev_port->ddir, ns,
					 &nsim_qreset_fops);
	ns->vlan_dfs = debugfs_create_file("vlan", 0400, nsim_dev_port->ddir,
					   ns, &nsim_vlan_fops);
	ns->rq_reset_mode = 0;
	debugfs_create_u32("rq_reset_mode", 0600, ns->nsim_dev_port->ddir,
			   &ns->rq_reset_mode);

	return ns;

err_queue_uninit:
	nsim_queue_uninit(ns);
err_ethtool_fini:
	nsim_ethtool_fini(ns);
	free_netdev(dev);
	return ERR_PTR(err);
}

void nsim_destroy(struct netdevsim *ns)
{
	struct net_device *dev = ns->netdev;
	struct netdevsim *peer;
	u16 vid;

	debugfs_remove(ns->vlan_dfs);
	debugfs_remove(ns->qr_dfs);
	debugfs_remove(ns->pp_dfs);
	nsim_ethtool_fini(ns);

	if (nsim_dev_port_is_pf(ns->nsim_dev_port))
		nsim_psp_uninit(ns);

	rtnl_lock();
	peer = rtnl_dereference(ns->peer);
	if (peer) {
		RCU_INIT_POINTER(peer->peer, NULL);
		RCU_INIT_POINTER(ns->peer, NULL);
		nsim_update_carrier(peer);
	}
	unregister_netdevice(dev);
	if (nsim_dev_port_is_pf(ns->nsim_dev_port)) {
		nsim_ipsec_teardown(ns);
		nsim_macsec_teardown(ns);
		nsim_bpf_uninit(ns);
		nsim_queue_uninit(ns);
	}
	rtnl_unlock();
	if (nsim_dev_port_is_pf(ns->nsim_dev_port)) {
		nsim_udp_tunnels_info_destroy(dev);
		mock_phc_destroy(ns->phc);
	}

	for_each_set_bit(vid, ns->vlan.ctag, VLAN_N_VID)
		WARN_ON_ONCE(1);
	for_each_set_bit(vid, ns->vlan.stag, VLAN_N_VID)
		WARN_ON_ONCE(1);

	/* Put this intentionally late to exercise the orphaning path */
	if (ns->page) {
		page_pool_put_full_page(pp_page_to_nmdesc(ns->page)->pp,
					ns->page, false);
		ns->page = NULL;
	}

	free_netdev(dev);
}

bool netdev_is_nsim(struct net_device *dev)
{
	return dev->netdev_ops == &nsim_netdev_ops;
}

static int nsim_validate(struct nlattr *tb[], struct nlattr *data[],
			 struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG_MOD(extack,
			   "Please use: echo \"[ID] [PORT_COUNT] [NUM_QUEUES]\" > /sys/bus/netdevsim/new_device");
	return -EOPNOTSUPP;
}

static struct rtnl_link_ops nsim_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.validate	= nsim_validate,
};

static int __init nsim_module_init(void)
{
	int err;

	err = nsim_dev_init();
	if (err)
		return err;

	err = nsim_bus_init();
	if (err)
		goto err_dev_exit;

	err = rtnl_link_register(&nsim_link_ops);
	if (err)
		goto err_bus_exit;

	return 0;

err_bus_exit:
	nsim_bus_exit();
err_dev_exit:
	nsim_dev_exit();
	return err;
}

static void __exit nsim_module_exit(void)
{
	rtnl_link_unregister(&nsim_link_ops);
	nsim_bus_exit();
	nsim_dev_exit();
}

module_init(nsim_module_init);
module_exit(nsim_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simulated networking device for testing");
MODULE_ALIAS_RTNL_LINK(DRV_NAME);
