// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/debugfs.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/random.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ipv6.h>
#include <net/netdev_queues.h>

#include "netdevsim.h"

static void
nsim_get_pause_stats(struct net_device *dev,
		     struct ethtool_pause_stats *pause_stats)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->ethtool.pauseparam.report_stats_rx)
		pause_stats->rx_pause_frames = 1;
	if (ns->ethtool.pauseparam.report_stats_tx)
		pause_stats->tx_pause_frames = 2;
}

static void
nsim_get_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	pause->autoneg = 0; /* We don't support ksettings, so can't pretend */
	pause->rx_pause = ns->ethtool.pauseparam.rx;
	pause->tx_pause = ns->ethtool.pauseparam.tx;
}

static int
nsim_set_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (pause->autoneg)
		return -EINVAL;

	ns->ethtool.pauseparam.rx = pause->rx_pause;
	ns->ethtool.pauseparam.tx = pause->tx_pause;
	return 0;
}

static int nsim_get_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(coal, &ns->ethtool.coalesce, sizeof(ns->ethtool.coalesce));
	return 0;
}

static int nsim_set_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal,
			     struct kernel_ethtool_coalesce *kernel_coal,
			     struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(&ns->ethtool.coalesce, coal, sizeof(ns->ethtool.coalesce));
	return 0;
}

static void nsim_get_ringparam(struct net_device *dev,
			       struct ethtool_ringparam *ring,
			       struct kernel_ethtool_ringparam *kernel_ring,
			       struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	memcpy(ring, &ns->ethtool.ring, sizeof(ns->ethtool.ring));
	kernel_ring->hds_thresh_max = NSIM_HDS_THRESHOLD_MAX;

	if (dev->cfg->hds_config == ETHTOOL_TCP_DATA_SPLIT_UNKNOWN)
		kernel_ring->tcp_data_split = ETHTOOL_TCP_DATA_SPLIT_ENABLED;
}

static int nsim_set_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *ring,
			      struct kernel_ethtool_ringparam *kernel_ring,
			      struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	ns->ethtool.ring.rx_pending = ring->rx_pending;
	ns->ethtool.ring.rx_jumbo_pending = ring->rx_jumbo_pending;
	ns->ethtool.ring.rx_mini_pending = ring->rx_mini_pending;
	ns->ethtool.ring.tx_pending = ring->tx_pending;
	return 0;
}

static void
nsim_get_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct netdevsim *ns = netdev_priv(dev);

	ch->max_combined = ns->nsim_bus_dev->num_queues;
	ch->combined_count = ns->ethtool.channels;
}

static void
nsim_wake_queues(struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;

	synchronize_net();
	netif_tx_wake_all_queues(dev);

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	if (peer)
		netif_tx_wake_all_queues(peer->netdev);
	rcu_read_unlock();
}

static int
nsim_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct netdevsim *ns = netdev_priv(dev);
	int err;

	err = netif_set_real_num_queues(dev, ch->combined_count,
					ch->combined_count);
	if (err)
		return err;

	ns->ethtool.channels = ch->combined_count;
	if (!ns->ethtool.rss_indir_configured) {
		u32 i;

		for (i = 0; i < NSIM_RSS_INDIR_SIZE; i++)
			ns->ethtool.rss_indir[i] =
				ethtool_rxfh_indir_default(i, ch->combined_count);
	}

	/* Only wake up queues if devices are linked */
	if (rcu_access_pointer(ns->peer))
		nsim_wake_queues(dev);

	return 0;
}

static int
nsim_get_fecparam(struct net_device *dev, struct ethtool_fecparam *fecparam)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (ns->ethtool.get_err)
		return -ns->ethtool.get_err;
	memcpy(fecparam, &ns->ethtool.fec, sizeof(ns->ethtool.fec));
	return 0;
}

static int
nsim_set_fecparam(struct net_device *dev, struct ethtool_fecparam *fecparam)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 fec;

	if (ns->ethtool.set_err)
		return -ns->ethtool.set_err;
	memcpy(&ns->ethtool.fec, fecparam, sizeof(ns->ethtool.fec));
	fec = fecparam->fec;
	if (fec == ETHTOOL_FEC_AUTO)
		fec |= ETHTOOL_FEC_OFF;
	fec |= ETHTOOL_FEC_NONE;
	ns->ethtool.fec.active_fec = 1 << (fls(fec) - 1);
	return 0;
}

static const struct ethtool_fec_hist_range netdevsim_fec_ranges[] = {
	{ 0, 0},
	{ 1, 3},
	{ 4, 7},
	{ 0, 0}
};

static void
nsim_get_fec_stats(struct net_device *dev, struct ethtool_fec_stats *fec_stats,
		   struct ethtool_fec_hist *hist)
{
	struct ethtool_fec_hist_value *values = hist->values;

	hist->ranges = netdevsim_fec_ranges;

	fec_stats->corrected_blocks.total = 123;
	fec_stats->uncorrectable_blocks.total = 4;

	values[0].per_lane[0] = 125;
	values[0].per_lane[1] = 120;
	values[0].per_lane[2] = 100;
	values[0].per_lane[3] = 100;
	values[1].sum = 12;
	values[2].sum = 2;
	values[2].per_lane[0] = 2;
	values[2].per_lane[1] = 0;
	values[2].per_lane[2] = 0;
	values[2].per_lane[3] = 0;
}

static int nsim_get_ts_info(struct net_device *dev,
			    struct kernel_ethtool_ts_info *info)
{
	struct netdevsim *ns = netdev_priv(dev);

	info->phc_index = mock_phc_index(ns->phc);

	return 0;
}

static u32 nsim_get_rxfh_key_size(struct net_device *dev)
{
	return NETDEV_RSS_KEY_LEN;
}

static u32 nsim_get_rxfh_indir_size(struct net_device *dev)
{
	return NSIM_RSS_INDIR_SIZE;
}

static int nsim_get_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh)
{
	struct netdevsim *ns = netdev_priv(dev);

	rxfh->hfunc = ETH_RSS_HASH_TOP;
	if (rxfh->indir)
		memcpy(rxfh->indir, ns->ethtool.rss_indir,
		       sizeof(ns->ethtool.rss_indir));
	if (rxfh->key)
		memcpy(rxfh->key, ns->ethtool.rss_key,
		       sizeof(ns->ethtool.rss_key));

	return 0;
}

static int nsim_set_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh,
			 struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 i;

	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (rxfh->indir) {
		for (i = 0; i < NSIM_RSS_INDIR_SIZE; i++) {
			if (rxfh->indir[i] >= dev->num_rx_queues)
				return -EINVAL;
		}
		memcpy(ns->ethtool.rss_indir, rxfh->indir,
		       sizeof(ns->ethtool.rss_indir));
		ns->ethtool.rss_indir_configured = true;
	}

	if (rxfh->key)
		memcpy(ns->ethtool.rss_key, rxfh->key,
		       sizeof(ns->ethtool.rss_key));

	return 0;
}

static u32 nsim_get_rx_ring_count(struct net_device *dev)
{
	return dev->num_rx_queues;
}

static int nsim_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd,
			  u32 *rule_locs)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 i, cnt = 0;

	switch (cmd->cmd) {
	case ETHTOOL_GRXCLSRLCNT:
		for (i = 0; i < NSIM_MAX_NTUPLE_RULES; i++) {
			if (ns->ethtool.ntuple_rules[i].used)
				cnt++;
		}
		cmd->rule_cnt = cnt;
		cmd->data = NSIM_MAX_NTUPLE_RULES | RX_CLS_LOC_SPECIAL;
		return 0;
	case ETHTOOL_GRXCLSRULE:
		if (cmd->fs.location >= NSIM_MAX_NTUPLE_RULES ||
		    !ns->ethtool.ntuple_rules[cmd->fs.location].used)
			return -ENOENT;
		cmd->fs = ns->ethtool.ntuple_rules[cmd->fs.location].fs;
		return 0;
	case ETHTOOL_GRXCLSRLALL:
		for (i = 0; i < NSIM_MAX_NTUPLE_RULES; i++) {
			if (!ns->ethtool.ntuple_rules[i].used)
				continue;
			if (cnt >= cmd->rule_cnt)
				return -EMSGSIZE;
			rule_locs[cnt++] = i;
		}
		cmd->rule_cnt = cnt;
		cmd->data = NSIM_MAX_NTUPLE_RULES;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int nsim_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	u32 loc;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		if (fs->ring_cookie != RX_CLS_FLOW_DISC &&
		    ethtool_get_flow_spec_ring(fs->ring_cookie) >=
		    dev->num_rx_queues)
			return -EINVAL;

		if (fs->location == RX_CLS_LOC_ANY ||
		    fs->location == RX_CLS_LOC_FIRST ||
		    fs->location == RX_CLS_LOC_LAST) {
			for (loc = 0; loc < NSIM_MAX_NTUPLE_RULES; loc++) {
				if (!ns->ethtool.ntuple_rules[loc].used)
					break;
			}
			if (loc == NSIM_MAX_NTUPLE_RULES)
				return -ENOSPC;
			fs->location = loc;
		} else {
			loc = fs->location;
			if (loc >= NSIM_MAX_NTUPLE_RULES)
				return -EINVAL;
		}

		ns->ethtool.ntuple_rules[loc].fs = *fs;
		ns->ethtool.ntuple_rules[loc].used = true;
		return 0;
	case ETHTOOL_SRXCLSRLDEL:
		if (fs->location >= NSIM_MAX_NTUPLE_RULES ||
		    !ns->ethtool.ntuple_rules[fs->location].used)
			return -ENOENT;
		ns->ethtool.ntuple_rules[fs->location].used = false;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static bool nsim_ntuple_match(const struct ethtool_rx_flow_spec *fs,
			      struct sk_buff *skb)
{
	u32 flow_type = fs->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
	__be16 proto = skb->protocol;
	unsigned int off = ETH_HLEN;

	if (eth_type_vlan(proto)) {
		struct vlan_hdr vhdr, *vp;

		vp = skb_header_pointer(skb, off, sizeof(vhdr), &vhdr);
		if (!vp)
			return false;
		proto = vp->h_vlan_encapsulated_proto;
		off += sizeof(vhdr);
	}

	if (proto == htons(ETH_P_IP)) {
		struct iphdr iph_buf, *iph;
		__be16 ports[2], *pptr;

		iph = skb_header_pointer(skb, off, sizeof(iph_buf), &iph_buf);
		if (!iph)
			return false;

		if (flow_type == TCP_V4_FLOW && iph->protocol != IPPROTO_TCP)
			return false;
		if (flow_type == UDP_V4_FLOW && iph->protocol != IPPROTO_UDP)
			return false;
		if (flow_type != TCP_V4_FLOW && flow_type != UDP_V4_FLOW)
			return false;

		if ((iph->saddr & fs->m_u.tcp_ip4_spec.ip4src) !=
		    (fs->h_u.tcp_ip4_spec.ip4src & fs->m_u.tcp_ip4_spec.ip4src))
			return false;
		if ((iph->daddr & fs->m_u.tcp_ip4_spec.ip4dst) !=
		    (fs->h_u.tcp_ip4_spec.ip4dst & fs->m_u.tcp_ip4_spec.ip4dst))
			return false;

		pptr = skb_header_pointer(skb, off + iph->ihl * 4,
					  sizeof(ports), ports);
		if (!pptr)
			return false;
		if ((pptr[0] & fs->m_u.tcp_ip4_spec.psrc) !=
		    (fs->h_u.tcp_ip4_spec.psrc & fs->m_u.tcp_ip4_spec.psrc))
			return false;
		if ((pptr[1] & fs->m_u.tcp_ip4_spec.pdst) !=
		    (fs->h_u.tcp_ip4_spec.pdst & fs->m_u.tcp_ip4_spec.pdst))
			return false;

		return true;
	}

	if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6h_buf, *ip6h;
		__be16 ports[2], *pptr;
		__be16 frag_off;
		u8 nexthdr;
		int l4_off;
		int i;

		ip6h = skb_header_pointer(skb, off, sizeof(ip6h_buf),
					  &ip6h_buf);
		if (!ip6h)
			return false;

		nexthdr = ip6h->nexthdr;
		l4_off = ipv6_skip_exthdr(skb, off + sizeof(*ip6h),
					  &nexthdr, &frag_off);
		if (l4_off < 0)
			return false;

		if (flow_type == TCP_V6_FLOW && nexthdr != IPPROTO_TCP)
			return false;
		if (flow_type == UDP_V6_FLOW && nexthdr != IPPROTO_UDP)
			return false;
		if (flow_type != TCP_V6_FLOW && flow_type != UDP_V6_FLOW)
			return false;

		for (i = 0; i < 4; i++) {
			if ((ip6h->saddr.s6_addr32[i] &
			     fs->m_u.tcp_ip6_spec.ip6src[i]) !=
			    (fs->h_u.tcp_ip6_spec.ip6src[i] &
			     fs->m_u.tcp_ip6_spec.ip6src[i]))
				return false;
			if ((ip6h->daddr.s6_addr32[i] &
			     fs->m_u.tcp_ip6_spec.ip6dst[i]) !=
			    (fs->h_u.tcp_ip6_spec.ip6dst[i] &
			     fs->m_u.tcp_ip6_spec.ip6dst[i]))
				return false;
		}

		pptr = skb_header_pointer(skb, l4_off, sizeof(ports), ports);
		if (!pptr)
			return false;
		if ((pptr[0] & fs->m_u.tcp_ip6_spec.psrc) !=
		    (fs->h_u.tcp_ip6_spec.psrc & fs->m_u.tcp_ip6_spec.psrc))
			return false;
		if ((pptr[1] & fs->m_u.tcp_ip6_spec.pdst) !=
		    (fs->h_u.tcp_ip6_spec.pdst & fs->m_u.tcp_ip6_spec.pdst))
			return false;

		return true;
	}

	return false;
}

int nsim_select_rxq(struct netdevsim *ns, struct sk_buff *skb)
{
	struct net_device *dev = ns->netdev;
	int i;

	for (i = 0; i < NSIM_MAX_NTUPLE_RULES; i++) {
		if (!ns->ethtool.ntuple_rules[i].used)
			continue;
		if (nsim_ntuple_match(&ns->ethtool.ntuple_rules[i].fs, skb)) {
			u64 cookie = ns->ethtool.ntuple_rules[i].fs.ring_cookie;

			if (cookie == RX_CLS_FLOW_DISC)
				return -1;
			return ethtool_get_flow_spec_ring(cookie) %
			       dev->num_rx_queues;
		}
	}

	if (ns->ethtool.rss_indir_configured) {
		u32 hash = skb_frags_readable(skb) ?
			   skb_get_hash(skb) : skb_get_queue_mapping(skb);

		return ns->ethtool.rss_indir[hash % NSIM_RSS_INDIR_SIZE] %
		       dev->num_rx_queues;
	}

	return skb_get_queue_mapping(skb) % dev->num_rx_queues;
}

static int nsim_get_rxfh_fields(struct net_device *dev,
				struct ethtool_rxfh_fields *info)
{
	switch (info->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
		info->data = RXH_IP_SRC | RXH_IP_DST |
			     RXH_L4_B_0_1 | RXH_L4_B_2_3;
		return 0;
	case IPV4_FLOW:
	case IPV6_FLOW:
		info->data = RXH_IP_SRC | RXH_IP_DST;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops nsim_ethtool_ops = {
	.get_rx_ring_count		= nsim_get_rx_ring_count,
	.get_rxnfc			= nsim_get_rxnfc,
	.set_rxnfc			= nsim_set_rxnfc,
	.get_rxfh_key_size		= nsim_get_rxfh_key_size,
	.get_rxfh_indir_size		= nsim_get_rxfh_indir_size,
	.get_rxfh			= nsim_get_rxfh,
	.set_rxfh			= nsim_set_rxfh,
	.get_rxfh_fields		= nsim_get_rxfh_fields,
	.supported_coalesce_params	= ETHTOOL_COALESCE_ALL_PARAMS,
	.supported_ring_params		= ETHTOOL_RING_USE_TCP_DATA_SPLIT |
					  ETHTOOL_RING_USE_HDS_THRS,
	.op_needs_rtnl			= ETHTOOL_OP_NEEDS_RTNL_SCHANNELS,
	.get_pause_stats	        = nsim_get_pause_stats,
	.get_pauseparam		        = nsim_get_pauseparam,
	.set_pauseparam		        = nsim_set_pauseparam,
	.set_coalesce			= nsim_set_coalesce,
	.get_coalesce			= nsim_get_coalesce,
	.get_ringparam			= nsim_get_ringparam,
	.set_ringparam			= nsim_set_ringparam,
	.get_channels			= nsim_get_channels,
	.set_channels			= nsim_set_channels,
	.get_fecparam			= nsim_get_fecparam,
	.set_fecparam			= nsim_set_fecparam,
	.get_fec_stats			= nsim_get_fec_stats,
	.get_ts_info			= nsim_get_ts_info,
};

static void nsim_ethtool_ring_init(struct netdevsim *ns)
{
	ns->ethtool.ring.rx_pending = 512;
	ns->ethtool.ring.rx_max_pending = 4096;
	ns->ethtool.ring.rx_jumbo_max_pending = 4096;
	ns->ethtool.ring.rx_mini_max_pending = 4096;
	ns->ethtool.ring.tx_pending = 512;
	ns->ethtool.ring.tx_max_pending = 4096;
}

void nsim_ethtool_init(struct netdevsim *ns)
{
	struct dentry *ethtool, *dir;

	ns->netdev->ethtool_ops = &nsim_ethtool_ops;

	nsim_ethtool_ring_init(ns);

	ns->ethtool.pauseparam.report_stats_rx = true;
	ns->ethtool.pauseparam.report_stats_tx = true;

	ns->ethtool.fec.fec = ETHTOOL_FEC_NONE;
	ns->ethtool.fec.active_fec = ETHTOOL_FEC_NONE;

	ns->ethtool.channels = ns->nsim_bus_dev->num_queues;
	netdev_rss_key_fill(ns->ethtool.rss_key, sizeof(ns->ethtool.rss_key));
	for (u32 i = 0; i < NSIM_RSS_INDIR_SIZE; i++)
		ns->ethtool.rss_indir[i] =
			ethtool_rxfh_indir_default(i, ns->ethtool.channels);

	ethtool = debugfs_create_dir("ethtool", ns->nsim_dev_port->ddir);
	ns->ethtool_ddir = ethtool;

	debugfs_create_u32("get_err", 0600, ethtool, &ns->ethtool.get_err);
	debugfs_create_u32("set_err", 0600, ethtool, &ns->ethtool.set_err);

	dir = debugfs_create_dir("pause", ethtool);
	debugfs_create_bool("report_stats_rx", 0600, dir,
			    &ns->ethtool.pauseparam.report_stats_rx);
	debugfs_create_bool("report_stats_tx", 0600, dir,
			    &ns->ethtool.pauseparam.report_stats_tx);

	dir = debugfs_create_dir("ring", ethtool);
	debugfs_create_u32("rx_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_max_pending);
	debugfs_create_u32("rx_jumbo_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_jumbo_max_pending);
	debugfs_create_u32("rx_mini_max_pending", 0600, dir,
			   &ns->ethtool.ring.rx_mini_max_pending);
	debugfs_create_u32("tx_max_pending", 0600, dir,
			   &ns->ethtool.ring.tx_max_pending);
}

void nsim_ethtool_fini(struct netdevsim *ns)
{
	debugfs_remove(ns->ethtool_ddir);
}
