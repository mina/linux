// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/debugfs.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/linkmode.h>
#include <linux/random.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ipv6.h>
#include <net/netdev_queues.h>

#include "netdevsim.h"

static const struct ethtool_rmon_hist_range nsim_rmon_ranges[NSIM_RMON_BUCKETS + 1] = {
	{    1,    64 },
	{   65,   127 },
	{  128,   255 },
	{  256,   511 },
	{  512,  1023 },
	{ 1024, 65535 },
	{}
};

void nsim_mac_record_frame(struct netdevsim *ns, const struct sk_buff *skb,
			   unsigned int wire_len, int tc, bool is_tx)
{
	const struct ethhdr *eth = (const struct ethhdr *)skb->data;
	int src_idx = 0;
	struct nsim_mac_stats *ms;
	unsigned long flags;
	bool is_bcast = false;
	bool is_mcast = false;
	bool is_ctrl = false;
	bool is_pause = false;
	int i;

	if (tc >= 0 && (ns->preemptible_tcs & BIT(tc))) {
		if (is_tx) {
			if (ns->ethtool.mmsv.tx_enabled &&
			    (ns->ethtool.mmsv.status ==
			     ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED ||
			     ns->ethtool.mmsv.status ==
			     ETHTOOL_MM_VERIFY_STATUS_DISABLED))
				src_idx = 1;
		} else if (ns->ethtool.mmsv.pmac_enabled) {
			src_idx = 1;
		}
	}

	if (skb->len >= ETH_HLEN) {
		if (is_broadcast_ether_addr(eth->h_dest))
			is_bcast = true;
		else if (is_multicast_ether_addr(eth->h_dest))
			is_mcast = true;

		if (eth->h_proto == htons(ETH_P_PAUSE)) {
			is_ctrl = true;
			if (skb->len >= ETH_HLEN + 2 &&
			    *(__be16 *)(skb->data + ETH_HLEN) == htons(0x0001))
				is_pause = true;
		}
	}

	spin_lock_irqsave(&ns->stats_lock, flags);
	wire_len += ETH_FCS_LEN;
	ms = &ns->mac_stats[src_idx];
	if (is_tx) {
		ms->tx_frames++;
		ms->tx_octets += wire_len;
		if (is_bcast)
			ms->tx_bcast++;
		else if (is_mcast)
			ms->tx_mcast++;
		if (is_ctrl)
			ms->tx_ctrl++;
		if (is_pause)
			ms->tx_pause++;
		for (i = 0; i < NSIM_RMON_BUCKETS; i++) {
			if (wire_len >= nsim_rmon_ranges[i].low &&
			    wire_len <= nsim_rmon_ranges[i].high) {
				ms->rmon_tx[i]++;
				break;
			}
		}
	} else {
		ms->rx_frames++;
		ms->rx_octets += wire_len;
		if (is_bcast)
			ms->rx_bcast++;
		else if (is_mcast)
			ms->rx_mcast++;
		if (is_ctrl)
			ms->rx_ctrl++;
		if (is_pause)
			ms->rx_pause++;
		for (i = 0; i < NSIM_RMON_BUCKETS; i++) {
			if (wire_len >= nsim_rmon_ranges[i].low &&
			    wire_len <= nsim_rmon_ranges[i].high) {
				ms->rmon_rx[i]++;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&ns->stats_lock, flags);
}

static void
nsim_get_pause_stats(struct net_device *dev,
		     struct ethtool_pause_stats *pause_stats)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_mac_stats *ms;
	unsigned long flags;
	int idx;

	switch (pause_stats->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		idx = 0;
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		idx = 1;
		break;
	case ETHTOOL_MAC_STATS_SRC_AGGREGATE:
		ethtool_aggregate_pause_stats(dev, pause_stats);
		return;
	default:
		return;
	}

	spin_lock_irqsave(&ns->stats_lock, flags);
	ms = &ns->mac_stats[idx];
	if (ns->ethtool.pauseparam.report_stats_rx)
		pause_stats->rx_pause_frames = ms->rx_pause + (idx == 0 ? 1 : 0);
	if (ns->ethtool.pauseparam.report_stats_tx)
		pause_stats->tx_pause_frames = ms->tx_pause + (idx == 0 ? 2 : 0);
	spin_unlock_irqrestore(&ns->stats_lock, flags);
}

static void
nsim_get_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	pause->autoneg = ns->ethtool.pauseparam.autoneg;
	pause->rx_pause = ns->ethtool.pauseparam.rx;
	pause->tx_pause = ns->ethtool.pauseparam.tx;
}

static void nsim_trigger_aneg(struct netdevsim *ns);

static int
nsim_set_pauseparam(struct net_device *dev, struct ethtool_pauseparam *pause)
{
	struct netdevsim *ns = netdev_priv(dev);

	ns->ethtool.pauseparam.autoneg = pause->autoneg;
	ns->ethtool.pauseparam.rx = pause->rx_pause;
	ns->ethtool.pauseparam.tx = pause->tx_pause;

	if (pause->rx_pause && pause->tx_pause) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				 ns->ethtool.advertising);
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				   ns->ethtool.advertising);
	} else if (pause->rx_pause) {
		linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				 ns->ethtool.advertising);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				 ns->ethtool.advertising);
	} else if (pause->tx_pause) {
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				   ns->ethtool.advertising);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				 ns->ethtool.advertising);
	} else {
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Pause_BIT,
				   ns->ethtool.advertising);
		linkmode_clear_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT,
				   ns->ethtool.advertising);
	}

	if (ns->ethtool.autoneg && pause->autoneg)
		nsim_trigger_aneg(ns);

	return 0;
}

static void nsim_get_eth_mac_stats(struct net_device *dev,
				   struct ethtool_eth_mac_stats *mac_stats)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_mac_stats *ms;
	unsigned long flags;
	int idx;

	switch (mac_stats->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		idx = 0;
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		idx = 1;
		break;
	case ETHTOOL_MAC_STATS_SRC_AGGREGATE:
		ethtool_aggregate_mac_stats(dev, mac_stats);
		return;
	default:
		return;
	}

	spin_lock_irqsave(&ns->stats_lock, flags);
	ms = &ns->mac_stats[idx];
	mac_stats->FramesTransmittedOK = ms->tx_frames;
	mac_stats->OctetsTransmittedOK = ms->tx_octets;
	mac_stats->MulticastFramesXmittedOK = ms->tx_mcast;
	mac_stats->BroadcastFramesXmittedOK = ms->tx_bcast;
	mac_stats->FramesReceivedOK = ms->rx_frames;
	mac_stats->OctetsReceivedOK = ms->rx_octets;
	mac_stats->MulticastFramesReceivedOK = ms->rx_mcast;
	mac_stats->BroadcastFramesReceivedOK = ms->rx_bcast;
	spin_unlock_irqrestore(&ns->stats_lock, flags);
}

static void nsim_get_eth_ctrl_stats(struct net_device *dev,
				    struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_mac_stats *ms;
	unsigned long flags;
	int idx;

	switch (ctrl_stats->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		idx = 0;
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		idx = 1;
		break;
	case ETHTOOL_MAC_STATS_SRC_AGGREGATE:
		ethtool_aggregate_ctrl_stats(dev, ctrl_stats);
		return;
	default:
		return;
	}

	spin_lock_irqsave(&ns->stats_lock, flags);
	ms = &ns->mac_stats[idx];
	ctrl_stats->MACControlFramesTransmitted = ms->tx_ctrl;
	ctrl_stats->MACControlFramesReceived = ms->rx_ctrl;
	spin_unlock_irqrestore(&ns->stats_lock, flags);
}

static void nsim_get_rmon_stats(struct net_device *dev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_mac_stats *ms;
	unsigned long flags;
	int idx, i;

	*ranges = nsim_rmon_ranges;

	switch (rmon_stats->src) {
	case ETHTOOL_MAC_STATS_SRC_EMAC:
		idx = 0;
		break;
	case ETHTOOL_MAC_STATS_SRC_PMAC:
		idx = 1;
		break;
	case ETHTOOL_MAC_STATS_SRC_AGGREGATE:
		ethtool_aggregate_rmon_stats(dev, rmon_stats);
		return;
	default:
		return;
	}

	spin_lock_irqsave(&ns->stats_lock, flags);
	ms = &ns->mac_stats[idx];
	rmon_stats->undersize_pkts = ms->rmon_undersize;
	rmon_stats->oversize_pkts = ms->rmon_oversize;
	for (i = 0; i < NSIM_RMON_BUCKETS; i++) {
		rmon_stats->hist[i] = ms->rmon_rx[i];
		rmon_stats->hist_tx[i] = ms->rmon_tx[i];
	}
	spin_unlock_irqrestore(&ns->stats_lock, flags);
}

struct nsim_speed_mode {
	enum ethtool_link_mode_bit_indices bit;
	u32 speed;
	u8 duplex;
};

static const struct nsim_speed_mode nsim_speed_modes[] = {
	{ ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT, SPEED_100000, DUPLEX_FULL },
	{ ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,  SPEED_50000,  DUPLEX_FULL },
	{ ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,   SPEED_25000,  DUPLEX_FULL },
};

static bool nsim_resolve_common_mode(struct netdevsim *a, struct netdevsim *b,
				     u32 *speed, u8 *duplex)
{
	int i;

	if (a->ethtool.autoneg && b->ethtool.autoneg) {
		for (i = 0; i < ARRAY_SIZE(nsim_speed_modes); i++) {
			int bit = nsim_speed_modes[i].bit;

			if (test_bit(bit, a->ethtool.advertising) &&
			    test_bit(bit, b->ethtool.advertising)) {
				if (speed)
					*speed = nsim_speed_modes[i].speed;
				if (duplex)
					*duplex = nsim_speed_modes[i].duplex;
				return true;
			}
		}
		return false;
	}

	if (!a->ethtool.autoneg && !b->ethtool.autoneg) {
		if (a->ethtool.speed == b->ethtool.speed &&
		    a->ethtool.duplex == b->ethtool.duplex) {
			if (speed)
				*speed = a->ethtool.speed;
			if (duplex)
				*duplex = a->ethtool.duplex;
			return true;
		}
		return false;
	}

	/* One side autoneg, one side forced */
	if (a->ethtool.autoneg) {
		for (i = 0; i < ARRAY_SIZE(nsim_speed_modes); i++) {
			if (nsim_speed_modes[i].speed == b->ethtool.speed &&
			    nsim_speed_modes[i].duplex == b->ethtool.duplex &&
			    test_bit(nsim_speed_modes[i].bit, a->ethtool.advertising)) {
				if (speed)
					*speed = b->ethtool.speed;
				if (duplex)
					*duplex = b->ethtool.duplex;
				return true;
			}
		}
		return false;
	}

	for (i = 0; i < ARRAY_SIZE(nsim_speed_modes); i++) {
		if (nsim_speed_modes[i].speed == a->ethtool.speed &&
		    nsim_speed_modes[i].duplex == a->ethtool.duplex &&
		    test_bit(nsim_speed_modes[i].bit, b->ethtool.advertising)) {
			if (speed)
				*speed = a->ethtool.speed;
			if (duplex)
				*duplex = a->ethtool.duplex;
			return true;
		}
	}
	return false;
}

bool nsim_link_can_up(struct netdevsim *a, struct netdevsim *b)
{
	if (!a || !b)
		return false;
	if (!netif_running(a->netdev) || !netif_running(b->netdev))
		return false;
	if (a->ethtool.aneg_in_progress || b->ethtool.aneg_in_progress)
		return false;
	return nsim_resolve_common_mode(a, b, NULL, NULL);
}

static void nsim_update_one_carrier(struct netdevsim *ns, struct netdevsim *peer)
{
	u32 speed;
	u8 duplex;

	if (!ns->require_link && !peer) {
		if (netif_running(ns->netdev))
			netif_carrier_on(ns->netdev);
		else
			netif_carrier_off(ns->netdev);
		return;
	}

	if (peer && netif_running(ns->netdev) && netif_running(peer->netdev) &&
	    !ns->ethtool.aneg_in_progress && !peer->ethtool.aneg_in_progress &&
	    nsim_resolve_common_mode(ns, peer, &speed, &duplex)) {
		ns->ethtool.speed = speed;
		ns->ethtool.duplex = duplex;
		netif_carrier_on(ns->netdev);
		ethtool_mmsv_link_state_handle(&ns->ethtool.mmsv, true);
	} else {
		ethtool_mmsv_link_state_handle(&ns->ethtool.mmsv, false);
		netif_carrier_off(ns->netdev);
	}
}

void nsim_update_carrier(struct netdevsim *ns)
{
	struct netdevsim *peer;

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	nsim_update_one_carrier(ns, peer);
	if (peer)
		nsim_update_one_carrier(peer, ns);
	rcu_read_unlock();
}

static void nsim_aneg_work_fn(struct work_struct *work)
{
	struct netdevsim *ns = container_of(work, struct netdevsim,
					    ethtool.aneg_work.work);

	ns->ethtool.aneg_in_progress = false;
	nsim_update_carrier(ns);
}

static void nsim_trigger_aneg(struct netdevsim *ns)
{
	struct netdevsim *peer;

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	if (!peer && !ns->require_link) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	ns->ethtool.aneg_in_progress = true;
	nsim_update_carrier(ns);
	mod_delayed_work(system_wq, &ns->ethtool.aneg_work,
			 msecs_to_jiffies(100));
}

static int nsim_get_link_ext_state(struct net_device *dev,
				   struct ethtool_link_ext_state_info *info)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;

	if (netif_carrier_ok(dev))
		return -ENODATA;

	if (!netif_running(dev)) {
		info->link_ext_state = ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH;
		return 0;
	}

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	if (!peer) {
		info->link_ext_state = ETHTOOL_LINK_EXT_STATE_NO_CABLE;
		rcu_read_unlock();
		return 0;
	}

	if (!netif_running(peer->netdev)) {
		info->link_ext_state = ETHTOOL_LINK_EXT_STATE_AUTONEG;
		info->__link_ext_substate =
			ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED;
		rcu_read_unlock();
		return 0;
	}

	if (ns->ethtool.aneg_in_progress || peer->ethtool.aneg_in_progress ||
	    !nsim_resolve_common_mode(ns, peer, NULL, NULL)) {
		info->link_ext_state = ETHTOOL_LINK_EXT_STATE_AUTONEG;
		if (!ns->ethtool.autoneg || !peer->ethtool.autoneg)
			info->__link_ext_substate =
				ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE;
		else
			info->__link_ext_substate =
				ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	info->link_ext_state = ETHTOOL_LINK_EXT_STATE_NO_CABLE;
	return 0;
}

static int nsim_get_link_ksettings(struct net_device *dev,
				   struct ethtool_link_ksettings *cmd)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct netdevsim *peer;

	linkmode_copy(cmd->link_modes.supported, ns->ethtool.supported);
	linkmode_copy(cmd->link_modes.advertising, ns->ethtool.advertising);
	linkmode_zero(cmd->link_modes.lp_advertising);

	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	if (peer && (dev->flags & IFF_UP) && (peer->netdev->flags & IFF_UP) &&
	    ns->ethtool.autoneg && peer->ethtool.autoneg)
		linkmode_copy(cmd->link_modes.lp_advertising,
			      peer->ethtool.advertising);
	rcu_read_unlock();

	cmd->base.autoneg = ns->ethtool.autoneg;
	cmd->base.port = PORT_TP;
	cmd->lanes = ns->nsim_dev_port->lanes ?: 4;

	if (netif_carrier_ok(dev)) {
		cmd->base.speed = ns->ethtool.speed;
		cmd->base.duplex = ns->ethtool.duplex;
	} else {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
	}

	return 0;
}

static int nsim_set_link_ksettings(struct net_device *dev,
				   const struct ethtool_link_ksettings *cmd)
{
	struct netdevsim *ns = netdev_priv(dev);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(adv);
	int i;

	if (cmd->base.autoneg == AUTONEG_ENABLE) {
		if (!linkmode_subset(cmd->link_modes.advertising,
				     ns->ethtool.supported))
			return -EINVAL;
		linkmode_copy(adv, cmd->link_modes.advertising);
		linkmode_copy(ns->ethtool.advertising, adv);
		linkmode_set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT,
				 ns->ethtool.advertising);
		ns->ethtool.autoneg = AUTONEG_ENABLE;
		nsim_trigger_aneg(ns);
	} else if (cmd->base.autoneg == AUTONEG_DISABLE) {
		u8 duplex = cmd->base.duplex == DUPLEX_UNKNOWN ?
			    DUPLEX_FULL : cmd->base.duplex;
		bool valid = false;

		for (i = 0; i < ARRAY_SIZE(nsim_speed_modes); i++) {
			if (nsim_speed_modes[i].speed == cmd->base.speed &&
			    nsim_speed_modes[i].duplex == duplex) {
				valid = true;
				break;
			}
		}
		if (!valid)
			return -EINVAL;

		ns->ethtool.autoneg = AUTONEG_DISABLE;
		ns->ethtool.speed = cmd->base.speed;
		ns->ethtool.duplex = duplex;
		cancel_delayed_work_sync(&ns->ethtool.aneg_work);
		ns->ethtool.aneg_in_progress = false;
		nsim_update_carrier(ns);
	} else {
		return -EINVAL;
	}

	return 0;
}

static int nsim_nway_reset(struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (!ns->ethtool.autoneg)
		return -EINVAL;

	nsim_trigger_aneg(ns);
	return 0;
}

static void nsim_mm_work_fn(struct work_struct *work)
{
	struct netdevsim *ns = container_of(work, struct netdevsim,
					    ethtool.mm_work);
	struct netdevsim *peer;
	int ev = xchg(&ns->ethtool.mm_pending_event, 0);

	local_bh_disable();
	if (ev & BIT(ETHTOOL_MPACKET_VERIFY))
		ethtool_mmsv_event_handle(&ns->ethtool.mmsv,
					  ETHTOOL_MMSV_LD_SENT_VERIFY_MPACKET);
	rcu_read_lock();
	peer = rcu_dereference(ns->peer);
	if (peer) {
		if (ev & BIT(ETHTOOL_MPACKET_VERIFY))
			ethtool_mmsv_event_handle(&peer->ethtool.mmsv,
						  ETHTOOL_MMSV_LP_SENT_VERIFY_MPACKET);
		if (ev & BIT(ETHTOOL_MPACKET_RESPONSE))
			ethtool_mmsv_event_handle(&peer->ethtool.mmsv,
						  ETHTOOL_MMSV_LP_SENT_RESPONSE_MPACKET);
	}
	rcu_read_unlock();
	local_bh_enable();
}

static void nsim_mm_configure_tx(struct ethtool_mmsv *mmsv, bool tx_active)
{
}

static void nsim_mm_configure_pmac(struct ethtool_mmsv *mmsv, bool pmac_enabled)
{
}

static void nsim_mm_send_mpacket(struct ethtool_mmsv *mmsv,
				 enum ethtool_mpacket mpacket)
{
	struct netdevsim *ns = container_of(mmsv, struct netdevsim,
					    ethtool.mmsv);

	if (mpacket != ETHTOOL_MPACKET_VERIFY &&
	    mpacket != ETHTOOL_MPACKET_RESPONSE)
		return;

	WRITE_ONCE(ns->ethtool.mm_pending_event,
		   READ_ONCE(ns->ethtool.mm_pending_event) | BIT(mpacket));
	schedule_work(&ns->ethtool.mm_work);
}

static const struct ethtool_mmsv_ops nsim_mmsv_ops = {
	.configure_tx	= nsim_mm_configure_tx,
	.configure_pmac	= nsim_mm_configure_pmac,
	.send_mpacket	= nsim_mm_send_mpacket,
};

static int nsim_get_mm(struct net_device *dev, struct ethtool_mm_state *state)
{
	struct netdevsim *ns = netdev_priv(dev);

	ethtool_mmsv_get_mm(&ns->ethtool.mmsv, state);
	state->tx_min_frag_size = ns->ethtool.mm_tx_min_frag_size;
	state->rx_min_frag_size = 60;
	return 0;
}

static int nsim_set_mm(struct net_device *dev, struct ethtool_mm_cfg *cfg,
		       struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 frag_size;
	int err;

	err = ethtool_mm_frag_size_min_to_add(cfg->tx_min_frag_size,
					      &frag_size, extack);
	if (err)
		return err;

	ns->ethtool.mm_tx_min_frag_size = cfg->tx_min_frag_size;
	ethtool_mmsv_set_mm(&ns->ethtool.mmsv, cfg);
	return 0;
}

static void nsim_get_mm_stats(struct net_device *dev,
			      struct ethtool_mm_stats *stats)
{
	stats->MACMergeFrameAssOkCount = 0;
	stats->MACMergeFrameAssErrorCount = 0;
	stats->MACMergeFrameSmdErrorCount = 0;
	stats->MACMergeFragCountRx = 0;
	stats->MACMergeFragCountTx = 0;
	stats->MACMergeHoldCount = 0;
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
	if (kernel_ring->tcp_data_split == ETHTOOL_TCP_DATA_SPLIT_UNKNOWN)
		kernel_ring->tcp_data_split = ns->xdp.prog ?
					      ETHTOOL_TCP_DATA_SPLIT_DISABLED :
					      ETHTOOL_TCP_DATA_SPLIT_ENABLED;
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
	if (ring->tx_pending > 1 && netif_queue_stopped(dev))
		netif_tx_wake_all_queues(dev);
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

static u32 nsim_rss_size_for_channels(u32 channels)
{
	return (channels <= 4) ? 16 : NSIM_RSS_INDIR_SIZE;
}

static int
nsim_set_channels(struct net_device *dev, struct ethtool_channels *ch)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 old_size = ns->ethtool.rss_ctx[0].indir_size;
	u32 new_size = nsim_rss_size_for_channels(ch->combined_count);
	struct ethtool_rxfh_context *ctx;
	unsigned long context;
	unsigned int i;
	int err;

	for (i = ch->combined_count; i < dev->real_num_rx_queues; i++)
		if (netif_rxq_has_unreadable_mp(dev, i))
			return -EBUSY;

	if (new_size < old_size) {
		if (netif_is_rxfh_configured(dev)) {
			if (dev->ethtool->rss_indir_user_size > new_size)
				return -EINVAL;
			for (i = new_size; i < old_size; i++) {
				if (ns->ethtool.rss_ctx[0].indir[i] !=
				    ns->ethtool.rss_ctx[0].indir[i % new_size])
					return -EINVAL;
			}
		}

		mutex_lock(&dev->ethtool->rss_lock);
		xa_for_each(&dev->ethtool->rss_ctx, context, ctx) {
			u32 *tbl = ethtool_rxfh_context_indir(ctx);

			if (ctx->indir_user_size > new_size) {
				mutex_unlock(&dev->ethtool->rss_lock);
				return -EINVAL;
			}
			for (i = new_size; i < old_size; i++) {
				if (tbl[i] != tbl[i % new_size]) {
					mutex_unlock(&dev->ethtool->rss_lock);
					return -EINVAL;
				}
			}
		}
		mutex_unlock(&dev->ethtool->rss_lock);
	}

	err = netif_set_real_num_queues(dev, ch->combined_count,
					ch->combined_count);
	if (err)
		return err;

	ns->ethtool.channels = ch->combined_count;
	if (!netif_is_rxfh_configured(dev)) {
		for (i = 0; i < new_size; i++)
			ns->ethtool.rss_ctx[0].indir[i] =
				ethtool_rxfh_indir_default(i, ch->combined_count);
	} else if (new_size > old_size) {
		for (i = old_size; i < new_size; i++)
			ns->ethtool.rss_ctx[0].indir[i] =
				ns->ethtool.rss_ctx[0].indir[i % old_size];
	}
	ns->ethtool.rss_ctx[0].indir_size = new_size;

	mutex_lock(&dev->ethtool->rss_lock);
	xa_for_each(&dev->ethtool->rss_ctx, context, ctx) {
		u32 *tbl = ethtool_rxfh_context_indir(ctx);

		if (new_size > old_size) {
			for (i = old_size; i < new_size; i++) {
				tbl[i] = tbl[i % old_size];
				if (context < NSIM_RSS_MAX_CTX)
					ns->ethtool.rss_ctx[context].indir[i] = tbl[i];
			}
		}
		ctx->indir_size = new_size;
		if (context < NSIM_RSS_MAX_CTX)
			ns->ethtool.rss_ctx[context].indir_size = new_size;
	}
	mutex_unlock(&dev->ethtool->rss_lock);

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
	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;
	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) | BIT(HWTSTAMP_FILTER_ALL);

	return 0;
}

static u32 nsim_get_rxfh_key_size(struct net_device *dev)
{
	return NETDEV_RSS_KEY_LEN;
}

static u32 nsim_get_rxfh_indir_size(struct net_device *dev)
{
	struct netdevsim *ns = netdev_priv(dev);

	return ns->ethtool.rss_ctx[0].indir_size;
}

static int nsim_get_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_rss_ctx *rctx = &ns->ethtool.rss_ctx[0];

	rxfh->hfunc = ETH_RSS_HASH_TOP;
	rxfh->input_xfrm = rctx->input_xfrm;
	if (rxfh->indir)
		memcpy(rxfh->indir, rctx->indir,
		       rctx->indir_size * sizeof(rctx->indir[0]));
	if (rxfh->key)
		memcpy(rxfh->key, rctx->key, sizeof(rctx->key));

	return 0;
}

static int nsim_set_rxfh(struct net_device *dev,
			 struct ethtool_rxfh_param *rxfh,
			 struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_rss_ctx *rctx = &ns->ethtool.rss_ctx[0];
	u32 i;

	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (rxfh->input_xfrm != RXH_XFRM_NO_CHANGE) {
		if (rxfh->input_xfrm != 0 &&
		    rxfh->input_xfrm != RXH_XFRM_SYM_XOR)
			return -EOPNOTSUPP;
		rctx->input_xfrm = rxfh->input_xfrm;
	}

	if (rxfh->indir) {
		for (i = 0; i < rctx->indir_size; i++) {
			if (rxfh->indir[i] >= dev->real_num_rx_queues)
				return -EINVAL;
		}
		memcpy(rctx->indir, rxfh->indir,
		       rctx->indir_size * sizeof(rctx->indir[0]));
		rctx->indir_configured = true;
	}

	if (rxfh->key)
		memcpy(rctx->key, rxfh->key, sizeof(rctx->key));

	return 0;
}

static int nsim_create_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_rss_ctx *rctx;
	u32 *indir = ethtool_rxfh_context_indir(ctx);
	u8 *key = ethtool_rxfh_context_key(ctx);
	u32 i;

	if (rxfh->rss_context >= NSIM_RSS_MAX_CTX)
		return -ENOSPC;

	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (rxfh->input_xfrm != RXH_XFRM_NO_CHANGE &&
	    rxfh->input_xfrm != 0 &&
	    rxfh->input_xfrm != RXH_XFRM_SYM_XOR)
		return -EOPNOTSUPP;

	rctx = &ns->ethtool.rss_ctx[rxfh->rss_context];
	ctx->hfunc = ETH_RSS_HASH_TOP;
	ctx->input_xfrm = (rxfh->input_xfrm == RXH_XFRM_NO_CHANGE) ?
			  ns->ethtool.rss_ctx[0].input_xfrm : rxfh->input_xfrm;

	if (rxfh->key)
		memcpy(key, rxfh->key, NETDEV_RSS_KEY_LEN);
	else
		memcpy(key, ns->ethtool.rss_ctx[0].key, NETDEV_RSS_KEY_LEN);

	if (rxfh->indir) {
		for (i = 0; i < ctx->indir_size; i++)
			indir[i] = rxfh->indir[i];
		rctx->indir_configured = true;
	} else {
		for (i = 0; i < ctx->indir_size; i++)
			indir[i] = ethtool_rxfh_indir_default(i, dev->real_num_rx_queues);
		rctx->indir_configured = false;
	}

	rctx->indir_size = ctx->indir_size;
	rctx->input_xfrm = ctx->input_xfrm;
	memcpy(rctx->key, key, NETDEV_RSS_KEY_LEN);
	memcpy(rctx->indir, indir, ctx->indir_size * sizeof(u32));
	memcpy(rctx->flow_fields, ns->ethtool.rss_ctx[0].flow_fields,
	       sizeof(rctx->flow_fields));
	rctx->used = true;

	return 0;
}

static int nsim_modify_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    const struct ethtool_rxfh_param *rxfh,
				    struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_rss_ctx *rctx;
	u32 *indir = ethtool_rxfh_context_indir(ctx);
	u8 *key = ethtool_rxfh_context_key(ctx);

	if (rxfh->rss_context >= NSIM_RSS_MAX_CTX ||
	    !ns->ethtool.rss_ctx[rxfh->rss_context].used)
		return -ENOENT;

	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (rxfh->input_xfrm != RXH_XFRM_NO_CHANGE &&
	    rxfh->input_xfrm != 0 &&
	    rxfh->input_xfrm != RXH_XFRM_SYM_XOR)
		return -EOPNOTSUPP;

	rctx = &ns->ethtool.rss_ctx[rxfh->rss_context];
	if (rxfh->input_xfrm != RXH_XFRM_NO_CHANGE)
		rctx->input_xfrm = rxfh->input_xfrm;
	if (rxfh->key)
		memcpy(rctx->key, rxfh->key, NETDEV_RSS_KEY_LEN);
	else
		memcpy(rctx->key, key, NETDEV_RSS_KEY_LEN);
	if (rxfh->indir) {
		memcpy(rctx->indir, rxfh->indir, ctx->indir_size * sizeof(u32));
		rctx->indir_configured = true;
	} else {
		memcpy(rctx->indir, indir, ctx->indir_size * sizeof(u32));
	}

	return 0;
}

static int nsim_remove_rxfh_context(struct net_device *dev,
				    struct ethtool_rxfh_context *ctx,
				    u32 rss_context,
				    struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);

	if (rss_context < NSIM_RSS_MAX_CTX)
		ns->ethtool.rss_ctx[rss_context].used = false;
	return 0;
}

static u32 nsim_get_rx_ring_count(struct net_device *dev)
{
	return dev->real_num_rx_queues;
}

static int nsim_get_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd,
			  u32 *rule_locs)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct nsim_ntuple_rule *rule;
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
		rule = &ns->ethtool.ntuple_rules[cmd->fs.location];
		cmd->fs = rule->fs;
		cmd->flow_type = rule->fs.flow_type;
		if (rule->fs.flow_type & FLOW_RSS)
			cmd->rss_context = be32_to_cpu(rule->fs.h_ext.data[0]);
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

static bool nsim_ntuple_same_match(const struct ethtool_rx_flow_spec *a,
				   const struct ethtool_rx_flow_spec *b)
{
	u32 ft_a = a->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);
	u32 ft_b = b->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS);

	if (ft_a != ft_b)
		return false;
	return !memcmp(&a->h_u, &b->h_u, sizeof(a->h_u)) &&
	       !memcmp(&a->m_u, &b->m_u, sizeof(a->m_u));
}

static int nsim_set_rxnfc(struct net_device *dev, struct ethtool_rxnfc *cmd)
{
	struct netdevsim *ns = netdev_priv(dev);
	struct ethtool_rx_flow_spec *fs = &cmd->fs;
	u32 loc, i;

	switch (cmd->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		if (fs->ring_cookie != RX_CLS_FLOW_DISC) {
			u64 max_ring = ethtool_get_flow_spec_ring(fs->ring_cookie);

			if (fs->flow_type & FLOW_RSS) {
				struct nsim_rss_ctx *rctx;
				u32 max_indir = 0;

				if (cmd->rss_context >= NSIM_RSS_MAX_CTX ||
				    (cmd->rss_context > 0 &&
				     !ns->ethtool.rss_ctx[cmd->rss_context].used))
					return -EINVAL;
				rctx = &ns->ethtool.rss_ctx[cmd->rss_context];
				for (i = 0; i < rctx->indir_size; i++) {
					if (rctx->indir[i] > max_indir)
						max_indir = rctx->indir[i];
				}
				max_ring += max_indir;
			}
			if (max_ring >= dev->real_num_rx_queues)
				return -EINVAL;
		} else if (fs->flow_type & FLOW_RSS) {
			return -EINVAL;
		}

		if (fs->location == RX_CLS_LOC_ANY ||
		    fs->location == RX_CLS_LOC_FIRST ||
		    fs->location == RX_CLS_LOC_LAST) {
			loc = NSIM_MAX_NTUPLE_RULES;
			/* Replace existing rule with identical match criteria if present */
			for (i = 0; i < NSIM_MAX_NTUPLE_RULES; i++) {
				if (ns->ethtool.ntuple_rules[i].used &&
				    nsim_ntuple_same_match(&ns->ethtool.ntuple_rules[i].fs, fs)) {
					loc = i;
					break;
				}
			}
			if (loc == NSIM_MAX_NTUPLE_RULES) {
				for (loc = 0; loc < NSIM_MAX_NTUPLE_RULES; loc++) {
					if (!ns->ethtool.ntuple_rules[loc].used)
						break;
				}
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
		if (fs->flow_type & FLOW_RSS)
			ns->ethtool.ntuple_rules[loc].fs.h_ext.data[0] =
				cpu_to_be32(cmd->rss_context);
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
	struct ethhdr eth_buf, *eth;
	unsigned int off = ETH_HLEN;
	__be16 proto;

	eth = skb_header_pointer(skb, 0, sizeof(eth_buf), &eth_buf);
	if (!eth)
		return false;
	proto = eth->h_proto;

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

static u32 nsim_toeplitz_hash(const u8 *data, size_t len, const u8 *key)
{
	u32 hash = 0;
	u32 key_val = get_unaligned_be32(key);
	size_t i;
	int b;

	for (i = 0; i < len; i++) {
		u8 byte = data[i];
		u8 next_key = key[i + 4];

		for (b = 7; b >= 0; b--) {
			if (byte & (1 << b))
				hash ^= key_val;
			key_val = (key_val << 1) | ((next_key >> b) & 1);
		}
	}
	return hash;
}

static u32 nsim_compute_rss_hash(struct netdevsim *ns, struct sk_buff *skb,
				 u32 ctx_id, enum pkt_hash_types *rss_type)
{
	struct nsim_rss_ctx *rctx = &ns->ethtool.rss_ctx[ctx_id];
	bool sym = (rctx->input_xfrm & RXH_XFRM_SYM_XOR);
	struct ethhdr eth_buf, *eth;
	unsigned int off = ETH_HLEN;
	__be16 proto;
	u8 input[48];
	size_t in_len = 0;

	eth = skb_header_pointer(skb, 0, sizeof(eth_buf), &eth_buf);
	if (!eth)
		return 0;
	proto = eth->h_proto;

	*rss_type = PKT_HASH_TYPE_L3;

	while (eth_type_vlan(proto)) {
		struct vlan_hdr vhdr, *vp;

		vp = skb_header_pointer(skb, off, sizeof(vhdr), &vhdr);
		if (!vp)
			return 0;
		proto = vp->h_vlan_encapsulated_proto;
		off += sizeof(vhdr);
	}

	if (proto == htons(ETH_P_IP)) {
		struct iphdr iph_buf, *iph;
		u32 ftype = IPV4_FLOW;
		u64 fields;

		iph = skb_header_pointer(skb, off, sizeof(iph_buf), &iph_buf);
		if (!iph)
			return 0;

		if (!(ntohs(iph->frag_off) & (IP_MF | IP_OFFSET))) {
			if (iph->protocol == IPPROTO_TCP)
				ftype = TCP_V4_FLOW;
			else if (iph->protocol == IPPROTO_UDP)
				ftype = UDP_V4_FLOW;
		}
		fields = rctx->flow_fields[ftype];

		if ((fields & RXH_IP_SRC) && (fields & RXH_IP_DST)) {
			__be32 s = iph->saddr;
			__be32 d = iph->daddr;

			if (sym) {
				s ^= d;
				d = s;
			}
			memcpy(input + in_len, &s, 4);
			in_len += 4;
			memcpy(input + in_len, &d, 4);
			in_len += 4;
		} else if (fields & RXH_IP_SRC) {
			memcpy(input + in_len, &iph->saddr, 4);
			in_len += 4;
		} else if (fields & RXH_IP_DST) {
			memcpy(input + in_len, &iph->daddr, 4);
			in_len += 4;
		}

		if ((ftype == TCP_V4_FLOW || ftype == UDP_V4_FLOW) &&
		    (fields & (RXH_L4_B_0_1 | RXH_L4_B_2_3))) {
			__be16 ports[2], *pptr;

			pptr = skb_header_pointer(skb, off + iph->ihl * 4,
						  sizeof(ports), ports);
			if (pptr) {
				__be16 sp = pptr[0], dp = pptr[1];

				*rss_type = PKT_HASH_TYPE_L4;
				if ((fields & RXH_L4_B_0_1) && (fields & RXH_L4_B_2_3)) {
					if (sym) {
						sp ^= dp;
						dp = sp;
					}
					memcpy(input + in_len, &sp, 2);
					in_len += 2;
					memcpy(input + in_len, &dp, 2);
					in_len += 2;
				} else if (fields & RXH_L4_B_0_1) {
					memcpy(input + in_len, &sp, 2);
					in_len += 2;
				} else if (fields & RXH_L4_B_2_3) {
					memcpy(input + in_len, &dp, 2);
					in_len += 2;
				}
			}
		}
		return nsim_toeplitz_hash(input, in_len, rctx->key);
	}

	if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6h_buf, *ip6h;
		u32 ftype = IPV6_FLOW;
		__be16 frag_off = 0;
		u8 nexthdr;
		int l4_off;
		u64 fields;
		int i;

		ip6h = skb_header_pointer(skb, off, sizeof(ip6h_buf), &ip6h_buf);
		if (!ip6h)
			return 0;

		nexthdr = ip6h->nexthdr;
		l4_off = ipv6_skip_exthdr(skb, off + sizeof(*ip6h),
					  &nexthdr, &frag_off);
		if (l4_off >= 0 && !(ntohs(frag_off) & (IP6_MF | IP6_OFFSET))) {
			if (nexthdr == IPPROTO_TCP)
				ftype = TCP_V6_FLOW;
			else if (nexthdr == IPPROTO_UDP)
				ftype = UDP_V6_FLOW;
		}
		fields = rctx->flow_fields[ftype];

		if ((fields & RXH_IP_SRC) && (fields & RXH_IP_DST)) {
			__be32 s[4], d[4];

			for (i = 0; i < 4; i++) {
				s[i] = ip6h->saddr.s6_addr32[i];
				d[i] = ip6h->daddr.s6_addr32[i];
				if (sym) {
					s[i] ^= d[i];
					d[i] = s[i];
				}
			}
			memcpy(input + in_len, s, 16);
			in_len += 16;
			memcpy(input + in_len, d, 16);
			in_len += 16;
		} else if (fields & RXH_IP_SRC) {
			memcpy(input + in_len, &ip6h->saddr, 16);
			in_len += 16;
		} else if (fields & RXH_IP_DST) {
			memcpy(input + in_len, &ip6h->daddr, 16);
			in_len += 16;
		}

		if (fields & RXH_IP6_FL) {
			__be32 fl = ip6_flowlabel(ip6h);

			*rss_type = PKT_HASH_TYPE_L4;
			memcpy(input + in_len, &fl, 4);
			in_len += 4;
		}

		if ((ftype == TCP_V6_FLOW || ftype == UDP_V6_FLOW) &&
		    l4_off >= 0 && (fields & (RXH_L4_B_0_1 | RXH_L4_B_2_3))) {
			__be16 ports[2], *pptr;

			pptr = skb_header_pointer(skb, l4_off, sizeof(ports), ports);
			if (pptr) {
				__be16 sp = pptr[0], dp = pptr[1];

				*rss_type = PKT_HASH_TYPE_L4;
				if ((fields & RXH_L4_B_0_1) && (fields & RXH_L4_B_2_3)) {
					if (sym) {
						sp ^= dp;
						dp = sp;
					}
					memcpy(input + in_len, &sp, 2);
					in_len += 2;
					memcpy(input + in_len, &dp, 2);
					in_len += 2;
				} else if (fields & RXH_L4_B_0_1) {
					memcpy(input + in_len, &sp, 2);
					in_len += 2;
				} else if (fields & RXH_L4_B_2_3) {
					memcpy(input + in_len, &dp, 2);
					in_len += 2;
				}
			}
		}
		return nsim_toeplitz_hash(input, in_len, rctx->key);
	}

	return 0;
}

int nsim_select_rxq(struct netdevsim *ns, struct sk_buff *skb,
		    u32 *rss_hash, enum pkt_hash_types *rss_type)
{
	struct net_device *dev = ns->netdev;
	struct nsim_rss_ctx *rctx;
	u32 ctx_id = 0;
	u32 base_ring = 0;
	u32 hash;
	int i;

	*rss_hash = 0;
	*rss_type = PKT_HASH_TYPE_NONE;

	for (i = 0; i < NSIM_MAX_NTUPLE_RULES; i++) {
		const struct ethtool_rx_flow_spec *fs;
		u64 cookie;

		if (!ns->ethtool.ntuple_rules[i].used)
			continue;
		fs = &ns->ethtool.ntuple_rules[i].fs;
		if (!nsim_ntuple_match(fs, skb))
			continue;

		cookie = fs->ring_cookie;
		if (cookie == RX_CLS_FLOW_DISC)
			return -1;

		base_ring = ethtool_get_flow_spec_ring(cookie);
		if (fs->flow_type & FLOW_RSS) {
			ctx_id = be32_to_cpu(fs->h_ext.data[0]);
			if (ctx_id >= NSIM_RSS_MAX_CTX ||
			    (ctx_id > 0 && !ns->ethtool.rss_ctx[ctx_id].used))
				ctx_id = 0;
			goto do_rss;
		}
		return base_ring % dev->real_num_rx_queues;
	}

do_rss:
	rctx = &ns->ethtool.rss_ctx[ctx_id];
	if (skb_frags_readable(skb)) {
		hash = nsim_compute_rss_hash(ns, skb, ctx_id, rss_type);
		*rss_hash = hash;
	} else {
		hash = skb_get_queue_mapping(skb);
	}

	if (ctx_id > 0 || netif_is_rxfh_configured(dev) ||
	    rctx->indir_configured || *rss_hash) {
		u32 idx = hash % rctx->indir_size;

		return (base_ring + rctx->indir[idx]) % dev->real_num_rx_queues;
	}

	return skb_get_queue_mapping(skb) % dev->real_num_rx_queues;
}

static int nsim_get_rxfh_fields(struct net_device *dev,
				struct ethtool_rxfh_fields *info)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 ctx = info->rss_context;

	if (ctx >= NSIM_RSS_MAX_CTX ||
	    (ctx > 0 && !ns->ethtool.rss_ctx[ctx].used))
		return -ENOENT;

	switch (info->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case IPV4_FLOW:
	case IPV6_FLOW:
		info->data = ns->ethtool.rss_ctx[ctx].flow_fields[info->flow_type];
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int nsim_set_rxfh_fields(struct net_device *dev,
				const struct ethtool_rxfh_fields *info,
				struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = netdev_priv(dev);
	u32 ctx = info->rss_context;
	u64 allowed;

	if (ctx >= NSIM_RSS_MAX_CTX ||
	    (ctx > 0 && !ns->ethtool.rss_ctx[ctx].used))
		return -ENOENT;

	switch (info->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
		allowed = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3;
		break;
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
		allowed = RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 | RXH_L4_B_2_3 |
			  RXH_IP6_FL;
		break;
	case IPV4_FLOW:
		allowed = RXH_IP_SRC | RXH_IP_DST;
		break;
	case IPV6_FLOW:
		allowed = RXH_IP_SRC | RXH_IP_DST | RXH_IP6_FL;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (info->data & ~allowed)
		return -EINVAL;

	if ((ns->ethtool.rss_ctx[ctx].input_xfrm & RXH_XFRM_SYM_XOR)) {
		bool src = !!(info->data & RXH_IP_SRC);
		bool dst = !!(info->data & RXH_IP_DST);
		bool l4s = !!(info->data & RXH_L4_B_0_1);
		bool l4d = !!(info->data & RXH_L4_B_2_3);

		if (src != dst || l4s != l4d)
			return -EINVAL;
	}

	ns->ethtool.rss_ctx[ctx].flow_fields[info->flow_type] = info->data;
	return 0;
}

static const struct ethtool_ops nsim_ethtool_ops = {
	.supported_coalesce_params	= ETHTOOL_COALESCE_ALL_PARAMS,
	.supported_ring_params		= ETHTOOL_RING_USE_TCP_DATA_SPLIT |
					  ETHTOOL_RING_USE_HDS_THRS,
	.rxfh_indir_space		= NSIM_RSS_INDIR_SIZE,
	.rxfh_key_space			= NETDEV_RSS_KEY_LEN,
	.rxfh_max_num_contexts		= NSIM_RSS_MAX_CTX,
	.rxfh_per_ctx_key		= 1,
	.rxfh_per_ctx_fields		= 1,
	.cap_rss_rxnfc_adds		= 1,
	.supported_input_xfrm		= RXH_XFRM_SYM_XOR,
	.op_needs_rtnl			= ETHTOOL_OP_NEEDS_RTNL_SCHANNELS,
	.get_link			= ethtool_op_get_link,
	.get_link_ext_state		= nsim_get_link_ext_state,
	.get_link_ksettings		= nsim_get_link_ksettings,
	.set_link_ksettings		= nsim_set_link_ksettings,
	.nway_reset			= nsim_nway_reset,
	.get_rx_ring_count		= nsim_get_rx_ring_count,
	.get_rxnfc			= nsim_get_rxnfc,
	.set_rxnfc			= nsim_set_rxnfc,
	.get_rxfh_key_size		= nsim_get_rxfh_key_size,
	.get_rxfh_indir_size		= nsim_get_rxfh_indir_size,
	.get_rxfh			= nsim_get_rxfh,
	.set_rxfh			= nsim_set_rxfh,
	.create_rxfh_context		= nsim_create_rxfh_context,
	.modify_rxfh_context		= nsim_modify_rxfh_context,
	.remove_rxfh_context		= nsim_remove_rxfh_context,
	.get_rxfh_fields		= nsim_get_rxfh_fields,
	.set_rxfh_fields		= nsim_set_rxfh_fields,
	.get_pause_stats		= nsim_get_pause_stats,
	.get_pauseparam			= nsim_get_pauseparam,
	.set_pauseparam			= nsim_set_pauseparam,
	.get_mm				= nsim_get_mm,
	.set_mm				= nsim_set_mm,
	.get_mm_stats			= nsim_get_mm_stats,
	.get_eth_mac_stats		= nsim_get_eth_mac_stats,
	.get_eth_ctrl_stats		= nsim_get_eth_ctrl_stats,
	.get_rmon_stats			= nsim_get_rmon_stats,
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

static void nsim_rss_ctx_init_fields(struct nsim_rss_ctx *rctx)
{
	rctx->flow_fields[TCP_V4_FLOW] = RXH_IP_SRC | RXH_IP_DST |
					 RXH_L4_B_0_1 | RXH_L4_B_2_3;
	rctx->flow_fields[UDP_V4_FLOW] = RXH_IP_SRC | RXH_IP_DST |
					 RXH_L4_B_0_1 | RXH_L4_B_2_3;
	rctx->flow_fields[TCP_V6_FLOW] = RXH_IP_SRC | RXH_IP_DST |
					 RXH_L4_B_0_1 | RXH_L4_B_2_3;
	rctx->flow_fields[UDP_V6_FLOW] = RXH_IP_SRC | RXH_IP_DST |
					 RXH_L4_B_0_1 | RXH_L4_B_2_3;
	rctx->flow_fields[IPV4_FLOW] = RXH_IP_SRC | RXH_IP_DST;
	rctx->flow_fields[IPV6_FLOW] = RXH_IP_SRC | RXH_IP_DST;
}

void nsim_ethtool_init(struct netdevsim *ns)
{
	struct dentry *ethtool, *dir;
	struct nsim_rss_ctx *rctx0 = &ns->ethtool.rss_ctx[0];
	int i;

	ns->netdev->ethtool_ops = &nsim_ethtool_ops;

	INIT_DELAYED_WORK(&ns->ethtool.aneg_work, nsim_aneg_work_fn);
	INIT_WORK(&ns->ethtool.mm_work, nsim_mm_work_fn);

	nsim_ethtool_ring_init(ns);

	ns->ethtool.pauseparam.report_stats_rx = true;
	ns->ethtool.pauseparam.report_stats_tx = true;
	ns->ethtool.coalesce.rx_coalesce_usecs = 5;

	ns->ethtool.fec.fec = ETHTOOL_FEC_NONE;
	ns->ethtool.fec.active_fec = ETHTOOL_FEC_NONE;

	ns->ethtool.speed = SPEED_100000;
	ns->ethtool.duplex = DUPLEX_FULL;
	ns->ethtool.autoneg = AUTONEG_ENABLE;
	linkmode_zero(ns->ethtool.supported);
	for (i = 0; i < ARRAY_SIZE(nsim_speed_modes); i++)
		__set_bit(nsim_speed_modes[i].bit, ns->ethtool.supported);
	__set_bit(ETHTOOL_LINK_MODE_Autoneg_BIT, ns->ethtool.supported);
	__set_bit(ETHTOOL_LINK_MODE_TP_BIT, ns->ethtool.supported);
	__set_bit(ETHTOOL_LINK_MODE_Pause_BIT, ns->ethtool.supported);
	__set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, ns->ethtool.supported);
	linkmode_copy(ns->ethtool.advertising, ns->ethtool.supported);

	ns->ethtool.mm_tx_min_frag_size = 60;
	ethtool_mmsv_init(&ns->ethtool.mmsv, ns->netdev, &nsim_mmsv_ops);

	ns->ethtool.channels = ns->nsim_bus_dev->num_queues;
	rctx0->used = true;
	rctx0->indir_size = nsim_rss_size_for_channels(ns->ethtool.channels);
	netdev_rss_key_fill(rctx0->key, sizeof(rctx0->key));
	for (u32 j = 0; j < NSIM_RSS_INDIR_SIZE; j++)
		rctx0->indir[j] =
			ethtool_rxfh_indir_default(j, ns->ethtool.channels);
	nsim_rss_ctx_init_fields(rctx0);

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
	cancel_delayed_work_sync(&ns->ethtool.aneg_work);
	cancel_work_sync(&ns->ethtool.mm_work);
	ethtool_mmsv_stop(&ns->ethtool.mmsv);
	debugfs_remove(ns->ethtool_ddir);
}
