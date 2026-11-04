/*
 * Copyright (C) 2017 Netronome Systems, Inc.
 *
 * This software is licensed under the GNU General License Version 2,
 * June 1991 as shown in the file COPYING in the top-level directory of this
 * source tree.
 *
 * THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS"
 * WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE
 * OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME
 * THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
 */

#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/if_vlan.h>
#include <linux/list.h>
#include <linux/net_tstamp.h>
#include <linux/netdevice.h>
#include <linux/ptp_mock.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <net/devlink.h>
#include <net/gro.h>
#include <net/udp_tunnel.h>
#include <net/xdp.h>
#include <net/xdp_sock_drv.h>
#include <net/macsec.h>

#define DRV_NAME	"netdevsim"

#define NSIM_XDP_MAX_MTU	4000

#define NSIM_EA(extack, msg)	NL_SET_ERR_MSG_MOD((extack), msg)

#define NSIM_IPSEC_MAX_SA_COUNT		33
#define NSIM_IPSEC_VALID		BIT(31)
#define NSIM_UDP_TUNNEL_N_PORTS		4

#define NSIM_HDS_THRESHOLD_MAX		1024

struct nsim_sa {
	struct xfrm_state *xs;
	__be32 ipaddr[4];
	__be32 key[4];
	__be32 salt;
	bool used;
	bool crypt;
	bool rx;
};

struct nsim_ipsec {
	struct nsim_sa sa[NSIM_IPSEC_MAX_SA_COUNT];
	struct dentry *pfile;
	u32 count;
	u32 tx;
};

#define NSIM_MACSEC_MAX_SECY_COUNT 3
#define NSIM_MACSEC_MAX_RXSC_COUNT 1
struct nsim_rxsc {
	sci_t sci;
	bool used;
};

struct nsim_secy {
	sci_t sci;
	struct nsim_rxsc nsim_rxsc[NSIM_MACSEC_MAX_RXSC_COUNT];
	u8 nsim_rxsc_count;
	bool used;
};

struct nsim_macsec {
	struct nsim_secy nsim_secy[NSIM_MACSEC_MAX_SECY_COUNT];
	u8 nsim_secy_count;
};

struct nsim_vlan {
	DECLARE_BITMAP(ctag, VLAN_N_VID);
	DECLARE_BITMAP(stag, VLAN_N_VID);
};

struct nsim_ethtool_pauseparam {
	bool autoneg;
	bool rx;
	bool tx;
	bool report_stats_rx;
	bool report_stats_tx;
};

#define NSIM_RSS_INDIR_SIZE		128
#define NSIM_RSS_MAX_CTX		33
#define NSIM_MAX_NTUPLE_RULES		16
#define NSIM_RMON_BUCKETS		6

struct nsim_ntuple_rule {
	struct ethtool_rx_flow_spec fs;
	bool used;
};

struct nsim_rss_ctx {
	u8 key[NETDEV_RSS_KEY_LEN];
	u32 indir[NSIM_RSS_INDIR_SIZE];
	u32 indir_size;
	bool indir_configured;
	u8 input_xfrm;
	u64 flow_fields[IPV6_FLOW + 1];
	bool used;
};

struct nsim_mac_stats {
	u64 tx_frames;
	u64 tx_octets;
	u64 tx_mcast;
	u64 tx_bcast;
	u64 tx_ctrl;
	u64 tx_pause;
	u64 rx_frames;
	u64 rx_octets;
	u64 rx_mcast;
	u64 rx_bcast;
	u64 rx_ctrl;
	u64 rx_pause;
	u64 rmon_rx[NSIM_RMON_BUCKETS];
	u64 rmon_tx[NSIM_RMON_BUCKETS];
	u64 rmon_undersize;
	u64 rmon_oversize;
};

struct nsim_txq {
	u64 packets;
	u64 bytes;
	u64 hw_gso_packets;
	u64 hw_gso_wire_packets;
	bool netpoll_polled;
};

struct nsim_ethtool {
	u32 get_err;
	u32 set_err;
	u32 channels;
	struct nsim_rss_ctx rss_ctx[NSIM_RSS_MAX_CTX];
	struct nsim_ntuple_rule ntuple_rules[NSIM_MAX_NTUPLE_RULES];
	struct nsim_ethtool_pauseparam pauseparam;
	struct ethtool_coalesce coalesce;
	struct ethtool_ringparam ring;
	struct ethtool_fecparam fec;
	u32 speed;
	u8 duplex;
	u8 autoneg;
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
	struct delayed_work aneg_work;
	bool aneg_in_progress;
	struct ethtool_mmsv mmsv;
	struct work_struct mm_work;
	u32 mm_tx_min_frag_size;
	int mm_pending_event;
};

struct nsim_rq {
	struct napi_struct napi;
	struct sk_buff_head skb_queue;
	struct page_pool *page_pool;
	struct hrtimer napi_timer;
	struct gro_node hw_gro;
	struct hrtimer gro_timer;
	spinlock_t gro_lock; /* protects hw_gro state */
	bool gro_flush_pending;
	struct xdp_rxq_info xdp_rxq;
	struct xsk_buff_pool *xsk_pool;
	call_single_data_t csd;
	int irq;
	u64 rx_packets;
	u64 rx_bytes;
	u64 alloc_fail;
	u64 cur_rx_tstamp;
	u32 cur_rx_hash;
	enum xdp_rss_hash_type cur_rx_hash_type;
};

struct netdevsim {
	struct net_device *netdev;
	struct nsim_dev *nsim_dev;
	struct nsim_dev_port *nsim_dev_port;
	struct mock_phc *phc;
	struct nsim_rq **rq;
	struct nsim_txq *txq;

	u64 base_rx_packets;
	u64 base_rx_bytes;
	u64 base_rx_hw_gro_packets;
	u64 base_rx_hw_gro_wire_packets;
	u64 base_rx_alloc_fail;
	u64_stats_t tx_dropped;
	struct u64_stats_sync syncp;

	spinlock_t stats_lock; /* protects mac_stats */
	struct nsim_mac_stats mac_stats[2];
	struct kernel_hwtstamp_config hwtstamp_cfg;
	u8 preemptible_tcs;
	bool require_link;

	int rq_reset_mode;

	struct {
		atomic64_t rx_packets;
		atomic64_t rx_bytes;
		atomic64_t tx_packets;
		atomic64_t tx_bytes;
		struct psp_dev __rcu *dev;
		struct dentry *rereg;
		struct mutex rereg_lock;
		u32 spi;
	} psp;

	struct nsim_bus_dev *nsim_bus_dev;

	struct bpf_prog	*bpf_offloaded;
	u32 bpf_offloaded_id;

	struct xdp_attachment_info xdp;
	struct xdp_attachment_info xdp_hw;

	bool bpf_tc_accept;
	bool bpf_tc_non_bound_accept;
	bool bpf_xdpdrv_accept;
	bool bpf_xdpoffload_accept;

	bool bpf_map_accept;
	struct nsim_ipsec ipsec;
	struct nsim_macsec macsec;
	struct nsim_vlan vlan;
	struct {
		u32 inject_error;
		u32 __ports[2][NSIM_UDP_TUNNEL_N_PORTS];
		u32 (*ports)[NSIM_UDP_TUNNEL_N_PORTS];
		struct dentry *ddir;
		struct debugfs_u32_array dfs_ports[2];
	} udp_ports;

	struct page *page;
	struct dentry *pp_dfs;
	struct dentry *qr_dfs;
	struct dentry *vlan_dfs;
	struct dentry *ethtool_ddir;

	struct nsim_ethtool ethtool;
	struct netdevsim __rcu *peer;

	struct notifier_block nb;
	struct netdev_net_notifier nn;
};

struct netdevsim *nsim_create(struct nsim_dev *nsim_dev,
			      struct nsim_dev_port *nsim_dev_port,
			      u8 perm_addr[ETH_ALEN]);
void nsim_destroy(struct netdevsim *ns);
bool netdev_is_nsim(struct net_device *dev);

void nsim_ethtool_init(struct netdevsim *ns);
void nsim_ethtool_fini(struct netdevsim *ns);
int nsim_select_rxq(struct netdevsim *ns, struct sk_buff *skb,
		    u32 *rss_hash, enum pkt_hash_types *rss_type);
void nsim_update_carrier(struct netdevsim *ns);
bool nsim_link_can_up(struct netdevsim *a, struct netdevsim *b);
void nsim_mac_record_frame(struct netdevsim *ns, const struct sk_buff *skb,
			   unsigned int wire_len, int tc, bool is_tx);

void nsim_udp_tunnels_debugfs_create(struct nsim_dev *nsim_dev);
int nsim_udp_tunnels_info_create(struct nsim_dev *nsim_dev,
				 struct net_device *dev);
void nsim_udp_tunnels_info_destroy(struct net_device *dev);

#ifdef CONFIG_BPF_SYSCALL
int nsim_bpf_dev_init(struct nsim_dev *nsim_dev);
void nsim_bpf_dev_exit(struct nsim_dev *nsim_dev);
int nsim_bpf_init(struct netdevsim *ns);
void nsim_bpf_uninit(struct netdevsim *ns);
int nsim_bpf(struct net_device *dev, struct netdev_bpf *bpf);
int nsim_bpf_disable_tc(struct netdevsim *ns);
int nsim_bpf_setup_tc_block_cb(enum tc_setup_type type,
			       void *type_data, void *cb_priv);
#else

static inline int nsim_bpf_dev_init(struct nsim_dev *nsim_dev)
{
	return 0;
}

static inline void nsim_bpf_dev_exit(struct nsim_dev *nsim_dev)
{
}
static inline int nsim_bpf_init(struct netdevsim *ns)
{
	return 0;
}

static inline void nsim_bpf_uninit(struct netdevsim *ns)
{
}

static inline int nsim_bpf(struct net_device *dev, struct netdev_bpf *bpf)
{
	return -EOPNOTSUPP;
}

static inline int nsim_bpf_disable_tc(struct netdevsim *ns)
{
	return 0;
}

static inline int
nsim_bpf_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			   void *cb_priv)
{
	return -EOPNOTSUPP;
}
#endif

enum nsim_resource_id {
	NSIM_RESOURCE_NONE,   /* DEVLINK_RESOURCE_ID_PARENT_TOP */
	NSIM_RESOURCE_IPV4,
	NSIM_RESOURCE_IPV4_FIB,
	NSIM_RESOURCE_IPV4_FIB_RULES,
	NSIM_RESOURCE_IPV6,
	NSIM_RESOURCE_IPV6_FIB,
	NSIM_RESOURCE_IPV6_FIB_RULES,
	NSIM_RESOURCE_NEXTHOPS,
};

enum nsim_port_resource_id {
	NSIM_PORT_RESOURCE_TEST = 1,
};

struct nsim_dev_health {
	struct devlink_health_reporter *empty_reporter;
	struct devlink_health_reporter *dummy_reporter;
	struct dentry *ddir;
	char *recovered_break_msg;
	u32 binary_len;
	bool fail_recover;
};

int nsim_dev_health_init(struct nsim_dev *nsim_dev, struct devlink *devlink);
void nsim_dev_health_exit(struct nsim_dev *nsim_dev);

struct nsim_dev_hwstats_netdev {
	struct list_head list;
	struct net_device *netdev;
	struct rtnl_hw_stats64 stats;
	bool enabled;
	bool fail_enable;
	bool auto_tracked;
};

struct nsim_dev_hwstats {
	struct dentry *ddir;
	struct dentry *l3_ddir;

	struct mutex hwsdev_list_lock; /* protects hwsdev list(s) */
	spinlock_t stats_lock;
	struct list_head l3_list;

	struct notifier_block netdevice_nb;
	struct delayed_work traffic_dw;
};

int nsim_dev_hwstats_init(struct nsim_dev *nsim_dev);
void nsim_dev_hwstats_exit(struct nsim_dev *nsim_dev);
void nsim_dev_hwstats_record(struct net_device *dev, unsigned int len,
			     bool is_tx);

#if IS_ENABLED(CONFIG_PSAMPLE)
int nsim_dev_psample_init(struct nsim_dev *nsim_dev);
void nsim_dev_psample_exit(struct nsim_dev *nsim_dev);
#else
static inline int nsim_dev_psample_init(struct nsim_dev *nsim_dev)
{
	return 0;
}

static inline void nsim_dev_psample_exit(struct nsim_dev *nsim_dev)
{
}
#endif

enum nsim_dev_port_type {
	NSIM_DEV_PORT_TYPE_PF,
	NSIM_DEV_PORT_TYPE_VF,
};

#define NSIM_DEV_VF_PORT_INDEX_BASE 128

struct nsim_rate_node;

struct nsim_dev_port {
	struct list_head list;
	struct devlink_port devlink_port;
	unsigned int port_index;
	enum nsim_dev_port_type port_type;
	struct dentry *ddir;
	struct dentry *rate_parent;
	char *parent_name;
	struct nsim_rate_node *parent_node;
	u32 tc_bw[DEVLINK_RATE_TCS_MAX];
	struct netdevsim *ns;
	bool is_split_subport;
	unsigned int split_parent_idx;
	unsigned int split_count;
	unsigned int lanes;
	char ifname[IFNAMSIZ];
	char split_parent_ifname[IFNAMSIZ];
};

struct nsim_vf_config {
	int link_state;
	u16 min_tx_rate;
	u16 max_tx_rate;
	u16 vlan;
	__be16 vlan_proto;
	u16 qos;
	u8 vf_mac[ETH_ALEN];
	bool spoofchk_enabled;
	bool trusted;
	bool rss_query_enabled;
};

struct nsim_dev {
	struct nsim_bus_dev *nsim_bus_dev;
	struct nsim_fib_data *fib_data;
	struct nsim_trap_data *trap_data;
	struct dentry *ddir;
	struct dentry *ports_ddir;
	struct dentry *take_snapshot;
	struct dentry *nodes_ddir;

	struct nsim_vf_config *vfconfigs;
	struct device *vf_devs[4];
	struct net_device *vf_netdevs[4];
	struct netdevsim *vf_rep[4];
	struct list_head rate_node_list;

	struct bpf_offload_dev *bpf_dev;
	bool bpf_bind_accept;
	bool bpf_bind_verifier_accept;
	u32 bpf_bind_verifier_delay;
	struct dentry *ddir_bpf_bound_progs;
	u32 prog_id_gen;
	struct list_head bpf_bound_progs;
	struct list_head bpf_bound_maps;
	struct mutex progs_list_lock;
	struct netdev_phys_item_id switch_id;
	struct list_head port_list;
	bool fw_update_status;
	u32 fw_update_overwrite_mask;
	u32 fw_update_flash_chunk_time_ms;
	u32 max_macs;
	bool test1;
	u32 test2;
	bool dont_allow_reload;
	bool fail_reload;
	struct devlink *parent_devlink;
	struct devlink_region *dummy_region;
	struct nsim_dev_health health;
	struct nsim_dev_hwstats hwstats;
	struct flow_action_cookie *fa_cookie;
	spinlock_t fa_cookie_lock; /* protects fa_cookie */
	bool fail_trap_group_set;
	bool fail_trap_policer_set;
	bool fail_trap_policer_counter_get;
	bool fail_trap_drop_counter_get;
	struct {
		struct udp_tunnel_nic_shared utn_shared;
		u32 __ports[2][NSIM_UDP_TUNNEL_N_PORTS];
		bool sync_all;
		bool open_only;
		bool ipv4_only;
		bool shared;
		bool static_iana_vxlan;
	} udp_ports;
	struct nsim_dev_psample *psample;
	u16 esw_mode;
};

static inline bool nsim_esw_mode_is_legacy(struct nsim_dev *nsim_dev)
{
	return nsim_dev->esw_mode == DEVLINK_ESWITCH_MODE_LEGACY;
}

static inline bool nsim_esw_mode_is_switchdev(struct nsim_dev *nsim_dev)
{
	return nsim_dev->esw_mode == DEVLINK_ESWITCH_MODE_SWITCHDEV;
}

static inline struct net *nsim_dev_net(struct nsim_dev *nsim_dev)
{
	return devlink_net(priv_to_devlink(nsim_dev));
}

int nsim_dev_init(void);
void nsim_dev_exit(void);
int nsim_drv_probe(struct nsim_bus_dev *nsim_bus_dev);
void nsim_drv_remove(struct nsim_bus_dev *nsim_bus_dev);
int nsim_drv_port_add(struct nsim_bus_dev *nsim_bus_dev,
		      enum nsim_dev_port_type type, unsigned int port_index,
		      u8 perm_addr[ETH_ALEN]);
int nsim_drv_port_del(struct nsim_bus_dev *nsim_bus_dev,
		      enum nsim_dev_port_type type,
		      unsigned int port_index);
int nsim_drv_configure_vfs(struct nsim_bus_dev *nsim_bus_dev,
			   unsigned int num_vfs);

unsigned int nsim_dev_get_vfs(struct nsim_dev *nsim_dev);

struct nsim_fib_data *nsim_fib_create(struct devlink *devlink,
				      struct netlink_ext_ack *extack);
void nsim_fib_destroy(struct devlink *devlink, struct nsim_fib_data *fib_data);
u64 nsim_fib_get_val(struct nsim_fib_data *fib_data,
		     enum nsim_resource_id res_id, bool max);

static inline bool nsim_dev_port_is_pf(struct nsim_dev_port *nsim_dev_port)
{
	return nsim_dev_port->port_type == NSIM_DEV_PORT_TYPE_PF;
}

static inline bool nsim_dev_port_is_vf(struct nsim_dev_port *nsim_dev_port)
{
	return nsim_dev_port->port_type == NSIM_DEV_PORT_TYPE_VF;
}
#if IS_ENABLED(CONFIG_XFRM_OFFLOAD)
void nsim_ipsec_init(struct netdevsim *ns);
void nsim_ipsec_teardown(struct netdevsim *ns);
struct sk_buff *nsim_ipsec_tx(struct netdevsim *ns, struct sk_buff *skb,
			      bool do_crypto);
#else
static inline void nsim_ipsec_init(struct netdevsim *ns)
{
}

static inline void nsim_ipsec_teardown(struct netdevsim *ns)
{
}

static inline struct sk_buff *nsim_ipsec_tx(struct netdevsim *ns,
					    struct sk_buff *skb,
					    bool do_crypto)
{
	skb->next = NULL;
	return skb;
}
#endif

#if IS_ENABLED(CONFIG_MACSEC)
void nsim_macsec_init(struct netdevsim *ns);
void nsim_macsec_teardown(struct netdevsim *ns);
#else
static inline void nsim_macsec_init(struct netdevsim *ns)
{
}

static inline void nsim_macsec_teardown(struct netdevsim *ns)
{
}
#endif

#if IS_ENABLED(CONFIG_INET_PSP)
int nsim_psp_init(struct netdevsim *ns);
void nsim_psp_uninit(struct netdevsim *ns);
void nsim_psp_handle_ext(struct sk_buff *skb, struct skb_ext *psp_ext);
enum skb_drop_reason
nsim_do_psp(struct sk_buff *skb, struct netdevsim *ns,
	    struct netdevsim *peer_ns, struct skb_ext **psp_ext);
#else
static inline int nsim_psp_init(struct netdevsim *ns) { return 0; }
static inline void nsim_psp_uninit(struct netdevsim *ns) {}
static inline enum skb_drop_reason
nsim_do_psp(struct sk_buff *skb, struct netdevsim *ns,
	    struct netdevsim *peer_ns, struct skb_ext **psp_ext)
{
	return 0;
}

static inline void
nsim_psp_handle_ext(struct sk_buff *skb, struct skb_ext *psp_ext) {}
#endif

int nsim_setup_tc(struct net_device *dev, enum tc_setup_type type,
		  void *type_data);

#define NSIM_BUS_DEV_MAX_VFS 4
struct nsim_bus_dev {
	struct device dev;
	struct device_dma_parameters dma_parms;
	struct list_head list;
	unsigned int port_count;
	unsigned int num_queues; /* Number of queues for each port on this bus */
	struct net *initial_net; /* Purpose of this is to carry net pointer
				  * during the probe time only.
				  */
	int parent_dev_id;
	unsigned int num_vfs;
	bool init;
};

struct nsim_bus_dev *nsim_bus_dev_find(int id);
int nsim_bus_init(void);
void nsim_bus_exit(void);
