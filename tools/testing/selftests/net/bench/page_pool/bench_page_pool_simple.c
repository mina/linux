// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark and coverage module for page_pool.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/dma-mapping.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/topology.h>
#include <net/page_pool/helpers.h>
#include <net/xdp.h>

#include "time_bench.h"

static int verbose = 1;

#define MY_POOL_SIZE		1024
#define MY_BULK_SIZE		XDP_BULK_QUEUE_SIZE
#define MY_OVERFLOW_BATCH	(PP_ALLOC_CACHE_SIZE + PP_ALLOC_CACHE_REFILL)
#define MY_RING_SMALL_SIZE	64
#define MY_RING_OVERFLOW_BATCH	(MY_RING_SMALL_SIZE * 2)
#define MY_HIGH_ORDER		2
#define MY_FRAG_SMALL_SIZE	256
#define MY_LOOPS_MIN		\
	max_t(unsigned long, 1000UL, (PAGE_SIZE / MY_FRAG_SMALL_SIZE) + 1)
#define MY_LOOPS_MAX		10000000UL

/* Makes tests selectable. Useful for perf-record to analyze a single test.
 * Hint: Bash shells support writing binary number like: $((2#101010))
 *
 * # insmod bench_page_pool.ko run_flags=$((1 << 0))
 */
static unsigned long run_flags = ULONG_MAX;
module_param(run_flags, ulong, 0);
MODULE_PARM_DESC(run_flags, "Bitmask limiting which benchmark groups run");

/* Count the bit number from the enum */
enum benchmark_bit {
	bit_run_bench_bh_fast,
	bit_run_bench_bh_ring_slow,
	bit_run_bench_high_order,
	bit_run_bench_frag,
	bit_run_bench_dma,
	bit_run_bench_bulk,
	bit_run_bench_skb,
};

#define enabled(b)	(run_flags & BIT(b))

static unsigned long loops = 1000000;
module_param(loops, ulong, 0);
MODULE_PARM_DESC(loops, "Specify loops bench will run");

static int bench_failures;
static int bench_skips;

enum test_type {
	type_fast_path,
	type_napi_local_cpuid,
	type_napi_local_ptr,
	type_ptr_ring,
	type_page_allocator,
};

struct pp_bench_cfg {
	const char *name;
	enum test_type type;
	unsigned int order;
	unsigned int flags;
	struct device *dev;
	bool use_init_cb;
};

struct pp_overflow_cfg {
	const char *name;
	unsigned int pool_size;
	unsigned int batch_size;
	unsigned int min_batches;
	u32 expect_mask;
	bool recycle_direct;
};

static u32 scale_slow_loops(u32 nr_loops, u32 div)
{
	return max_t(u32, nr_loops / div, (u32)MY_LOOPS_MIN);
}

static void run_bench_case(u32 nr_loops, int step, const char *name, void *data,
			   int (*func)(struct time_bench_record *rec,
				       void *data))
{
	int ret = time_bench_loop(nr_loops, step, name, data, func);

	if (ret < 0) {
		pr_err("FAIL: benchmark %s failed\n", name);
		bench_failures++;
	} else if (ret > 0) {
		bench_skips++;
	}
	cond_resched();
}

enum pp_stat_mask {
	PP_EXPECT_ALLOC_FAST		= BIT(0),
	PP_EXPECT_ALLOC_SLOW		= BIT(1),
	PP_EXPECT_ALLOC_EMPTY		= BIT(2),
	PP_EXPECT_ALLOC_REFILL		= BIT(3),
	PP_EXPECT_RECYCLE_CACHED	= BIT(4),
	PP_EXPECT_RECYCLE_CACHE_FULL	= BIT(5),
	PP_EXPECT_RECYCLE_RING		= BIT(6),
	PP_EXPECT_RECYCLE_RING_FULL	= BIT(7),
	PP_EXPECT_RECYCLE_RELEASED	= BIT(8),
};

struct pp_stats_snap {
#ifdef CONFIG_PAGE_POOL_STATS
	struct page_pool_stats stats;
#endif
};

#ifdef CONFIG_PAGE_POOL_STATS
static void pp_snapshot_stats(const struct page_pool *pp,
			      struct pp_stats_snap *snap)
{
	memset(&snap->stats, 0, sizeof(snap->stats));
	page_pool_get_stats(pp, &snap->stats);
}

static bool pp_verify_ethtool_stats(const struct page_pool_stats *stats,
				    const char *name)
{
	bool found_fast = false, found_cached = false, found_ring = false;
	int i, nstats = page_pool_ethtool_stats_get_count();
	bool ok = true;
	u64 *vals;
	u8 *strs;

	if (nstats <= 0) {
		pr_err("%s: invalid ethtool stats count %d\n", name, nstats);
		return false;
	}

	strs = kcalloc(nstats, ETH_GSTRING_LEN, GFP_KERNEL);
	vals = kcalloc(nstats, sizeof(*vals), GFP_KERNEL);
	if (!strs || !vals) {
		pr_err("%s: failed to allocate ethtool stats buffers\n", name);
		kfree(vals);
		kfree(strs);
		return false;
	}

	page_pool_ethtool_stats_get_strings(strs);
	page_pool_ethtool_stats_get(vals, stats);
	for (i = 0; i < nstats; i++) {
		const char *s = (const char *)(strs + i * ETH_GSTRING_LEN);

		if (!strncmp(s, "rx_pp_alloc_fast", ETH_GSTRING_LEN)) {
			found_fast = true;
			if (vals[i] != stats->alloc_stats.fast)
				ok = false;
		} else if (!strncmp(s, "rx_pp_recycle_cached",
				    ETH_GSTRING_LEN)) {
			found_cached = true;
			if (vals[i] != stats->recycle_stats.cached)
				ok = false;
		} else if (!strncmp(s, "rx_pp_recycle_ring", ETH_GSTRING_LEN)) {
			found_ring = true;
			if (vals[i] != stats->recycle_stats.ring)
				ok = false;
		}
	}

	if (!ok || !found_fast || !found_cached || !found_ring) {
		pr_err("%s: ethtool stats mismatch\n", name);
		ok = false;
	}

	kfree(vals);
	kfree(strs);
	return ok;
}

static bool pp_verify_stats(const struct page_pool *pp, const char *name,
			    const struct pp_stats_snap *before,
			    u32 expect_mask, u32 forbid_mask)
{
	struct page_pool_stats after = {};
	u64 fast, slow, slow_ho, empty, refill;
	u64 cached, cache_full, ring, ring_full, released;
	u32 seen = 0, strict_forbid;
	bool ok;

	page_pool_get_stats(pp, &after);
	ok = pp_verify_ethtool_stats(&after, name);

	fast = after.alloc_stats.fast - before->stats.alloc_stats.fast;
	slow = after.alloc_stats.slow - before->stats.alloc_stats.slow;
	slow_ho = after.alloc_stats.slow_high_order -
		  before->stats.alloc_stats.slow_high_order;
	slow += slow_ho;
	empty = after.alloc_stats.empty - before->stats.alloc_stats.empty;
	refill = after.alloc_stats.refill - before->stats.alloc_stats.refill;
	cached = after.recycle_stats.cached -
		 before->stats.recycle_stats.cached;
	cache_full = after.recycle_stats.cache_full -
		     before->stats.recycle_stats.cache_full;
	ring = after.recycle_stats.ring - before->stats.recycle_stats.ring;
	ring_full = after.recycle_stats.ring_full -
		    before->stats.recycle_stats.ring_full;
	released = after.recycle_stats.released_refcnt -
		   before->stats.recycle_stats.released_refcnt;

	if (fast)
		seen |= PP_EXPECT_ALLOC_FAST;
	if (slow)
		seen |= PP_EXPECT_ALLOC_SLOW;
	if (empty)
		seen |= PP_EXPECT_ALLOC_EMPTY;
	if (refill)
		seen |= PP_EXPECT_ALLOC_REFILL;
	if (cached)
		seen |= PP_EXPECT_RECYCLE_CACHED;
	if (cache_full)
		seen |= PP_EXPECT_RECYCLE_CACHE_FULL;
	if (ring)
		seen |= PP_EXPECT_RECYCLE_RING;
	if (ring_full)
		seen |= PP_EXPECT_RECYCLE_RING_FULL;
	if (released)
		seen |= PP_EXPECT_RECYCLE_RELEASED;

	strict_forbid = forbid_mask & ~PP_EXPECT_ALLOC_SLOW;
	if ((seen & expect_mask) != expect_mask || (seen & strict_forbid))
		ok = false;

	/*
	 * Tolerate isolated slow-path fallbacks (e.g., NUMA fallback or
	 * pfmemalloc under memory pressure) while still failing if slow
	 * allocations dominate fast/refill traffic (for both order-0 and
	 * high-order pools).
	 */
	if ((forbid_mask & PP_EXPECT_ALLOC_SLOW) &&
	    slow * PP_ALLOC_CACHE_REFILL > (fast + refill) / 2)
		ok = false;

	if (!ok) {
		pr_err("%s: unexpected stats delta expect=0x%x forbid=0x%x seen=0x%x fast=%llu slow=%llu(ho=%llu) empty=%llu refill=%llu cached=%llu cache_full=%llu ring=%llu ring_full=%llu released=%llu\n",
		       name, expect_mask, forbid_mask, seen, fast, slow,
		       slow_ho, empty, refill, cached, cache_full, ring,
		       ring_full, released);
	}
	return ok;
}
#else
static void pp_snapshot_stats(const struct page_pool *pp,
			      struct pp_stats_snap *snap)
{
}

static bool pp_verify_stats(const struct page_pool *pp, const char *name,
			    const struct pp_stats_snap *before,
			    u32 expect_mask, u32 forbid_mask)
{
	return true;
}
#endif

static void pp_bh_yield(void)
{
	local_bh_enable();
	cond_resched();
	local_bh_disable();
}

static void pp_init_cb(netmem_ref netmem, void *arg)
{
	atomic_long_t *cnt = arg;

	atomic_long_inc(cnt);
}

static int pp_fill_ptr_ring(struct page_pool *pp, int elems, gfp_t gfp)
{
	bool blocking = gfpflags_allow_blocking(gfp);
	netmem_ref *array;
	int i, allocated = 0;

	array = kcalloc(elems, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	if (!blocking)
		local_bh_disable();
	for (i = 0; i < elems; i++) {
		array[i] = page_pool_alloc_netmems(pp, gfp);
		if (!array[i])
			break;
		allocated++;
	}
	if (blocking)
		local_bh_disable();
	for (i = 0; i < allocated; i++)
		page_pool_put_unrefed_netmem(pp, array[i], -1, false);
	local_bh_enable();

	kfree(array);
	return allocated == elems ? 0 : -EAGAIN;
}

static int time_bench_page_pool_cfg(struct time_bench_record *rec, void *data)
{
	const struct pp_bench_cfg *cfg = data;
	unsigned int offset =
		(cfg->flags & PP_FLAG_DMA_SYNC_DEV) ? NET_SKB_PAD : 0;
	struct page_pool_params pp_params = {
		.order = cfg->order,
		.flags = cfg->flags,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dev = cfg->dev,
		.dma_dir = DMA_BIDIRECTIONAL,
		.max_len = (PAGE_SIZE << cfg->order) - offset,
		.offset = offset,
	};
	gfp_t fill_gfp = (cfg->flags & PP_FLAG_DMA_MAP) ? GFP_ATOMIC :
			 cfg->order ? (GFP_KERNEL | __GFP_NORETRY |
				       __GFP_NOWARN | __GFP_THISNODE) :
			 GFP_KERNEL;
	struct napi_struct dummy_napi = {
		.list_owner = -1,
	};
	struct pp_stats_snap before;
	atomic_long_t init_cb_cnt;
	u32 expect_mask = 0, forbid_mask = 0;
	bool alloc_failed = false;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	netmem_ref netmem;
	int fill_err;
	u32 i;

	atomic_long_set(&init_cb_cnt, 0);
	if (cfg->use_init_cb) {
		pp_params.init_callback = pp_init_cb;
		pp_params.init_arg = &init_cb_cnt;
	}

	if (cfg->type == type_napi_local_cpuid)
		pp = page_pool_create_percpu(&pp_params,
					     raw_smp_processor_id());
	else
		pp = page_pool_create(&pp_params);
	if (IS_ERR(pp)) {
		pr_err("%s: Error(%ld) creating page_pool\n", cfg->name,
		       PTR_ERR(pp));
		return 0;
	}

	if (cfg->type == type_napi_local_ptr)
		page_pool_enable_direct_recycling(pp, &dummy_napi);

	fill_err = pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL, fill_gfp);
	if (fill_err) {
		if (cfg->order && fill_err == -EAGAIN)
			goto out_skip;
		pr_err("ERR: %s: failed to prefill ptr_ring (%d)\n",
		       cfg->name, fill_err);
		loops_cnt = 0;
		goto out_disable;
	}

	atomic_long_set(&init_cb_cnt, 0);
	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	if (cfg->type == type_napi_local_cpuid)
		WRITE_ONCE(pp->cpuid, smp_processor_id());
	else if (cfg->type == type_napi_local_ptr)
		WRITE_ONCE(dummy_napi.list_owner, smp_processor_id());

	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		if (unlikely((i & 0xffff) == 0 && i)) {
			if (cfg->type == type_napi_local_ptr)
				WRITE_ONCE(dummy_napi.list_owner, -1);
			pp_bh_yield();
			if (cfg->type == type_napi_local_cpuid)
				WRITE_ONCE(pp->cpuid, smp_processor_id());
			else if (cfg->type == type_napi_local_ptr)
				WRITE_ONCE(dummy_napi.list_owner,
					   smp_processor_id());
		}

		netmem = page_pool_alloc_netmems(pp, GFP_ATOMIC);
		if (unlikely(!netmem)) {
			alloc_failed = true;
			break;
		}
		loops_cnt++;
		barrier();

		if (cfg->flags & PP_FLAG_DMA_MAP) {
			dma_addr_t dma = page_pool_get_dma_addr_netmem(netmem);

			if (unlikely(dma_mapping_error(cfg->dev, dma))) {
				page_pool_put_full_netmem(pp, netmem, false);
				loops_cnt = 0;
				break;
			}
			page_pool_dma_sync_netmem_for_cpu(pp, netmem, 0, 64);
		}

		switch (cfg->type) {
		case type_fast_path:
			page_pool_recycle_direct_netmem(pp, netmem);
			break;
		case type_napi_local_cpuid:
		case type_napi_local_ptr:
		case type_ptr_ring:
			page_pool_put_full_netmem(pp, netmem, false);
			break;
		case type_page_allocator:
			get_page(netmem_to_page(netmem));
			page_pool_put_full_netmem(pp, netmem, false);
			put_page(netmem_to_page(netmem));
			break;
		}
	}
	time_bench_stop(rec, loops_cnt);

	if (cfg->type == type_napi_local_ptr)
		WRITE_ONCE(dummy_napi.list_owner, -1);
	local_bh_enable();

	if (loops_cnt < rec->loops) {
		if (cfg->order && alloc_failed)
			goto out_skip;
		loops_cnt = 0;
		goto out_disable;
	}

	if (cfg->type == type_fast_path) {
		expect_mask = PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED;
		forbid_mask = PP_EXPECT_RECYCLE_RING | PP_EXPECT_ALLOC_SLOW;
	} else if (cfg->type == type_napi_local_cpuid ||
		   cfg->type == type_napi_local_ptr) {
		if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
			expect_mask = PP_EXPECT_ALLOC_FAST |
				      PP_EXPECT_RECYCLE_CACHED;
			forbid_mask = PP_EXPECT_RECYCLE_RING |
				      PP_EXPECT_ALLOC_SLOW;
		} else {
			expect_mask = PP_EXPECT_RECYCLE_RING;
		}
	} else if (cfg->type == type_ptr_ring) {
		expect_mask = PP_EXPECT_ALLOC_REFILL | PP_EXPECT_RECYCLE_RING;
		forbid_mask = PP_EXPECT_RECYCLE_CACHED | PP_EXPECT_ALLOC_SLOW;
	} else if (cfg->type == type_page_allocator) {
		expect_mask = PP_EXPECT_RECYCLE_RELEASED | PP_EXPECT_ALLOC_SLOW;
		forbid_mask = PP_EXPECT_RECYCLE_CACHED | PP_EXPECT_RECYCLE_RING;
		if (cfg->use_init_cb && !atomic_long_read(&init_cb_cnt)) {
			pr_err("%s: init_callback never invoked\n", cfg->name);
			loops_cnt = 0;
		}
	}

	if (!pp_verify_stats(pp, cfg->name, &before, expect_mask, forbid_mask))
		loops_cnt = 0;

out_disable:
	if (cfg->type == type_napi_local_ptr ||
	    cfg->type == type_napi_local_cpuid) {
		struct pp_stats_snap before_disable;

		pp_snapshot_stats(pp, &before_disable);
		page_pool_disable_direct_recycling(pp);
		if (loops_cnt) {
			local_bh_disable();
			if (cfg->type == type_napi_local_ptr)
				WRITE_ONCE(dummy_napi.list_owner,
					   smp_processor_id());
			netmem = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (netmem)
				page_pool_put_full_netmem(pp, netmem, false);
			if (cfg->type == type_napi_local_ptr)
				WRITE_ONCE(dummy_napi.list_owner, -1);
			local_bh_enable();
			if (!netmem ||
			    !pp_verify_stats(pp, cfg->name, &before_disable,
					     PP_EXPECT_RECYCLE_RING,
					     PP_EXPECT_RECYCLE_CACHED))
				loops_cnt = 0;
		}
	}
	page_pool_destroy(pp);
	if (!loops_cnt)
		rec->invoked_cnt = 0;
	return loops_cnt;

out_skip:
	pr_info("SKIP: %s: order-%u pages unavailable\n",
		cfg->name, cfg->order);
	if (cfg->type == type_napi_local_ptr)
		page_pool_disable_direct_recycling(pp);
	page_pool_destroy(pp);
	return -EAGAIN;
}

static const struct pp_bench_cfg cfg_bh_fast_direct = {
	.name = "bh-fast-recycle-direct",
	.type = type_fast_path,
};

static const struct pp_bench_cfg cfg_bh_napi_cpuid = {
	.name = "bh-fast-napi-cpuid",
	.type = type_napi_local_cpuid,
};

static const struct pp_bench_cfg cfg_bh_napi_ptr = {
	.name = "bh-fast-napi-ptr",
	.type = type_napi_local_ptr,
};

static const struct pp_bench_cfg cfg_bh_ptr_ring = {
	.name = "bh-ptr-ring",
	.type = type_ptr_ring,
};

static const struct pp_bench_cfg cfg_bh_slow_alloc = {
	.name = "bh-slow-page-alloc",
	.type = type_page_allocator,
	.use_init_cb = true,
};

static int time_bench_bh_overflow(struct time_bench_record *rec, void *data)
{
	const struct pp_overflow_cfg *cfg = data;
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = cfg->pool_size,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	netmem_ref *batch;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 outer, j, batches;

	batch = kcalloc(cfg->batch_size, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return 0;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp)) {
		kfree(batch);
		return 0;
	}

	batches = max_t(u32, rec->loops / cfg->batch_size, cfg->min_batches);
	rec->loops = batches * cfg->batch_size;
	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	time_bench_start(rec);
	for (outer = 0; outer < batches; outer++) {
		u32 got = 0;

		if (unlikely((outer & 0xff) == 0 && outer))
			pp_bh_yield();

		for (j = 0; j < cfg->batch_size; j++) {
			batch[j] = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (unlikely(!batch[j]))
				break;
			got++;
		}
		for (j = 0; j < got; j++) {
			if (cfg->recycle_direct)
				page_pool_recycle_direct_netmem(pp, batch[j]);
			else
				page_pool_put_full_netmem(pp, batch[j], false);
		}

		loops_cnt += got;
		if (unlikely(got < cfg->batch_size))
			break;
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, cfg->name, &before, cfg->expect_mask, 0)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	kfree(batch);
	return loops_cnt;
}

static const struct pp_overflow_cfg cfg_bh_cache_overflow = {
	.name = "bh-cache-overflow-refill",
	.pool_size = MY_POOL_SIZE,
	.batch_size = MY_OVERFLOW_BATCH,
	.min_batches = 8,
	.recycle_direct = true,
	.expect_mask = PP_EXPECT_ALLOC_FAST | PP_EXPECT_ALLOC_REFILL |
		       PP_EXPECT_RECYCLE_CACHED | PP_EXPECT_RECYCLE_CACHE_FULL |
		       PP_EXPECT_RECYCLE_RING,
};

static const struct pp_overflow_cfg cfg_bh_ring_full = {
	.name = "bh-ring-full-return",
	.pool_size = MY_RING_SMALL_SIZE,
	.batch_size = MY_RING_OVERFLOW_BATCH,
	.min_batches = 16,
	.recycle_direct = false,
	.expect_mask = PP_EXPECT_ALLOC_EMPTY | PP_EXPECT_ALLOC_SLOW |
		       PP_EXPECT_RECYCLE_RING | PP_EXPECT_RECYCLE_RING_FULL,
};

static const struct pp_bench_cfg cfg_high_order_fast = {
	.name = "bh-high-order-fast",
	.type = type_fast_path,
	.order = MY_HIGH_ORDER,
};

static const struct pp_bench_cfg cfg_high_order_ring = {
	.name = "bh-high-order-ptr-ring",
	.type = type_ptr_ring,
	.order = MY_HIGH_ORDER,
};

/* Fragment allocator: immediate free exercises BIAS_MAX & in-place reset */
static int time_bench_frag_fast_reuse(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int offset;
		netmem_ref netmem;

		if (unlikely((i & 0xffff) == 0 && i))
			pp_bh_yield();

		netmem = page_pool_alloc_frag_netmem(pp, &offset,
						     MY_FRAG_SMALL_SIZE,
						     GFP_ATOMIC);
		if (unlikely(!netmem))
			break;
		loops_cnt++;
		barrier();
		page_pool_put_full_netmem(pp, netmem, true);
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, __func__, &before,
			     PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED,
			     0)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	return loops_cnt;
}

/* Hold one frag across page boundary to exercise slow page_pool_drain_frag();
 * page_pool_destroy() cleans up the active pp->frag_page via
 * page_pool_free_frag().
 */
static int time_bench_frag_slow_drain(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	netmem_ref held = 0;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int offset;
		netmem_ref netmem;

		if (unlikely((i & 0xffff) == 0 && i))
			pp_bh_yield();

		netmem = page_pool_alloc_frag_netmem(pp, &offset, 1024,
						     GFP_ATOMIC);
		if (unlikely(!netmem))
			break;
		loops_cnt++;

		if (offset == 0) {
			if (held)
				page_pool_put_full_netmem(pp, held, true);
			held = netmem;
		} else {
			page_pool_put_full_netmem(pp, netmem, true);
		}
	}
	if (held)
		page_pool_put_full_netmem(pp, held, true);
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, __func__, &before, PP_EXPECT_RECYCLE_CACHED,
			     0)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	return loops_cnt;
}

/* Exercises page_pool_dev_alloc_va(), page_pool_free_va(), tail-room expansion
 * in page_pool_alloc_netmem(), full-page (> PAGE_SIZE/2) branch, and
 * page_pool_ref_page() / page_pool_unref_page().
 */
static int time_bench_frag_alloc_va(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int size = (i & 7) ? 1536 : (PAGE_SIZE - 512);
		struct page *page;
		void *va;

		if (unlikely((i & 0xffff) == 0 && i))
			pp_bh_yield();

		va = page_pool_dev_alloc_va(pp, &size);
		if (unlikely(!va))
			break;

		page = virt_to_head_page(va);
		page_pool_ref_page(page);
		if (unlikely(!page_pool_unref_page(page, 1))) {
			loops_cnt = 0;
			break;
		}
		loops_cnt++;
		page_pool_free_va(pp, va, true);
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, __func__, &before,
			     PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED,
			     0)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	return loops_cnt;
}

/* Exercise direct DMA mapping, XArray tracking, and DMA sync wrapper checks
 * via a synthetic platform device (matching netdevsim's direct-DMA setup;
 * hardware cache maintenance runs only on !dma_default_coherent architectures,
 * without IOMMU translation overhead).
 */
static void run_dma_benchmarks(u32 nr_loops)
{
	struct platform_device *pdev;
	struct pp_bench_cfg cfg_fast, cfg_ring, cfg_slow;
	int err;

	if (!IS_ENABLED(CONFIG_HAS_DMA)) {
		pr_info("SKIP: DMA benchmarks require CONFIG_HAS_DMA\n");
		bench_skips += 3;
		return;
	}

	pdev = platform_device_register_simple("pp_bench_dma",
					       PLATFORM_DEVID_NONE, NULL, 0);
	if (IS_ERR(pdev)) {
		pr_info("SKIP: DMA benchmarks skipped (pdev register failed: %ld)\n",
			PTR_ERR(pdev));
		bench_skips += 3;
		return;
	}

	if (!dma_pci_p2pdma_supported(&pdev->dev)) {
		pr_info("SKIP: DMA benchmarks require direct DMA ops\n");
		platform_device_unregister(pdev);
		bench_skips += 3;
		return;
	}

	err = dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		pr_info("SKIP: DMA benchmarks skipped (DMA mask failed: %d)\n",
			err);
		platform_device_unregister(pdev);
		bench_skips += 3;
		return;
	}

	cfg_fast = (struct pp_bench_cfg){
		.name = "bh-dma-fast-sync",
		.type = type_fast_path,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &pdev->dev,
	};
	cfg_ring = (struct pp_bench_cfg){
		.name = "bh-dma-ptr-ring-sync",
		.type = type_ptr_ring,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &pdev->dev,
	};
	cfg_slow = (struct pp_bench_cfg){
		.name = "bh-dma-slow-map-unmap",
		.type = type_page_allocator,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &pdev->dev,
	};

	run_bench_case(nr_loops, 0, cfg_fast.name, &cfg_fast,
		       time_bench_page_pool_cfg);
	run_bench_case(nr_loops, 0, cfg_ring.name, &cfg_ring,
		       time_bench_page_pool_cfg);
	run_bench_case(scale_slow_loops(nr_loops, 16), 0, cfg_slow.name,
		       &cfg_slow, time_bench_page_pool_cfg);

	platform_device_unregister(pdev);
}

static int time_bench_bulk_single_pool(struct time_bench_record *rec,
				       void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	netmem_ref bulk[MY_BULK_SIZE];
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 outer, j, batches;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	if (pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL, GFP_KERNEL)) {
		page_pool_destroy(pp);
		return 0;
	}

	batches = max_t(u32, rec->loops / MY_BULK_SIZE, 64U);
	rec->loops = batches * MY_BULK_SIZE;
	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	time_bench_start(rec);
	for (outer = 0; outer < batches; outer++) {
		u32 got = 0;

		if (unlikely((outer & 0xfff) == 0 && outer))
			pp_bh_yield();

		for (j = 0; j < MY_BULK_SIZE; j++) {
			bulk[j] = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (unlikely(!bulk[j]))
				break;
			got++;
		}
		if (got)
			page_pool_put_netmem_bulk(bulk, got);
		loops_cnt += got;
		if (unlikely(got < MY_BULK_SIZE))
			break;
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, __func__, &before,
			     PP_EXPECT_ALLOC_REFILL | PP_EXPECT_RECYCLE_RING,
			     PP_EXPECT_RECYCLE_CACHED | PP_EXPECT_ALLOC_SLOW)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	return loops_cnt;
}

static int time_bench_skb_recycle_linear(struct time_bench_record *rec,
					 void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct pp_stats_snap before;
	u32 expect_mask, forbid_mask = 0;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create_percpu(&pp_params, raw_smp_processor_id());
	if (IS_ERR(pp))
		return 0;

	if (pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL, GFP_KERNEL)) {
		page_pool_destroy(pp);
		return 0;
	}

	pp_snapshot_stats(pp, &before);

	local_bh_disable();
	WRITE_ONCE(pp->cpuid, smp_processor_id());
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int truesize = PAGE_SIZE;
		struct sk_buff *skb;
		void *va;

		if (unlikely((i & 0xffff) == 0 && i)) {
			pp_bh_yield();
			WRITE_ONCE(pp->cpuid, smp_processor_id());
		}

		/* Request a full page so page_pool_alloc_netmem() takes the
		 * whole-page path (pp_ref_count == 1) and napi_consume_skb()
		 * exercises skb_pp_recycle() -> napi_pp_put_page().
		 */
		va = page_pool_dev_alloc_va(pp, &truesize);
		if (unlikely(!va))
			break;
		skb = napi_build_skb(va, truesize);
		if (unlikely(!skb)) {
			page_pool_free_va(pp, va, true);
			break;
		}
		skb_mark_for_recycle(skb);
		skb_put(skb, 64);
		loops_cnt++;
		napi_consume_skb(skb, 64);
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
		expect_mask = PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED;
		forbid_mask = PP_EXPECT_RECYCLE_RING | PP_EXPECT_ALLOC_SLOW;
	} else {
		expect_mask = PP_EXPECT_RECYCLE_RING;
	}

	if (loops_cnt < rec->loops ||
	    !pp_verify_stats(pp, __func__, &before, expect_mask, forbid_mask)) {
		loops_cnt = 0;
		rec->invoked_cnt = 0;
	}

	page_pool_destroy(pp);
	return loops_cnt;
}

static int run_benchmark_tests(void)
{
	u32 nr_loops = loops;

	/* BH / NAPI-local fast-path recycling */
	if (enabled(bit_run_bench_bh_fast)) {
		run_bench_case(nr_loops, 0, cfg_bh_fast_direct.name,
			       (void *)&cfg_bh_fast_direct,
			       time_bench_page_pool_cfg);
		run_bench_case(nr_loops, 0, cfg_bh_napi_cpuid.name,
			       (void *)&cfg_bh_napi_cpuid,
			       time_bench_page_pool_cfg);
		run_bench_case(nr_loops, 0, cfg_bh_napi_ptr.name,
			       (void *)&cfg_bh_napi_ptr,
			       time_bench_page_pool_cfg);
	}

	/* BH ptr_ring, cache_full refill, ring_full overflow, and slow alloc */
	if (enabled(bit_run_bench_bh_ring_slow)) {
		run_bench_case(nr_loops, 0, cfg_bh_ptr_ring.name,
			       (void *)&cfg_bh_ptr_ring,
			       time_bench_page_pool_cfg);
		run_bench_case(roundup(nr_loops, MY_OVERFLOW_BATCH),
			       MY_OVERFLOW_BATCH, cfg_bh_cache_overflow.name,
			       (void *)&cfg_bh_cache_overflow,
			       time_bench_bh_overflow);
		run_bench_case(roundup(scale_slow_loops(nr_loops, 16),
				       MY_RING_OVERFLOW_BATCH),
			       MY_RING_OVERFLOW_BATCH, cfg_bh_ring_full.name,
			       (void *)&cfg_bh_ring_full,
			       time_bench_bh_overflow);
		run_bench_case(scale_slow_loops(nr_loops, 16), 0,
			       cfg_bh_slow_alloc.name,
			       (void *)&cfg_bh_slow_alloc,
			       time_bench_page_pool_cfg);
	}

	/* High-order compound pages (order=2) */
	if (enabled(bit_run_bench_high_order)) {
		run_bench_case(nr_loops, 0, cfg_high_order_fast.name,
			       (void *)&cfg_high_order_fast,
			       time_bench_page_pool_cfg);
		run_bench_case(nr_loops, 0, cfg_high_order_ring.name,
			       (void *)&cfg_high_order_ring,
			       time_bench_page_pool_cfg);
	}

	/* Fragment allocation & sub-page refcounting */
	if (enabled(bit_run_bench_frag)) {
		run_bench_case(nr_loops, 0, "bh-frag-fast-reuse", NULL,
			       time_bench_frag_fast_reuse);
		run_bench_case(nr_loops, 0, "bh-frag-slow-drain", NULL,
			       time_bench_frag_slow_drain);
		run_bench_case(nr_loops, 0, "bh-frag-alloc-va", NULL,
			       time_bench_frag_alloc_va);
	}

	/* DMA mapping, XArray tracking, and DMA sync */
	if (enabled(bit_run_bench_dma))
		run_dma_benchmarks(nr_loops);

	/* Bulk return API */
	if (enabled(bit_run_bench_bulk)) {
		u32 bulk_loops = roundup(nr_loops, MY_BULK_SIZE);

		run_bench_case(bulk_loops, MY_BULK_SIZE, "bh-bulk-single-pool",
			       NULL, time_bench_bulk_single_pool);
	}

	/* SKB pp_recycle head_frag recycling */
	if (enabled(bit_run_bench_skb)) {
		run_bench_case(nr_loops, 0, "bh-skb-recycle-linear", NULL,
			       time_bench_skb_recycle_linear);
	}

	if (bench_failures) {
		pr_err("Completed with %d benchmark failure(s) (%d skipped)\n",
		       bench_failures, bench_skips);
		return -EINVAL;
	}

	pr_info("All page_pool benchmarks passed (%d skipped)\n", bench_skips);
	return 0;
}

static int __init bench_page_pool_simple_module_init(void)
{
	if (verbose)
		pr_info("Loaded\n");

	if (loops < MY_LOOPS_MIN || loops > MY_LOOPS_MAX) {
		pr_err("Module param loops(%lu) out of range [%lu, %lu]\n",
		       loops, MY_LOOPS_MIN, MY_LOOPS_MAX);
		return -ECHRNG;
	}

	return run_benchmark_tests();
}
module_init(bench_page_pool_simple_module_init);

static void __exit bench_page_pool_simple_module_exit(void)
{
	if (verbose)
		pr_info("Unloaded\n");
}
module_exit(bench_page_pool_simple_module_exit);

MODULE_DESCRIPTION("Benchmark and coverage suite for page_pool");
MODULE_AUTHOR("Jesper Dangaard Brouer <netoptimizer@brouer.com>");
MODULE_LICENSE("GPL");
