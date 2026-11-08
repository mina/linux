// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark and coverage module for page_pool.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/dma-mapping.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/numa.h>
#include <linux/platform_device.h>
#include <linux/ptr_ring.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
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

/* Notice time_bench is limited to U32_MAX nr loops */
static unsigned long loops = 1000000;
module_param(loops, ulong, 0);
MODULE_PARM_DESC(loops, "Specify loops bench will run");

static struct platform_device *bench_dma_pdev;
static int bench_failures;

enum test_type {
	type_fast_path,
	type_napi_local_cpuid,
	type_napi_local_ptr,
	type_ptr_ring,
	type_page_allocator,
};

struct pp_bench_cfg {
	enum test_type type;
	unsigned int order;
	unsigned int flags;
	struct device *dev;
	bool use_init_cb;
};

static u32 scale_slow_loops(u32 nr_loops, u32 div)
{
	return max_t(u32, nr_loops / div, 4096U);
}

static void run_bench_case(u32 nr_loops, int step, const char *name, void *data,
			   int (*func)(struct time_bench_record *rec,
				       void *data))
{
	if (!time_bench_loop(nr_loops, step, name, data, func)) {
		pr_err("FAIL: benchmark %s failed\n", name);
		bench_failures++;
	}
	cond_resched();
}

#ifdef CONFIG_PAGE_POOL_STATS
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

static bool pp_verify_stats(const struct page_pool *pp, const char *name,
			    u32 expect_mask)
{
	struct page_pool_stats stats = {};
	int nstats;
	u64 *vals;
	u8 *strs;
	bool ok = true;

	page_pool_get_stats(pp, &stats);

	nstats = page_pool_ethtool_stats_get_count();
	if (nstats <= 0) {
		pr_err("%s: invalid ethtool stats count %d\n", name, nstats);
		return false;
	}

	strs = kcalloc(nstats, ETH_GSTRING_LEN, GFP_KERNEL);
	vals = kcalloc(nstats, sizeof(*vals), GFP_KERNEL);
	if (strs && vals) {
		page_pool_ethtool_stats_get_strings(strs);
		page_pool_ethtool_stats_get(vals, &stats);
		if (vals[0] != stats.alloc_stats.fast ||
		    vals[6] != stats.recycle_stats.cached ||
		    vals[8] != stats.recycle_stats.ring) {
			pr_err("%s: ethtool stats mismatch\n", name);
			ok = false;
		}
	}
	kfree(vals);
	kfree(strs);

	if ((expect_mask & PP_EXPECT_ALLOC_FAST) && !stats.alloc_stats.fast)
		ok = false;
	if ((expect_mask & PP_EXPECT_ALLOC_SLOW) && !stats.alloc_stats.slow)
		ok = false;
	if ((expect_mask & PP_EXPECT_ALLOC_EMPTY) && !stats.alloc_stats.empty)
		ok = false;
	if ((expect_mask & PP_EXPECT_ALLOC_REFILL) && !stats.alloc_stats.refill)
		ok = false;
	if ((expect_mask & PP_EXPECT_RECYCLE_CACHED) &&
	    !stats.recycle_stats.cached)
		ok = false;
	if ((expect_mask & PP_EXPECT_RECYCLE_CACHE_FULL) &&
	    !stats.recycle_stats.cache_full)
		ok = false;
	if ((expect_mask & PP_EXPECT_RECYCLE_RING) && !stats.recycle_stats.ring)
		ok = false;
	if ((expect_mask & PP_EXPECT_RECYCLE_RING_FULL) &&
	    !stats.recycle_stats.ring_full)
		ok = false;
	if ((expect_mask & PP_EXPECT_RECYCLE_RELEASED) &&
	    !stats.recycle_stats.released_refcnt)
		ok = false;

	if (!ok) {
		pr_err("%s: unexpected stats mask=0x%x fast=%llu slow=%llu empty=%llu refill=%llu cached=%llu cache_full=%llu ring=%llu ring_full=%llu released=%llu\n",
		       name, expect_mask, stats.alloc_stats.fast,
		       stats.alloc_stats.slow, stats.alloc_stats.empty,
		       stats.alloc_stats.refill, stats.recycle_stats.cached,
		       stats.recycle_stats.cache_full,
		       stats.recycle_stats.ring, stats.recycle_stats.ring_full,
		       stats.recycle_stats.released_refcnt);
	}
	return ok;
}
#else
enum pp_stat_mask {
	PP_EXPECT_ALLOC_FAST		= 0,
	PP_EXPECT_ALLOC_SLOW		= 0,
	PP_EXPECT_ALLOC_EMPTY		= 0,
	PP_EXPECT_ALLOC_REFILL		= 0,
	PP_EXPECT_RECYCLE_CACHED	= 0,
	PP_EXPECT_RECYCLE_CACHE_FULL	= 0,
	PP_EXPECT_RECYCLE_RING		= 0,
	PP_EXPECT_RECYCLE_RING_FULL	= 0,
	PP_EXPECT_RECYCLE_RELEASED	= 0,
};

static bool pp_verify_stats(const struct page_pool *pp, const char *name,
			    u32 expect_mask)
{
	return true;
}
#endif

static void pp_init_cb(netmem_ref netmem, void *arg)
{
	atomic_long_t *cnt = arg;

	atomic_long_inc(cnt);
}

static int pp_fill_ptr_ring(struct page_pool *pp, int elems)
{
	netmem_ref *array;
	int i, allocated = 0;

	array = kcalloc(elems, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	local_bh_disable();
	for (i = 0; i < elems; i++) {
		array[i] = page_pool_alloc_netmems(pp, GFP_ATOMIC);
		if (!array[i])
			break;
		allocated++;
	}
	for (i = 0; i < allocated; i++)
		page_pool_put_unrefed_netmem(pp, array[i], -1, false);
	local_bh_enable();

	kfree(array);
	return allocated == elems ? 0 : -ENOMEM;
}

static int time_bench_page_pool_cfg(struct time_bench_record *rec,
				    const struct pp_bench_cfg *cfg,
				    const char *func)
{
	struct page_pool_params pp_params = {
		.order = cfg->order,
		.flags = cfg->flags,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dev = cfg->dev,
		.dma_dir = DMA_BIDIRECTIONAL,
		.max_len = PAGE_SIZE << cfg->order,
		.offset = (cfg->flags & PP_FLAG_DMA_SYNC_DEV) ? NET_SKB_PAD : 0,
	};
	struct napi_struct dummy_napi = {};
	atomic_long_t init_cb_cnt;
	struct page_pool *pp;
	u32 expect_mask = 0;
	u64 loops_cnt = 0;
	netmem_ref netmem;
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
		pr_err("%s: Error(%ld) creating page_pool\n", func,
		       PTR_ERR(pp));
		return 0;
	}

	if (cfg->type == type_napi_local_ptr)
		page_pool_enable_direct_recycling(pp, &dummy_napi);

	if (pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL)) {
		loops_cnt = 0;
		goto out_disable;
	}

	local_bh_disable();
	if (cfg->type == type_napi_local_cpuid)
		WRITE_ONCE(pp->cpuid, smp_processor_id());
	else if (cfg->type == type_napi_local_ptr)
		WRITE_ONCE(dummy_napi.list_owner, smp_processor_id());

	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		netmem = page_pool_alloc_netmems(pp, GFP_ATOMIC);
		if (unlikely(!netmem))
			break;
		loops_cnt++;
		barrier();

		if (cfg->flags & PP_FLAG_DMA_MAP) {
			if (unlikely(!page_pool_get_dma_addr_netmem(netmem))) {
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

	if (!loops_cnt)
		goto out_disable;

	if (cfg->type == type_fast_path) {
		expect_mask = PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED;
	} else if ((cfg->type == type_napi_local_cpuid ||
		    cfg->type == type_napi_local_ptr) &&
		   !IS_ENABLED(CONFIG_PREEMPT_RT)) {
		expect_mask = PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED;
	} else if (cfg->type == type_ptr_ring) {
		expect_mask = PP_EXPECT_ALLOC_REFILL | PP_EXPECT_RECYCLE_RING;
	} else if (cfg->type == type_page_allocator) {
		expect_mask = PP_EXPECT_RECYCLE_RELEASED | PP_EXPECT_ALLOC_SLOW;
		if (cfg->use_init_cb && !atomic_long_read(&init_cb_cnt)) {
			pr_err("%s: init_callback never invoked\n", func);
			loops_cnt = 0;
		}
	}

	if (!pp_verify_stats(pp, func, expect_mask))
		loops_cnt = 0;

out_disable:
	if (cfg->type == type_napi_local_ptr ||
	    cfg->type == type_napi_local_cpuid) {
		page_pool_disable_direct_recycling(pp);
		if (loops_cnt) {
			local_bh_disable();
			netmem = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (netmem)
				page_pool_put_full_netmem(pp, netmem, false);
			local_bh_enable();
			if (!pp_verify_stats(pp, func, PP_EXPECT_RECYCLE_RING))
				loops_cnt = 0;
		}
	}
	page_pool_destroy(pp);
	return loops_cnt;
}

static int time_bench_bh_fast_direct(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_fast_path,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bh_napi_cpuid(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_napi_local_cpuid,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bh_napi_ptr(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_napi_local_ptr,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bh_ptr_ring(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_ptr_ring,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bh_slow_alloc(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_page_allocator,
		.use_init_cb = true,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bh_cache_overflow(struct time_bench_record *rec,
					void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	netmem_ref *batch;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 outer, j, batches;

	batch = kcalloc(MY_OVERFLOW_BATCH, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return 0;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp)) {
		kfree(batch);
		return 0;
	}

	batches = max_t(u32, rec->loops / MY_OVERFLOW_BATCH, 8U);
	rec->loops = batches * MY_OVERFLOW_BATCH;

	local_bh_disable();
	time_bench_start(rec);
	for (outer = 0; outer < batches; outer++) {
		u32 got = 0;

		for (j = 0; j < MY_OVERFLOW_BATCH; j++) {
			batch[j] = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (unlikely(!batch[j]))
				break;
			got++;
		}
		for (j = 0; j < got; j++)
			page_pool_recycle_direct_netmem(pp, batch[j]);

		loops_cnt += got;
		if (unlikely(got < MY_OVERFLOW_BATCH))
			break;
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (!pp_verify_stats(pp, __func__,
			     PP_EXPECT_ALLOC_FAST | PP_EXPECT_ALLOC_REFILL |
			     PP_EXPECT_RECYCLE_CACHED |
			     PP_EXPECT_RECYCLE_CACHE_FULL |
			     PP_EXPECT_RECYCLE_RING))
		loops_cnt = 0;

	page_pool_destroy(pp);
	kfree(batch);
	return loops_cnt;
}

static int time_bench_bh_ring_full(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_RING_SMALL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	netmem_ref *batch;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 outer, j, batches;

	batch = kcalloc(MY_RING_OVERFLOW_BATCH, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return 0;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp)) {
		kfree(batch);
		return 0;
	}

	batches = max_t(u32, rec->loops / MY_RING_OVERFLOW_BATCH, 16U);
	rec->loops = batches * MY_RING_OVERFLOW_BATCH;

	local_bh_disable();
	time_bench_start(rec);
	for (outer = 0; outer < batches; outer++) {
		u32 got = 0;

		for (j = 0; j < MY_RING_OVERFLOW_BATCH; j++) {
			batch[j] = page_pool_alloc_netmems(pp, GFP_ATOMIC);
			if (unlikely(!batch[j]))
				break;
			got++;
		}
		for (j = 0; j < got; j++)
			page_pool_put_full_netmem(pp, batch[j], false);

		loops_cnt += got;
		if (unlikely(got < MY_RING_OVERFLOW_BATCH))
			break;
	}
	time_bench_stop(rec, loops_cnt);
	local_bh_enable();

	if (!pp_verify_stats(pp, __func__,
			     PP_EXPECT_ALLOC_EMPTY | PP_EXPECT_ALLOC_SLOW |
			     PP_EXPECT_RECYCLE_RING |
			     PP_EXPECT_RECYCLE_RING_FULL))
		loops_cnt = 0;

	page_pool_destroy(pp);
	kfree(batch);
	return loops_cnt;
}

static int time_bench_high_order_fast(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_fast_path,
		.order = MY_HIGH_ORDER,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_high_order_ring(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_ptr_ring,
		.order = MY_HIGH_ORDER,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

/* Fragment allocator: immediate free exercises BIAS_MAX & in-place reset */
static int time_bench_frag_fast_reuse(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int offset;
		netmem_ref netmem;

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

	if (!pp_verify_stats(pp, __func__,
			     PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED))
		loops_cnt = 0;

	page_pool_destroy(pp);
	return loops_cnt;
}

/* Hold one frag across page boundary to exercise slow page_pool_drain_frag()
 * and leave an active frag_page on destroy to exercise page_pool_free_frag().
 */
static int time_bench_frag_slow_drain(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	netmem_ref held = 0;
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int offset;
		netmem_ref netmem;

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

	/* Leave one unexhausted frag_page cached in pp->frag_page so
	 * page_pool_destroy() exercises page_pool_free_frag().
	 */
	held = page_pool_alloc_frag_netmem(pp, &i, MY_FRAG_SMALL_SIZE,
					   GFP_ATOMIC);
	if (held)
		page_pool_put_full_netmem(pp, held, true);
	local_bh_enable();

	if (!pp_verify_stats(pp, __func__, PP_EXPECT_RECYCLE_CACHED))
		loops_cnt = 0;

	page_pool_destroy(pp);
	return loops_cnt;
}

/* Exercises page_pool_dev_alloc_va(), page_pool_free_va(), tail-room expansion
 * in page_pool_alloc_netmem(), full-page (> PAGE_SIZE/2) branch, and
 * page_pool_ref_netmem() / page_pool_unref_netmem().
 */
static int time_bench_frag_alloc_va(struct time_bench_record *rec, void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	local_bh_disable();
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int size = (i & 7) ? 1536 : (PAGE_SIZE - 512);
		struct page *page;
		void *va;

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

	if (!pp_verify_stats(pp, __func__,
			     PP_EXPECT_ALLOC_FAST | PP_EXPECT_RECYCLE_CACHED))
		loops_cnt = 0;

	page_pool_destroy(pp);
	return loops_cnt;
}

static int time_bench_dma_fast(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_fast_path,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &bench_dma_pdev->dev,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_dma_ptr_ring(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_ptr_ring,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &bench_dma_pdev->dev,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_dma_slow_map(struct time_bench_record *rec, void *data)
{
	struct pp_bench_cfg cfg = {
		.type = type_page_allocator,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dev = &bench_dma_pdev->dev,
	};

	return time_bench_page_pool_cfg(rec, &cfg, __func__);
}

static int time_bench_bulk_single_pool(struct time_bench_record *rec,
				       void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	netmem_ref bulk[MY_BULK_SIZE];
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 outer, j, batches;

	pp = page_pool_create(&pp_params);
	if (IS_ERR(pp))
		return 0;

	if (pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL)) {
		page_pool_destroy(pp);
		return 0;
	}

	batches = max_t(u32, rec->loops / MY_BULK_SIZE, 64U);
	rec->loops = batches * MY_BULK_SIZE;

	local_bh_disable();
	time_bench_start(rec);
	for (outer = 0; outer < batches; outer++) {
		u32 got = 0;

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

	if (!pp_verify_stats(pp, __func__,
			     PP_EXPECT_ALLOC_REFILL | PP_EXPECT_RECYCLE_RING))
		loops_cnt = 0;

	page_pool_destroy(pp);
	return loops_cnt;
}

static int time_bench_skb_recycle_linear(struct time_bench_record *rec,
					 void *data)
{
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = NUMA_NO_NODE,
		.dma_dir = DMA_BIDIRECTIONAL,
	};
	struct page_pool *pp;
	u64 loops_cnt = 0;
	u32 i;

	pp = page_pool_create_percpu(&pp_params, raw_smp_processor_id());
	if (IS_ERR(pp))
		return 0;

	local_bh_disable();
	WRITE_ONCE(pp->cpuid, smp_processor_id());
	time_bench_start(rec);
	for (i = 0; i < rec->loops; i++) {
		unsigned int truesize =
			SKB_DATA_ALIGN(256) +
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
		struct sk_buff *skb;
		void *va;

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

	if (!IS_ENABLED(CONFIG_PREEMPT_RT) &&
	    !pp_verify_stats(pp, __func__, PP_EXPECT_RECYCLE_CACHED))
		loops_cnt = 0;

	page_pool_destroy(pp);
	return loops_cnt;
}

static int run_benchmark_tests(void)
{
	u32 nr_loops = loops;

	/* BH / NAPI-local fast-path recycling */
	if (enabled(bit_run_bench_bh_fast)) {
		run_bench_case(nr_loops, 0, "bh-fast-recycle-direct", NULL,
			       time_bench_bh_fast_direct);
		run_bench_case(nr_loops, 0, "bh-fast-napi-cpuid", NULL,
			       time_bench_bh_napi_cpuid);
		run_bench_case(nr_loops, 0, "bh-fast-napi-ptr", NULL,
			       time_bench_bh_napi_ptr);
	}

	/* BH ptr_ring, cache_full refill, ring_full overflow, and slow alloc */
	if (enabled(bit_run_bench_bh_ring_slow)) {
		run_bench_case(nr_loops, 0, "bh-ptr-ring", NULL,
			       time_bench_bh_ptr_ring);
		run_bench_case(roundup(nr_loops, MY_OVERFLOW_BATCH),
			       MY_OVERFLOW_BATCH, "bh-cache-overflow-refill",
			       NULL, time_bench_bh_cache_overflow);
		run_bench_case(roundup(scale_slow_loops(nr_loops, 16),
				       MY_RING_OVERFLOW_BATCH),
			       MY_RING_OVERFLOW_BATCH, "bh-ring-full-return",
			       NULL, time_bench_bh_ring_full);
		run_bench_case(scale_slow_loops(nr_loops, 16), 0,
			       "bh-slow-page-alloc", NULL,
			       time_bench_bh_slow_alloc);
	}

	/* High-order compound pages (order=2, 16KB) */
	if (enabled(bit_run_bench_high_order)) {
		run_bench_case(nr_loops, 0, "bh-high-order-fast", NULL,
			       time_bench_high_order_fast);
		run_bench_case(nr_loops, 0, "bh-high-order-ptr-ring", NULL,
			       time_bench_high_order_ring);
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
	if (enabled(bit_run_bench_dma)) {
		run_bench_case(nr_loops, 0, "bh-dma-fast-sync", NULL,
			       time_bench_dma_fast);
		run_bench_case(nr_loops, 0, "bh-dma-ptr-ring-sync", NULL,
			       time_bench_dma_ptr_ring);
		run_bench_case(scale_slow_loops(nr_loops, 16), 0,
			       "bh-dma-slow-map-unmap", NULL,
			       time_bench_dma_slow_map);
	}

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
		pr_err("Completed with %d benchmark failure(s)\n",
		       bench_failures);
		return -EINVAL;
	}

	pr_info("All page_pool benchmarks passed\n");
	return 0;
}

static int __init bench_page_pool_simple_module_init(void)
{
	int err;

	if (verbose)
		pr_info("Loaded\n");

	if (loops > U32_MAX / 4) {
		pr_err("Module param loops(%lu) exceeded max(%u)\n", loops,
		       U32_MAX / 4);
		return -ECHRNG;
	}

	bench_dma_pdev = platform_device_register_simple("pp_bench_dma",
							 PLATFORM_DEVID_NONE,
							 NULL, 0);
	if (IS_ERR(bench_dma_pdev))
		return PTR_ERR(bench_dma_pdev);

	err = dma_coerce_mask_and_coherent(&bench_dma_pdev->dev,
					   DMA_BIT_MASK(64));
	if (err) {
		platform_device_unregister(bench_dma_pdev);
		return err;
	}

	err = run_benchmark_tests();
	if (err) {
		platform_device_unregister(bench_dma_pdev);
		return err;
	}

	return 0;
}
module_init(bench_page_pool_simple_module_init);

static void __exit bench_page_pool_simple_module_exit(void)
{
	platform_device_unregister(bench_dma_pdev);
	if (verbose)
		pr_info("Unloaded\n");
}
module_exit(bench_page_pool_simple_module_exit);

MODULE_DESCRIPTION("Benchmark and coverage suite for page_pool");
MODULE_AUTHOR("Jesper Dangaard Brouer <netoptimizer@brouer.com>");
MODULE_LICENSE("GPL");
