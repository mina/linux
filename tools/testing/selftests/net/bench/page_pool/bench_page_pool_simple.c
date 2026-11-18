// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark and coverage module for page_pool.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/ethtool.h>
#include <linux/interrupt.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/topology.h>
#include <net/page_pool/helpers.h>

#include "time_bench.h"

static int verbose = 1;

#define MY_POOL_SIZE		1024
#define MY_LOOPS_MIN		1000UL
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
};

#define enabled(b)	(run_flags & BIT(b))

static unsigned long loops = 1000000;
module_param(loops, ulong, 0);
MODULE_PARM_DESC(loops, "Specify loops bench will run");

static int bench_failures;

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
	bool use_init_cb;
};

static u32 scale_slow_loops(u32 nr_loops, u32 div)
{
	return max_t(u32, nr_loops / div, (u32)MY_LOOPS_MIN);
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

static int pp_fill_ptr_ring(struct page_pool *pp, int elems)
{
	netmem_ref *array;
	int i, allocated = 0;

	array = kcalloc(elems, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	for (i = 0; i < elems; i++) {
		array[i] = page_pool_alloc_netmems(pp, GFP_KERNEL);
		if (!array[i])
			break;
		allocated++;
	}
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
	struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = MY_POOL_SIZE,
		.nid = numa_mem_id(),
		.dma_dir = DMA_BIDIRECTIONAL,
		.max_len = PAGE_SIZE,
	};
	struct napi_struct dummy_napi = {
		.list_owner = -1,
	};
	struct pp_stats_snap before;
	atomic_long_t init_cb_cnt;
	u32 expect_mask = 0, forbid_mask = 0;
	struct page_pool *pp;
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
		pr_err("%s: Error(%ld) creating page_pool\n", cfg->name,
		       PTR_ERR(pp));
		return 0;
	}

	if (cfg->type == type_napi_local_ptr)
		page_pool_enable_direct_recycling(pp, &dummy_napi);

	if (pp_fill_ptr_ring(pp, PP_ALLOC_CACHE_REFILL)) {
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
		if (unlikely(!netmem))
			break;
		loops_cnt++;
		barrier();

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

	/* BH ptr_ring and slow page allocator */
	if (enabled(bit_run_bench_bh_ring_slow)) {
		run_bench_case(nr_loops, 0, cfg_bh_ptr_ring.name,
			       (void *)&cfg_bh_ptr_ring,
			       time_bench_page_pool_cfg);
		run_bench_case(scale_slow_loops(nr_loops, 16), 0,
			       cfg_bh_slow_alloc.name,
			       (void *)&cfg_bh_slow_alloc,
			       time_bench_page_pool_cfg);
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
