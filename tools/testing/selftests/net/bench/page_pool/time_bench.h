/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Benchmarking code execution time inside the kernel
 *
 * Copyright (C) 2014, Red Hat, Inc., Jesper Dangaard Brouer
 *  for licensing details see kernel-base/COPYING
 */
#ifndef _LINUX_TIME_BENCH_H
#define _LINUX_TIME_BENCH_H

#include <linux/timex.h>

/* Main structure used for recording a benchmark run */
struct time_bench_record {
	uint32_t version_abi;
	uint32_t loops;		/* Requested loop invocations */
	uint32_t step;		/* option for e.g. bulk invocations */

	uint32_t flags;		/* Measurements types enabled */
#define TIME_BENCH_LOOP		BIT(0)
#define TIME_BENCH_TSC		BIT(1)
#define TIME_BENCH_WALLCLOCK	BIT(2)
#define TIME_BENCH_PMU		BIT(3)

	uint32_t cpu; /* Used when embedded in time_bench_cpu */

	/* Records */
	uint64_t invoked_cnt;	/* Returned actual invocations */
	uint64_t tsc_start;
	uint64_t tsc_stop;
	struct timespec64 ts_start;
	struct timespec64 ts_stop;
	/* PMU counters for instruction and cycles
	 * instructions counter including pipelined instructions
	 */
	uint64_t pmc_inst_start;
	uint64_t pmc_inst_stop;
	/* CPU unhalted clock counter */
	uint64_t pmc_clk_start;
	uint64_t pmc_clk_stop;

	/* Result records */
	uint64_t tsc_interval;
	uint64_t time_start, time_stop, time_interval; /* in nanosec */
	uint64_t pmc_inst, pmc_clk;

	/* Derived result records */
	uint64_t tsc_cycles; // +decimal?
	uint64_t ns_per_call_quotient, ns_per_call_decimal;
	uint64_t time_sec;
	uint32_t time_sec_remainder;
	uint64_t pmc_ipc_quotient, pmc_ipc_decimal; /* inst per cycle */
};

/* For synchronizing parallel CPUs to run concurrently */
struct time_bench_sync {
	atomic_t nr_tests_running;
	struct completion start_event;
};

/* Keep track of CPUs executing our bench function.
 *
 * Embed a time_bench_record for storing info per cpu
 */
struct time_bench_cpu {
	struct time_bench_record rec;
	struct time_bench_sync *sync; /* back ptr */
	struct task_struct *task;
	/* "data" opaque could have been placed in time_bench_sync,
	 * but to avoid any false sharing, place it per CPU
	 */
	void *data;
	/* Support masking outsome CPUs, mark if it ran */
	bool did_bench_run;
	bool failed;
	/* int cpu; // note CPU stored in time_bench_record */
	int (*bench_func)(struct time_bench_record *record, void *data);
};

/*
 * Use rdtsc_ordered() on x86 when TSC is available so guests without RDTSCP
 * do not fault with #UD; non-TSC architectures rely on wall-clock timing.
 */
#if defined(CONFIG_X86) && !defined(CONFIG_UML)
static __always_inline bool time_bench_has_tsc(void)
{
	return cpu_feature_enabled(X86_FEATURE_TSC);
}

static __always_inline uint64_t tsc_start_clock(void)
{
	if (!time_bench_has_tsc())
		return 0;
	return rdtsc_ordered();
}

static __always_inline uint64_t tsc_stop_clock(void)
{
	if (!time_bench_has_tsc())
		return 0;
	return rdtsc_ordered();
}
#else
static __always_inline bool time_bench_has_tsc(void)
{
	return false;
}

static __always_inline uint64_t tsc_start_clock(void)
{
	return 0;
}

static __always_inline uint64_t tsc_stop_clock(void)
{
	return 0;
}
#endif

/** Wall-clock based **
 *
 * use: getnstimeofday()
 *  getnstimeofday(&rec->ts_start);
 *  getnstimeofday(&rec->ts_stop);
 *
 * API changed see: Documentation/core-api/timekeeping.rst
 *  https://www.kernel.org/doc/html/latest/core-api/timekeeping.html#c.getnstimeofday
 *
 * We should instead use: ktime_get_real_ts64() is a direct
 *  replacement, but consider using monotonic time (ktime_get_ts64())
 *  and/or a ktime_t based interface (ktime_get()/ktime_get_real()).
 */

/** PMU (Performance Monitor Unit) based **
 *
 * Needed for calculating: Instructions Per Cycle (IPC)
 * - The IPC number tell how efficient the CPU pipelining were
 */
//lookup: perf_event_create_kernel_counter()

bool time_bench_PMU_config(bool enable);

/* Raw reading via rdpmc() using fixed counters
 *
 * From: https://github.com/andikleen/simple-pmu
 */
enum {
	FIXED_SELECT = (1U << 30), /* == 0x40000000 */
	FIXED_INST_RETIRED_ANY = 0,
	FIXED_CPU_CLK_UNHALTED_CORE = 1,
	FIXED_CPU_CLK_UNHALTED_REF = 2,
};

#if defined(CONFIG_X86) && !defined(CONFIG_UML)
static __always_inline unsigned long long p_rdpmc(unsigned int in)
{
	unsigned int d, a;

	asm volatile("rdpmc" : "=d"(d), "=a"(a) : "c"(in) : "memory");
	return ((unsigned long long)d << 32) | a;
}
#else
static __always_inline unsigned long long p_rdpmc(unsigned int in)
{
	return 0;
}
#endif

/* These PMU counter needs to be enabled, but I don't have the
 * configure code implemented.  My current hack is running:
 *  sudo perf stat -e cycles:k -e instructions:k insmod lib/ring_queue_test.ko
 */
/* Reading all pipelined instruction */
static __always_inline unsigned long long pmc_inst(void)
{
	return p_rdpmc(FIXED_SELECT | FIXED_INST_RETIRED_ANY);
}

/* Reading CPU clock cycles */
static __always_inline unsigned long long pmc_clk(void)
{
	return p_rdpmc(FIXED_SELECT | FIXED_CPU_CLK_UNHALTED_CORE);
}

#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
/* Raw reading via MSR rdmsr() is likely wrong
 * FIXME: How can I know which raw MSR registers are conf for what?
 */
#define MSR_IA32_PCM0 0x400000C1 /* PERFCTR0 */
#define MSR_IA32_PCM1 0x400000C2 /* PERFCTR1 */
#define MSR_IA32_PCM2 0x400000C3
static inline uint64_t msr_inst(unsigned long long *msr_result)
{
	return rdmsrq_safe(MSR_IA32_PCM0, msr_result);
}
#endif

/** Generic functions **
 */
int time_bench_loop(uint32_t loops, int step, const char *txt, void *data,
		    int (*func)(struct time_bench_record *rec, void *data));
bool time_bench_calc_stats(struct time_bench_record *rec);

bool time_bench_run_concurrent(uint32_t loops, int step, void *data,
			       const struct cpumask *mask, /* Support masking outsome CPUs*/
			       struct time_bench_sync *sync, struct time_bench_cpu *cpu_tasks,
			       int (*func)(struct time_bench_record *record, void *data));
void time_bench_print_stats_cpumask(const char *desc,
				    struct time_bench_cpu *cpu_tasks,
				    const struct cpumask *mask);

//FIXME: use rec->flags to select measurement, should be MACRO
static __always_inline void time_bench_start(struct time_bench_record *rec)
{
	//getnstimeofday(&rec->ts_start);
	ktime_get_real_ts64(&rec->ts_start);
	if (rec->flags & TIME_BENCH_PMU) {
		rec->pmc_inst_start = pmc_inst();
		rec->pmc_clk_start = pmc_clk();
	}
	if (rec->flags & TIME_BENCH_TSC)
		rec->tsc_start = tsc_start_clock();
}

static __always_inline void time_bench_stop(struct time_bench_record *rec,
					    uint64_t invoked_cnt)
{
	if (rec->flags & TIME_BENCH_TSC)
		rec->tsc_stop = tsc_stop_clock();
	if (rec->flags & TIME_BENCH_PMU) {
		rec->pmc_inst_stop = pmc_inst();
		rec->pmc_clk_stop = pmc_clk();
	}
	//getnstimeofday(&rec->ts_stop);
	ktime_get_real_ts64(&rec->ts_stop);
	rec->invoked_cnt = invoked_cnt;
}

#endif /* _LINUX_TIME_BENCH_H */
