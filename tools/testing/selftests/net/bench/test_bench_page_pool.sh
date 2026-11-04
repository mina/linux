#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#

set -e

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
DRIVER="${SCRIPT_DIR}/page_pool/bench_page_pool.ko"
NSIM_BENCH="${SCRIPT_DIR}/bench_page_pool_nsim.py"
result=""

function run_test()
{
	local before_lines

	rmmod bench_page_pool 2>/dev/null || true
	before_lines=$(dmesg | wc -l)
	insmod "$DRIVER" > /dev/null 2>&1
	rmmod bench_page_pool 2>/dev/null || true

	result=$(dmesg | tail -n +$((before_lines + 1)))
	echo "$result"

	echo
	echo "Fast path results:"
	echo "${result}" | grep -o -E \
		"bh-fast-recycle-direct Per elem: ([0-9]+) cycles\(tsc\) ([0-9]+\.[0-9]+) ns"

	echo
	echo "ptr_ring results:"
	echo "${result}" | grep -o -E \
		"bh-ptr-ring Per elem: ([0-9]+) cycles\(tsc\) ([0-9]+\.[0-9]+) ns"

	echo
	echo "slow path results:"
	echo "${result}" | grep -o -E \
		"bh-slow-page-alloc Per elem: ([0-9]+) cycles\(tsc\) ([0-9]+\.[0-9]+) ns"

	echo
	echo "All page_pool microbenchmark results:"
	echo "${result}" | grep -o -E \
		"Type:[^ ]+ Per elem: ([0-9]+) cycles\(tsc\) ([0-9]+\.[0-9]+) ns"

	if ! echo "${result}" | grep -q "All page_pool benchmarks passed"; then
		echo "ERROR: page_pool kernel benchmark failed" >&2
		exit 1
	fi

	if [ -f "$NSIM_BENCH" ]; then
		echo
		echo "netdevsim page_pool & devmem benchmark results:"
		python3 "$NSIM_BENCH"
	fi

	echo "[PASS] test_bench_page_pool"
}

run_test

exit 0
