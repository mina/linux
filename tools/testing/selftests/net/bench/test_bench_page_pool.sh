#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -u

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
DRIVER="${SCRIPT_DIR}/page_pool/bench_page_pool.ko"
KSFT_SKIP=4

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: test_bench_page_pool requires root privileges"
	exit "$KSFT_SKIP"
fi

if [ ! -f "$DRIVER" ]; then
	echo "SKIP: $DRIVER not built (build kernel first)"
	exit "$KSFT_SKIP"
fi

cleanup()
{
	rmmod bench_page_pool 2>/dev/null || true
}
trap cleanup EXIT

run_test()
{
	local marker
	local insmod_rc=0
	local result=""

	marker="pp_bench_start_$$_$(date +%s)"
	rmmod bench_page_pool 2>/dev/null || true

	if [ ! -w /dev/kmsg ] || ! echo "$marker" > /dev/kmsg 2>/dev/null; then
		marker=""
	fi

	insmod "$DRIVER" || insmod_rc=$?
	rmmod bench_page_pool 2>/dev/null || true

	if [ -n "$marker" ]; then
		result=$(dmesg | awk -v m="$marker" \
			 'found { print } index($0, m) { found = 1 }')
	else
		result=$(dmesg)
	fi

	echo "$result"

	echo
	echo "All page_pool microbenchmark results:"
	echo "$result" | grep -E "Type:[^ ]+ Per elem:|Sum Type:" || true

	if [ "$insmod_rc" -ne 0 ] ||
	   ! echo "$result" | grep -q "All page_pool benchmarks passed"; then
		echo "ERROR: benchmark failed (insmod_rc=$insmod_rc)" >&2
		exit 1
	fi

	echo "[PASS] test_bench_page_pool"
}

run_test

exit 0
