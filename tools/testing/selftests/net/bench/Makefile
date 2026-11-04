# SPDX-License-Identifier: GPL-2.0

KDIR ?= $(if $(O),$(O),$(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT),$(if $(wildcard ../../../../Module.symvers),$(realpath ../../../..),/lib/modules/$(shell uname -r)/build)))
ifneq (,$(wildcard $(KDIR)/Module.symvers))
TEST_GEN_MODS_DIR := page_pool
endif

TEST_PROGS += test_bench_page_pool.sh
TEST_FILES := bench_page_pool_nsim.py

include ../../lib.mk
