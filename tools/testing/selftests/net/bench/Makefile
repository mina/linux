# SPDX-License-Identifier: GPL-2.0

_kdir_raw := $(if $(O),$(O),$(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT),$(realpath ../../../../..)))
KDIR ?= $(if $(filter %/kselftest,$(BUILD)),$(patsubst %/kselftest,%,$(BUILD)),$(abspath $(_kdir_raw)))
export KDIR
ifneq (,$(wildcard $(KDIR)/Module.symvers))
ifneq (,$(shell grep -qw page_pool_create "$(KDIR)/Module.symvers" && echo y))
TEST_GEN_MODS_DIR := page_pool
else
pp_bench_warning := CONFIG_PAGE_POOL not enabled in $(KDIR)
endif
else
pp_bench_warning := missing Module.symvers in $(KDIR), please have the kernel built first
endif

TEST_PROGS := \
	bench_page_pool_nsim.py \
	test_bench_page_pool.sh \
# end of TEST_PROGS

TEST_INCLUDES := \
	$(wildcard ../lib/py/*.py) \
# end of TEST_INCLUDES

include ../../lib.mk

EXTRA_CLEAN += \
	$(OUTPUT)/page_pool/*.ko \
	page_pool/*.ko \
	page_pool/*.mod \
	page_pool/*.mod.c \
	page_pool/*.o \
	page_pool/.*.cmd \
	page_pool/.*.o \
	page_pool/.tmp_versions \
	page_pool/Module.symvers \
	page_pool/modules.order \
# end of EXTRA_CLEAN

ifneq ($(pp_bench_warning),)
all: warn_skip_pp_bench

.PHONY: warn_skip_pp_bench
warn_skip_pp_bench:
	@rm -f page_pool/bench_page_pool.ko $(OUTPUT)/page_pool/bench_page_pool.ko; \
	echo "Warning: $(pp_bench_warning), skipping bench_page_pool.ko."
endif
