BENCH_PAGE_POOL_SIMPLE_TEST_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
TOP_SRCDIR := $(realpath $(BENCH_PAGE_POOL_SIMPLE_TEST_DIR)/../../../../..)
DEFAULT_KDIR := $(if $(wildcard $(TOP_SRCDIR)/Module.symvers),$(TOP_SRCDIR),/lib/modules/$(shell uname -r)/build)
KDIR ?= $(if $(O),$(O),$(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT),$(DEFAULT_KDIR)))

ifeq ($(V),1)
Q =
else
Q = @
endif

obj-m	+= bench_page_pool.o
bench_page_pool-y += bench_page_pool_simple.o time_bench.o

all:
	+$(Q)$(MAKE) -C $(KDIR) O=$(realpath $(KDIR)) M=$(BENCH_PAGE_POOL_SIMPLE_TEST_DIR) modules

clean:
	+$(Q)$(MAKE) -C $(KDIR) O=$(realpath $(KDIR)) M=$(BENCH_PAGE_POOL_SIMPLE_TEST_DIR) clean
