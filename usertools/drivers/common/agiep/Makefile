# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Cavium, Inc
#

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_common_agiep.a

CFLAGS += $(WERROR_FLAGS) -Werror
CFLAGS += -I$(RTE_SDK)/drivers/bus/pci
CFLAGS += -I$(RTE_SDK)/drivers/raw/dpaa2_qdma
CFLAGS += -O3

EXPORT_MAP := rte_common_agiep_version.map

#
# all source are stored in SRCS-y
#
SRCS-y += agiep_dma.c agiep_lib.c agiep_pci.c
SRCS-y += agiep_reg_poller.c  agiep_virtio.c
SRCS-y += agiep_reg_expand.c agiep_vring_split_predict.c
SRCS-y += agiep_vring.c agiep_virtio_legacy.c
SRCS-y += agiep_vring_packed.c agiep_vring_packed_cache.c
SRCS-y += agiep_vring_split.c agiep_vring_split_cache.c
SRCS-y += agiep_dirty_log.c agiep_mng.c


LDLIBS += -lrte_eal
LDLIBS += -lrte_common_dpaax
LDLIBS += -lyaml
LDLIBS += -lpci_ep

SYMLINK-$(CONFIG_RTE_LIBRTE_AGIEP_PMD)-include += agiep_dma.h
SYMLINK-$(CONFIG_RTE_LIBRTE_AGIEP_PMD)-include += agiep_pci.h
SYMLINK-$(CONFIG_RTE_LIBRTE_AGIEP_PMD)-include += agiep_dirty_log.h
SYMLINK-$(CONFIG_RTE_LIBRTE_AGIEP_PMD)-include += agiep_mng.h
include $(RTE_SDK)/mk/rte.lib.mk
