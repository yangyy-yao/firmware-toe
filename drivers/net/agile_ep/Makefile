# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015-2018 Atomic Rules LLC

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_agile_ep.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -Werror
CFLAGS += -I$(RTE_SDK)/drivers/common/agiep
CFLAGS += -I$(RTE_SDK)/drivers/raw/dpaa2_qdma

CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/mc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/qbman/include
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/mc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/portal
CFLAGS += -I$(RTE_SDK)/drivers/mempool/dpaa2

#CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wno-deprecated-declarations

EXPORT_MAP := rte_pmd_agile_ep.map

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += agiep_mbuf_iov.c
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += agiep_vdev.c agiep_ctrl.c
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += agiep_virtio_ctrl.c agiep_virtio_port.c
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += agiep_vendor_net.c agiep_vendor_port.c
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += agiep_vendor_ctrl.c agiep_vendor_regpoll.c
SRCS-$(CONFIG_RTE_LIBRTE_AGILE_EP_PMD) += agiep_virtio_net.c agiep_virtio_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_AGILE_EP_PMD) += agiep_accel_net.c agiep_accel_soft.c agiep_accel_engine.c
SRCS-$(CONFIG_RTE_LIBRTE_AGILE_EP_PMD) += agiep_frep_loopback_net.c agiep_frep_loopback_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_AGILE_EP_PMD) += agiep_frep_task.c
SRCS-$(CONFIG_RTE_LIBRTE_AGILE_EP_PMD) += agiep_task.c


# this lib depends upon:
LDLIBS += -lrte_eal
LDLIBS += -lrte_mbuf
LDLIBS += -lrte_mempool
LDLIBS += -lrte_ring
LDLIBS += -lrte_ethdev
LDLIBS += -lrte_net
LDLIBS += -lrte_kvargs
LDLIBS += -lrte_bus_pci
LDLIBS += -lrte_common_agiep
LDLIBS += -lpthread
ifdef CONFIG_RTE_EXEC_ENV_LINUX
LDLIBS += -ldl
endif

include $(RTE_SDK)/mk/rte.lib.mk
