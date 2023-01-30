# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015-2018 Atomic Rules LLC

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_toe.a

CFLAGS += -O3 -w
#CFLAGS += $(WERROR_FLAGS) 

CFLAGS += -I$(RTE_SDK)/lib/librte_rawdev
CFLAGS += -I$(RTE_SDK)/lib/librte_tcpstack
CFLAGS += -I$(RTE_SDK)/drivers/common/dpaax
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/net/dpaa2/mc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/mc
CFLAGS += -I$(RTE_SDK)/drivers/bus/fslmc/portal
CFLAGS += -I$(RTE_SDK)/drivers/mempool/dpaa2
CFLAGS += -I$(RTE_SDK)/drivers/net/toe

#CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -Wno-deprecated-declarations

EXPORT_MAP := rte_pmd_toe.map

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_AGIEP_EP_PMD) += toe_dev.c toe_dma.c toe_engine.c toe_pcie.c

# this lib depends upon:
LDLIBS += -lrte_eal
LDLIBS += -lrte_mbuf
LDLIBS += -lrte_mempool
LDLIBS += -lrte_ring
LDLIBS += -lrte_ethdev
LDLIBS += -lrte_net
LDLIBS += -lrte_kvargs
LDLIBS += -lrte_bus_pci
LDLIBS += -lrte_tcpstack
LDLIBS += -lpthread
ifdef CONFIG_RTE_EXEC_ENV_LINUX
LDLIBS += -ldl
endif

include $(RTE_SDK)/mk/rte.lib.mk
