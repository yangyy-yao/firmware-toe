# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_tcpstack.a

# Debug Log Switch
#DEBUGLOG = -DNDEBUG
#DEBUGLOG = -DDBGMSG

# Compile Options
#COMPILEOPT = -O0 -g -D__USRLIB__
COMPILEOPT = -O3 -D__USRLIB__

# Function Switch
#COMPILEOPT += -DENABLELRO
#COMPILEOPT += -DENABLE_CCP
COMPILEOPT += -DDISABLE_HWCSUM
COMPILEOPT += -DDISABLE_PSIO
COMPILEOPT += -DDISABLE_NETMAP
COMPILEOPT += -DENFORCE_RX_IDLE -DRX_IDLE_THRESH=0

# Warning Cleanner
WARNINGFLAG = -fgnu89-inline

CFLAGS += -DALLOW_EXPERIMENTAL_API
#CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) $(COMPILEOPT) $(DEBUGLOG) 
CFLAGS += -I$(SRCDIR) $(COMPILEOPT) $(DEBUGLOG) $(WARNINGFLAG)
#LDLIBS += -lrte_eal

EXPORT_MAP := rte_tcpstack_version.map

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_TCP_STACK) :=  eth_in.c eth_out.c ip_in.c ip_out.c tcp_in.c tcp_out.c tcp_stream.c tcp_util.c tcp_rb_frag_queue.c tcp_ring_buffer.c tcp_send_buffer.c tcp_sb_queue.c tcp_stream_queue.c libccp.c machine.c serialize.c \
					ccp.c ccp_priv.c clock.c pacing.c debug.c config.c api.c eventpoll.c socket.c timer.c addr_pool.c fhash.c memory_mgt.c

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_TCP_STACK)-include := rte_tcpstack.h

include $(RTE_SDK)/mk/rte.lib.mk
