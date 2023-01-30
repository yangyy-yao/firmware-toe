#!/usr/bin/env bash
set -x
set -e

PWD=`pwd`

export RTE_TARGET="arm64-agile-linuxapp-gcc"
export RTE_SDK=/home/yyy/firmware-toe

make config T=${RTE_TARGET} O=${RTE_TARGET}
PCI_EP_CFLAG=-I${PWD}/../agile_install/include/
PCI_EP_LDFLAG=-L${PWD}/../agile_install/lib/libpci_ep.a

cd ${RTE_TARGET}

make -j8 all CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n  \
EXTRA_CFLAGS="-O3 -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC $PCI_EP_CFLAG -shared" \
EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml" 

make -j8 install V=1 CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
EXTRA_CFLAGS="-O3 -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC $PCI_EP_CFLAG -shared" \
EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml"

