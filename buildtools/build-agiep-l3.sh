#!/usr/bin/env bash
set -x
set -e
if [ "$1" == "cross" ]; then
  make all T=${RTE_TARGET} O=${RTE_TARGET} CROSS=${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu- CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
    EXTRA_CFLAGS="-O3 -g -isystem ${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/include -I/tmp/agile/include  -I /tmp/agile/pci_ep" \
    EXTRA_LDFLAGS="-L${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/lib -lnuma"

    make install T=${RTE_TARGET} O=${RTE_TARGET} CROSS=${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu- CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
    EXTRA_CFLAGS="-O3 -g -isystem ${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/include -I/tmp/agile/include  -I /tmp/agile/pci_ep" \
    EXTRA_LDFLAGS="-L${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/lib -lnuma"

  cd examples/l3fwd
  rm -r build
  make all T=${RTE_TARGET}  CROSS=${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu- CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
  EXTRA_CFLAGS="-O0 -g -isystem ${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/include -I/tmp/agile/include  -I /tmp/agile/pci_ep" \
  EXTRA_LDFLAGS="-L${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/lib -lnuma"
  cd -
#	cd examples/l2fwd
#	rm -r build
#	make all V=1 T=${RTE_TARGET}  CROSS=${TOOLCHAIN_PATH}/bin/aarch64-linux-gnu- CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
#	EXTRA_CFLAGS="-O3 -g -isystem ${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/include -I/tmp/agile/include  -I /tmp/agile/pci_ep" \
#	EXTRA_LDFLAGS="-L${TOOLCHAIN_PATH}/aarch64-linux-gnu/usr/local/lib -lnuma"
#	cd -
else
    PCI_EP_CFLAG=$(pkg-config --cflags pci_ep)
    PCI_EP_LDFLAG=$(pkg-config --libs pci_ep)
    make -j8 all T=${RTE_TARGET} O=${RTE_TARGET} CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
    EXTRA_CFLAGS="-O3 -g -Wno-discarded-qualifiers -Wno-undef -Wno-switch $PCI_EP_CFLAG" \
    EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml" 

    make -j8 install T=${RTE_TARGET} O=${RTE_TARGET} CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
    EXTRA_CFLAGS="-O3 -g -Wno-discarded-qualifiers -Wno-undef -Wno-switch $PCI_EP_CFLAG" \
    EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml"

#	cd examples/l2fwd
#	rm -rf build/*
#	make V=1 T=${RTE_TARGET}  CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
#	EXTRA_CFLAGS="-g $PCI_EP_CFLAG" \
#	EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml"
#	cd -
	cd examples/l3fwd
	rm -rf build/*
	make V=1 T=${RTE_TARGET}  CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_EAL_IGB_UIO=n \
	EXTRA_CFLAGS="-g $PCI_EP_CFLAG" \
	EXTRA_LDFLAGS="-lnuma $PCI_EP_LDFLAG -lyaml"
	cd -
fi
#cp -v build/l3fwd /tmp/l3fwd
#cp -v build/l3fwd ~/l3fwd_virtio
#rsync -av examples/l3fwd/build/l3fwd root@10.11.22.45:/tmp/l3fwd
#rsync -av examples/l2fwd/build/l2fwd root@10.11.22.241:/tmp/l2fwd
#cp examples/l2fwd/build/l2fwd /tmp
cp examples/l3fwd/build/l3fwd /tmp
exit


#seq 3 2 3 | xargs -n 1 -I{} bash -x -c "ovs-vsctl --db=unix:/root/open-vswitch/var/run/openvswitch/db.sock -- add Bridge br0 mirrors @m{} --\
# 	--id=@dpdk0  get port dpdk0 -- \
# 	--id=@pf0v1  get port pf0v1 -- \
# 	--id=@pf0v{}  get port pf0v{} -- \
# 	--id=@m{} create mirror name=m{} select-src-port=@dpdk0 output-port=@pf0v{}"

#seq 3 2 3 | xargs -n 1 -I{} bash -x -c "ovs-vsctl --db=unix:/root/open-vswitch/var/run/openvswitch/db.sock -- add Bridge br0 mirrors @m{} --\
# 	--id=@dpdk1  get port dpdk1 -- \
# 	--id=@pf0v2  get port pf0v2 -- \
# 	--id=@pf0v{}  get port pf0v{} -- \
# 	--id=@m{} create mirror name=m{} select-src-port=@dpdk1 select-dst-port=@pf0v2 output-port=@pf0v{}"
#ovs-vsctl -- --id=@m1 get mirror m1 -- remove bridge br0 mirror @m1
