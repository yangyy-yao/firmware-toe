cmd_ccp.o = gcc -Wp,-MD,./.ccp.o.d.tmp   -pthread -I/home/heboyan/firmware-dpdk/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/heboyan/firmware-dpdk/lib/librte_tcpstack/build/include -DRTE_USE_FUNCTION_VERSIONING -I/home/heboyan/firmware-dpdk/arm64-agile-linuxapp-gcc/include -include /home/heboyan/firmware-dpdk/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -I/home/heboyan/firmware-dpdk/lib/librte_tcpstack -O0 -g -D__USRLIB__ -DENABLE_CCP -DDISABLE_HWCSUM -DDISABLE_PSIO -DDISABLE_NETMAP -DENFORCE_RX_IDLE -DRX_IDLE_THRESH=0 -DDBGMSG -fgnu89-inline    -o ccp.o -c ccp.c 
