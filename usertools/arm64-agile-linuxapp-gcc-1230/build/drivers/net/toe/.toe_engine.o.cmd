cmd_toe_engine.o = gcc -Wp,-MD,./.toe_engine.o.d.tmp   -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -O3 -w -I/home/yyy/firmware-toe/lib/librte_rawdev -I/home/yyy/firmware-toe/lib/librte_tcpstack -I/home/yyy/firmware-toe/drivers/common/dpaax -I/home/yyy/firmware-toe/drivers/net/dpaa2 -I/home/yyy/firmware-toe/drivers/net/dpaa2/mc -I/home/yyy/firmware-toe/drivers/bus/fslmc -I/home/yyy/firmware-toe/drivers/bus/fslmc/mc -I/home/yyy/firmware-toe/drivers/bus/fslmc/portal -I/home/yyy/firmware-toe/drivers/mempool/dpaa2 -I/home/yyy/firmware-toe/drivers/net/toe -Wno-deprecated-declarations   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o toe_engine.o -c /home/yyy/firmware-toe/drivers/net/toe/toe_engine.c 
