cmd_clock.o = gcc -Wp,-MD,./.clock.o.d.tmp   -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -I/home/yyy/firmware-toe/lib/librte_tcpstack -O3 -D__USRLIB__ -DDISABLE_HWCSUM -DDISABLE_PSIO -DDISABLE_NETMAP -DENFORCE_RX_IDLE -DRX_IDLE_THRESH=0  -fgnu89-inline   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o clock.o -c /home/yyy/firmware-toe/lib/librte_tcpstack/clock.c 
