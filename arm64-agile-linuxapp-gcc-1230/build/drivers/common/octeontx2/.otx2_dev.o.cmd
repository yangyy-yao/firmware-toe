cmd_otx2_dev.o = gcc -Wp,-MD,./.otx2_dev.o.d.tmp   -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-error=pedantic -Werror -Wimplicit-fallthrough=2 -Wno-format-truncation -I/home/yyy/firmware-toe/drivers/common/octeontx2 -I/home/yyy/firmware-toe/drivers/mempool/octeontx2 -I/home/yyy/firmware-toe/drivers/bus/pci   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o otx2_dev.o -c /home/yyy/firmware-toe/drivers/common/octeontx2/otx2_dev.c 
