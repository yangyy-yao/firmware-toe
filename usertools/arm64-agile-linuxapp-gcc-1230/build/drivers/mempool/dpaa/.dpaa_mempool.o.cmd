cmd_dpaa_mempool.o = gcc -Wp,-MD,./.dpaa_mempool.o.d.tmp  -I/home/yyy/firmware-toe/drivers/mempool/dpaa  -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-error=pedantic -Werror -Wimplicit-fallthrough=2 -Wno-format-truncation -I/home/yyy/firmware-toe/drivers/bus/dpaa -I/home/yyy/firmware-toe/drivers/bus/dpaa/include/ -I/home/yyy/firmware-toe/drivers/common/dpaax -I/home/yyy/firmware-toe/drivers/mempool/dpaa -I/home/yyy/firmware-toe/lib/librte_mempool -DALLOW_EXPERIMENTAL_API   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o dpaa_mempool.o -c /home/yyy/firmware-toe/drivers/mempool/dpaa/dpaa_mempool.c 
