cmd_agiep_vendor_port.o = gcc -Wp,-MD,./.agiep_vendor_port.o.d.tmp   -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-error=pedantic -Werror -Wimplicit-fallthrough=2 -Wno-format-truncation -Werror -I/home/yyy/firmware-toe/drivers/common/agiep -I/home/yyy/firmware-toe/drivers/raw/dpaa2_qdma -I/home/yyy/firmware-toe/drivers/common/dpaax -I/home/yyy/firmware-toe/drivers/net/dpaa2 -I/home/yyy/firmware-toe/drivers/net/dpaa2/mc -I/home/yyy/firmware-toe/drivers/bus/fslmc -I/home/yyy/firmware-toe/drivers/bus/fslmc/qbman/include -I/home/yyy/firmware-toe/drivers/bus/fslmc/mc -I/home/yyy/firmware-toe/drivers/bus/fslmc/portal -I/home/yyy/firmware-toe/drivers/mempool/dpaa2 -Wno-deprecated-declarations   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o agiep_vendor_port.o -c /home/yyy/firmware-toe/drivers/net/agile_ep/agiep_vendor_port.c 
