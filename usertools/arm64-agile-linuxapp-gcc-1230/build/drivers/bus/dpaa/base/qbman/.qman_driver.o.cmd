cmd_base/qbman/qman_driver.o = gcc -Wp,-MD,base/qbman/.qman_driver.o.d.tmp  -I/home/yyy/firmware-toe/drivers/bus/dpaa  -pthread -I/home/yyy/firmware-toe/lib/librte_eal/linux/eal/include  -march=armv8-a+crc -mtune=cortex-a72 -mtls-dialect=trad -DRTE_MACHINE_CPUFLAG_NEON -DRTE_MACHINE_CPUFLAG_CRC32  -I/home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include -DRTE_USE_FUNCTION_VERSIONING -include /home/yyy/firmware-toe/arm64-agile-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wno-error=pedantic -Werror -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-pointer-arith -Wno-cast-qual -I/home/yyy/firmware-toe/drivers/bus/dpaa/ -I/home/yyy/firmware-toe/drivers/bus/dpaa/include -I/home/yyy/firmware-toe/drivers/bus/dpaa/base/qbman -I/home/yyy/firmware-toe/drivers/common/dpaax -I/home/yyy/firmware-toe/lib/librte_eal/common/include   -O3 -ggdb -g -Wno-unused-parameter -Wno-discarded-qualifiers -Wno-undef -Wno-switch -fPIC -I/home/yyy/firmware-toe/../agile_install/include/ -shared -o base/qbman/qman_driver.o -c /home/yyy/firmware-toe/drivers/bus/dpaa/base/qbman/qman_driver.c 
