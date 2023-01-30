#ifndef RTE_AGIEP_LIB_H_
#define RTE_AGIEP_LIB_H_
#include <stdio.h>
#include <rte_io.h>

#define POINT_SUM_INT(addr, offset)  ((void *)((char *)(addr) + (offset)))
#define VOID_SUM_INT_U64(addr, offset)  ((uint64_t)((char *)(addr) + (offset)))
/**
 * ~= a % b, b should be power of 2
 */
#define MOD2(a,b) ((a) & ((b) - 1))
/**
 * ~= a %= b , b should be power of 2
 */
#define MOD2TOA(a,b) ((a) &= ((b) - 1))

#define barrier() { asm volatile ("yield" : : : "memory");  }
#define cpu_relax barrier

void* agiep_mmap(void* start, size_t length, int prot, int flags,
	off_t offset, void **map_addr, int *retfd);
int agiep_ummap(void *p, size_t length, int retfd);

/**
 * Return the last (most-significant) bit set.
 *
 * @note The last (most significant) bit is at position 16.
 *
 * @param x
 *     The input parameter.
 * @return
 *     The last (most-significant) bit set, or 0 if the input is 0.
 */
static inline int
agiep_fls_u16(uint16_t x)
{
	uint32_t y = x;
	return (x == 0) ? 0 : 32 - __builtin_clz(y);
}

static inline __attribute__((always_inline)) void
agiep_write_bit(uint64_t value, void *addr, uint8_t bit)
{
	switch (bit) {
	case 8:
		rte_write8((uint8_t)value, addr);
		break;
	case 16:
		rte_write16((uint16_t)value, addr);
		break;
	case 32:
		rte_write32((uint32_t)value, addr);
		break;
	case 64:
		rte_write64(value, addr);
	default:
		break;
	}
}
#endif
