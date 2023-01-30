#ifndef RTE_AGIEP_EXPAND_H_
#define RTE_AGIEP_EXPAND_H_

#include <sys/queue.h>
#include <stdint.h>


// specially for virtio

// 32 byte - 2 poller one cache line
struct agiep_reg_expand {
	// 1 64 bit
	uint16_t id;
	uint16_t next;
	uint16_t prev;
	uint16_t free;
	// 2 64 bit
	union {
		void     *addr;
		uint8_t  *data8;
		uint16_t *data16;
		uint32_t *data32;
	};
	// 3 64 bit
	uint32_t init;
	uint16_t max_num;
	uint16_t prev_select;
	// 4 64 bit
	uint16_t *select16;
};

int agiep_reg_expand_register(struct agiep_reg_expand *reg, int bits);

void agiep_reg_expand_unregister(int id, int bits);

void agiep_reg_expand_run(void);

void agiep_reg_expand_reset(int id, int bits, struct agiep_reg_expand *reset);

uint16_t agiep_reg_expand16_get(int id, uint16_t select_id);

uint32_t agiep_reg_expand32_get(int id, uint16_t select_id);

void agiep_reg_expand16_set(int id, uint16_t select_id, uint16_t init);

void agiep_reg_expand32_set(int id, uint16_t select_id, uint32_t init);

void agiep_reg_expand_init(void);
#endif
