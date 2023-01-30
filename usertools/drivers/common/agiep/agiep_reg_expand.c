#include <rte_spinlock.h>
#include <rte_atomic.h>
#include <rte_io.h>
#include <rte_prefetch.h>
#include "agiep_reg_expand.h"
#include "agiep_lib.h"
#include "agiep_logs.h"

#define AGIEP_REG_EXPAND16_NUM 256
#define AGIEP_REG_EXPAND32_NUM 128

static struct agiep_reg_expand expand16[AGIEP_REG_EXPAND16_NUM];
static struct agiep_reg_expand expand32[AGIEP_REG_EXPAND32_NUM];

#define EXPAND16_INVALID_ID AGIEP_REG_EXPAND16_NUM
#define EXPAND32_INVALID_ID AGIEP_REG_EXPAND32_NUM

#define AGIEP_REG_EXPAND_NUM 8
static uint64_t expand16_array[AGIEP_REG_EXPAND16_NUM][AGIEP_REG_EXPAND_NUM];
static uint64_t expand32_array[AGIEP_REG_EXPAND32_NUM][AGIEP_REG_EXPAND_NUM];


static rte_spinlock_t expand16_lock = RTE_SPINLOCK_INITIALIZER;
static rte_spinlock_t expand32_lock = RTE_SPINLOCK_INITIALIZER;

static uint32_t used_num16;
static uint32_t used_num32;
static uint32_t free_head16 = EXPAND16_INVALID_ID;
static uint32_t free_head32 = EXPAND32_INVALID_ID;
static uint32_t used_head16 = EXPAND16_INVALID_ID;
static uint32_t used_head32 = EXPAND32_INVALID_ID;

static volatile uint16_t expand16_doing = 0;
static volatile uint16_t expand32_doing = 0;


#define AGIEP_REG_EXPAND_REGISTER_DEFINE(bits) \
static int agiep_reg_expand##bits##_register(struct agiep_reg_expand *reg) \
{ \
	int id; \
	int head_prev; \
	struct agiep_reg_expand *cur; \
	struct agiep_reg_expand *head = NULL; \
	rte_spinlock_lock(&expand##bits##_lock); \
	if (used_num##bits >= AGIEP_REG_EXPAND##bits##_NUM) { \
		rte_spinlock_unlock(&expand##bits##_lock); \
		return -1; \
	} \
	id = free_head##bits; \
	cur = &expand##bits[id]; \
	cur->addr = reg->addr; \
	cur->init = reg->init; \
	cur->select16 = reg->select16; \
        cur->prev_select = 0;             \
        cur->max_num = reg->max_num;          \
	free_head##bits = cur->next; \
	head_prev = id; \
	if (used_head##bits != EXPAND##bits##_INVALID_ID) { \
		head = &expand##bits[used_head##bits]; \
		head_prev = expand##bits[used_head##bits].prev; \
		head->prev = cur->id; \
	} \
	cur->next = used_head##bits; \
	cur->prev = head_prev; \
	cur->free = 0; \
        rte_mb();	\
	used_head##bits = id; \
	used_num##bits++; \
	rte_spinlock_unlock(&expand##bits##_lock); \
	return id; \
}

#define AGIEP_REG_EXPAND_UNREGISTER_DEFINE(bits) \
static void agiep_reg_expand##bits##_unregister(int id) \
{ \
	struct agiep_reg_expand *cur; \
	struct agiep_reg_expand *head; \
	struct agiep_reg_expand *prev; \
	struct agiep_reg_expand *next; \
	rte_spinlock_lock(&expand##bits##_lock); \
	cur = &expand##bits[id]; \
	if (cur->free) {\
                goto out_unlock; \
        } \
	head = &expand##bits[used_head##bits]; \
	if (cur->id == cur->prev) { \
		used_head##bits = EXPAND##bits##_INVALID_ID; \
	} else { \
		prev = &expand##bits[cur->prev]; \
		if (cur->next == EXPAND##bits##_INVALID_ID) { \
			prev->next = EXPAND##bits##_INVALID_ID; \
			head->prev = prev->id; \
		} else if ((uint##bits##_t)id == used_head##bits) { \
			next = &expand##bits[cur->next]; \
			used_head##bits = next->id; \
			next->prev = cur->prev; \
		} else {\
			next = &expand##bits[cur->next]; \
			prev->next = cur->next; \
			next->prev = cur->prev; \
		} \
	} \
	while(expand##bits##_doing)\
		cpu_relax(); \
	cur->free = 1; \
	cur->next = free_head##bits; \
	free_head##bits = cur->id; \
	used_num##bits--; \
out_unlock: \
	rte_spinlock_unlock(&expand##bits##_lock); \
}

AGIEP_REG_EXPAND_REGISTER_DEFINE(16)
AGIEP_REG_EXPAND_REGISTER_DEFINE(32)
AGIEP_REG_EXPAND_UNREGISTER_DEFINE(16)
AGIEP_REG_EXPAND_UNREGISTER_DEFINE(32)

int agiep_reg_expand_register(struct agiep_reg_expand *reg, int bits)
{
	switch(bits) {
		case 16:
			return agiep_reg_expand16_register(reg);
		case 32:
			return agiep_reg_expand32_register(reg);
		default:
			return -1;
	}
}

void agiep_reg_expand_unregister(int id, int bits)
{
	switch(bits) {
		case 16:
			return agiep_reg_expand16_unregister(id);
		case 32:
			return agiep_reg_expand32_unregister(id);
		default:
			return;
	}
}


static void agiep_reg_expand16_reset(int id, struct agiep_reg_expand *reset)
{
	if (unlikely(id < 0 || id >= AGIEP_REG_EXPAND16_NUM)) {
		return;
	}

	if (reset) {
		expand16[id].addr = reset->addr;
		expand16[id].init = reset->init;
		expand16[id].max_num = reset->max_num;
		expand16[id].select16 = reset->select16;
	}

	expand16[id].prev_select = 0;
	return;
}

static void agiep_reg_expand32_reset(int id, struct agiep_reg_expand *reset)
{
	if (unlikely(id < 0 || id >= AGIEP_REG_EXPAND32_NUM)) {
		return;
	}

	if (reset) {
		expand32[id].addr = reset->addr;
		expand32[id].init = reset->init;
		expand32[id].max_num = reset->max_num;
		expand32[id].select16 = reset->select16;
	}

	expand32[id].prev_select = 0;
	return;
}

void agiep_reg_expand_reset(int id, int bits, struct agiep_reg_expand *reset)
{
	switch(bits) {
		case 16:
			return agiep_reg_expand16_reset(id, reset);
		case 32:
			return agiep_reg_expand32_reset(id, reset);
		default:
			return;
	}
}

void agiep_reg_expand_run(void)
{
	struct agiep_reg_expand *expand;
	uint32_t id;
	uint32_t next16;
	uint32_t next32;
	uint16_t data16;
	uint32_t data32;
	uint16_t select16;

	expand16_doing = 1;
	rte_wmb();
	next16 = used_head16;
	while(next16 != EXPAND16_INVALID_ID) {
		expand = &expand16[next16];
		id = next16;
		next16 = expand->next;
		data16 = rte_read16(expand->data16);
		if (data16 != (uint16_t)expand->init) {
			select16 = rte_read16(expand->select16);
			expand16_array[id][select16] = data16;
			rte_write16((uint16_t)expand->init, expand->data16);
		}
	}
	rte_wmb();
	expand16_doing = 0;

	expand32_doing = 1;
	rte_wmb();
	next32 = used_head32;
	while(next32 != EXPAND32_INVALID_ID) {
		expand = &expand32[next32];
		id = next32;
		next32 = expand->next;
		data32 = rte_read32(expand->data32);
		if (data32 != (uint32_t)expand->init) {
			rte_write32(expand->init, expand->data32);
			rte_read32(expand->data32);
			expand32_array[id][expand->prev_select % expand->max_num] = data32;
			expand->prev_select++;
		}
	}
	rte_wmb();
	expand32_doing = 0;
}

uint16_t agiep_reg_expand16_get(int id, uint16_t select_id)
{
	return expand16_array[id][select_id];
}

uint32_t agiep_reg_expand32_get(int id, uint16_t select_id)
{
	return expand32_array[id][select_id];
}

void agiep_reg_expand16_set(int id, uint16_t select_id, uint16_t init)
{
	expand16_array[id][select_id] = init;
}

void agiep_reg_expand32_set(int id, uint16_t select_id, uint32_t init)
{
	expand32_array[id][select_id] = init;
}

void agiep_reg_expand_init(void)
{
	int i;

	free_head16 = 0;
	free_head32 = 0;

	for (i = 0; i < AGIEP_REG_EXPAND16_NUM; i++) {
		expand16[i].id = i;
		expand16[i].next = i + 1;
		expand16[i].free = 1;
	}
	for (i = 0; i < AGIEP_REG_EXPAND32_NUM; i++) {
		expand32[i].id = i;
		expand32[i].next = i + 1;
		expand32[i].free = 1;
	}
}
