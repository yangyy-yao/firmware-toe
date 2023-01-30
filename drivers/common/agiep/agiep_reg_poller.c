#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_ring.h>
#include <assert.h>
#include "agiep_reg_poller.h"
#include "agiep_reg_expand.h"
#include "agiep_lib.h"
//两个 pf，每个 pf 创建 64 个 vf， 每个 pf 支持 2 个 port，每个 vf 支持 1 个 port， 每个 port 最多 4 对队列
//regpoller数量：
//(2 * 64 + 2 * 2) * (4 * (VENDOR_RX_CFG_POLLER_COUNT + VENDOR_TX_CFG_POLLER_COUNT) + 
//		VENDOR_CQ_CFG_POLLER_COUNT + VENDOR_PORT_CFG_POLLER_COUNT + 
//		VENDOR_DIRTY_CFG_POLLER_COUNT + VENDOR_MNG_CFG_POLLER_COUNT)
//(2 * 64 + 2 * 2) * (4 * (6 + 6) + 10) = 7656
#define OP_RING_NUM 8192
LIST_HEAD(agiep_pollers, agiep_poller) pollers;

struct rte_ring *op_ring;


int agiep_reg_poller_register(struct agiep_poller *poller);
void agiep_reg_poller_unreigster(struct agiep_poller *poller);
struct agiep_poller *agiep_reg_poller_create(void *data, uint64_t init, enum action_t act, int expand)
{
	struct agiep_poller *poller;

	poller = rte_calloc(NULL, 1, sizeof(*poller), 0);

	if (!poller)
		return NULL;
	poller->expand_id = expand;
	poller->addr = data;
	poller->init = init;
	poller->act = act;
	return poller;
}

int agiep_reg_poller_register(struct agiep_poller *poller)
{
	struct agiep_poller *tmp;

	LIST_FOREACH(tmp, &pollers, next) {
		if (poller->expand_id == -1 && poller->addr == tmp->addr) {
			return -1;
		}
	}
	if (poller->act == ACT_INIT && poller->expand_id == -1)
		agiep_write_bit(poller->init, poller->addr, poller->bits);
	LIST_INSERT_HEAD(&pollers, poller, next);
	poller->status = POLLER_REGISTERED;
	return 0;
}

void agiep_reg_poller_unreigster(struct agiep_poller *poller)
{
	LIST_REMOVE(poller, next);
	// 一个expand 对应多个poller, 只在最后一个poller释放expand
	if (poller->expand_id != -1 && poller->select_id == (poller->select_num - 1)) {
		agiep_reg_expand_unregister(poller->expand_id, poller->bits);
	}
	rte_compiler_barrier();
	poller->status = POLLER_DELETED;
}

int agiep_reg_poller_send_reg(struct agiep_poller *poller)
{
	struct agiep_poller_op *op;
	int ret;

	op = rte_malloc(NULL, sizeof(struct agiep_poller), RTE_CACHE_LINE_SIZE);
	if (op == NULL)
		return -1;
	op->poller = poller;
	op->op = OP_REG;
	op->count = 1;
	poller->status = POLLER_SENDED;
	ret = rte_ring_mp_enqueue(op_ring, op);

	if (ret) {
		rte_free(op);
		return -1;
	}
	while (poller->status == POLLER_SENDED) {
		cpu_relax();
	}
	return 0;
}

int agiep_reg_poller_send_reg_batch(struct agiep_poller *poller, int count)
{
	struct agiep_poller_op *op;
	int ret;
	int i;

	op = rte_malloc(NULL, sizeof(struct agiep_poller), RTE_CACHE_LINE_SIZE);
	if (op == NULL)
		return -1;
	op->poller = poller;
	op->op = OP_REG;
	op->count = count;

	for (i = 0; i< count; i++) {
		poller[i].status = POLLER_SENDED;
	}

	ret = rte_ring_mp_enqueue(op_ring, op);

	if (ret) {
		rte_free(op);
		return -1;
	}
	for (i = 0; i< count; i++) {
		while (poller[i].status == POLLER_SENDED) {
			cpu_relax();
		}
	}
	return 0;
}

int agiep_reg_poller_send_unreg(struct agiep_poller *poller)
{
	struct agiep_poller_op *op;
	int ret;

	op = rte_malloc(NULL, sizeof(struct agiep_poller), RTE_CACHE_LINE_SIZE);
	if (op == NULL)
		return -1;
	op->poller = poller;
	op->op = OP_UNREG;
	op->count = 1;
	ret = rte_ring_mp_enqueue(op_ring, op);

	if (ret) {
		rte_free(op);
		return -1;
	}
	while(poller->status != POLLER_DELETED)
		cpu_relax();
	return 0;
}

int agiep_reg_poller_send_unreg_batch(struct agiep_poller *poller, int count)
{
	struct agiep_poller_op *op;
	int ret;
	int i;

	op = rte_malloc(NULL, sizeof(struct agiep_poller), RTE_CACHE_LINE_SIZE);
	if (op == NULL)
		return -1;
	op->poller = poller;
	op->op = OP_UNREG;
	op->count = count;
	ret = rte_ring_mp_enqueue(op_ring, op);

	if (ret) {
		rte_free(op);
		return -1;
	}
	for (i = 0; i < count; i++){
		while(poller[i].status != POLLER_DELETED)
			cpu_relax();
	}
	rte_free(poller);
	return 0;
}

static inline int agiep_reg_poller_chkact(struct agiep_poller *poller, uint64_t value, uint64_t *prev, uint64_t *init)
{
	uint64_t pvalue = 0;
	int change = 0;
	switch (poller->bits) {
		case 8:
			pvalue = *poller->data8;
			change = (uint8_t)pvalue != (uint8_t)value;
			if (change && init)
				*poller->data8 = *(uint8_t *)init;
			break;
		case 16:
			pvalue = *poller->data16;
			change = (uint16_t)pvalue != (uint16_t)value;
			if (change && init)
				*poller->data16 = *(uint16_t *)init;
			break;
		case 32:
			pvalue = *poller->data32;
			change = (uint32_t)pvalue != (uint32_t)value;
			if (change && init)
				*poller->data32 = *(uint32_t *)init;
			break;
		case 64:
			pvalue = *poller->data64;
			change = (uint64_t)pvalue != (uint64_t)value;
			if (change && init)
				*poller->data64 = *(uint64_t *)init;
			break;
	}

	if (change && prev != NULL)
		*prev = pvalue;

	return change;
}

static inline int agiep_reg_poller_expand_chkact(struct agiep_poller *poller, uint64_t value, uint64_t *prev, uint64_t *init)
{
	uint64_t pvalue;
	int change;
	switch (poller->bits) {
		case 16:
			pvalue = agiep_reg_expand16_get(poller->expand_id, poller->select_id);
			change = (uint16_t)pvalue != (uint16_t)value;
			if (change && init)
				agiep_reg_expand16_set(poller->expand_id, poller->select_id, *(uint16_t *)init);
			break;
		case 32:
			pvalue = agiep_reg_expand32_get(poller->expand_id, poller->select_id);
			change = (uint32_t)pvalue != (uint32_t)value;
			if (change && init)
				agiep_reg_expand32_set(poller->expand_id, poller->select_id, *(uint32_t *)init);
			break;
		default:
			return -1;
	}

	if (change && prev != NULL)
		*prev = pvalue;

	return change;
}

void * agiep_reg_poller_process(void * reg __rte_unused)
{
	struct agiep_poller *poller;
	struct agiep_poller_op *op;
	int change = 0;
	int i = 0;
	if (rte_ring_count(op_ring)){
		if (rte_ring_sc_dequeue(op_ring, (void **) &op) == 0){
			if (op->op == OP_REG) {
				for (i = 0; i < op->count; i++) {
					agiep_reg_poller_register(&op->poller[i]);
				}
			} else {
				for (i = 0; i < op->count; i++) {
					agiep_reg_poller_unreigster(&op->poller[i]);
				}
			}
			rte_free(op);
		}
	}

	LIST_FOREACH(poller, &pollers, next) {
		switch(poller->act) {
			case ACT_NO:
				// do not support reg expand when the action is ACT_NO
				assert(poller->expand_id == -1);
				change = agiep_reg_poller_chkact(poller, poller->prev, &poller->prev, NULL);
				break;
			case ACT_INIT:
				if (poller->expand_id != -1) {
					change = agiep_reg_poller_expand_chkact(poller, poller->init, &poller->prev, &poller->init);
				} else  {
					change = agiep_reg_poller_chkact(poller, poller->init,  &poller->prev, &poller->init);
				}
				break;
		}
		if (change)
			poller->intr(poller);
	}
	return NULL;
}

int agiep_reg_poller_init(void)
{
	agiep_reg_expand_init();
	op_ring = rte_ring_create("agiep_reg_poller_ring", OP_RING_NUM, 0, 0);

	if (op_ring == NULL)
		return -1;
	return 0;
}
