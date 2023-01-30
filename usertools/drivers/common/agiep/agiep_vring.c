#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <assert.h>
#include "agiep_vring.h"
#include "agiep_vring_split.h"
#include "agiep_vring_packed.h"
#define MAX_FLUSH_JOB 2

struct virtqueue *
virtqueue_create(int idx, uint16_t num, enum virtqueue_type vq_type, uint32_t flags)
{
	struct virtqueue *vq = NULL;
	void *vring = NULL;

	vq = rte_calloc(NULL, 1, sizeof(struct virtqueue), RTE_CACHE_LINE_SIZE);

	if (vq == NULL)
		return NULL;
	vq->vq_type = vq_type;
	vq->dma = NULL;
	vq->index = idx;
	vq->num = num;
	vq->flags = flags;
	if (vq_type == VQ_SPLIT) {
		vring = vring_split_create(idx, num, &vq->flags);
	} else {
		vring = vring_packed_create(idx, num, &vq->flags);
	}

	if (vring == NULL) {
		rte_free(vq);
		return NULL;
	}

	vq->vring = vring;
	return vq;
}

void virtqueue_free(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT) {
		vring_split_free(vq->vring);
	} else {
		vring_packed_free(vq->vring);
	}
	rte_free(vq);
}

void virtqueue_set_addr(struct virtqueue *vq, uint64_t avail, uint64_t used, uint64_t desc)
{
	vq->vq_type == VQ_SPLIT ? vring_split_set_addr(vq->vring, avail, used, desc) :
		vring_packed_set_addr(vq->vring, avail, used, desc);
	if (vq->cb)
		vq->cb(vq->cb_data);
}
void virtqueue_set_pci_addr(struct virtqueue *vq,uint64_t desc)
{
	vq->vq_type == VQ_SPLIT ? vring_split_set_pci_addr(vq->vring, desc) :
		vring_packed_set_pci_addr(vq->vring, desc);
	if (vq->cb)
		vq->cb(vq->cb_data);
}
void virtqueue_clear_addr(struct virtqueue *vq)
{
	vq->vq_type == VQ_SPLIT ? vring_split_clear_addr(vq->vring) :
		vring_packed_clear_addr(vq->vring);
}

inline int virtqueue_enabled(struct virtqueue *vq)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_enabled(vq->vring) :
		vring_packed_enabled(vq->vring);
}

void virtqueue_set_dma(struct virtqueue *vq, struct agiep_dma *dma)
{
	vq->vq_type == VQ_SPLIT ? vring_split_set_dma(vq->vring, dma):
		vring_packed_set_dma(vq->vring, dma);
}

void virtqueue_set_predict_size(struct virtqueue *vq, uint32_t size)
{
	vq->vq_type == VQ_SPLIT ? vring_split_set_predict_size(vq->vring, size) :
		vring_packed_set_predict_size(vq->vring, size);
}

void virtqueue_read_event(struct virtqueue *vq)
{
	vq->vq_type == VQ_SPLIT ? vring_split_read_event(vq->vring) :
		vring_packed_read_event(vq->vring);
}

void virtqueue_write_event(struct virtqueue *vq)
{
	vq->vq_type == VQ_SPLIT ? vring_split_write_event(vq->vring) :
		vring_packed_write_event(vq->vring);
}

uint16_t virtqueue_num(struct virtqueue *vq)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_num(vq->vring) :
		vring_packed_num(vq->vring);
}

uint16_t virtqueue_avail_idx(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT) {
		return vring_split_avail_idx(vq->vring);
	} else {
		return vring_packed_avail_idx(vq->vring);
	}
}

struct iovec *virtqueue_inv(struct virtqueue *vq, int eid, int id)
{
	if (vq->vq_type == VQ_SPLIT) {
		return vring_split_inv(vq->vring, eid, id);
	} else {
		return vring_packed_inv(vq->vring, eid, id);
	}
}

struct iovec *virtqueue_outv(struct virtqueue *vq, int eid, int id)
{
	if (vq->vq_type == VQ_SPLIT) {
		return vring_split_outv(vq->vring, eid, id);
	} else {
		return vring_packed_outv(vq->vring, eid, id);
	}
}

uint32_t virtqueue_desc_num(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT) {
		return ((struct vring_split *) (vq->vring))->num;
	} else {
		return ((struct vring_packed *) (vq->vring))->num;
	}
}

int virtqueue_pop(struct virtqueue *vq, struct vring_queue_elem **elems, uint32_t len)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_pops(vq->vring, elems, len) :
		   vring_packed_pops(vq->vring, elems, len);
}

struct vring_queue_elem *virtqueue_elems(struct virtqueue *vq, uint16_t *last_avail_idx, uint16_t *avail_idx)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_elems(vq->vring, last_avail_idx, avail_idx):
		vring_packed_elems(vq->vring, last_avail_idx, avail_idx);
}

void virtqueue_unpop(struct virtqueue *vq, int num)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_rewind(vq->vring, num) :
		   vring_packed_rewind(vq->vring, num);
}

int virtqueue_push(struct virtqueue *vq, struct vring_queue_elem **elems, uint32_t len)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_pushs(vq->vring, elems, len) :
		   vring_packed_pushs(vq->vring, elems, len);
}

int virtqueue_idx_push(struct virtqueue *vq, uint16_t last_avail_idx, uint16_t len)
{
	if (vq->vq_type == VQ_SPLIT)
		return vring_split_idx_pushs(vq->vring, last_avail_idx, len);
	else
		return vring_packed_idx_pushs(vq->vring, last_avail_idx, len);
}

void virtqueue_idx_pop(struct virtqueue *vq, uint32_t len)
{
	if (vq->vq_type == VQ_SPLIT)
		vring_split_idx_pop(vq->vring, len);
	else
		vring_packed_idx_pop(vq->vring, len);
}

int virtqueue_flush(struct virtqueue *vq) 
{
	return vq->vq_type == VQ_SPLIT ? vring_split_flush_job(vq->vring) :
		   vring_packed_flush_job(vq->vring);
}

void virtqueue_flush_synchronize(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT)
		vring_split_flush_synchronize(vq->vring);
}

uint16_t virtqueue_flags(struct virtqueue *vq)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_get_flags(vq->vring) :
		vring_packed_get_flags(vq->vring);
}

int virtqueue_cache(struct virtqueue *vq, int notify)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_cache(vq->vring, notify) :
		   vring_packed_cache(vq->vring);
}

int virtqueu_canbe_cache(struct virtqueue *vq)
{
	if (vq->flags & VRING_F_CACHE_FORCE)
		return 1;
	if (!(vq->flags & VRING_F_CACHE_PREDICT))
		return 0;
	if (unlikely(vq->err_tsc && rte_rdtsc() - vq->err_tsc <
			MS_PER_S * VRING_CANBE_CACHE_THRESHOLD))
		return 0;
	vq->err_tsc = 0;
	return vq->vq_type == VQ_SPLIT ? vring_split_canbe_cache(vq->vring):
		vring_packed_canbe_cache(vq->vring);
}

uint16_t virtqueue_flush_idx(struct virtqueue *vq)
{
	return vq->vq_type == VQ_SPLIT ? vring_split_flush_idx(vq->vring) :
		vring_packed_flush_idx(vq->vring);
}

void virtqueue_indir_cache(struct virtqueue *vq)
{
	vq->vq_type == VQ_SPLIT ? vring_split_indir_cache(vq->vring) :
		vring_packed_indir_cache(vq->vring);
}

int virtqueue_cache_error(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT)
		return vring_split_cache_error(vq->vring);
	return 0;
}

void virtqueue_dma_rejob(struct virtqueue *vq)
{
	struct agiep_async_dma_job *ajobs[JOB_ENQ_NUM];
	struct rte_ring *ring;
	unsigned int avail;
	unsigned int num;
	unsigned int ret;

	if (vq->vq_type == VQ_SPLIT) {
		ring = ((struct vring_split *)(vq->vring))->cache->pring;
	} else {
		ring = ((struct vring_packed *)(vq->vring))->cache->pring;
	}
	if (likely(rte_ring_count(ring) == 0))
		return;
	do {
		num = rte_ring_dequeue_burst(ring, (void **)ajobs, JOB_ENQ_NUM, &avail);

		if (!num)
			return;

		ret = agiep_dma_enqueue_buffers(vq->dma, ajobs, (int)num, DMA_JOB_F_FROM_PCI);

		if (ret < num) {
			rte_ring_enqueue_burst(ring,
				(void *const *) &ajobs[ret], num - ret, NULL);
			return;
		}

	} while(avail != 0);
}

void virtqueue_scan_avail(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT)
		vring_split_scan_avail(vq->vring);
}

__rte_always_inline size_t virtqueue_out_len(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT)
		return vring_split_out_len(vq->vring);

	return 0;
}
uint16_t virtqueue_get_last_avail(struct virtqueue *vq)
{
	uint16_t last_avail = 0;
	if (vq->vq_type == VQ_SPLIT) {
		last_avail = virtqueue_flush_idx(vq);
	}
	return last_avail;
}

uint16_t virtqueue_get_last_used(struct virtqueue *vq)
{
	uint16_t last_used;
	last_used = virtqueue_flush_idx(vq);
	return last_used;
}

void virtqueue_set_last_avail(struct virtqueue *vq, uint16_t last_avail)
{
	if (vq->vq_type == VQ_SPLIT) {
		((struct vring_split *)(vq->vring))->avail_idx = last_avail;
		((struct vring_split *)(vq->vring))->cache->desc.last_avail_idx = last_avail;
		((struct vring_split *)(vq->vring))->last_avail_idx = last_avail;
	}
}
void virtqueue_set_last_used(struct virtqueue *vq, uint16_t last_used)
{
	if (vq->vq_type == VQ_SPLIT) {
		((struct vring_split *)(vq->vring))->used_idx = last_used;
		((struct vring_split *)(vq->vring))->cache->used.used_flush_idx = last_used;
		((struct vring_split *)(vq->vring))->cache->used.used_clean_idx = last_used;
	}
}

void virtqueue_set_predict_mode(struct virtqueue *vq, uint16_t mode)
{
	if (vq->vq_type == VQ_SPLIT) {
		((struct vring_split *)(vq->vring))->cache->flags = mode;
	}
}

uint16_t virtqueue_get_predict_mode(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT && ((struct vring_split *)(vq->vring))->cache) {
		return ((struct vring_split *)(vq->vring))->cache->flags;
	}
	return 0;
}

uint32_t virtqueue_interruptable(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT) {
		return !(((struct vring_split *) (vq->vring))->avail->flags & VRING_AVAIL_F_NO_INTERRUPT) ;
	} else {
		return ((struct vring_packed *) (vq->vring))->driver->flags != VRING_PACKED_EVENT_FLAG_DISABLE;
	}
}

void virtqueue_set_interrupt(struct virtqueue *vq, uint16_t interrupt)
{
	if (vq->vq_type == VQ_SPLIT && ((struct vring_split *)(vq->vring))->cache) {
		((struct vring_split *)(vq->vring))->cache->interrupt = interrupt;
	}else {
		((struct vring_packed *)(vq->vring))->cache->interrupt = interrupt;
	}
}

uint16_t virtqueue_get_interrupt(struct virtqueue *vq)
{
	if (vq->vq_type == VQ_SPLIT && ((struct vring_split *)(vq->vring))->cache) {
		return ((struct vring_split *)(vq->vring))->cache->interrupt;
	} else {
		return ((struct vring_packed *)(vq->vring))->cache->interrupt;
	}
}