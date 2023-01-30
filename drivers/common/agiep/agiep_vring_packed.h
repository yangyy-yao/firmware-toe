#ifndef RTE_AGIEP_VRING_PACKED_H_
#define RTE_AGIEP_VRING_PACKED_H_

#include <stdint.h>
#include <sys/uio.h>
#include <rte_io.h>
#include "agiep_vring.h"
#include "agiep_dma.h"

#define PACKED_PREDICT_SIZE 8
/*
 * avail desc缓存过程：
 * 1. 从last_avail_idx开始缓存CACHE_SIZE个desc.
 * 2. DMA结束以后判断是否结尾，如果没有结尾，则继续CACHE_SIZE个。
 * 3. 如果结束，判断下一个ID是否为avail_desc，如果是跳到1继续
 *
 * 如果queue desc有avail_idx设置，则predict size等于 |cache->desc->last_avail_idx - avail_idx|
 */

#define CACHE_JOB_NUM 2

struct flush_context {
	int flush_idx;
	int used_idx;
	int flush_head;
	uint16_t flags;
	struct vring_packed *ring;
};

struct packed_desc_cache {
	uint16_t last_avail_idx; // 本地缓存位置
	uint16_t predict_size;
	uint64_t pci;
	uint64_t phy;
	struct vring_packed_desc *desc;
	struct vring_packed *ring;
};
struct packed_desc_used {
	uint64_t phy;
	struct vring_packed_desc *desc;
};

struct packed_driver_cache {
	uint64_t pci;
	uint64_t phy;
	struct vring_packed_desc_event *driver;
};

struct packed_device_cache {
	uint64_t pci;
	uint64_t phy;
	struct vring_packed_desc_event *device;
};

struct vring_packed_cache;

struct desc_dma_context {
	struct vring_packed_cache *cache;
	uint16_t next_desc_idx; // last should cache idx for desc
	uint16_t prev_avail_idx;
	uint16_t last_avail_idx;
	uint16_t reserved;
	int avail_wrap_counter;
};

struct vring_packed_desc_indir {
	struct vring_packed_cache *cache;
	uint16_t idx;
	uint64_t padding[8]; // dma cache align
	struct vring_packed_desc *indir_desc;
};

struct vring_desc_state_packed {
	int error;
	struct vring_packed_desc *indir_desc;
};

struct vring_packed_cache {
	struct agiep_dma *dma;
	struct desc_dma_context desc_ctx;
	struct vring_desc_state_packed *desc_state;
	struct packed_desc_cache desc;
	struct packed_driver_cache driver;
	struct packed_device_cache device;
	int caching;
	int avail_wrap_counter;
	uint16_t mask;  // num - 1
	uint16_t num;  // size of desc len
	uint16_t indir_idx;
	uint16_t next_desc_idx; // last should cache idx for desc
	struct rte_ring *pring;  // indir fail desc job ring
	struct vring_packed_desc_indir *indir_ctx;  // indir ctx array
	uint16_t interrupt;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	int idx;
#endif
};

struct vring_packed {
	struct vring_packed_cache *cache;
	struct agiep_dma *dma;
	uint32_t *flags;
	uint16_t mask; // num - 1
	uint16_t num;
	uint16_t last_avail_idx; // 本地使用到
	uint16_t flushing;
	uint16_t *avail_idx; //point to cache->desc->last_avail_idx;
	uint16_t avail_elem_idx;

	uint16_t last_avail_elem_idx;
	uint16_t used_idx;
	uint16_t flush_idx;
	struct vring_queue_elem *elems;

	struct iovec **inv;
	struct iovec *outv[MAX_IOV_SIZE];

	int used_wrap_counter;
	int scan_used_wrap_counter;
	struct vring_packed_desc_event *device;
	struct vring_packed_desc_event *driver;
	struct vring_packed_desc *desc; // point to cache->desc
	struct packed_desc_used used;  // desc shadow. save used desc->flags
	struct rte_mempool *flush_ctx_pool;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	int idx;
#endif
};


int vring_packed_cache(struct vring_packed *ring);
int vring_packed_flush_job(struct vring_packed *ring);
int vring_packed_pushs(struct vring_packed *vring, struct vring_queue_elem **elems, uint32_t len);
int vring_packed_pops(struct vring_packed *vring, struct vring_queue_elem **elems, uint32_t len);

struct vring_packed *vring_packed_create(int idx, uint16_t num, uint32_t *flags);
void vring_packed_free(struct vring_packed *vring);
void vring_packed_set_addr(struct vring_packed *vring,
	uint64_t apci, uint64_t upci, uint64_t dpci);
void vring_packed_set_pci_addr(struct vring_packed *vring, uint64_t desc);

int vring_packed_enabled(struct vring_packed *vring);
void vring_packed_clear_addr(struct vring_packed *vring);
void vring_packed_set_predict_size(struct vring_packed *vring,
		uint32_t size);
int vring_packed_pop_indir(struct vring_packed *vring, struct vring_packed_desc *descs,
	struct vring_queue_elem *elem, int len);
void vring_packed_indir_cache(struct vring_packed *ring);
int vring_packed_desc_cache(struct vring_packed_cache *cache);
struct vring_packed_cache *vring_packed_cache_create(int idx,
	struct vring_packed_desc *desc, struct vring_packed_desc_event *device,
	struct vring_packed_desc_event *driver, uint16_t num);
void vring_packed_set_dma(struct vring_packed *vring, struct agiep_dma *dma);
void vring_packed_cache_free(struct vring_packed_cache *cache);
void vring_packed_cache_indir_cache(struct vring_packed_cache *cache);
int vring_packed_write_event(struct vring_packed_cache *cache);
int vring_packed_read_event(struct vring_packed *vring);
void vring_packed_rewind(struct vring_packed *vring, int num);

uint16_t vring_packed_num(struct vring_packed *vring);
uint16_t vring_packed_flush_idx(struct vring_packed *ring);
uint16_t vring_packed_get_flags(struct vring_packed *ring);
uint32_t vring_packed_get_idx(struct vring_packed *ring);

int vring_packed_idx_pushs(struct vring_packed *vring,
	uint16_t last_avail_idx, uint16_t len);
void vring_packed_idx_pop(struct vring_packed *vring, uint32_t len);

struct vring_queue_elem *vring_packed_elems(struct vring_packed *vring,
	uint16_t *last_avail_idx, uint16_t *avail_idx);

struct iovec *vring_packed_inv(struct vring_packed *vring, int eid, int id);
struct iovec *vring_packed_outv(struct vring_packed *vring, int eid, int id);

int vring_packed_canbe_cache(struct vring_packed *vring);
uint16_t vring_packed_avail_idx(struct vring_packed *vring);
#endif
