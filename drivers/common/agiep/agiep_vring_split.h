#ifndef RTE_AGIEP_VRING_SPLIT_H_
#define RTE_AGIEP_VRING_SPLIT_H_

#include "agiep_vring.h"
#include "agiep_vring_split_predict.h"


#define DEFAULT_RING_NUM 32
#define CACHE_USED_FLUSHING_INIT	0xF
#define CACHE_USED_FLUSHING_INITED 	0xE


/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *      // The actual descriptors (16 bytes each)
 *      struct vring_desc desc[num];
 *
 *      // A ring of available descriptor heads with free-running index.
 *      __virtio16 avail_flags;
 *      __virtio16 avail_idx;
 *      __virtio16 available[num];
 *      __virtio16 used_event_idx;
 *
 *      // Padding to the next align boundary.
 *      char pad[];
 *
 *      // A ring of used descriptor heads with free-running index.
 *      __virtio16 used_flags;
 *      __virtio16 used_idx;
 *      struct vring_used_elem used[num];
 *      __virtio16 avail_event_idx;
 * };
 */
#define VRING_SPLIT_RING_IDX_NUM 3

// 48 byte
struct avail_cache {
	uint16_t avail_idx;
	uint16_t last_avail_idx;
	uint32_t reserved;
	uint64_t pci;
	uint64_t phy;
	// head pci addr
	uint64_t hpci;
	// head phy addr
	uint64_t hphy;
	struct vring_avail *avail;
} __rte_cache_aligned;

// 48 byte
struct desc_cache {
	uint32_t predict_size;
	uint16_t last_desc_idx;
	uint16_t last_avail_idx;
	uint64_t pci;
	uint64_t phy;
	struct vring_desc *desc;
} __rte_cache_aligned;

// 48 byte
struct used_cache {
	uint16_t used_flush_idx;
	uint16_t used_clean_idx;
	uint32_t reserved;
	uint64_t pci;
	uint64_t phy;
	// head pci addr
	uint64_t hpci;
	// head phy addr
	uint64_t hphy;
	struct vring_used *used;
} __rte_cache_aligned;

// 24 byte
struct vring_desc_state_split {
	int error;
	int desc_measur_len;
	uint64_t desc_cache_seq;
	struct vring_desc *indir_desc;
};

struct split_desc_context {
	struct vring_split_cache *cache;
	union {
		uint16_t idx;
		uint16_t last_avail_idx;
	};

	uint16_t avail_idx;
	uint64_t desc_cache_seq;
	struct vring_desc *indir_desc;
};

struct vring_split_cache {
	// -- cache line --
	// 8 byte
	uint8_t cacheing;
	uint8_t cache_error;
	uint16_t flags;
	uint16_t num;
	uint16_t used_flushing;
	// 8 * 7 = 56 byte
	struct vring_desc_state_split *desc_state;
	uint64_t *avail_state;
	struct agiep_dma *dma;
	// pending jobs ring
	struct rte_ring *pring;
	// indir cache ring
	struct rte_ring *iring;
	struct rte_mempool *ctx_pool;
	// -- cache line---
	struct avail_cache avail;
	// -- cache line---
	struct desc_cache desc;
	// -- cache line---
	struct used_cache used;
	// -- cache line---
	struct agiep_vring_split_predict predict;
	uint16_t interrupt;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	int idx;
#endif
};

struct vring_split {
	struct vring_split_cache *cache;
	struct agiep_dma *dma;

	uint16_t num;
	uint16_t mask;  /* mask num - 1 of vring */
	volatile uint16_t last_avail_idx;
	volatile uint16_t avail_idx;
	uint16_t used_idx;
	uint16_t out_len;
	uint16_t reserved1[2];
	struct vring_queue_elem *elems;
	uint64_t reserved2[3];
	// cache line
	struct iovec *inv[MAX_IOV_SIZE];
	struct iovec *outv[MAX_IOV_SIZE];
	// cache line
	struct vring_avail *avail;
	struct vring_used *used;
	struct vring_desc *desc;
	uint32_t *flags;
} __rte_cache_aligned;



struct vring_split *vring_split_create(int idx, uint16_t num, uint32_t *flags);

void vring_split_free(struct vring_split *vring);

int vring_split_flush_job(struct vring_split *ring);
void vring_split_flush_synchronize(struct vring_split *ring);

int vring_split_pop_indir(struct vring_split *vring, struct vring_desc *descs,
		struct vring_queue_elem *elem, uint16_t len);

int vring_split_pops(struct vring_split *ring, struct vring_queue_elem **elems,
		uint32_t len);

struct vring_queue_elem *vring_split_elems(struct vring_split *vring,
		uint16_t *last_avail_idx, uint16_t *avail_idx);

int vring_split_pushs(struct vring_split *ring, struct vring_queue_elem **elems,
		uint32_t len);

void vring_split_idx_pop(struct vring_split *ring, uint32_t len);
int vring_split_idx_pushs(struct vring_split *ring, uint16_t last_avail_idx,
		uint16_t len);

int vring_split_cache(struct vring_split *ring, int notify);

void vring_split_set_job(struct vring_split *ring);


void vring_split_set_dma(struct vring_split *vring, struct agiep_dma *dma);


void vring_split_set_addr(struct vring_split *vring, uint64_t apci,
		uint64_t upci, uint64_t dpci);
void vring_split_set_pci_addr(struct vring_split *vring, uint64_t desc);
void vring_split_clear_addr(struct vring_split *vring);
int vring_split_enabled(struct vring_split *vring);
void vring_split_set_predict_size(struct vring_split *vring, uint32_t size);


void vring_split_rewind(struct vring_split *ring, uint16_t num);
uint16_t vring_split_flush_idx(struct vring_split *ring);
uint32_t vring_split_get_idx(struct vring_split *ring);
uint16_t vring_split_get_flags(struct vring_split *ring);
uint16_t vring_split_num(struct vring_split *vring);
uint16_t vring_split_avail_idx(struct vring_split *vring);

struct iovec *vring_split_inv(struct vring_split *vring, int eid, int id);
struct iovec *vring_split_outv(struct vring_split *vring, int eid, int id);

static inline unsigned vring_size(unsigned int num, unsigned long align)
{
	return ((sizeof(struct vring_desc) * num + sizeof(uint16_t) *
		(VRING_SPLIT_RING_IDX_NUM + num) + align - 1) & ~(align - 1))
	       + sizeof(uint16_t) * VRING_SPLIT_RING_IDX_NUM
	       + sizeof(struct vring_used_elem) * num;
}


// cache
struct vring_split_cache *vring_split_cache_create(int idx,
	struct vring_desc *desc, uint64_t desc_phy, uint16_t num, uint32_t flags);
void vring_split_cache_clear_addr(struct vring_split_cache *cache);
void vring_split_cache_free(struct vring_split_cache *cache);

int vring_cache_pipeline(struct vring_split_cache *cache, int notify);
int vring_avail_cache(struct vring_split_cache *cache);

int vring_desc_cache(struct vring_split_cache *cache);

int vring_avail_head_cache(struct vring_split_cache *cache);
int vring_avail_cache_all(struct vring_split_cache *cache);
int vring_used_head_cache(struct vring_split_cache *cache);

void vring_split_indir_cache(struct vring_split *ring);
int vring_split_cache_error(struct vring_split *ring);

int vring_split_canbe_cache(struct vring_split *vring);

void vring_split_cache_indir_cache(struct vring_split_cache *cache);

int vring_split_read_event(struct vring_split_cache *cache);

int vring_split_write_event(struct vring_split_cache *cache);

size_t vring_split_out_len(struct vring_split *ring);

void vring_split_scan_avail(struct vring_split *vring);

#endif
