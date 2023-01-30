#ifndef RTE_AGIEP_VRING_H_
#define RTE_AGIEP_VRING_H_

#include <stdint.h>
#include <sys/uio.h>
#include <rte_io.h>

#include "agiep_dma.h"
#include "agiep_dirty_log.h"
#include "agiep_logs.h"
// align to one page
#define ALIGN_SIZE 4096
#define VIRTIO_PCI_VRING_ALIGN         4096

#define VRING_MAX_DESC 4096

#define QUEUE_FULL (-1)

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT		1U
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE		2U
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT		4U

/* This flag means the descriptor was made available by the driver */
#define VRING_PACKED_DESC_F_AVAIL	(1U << 7U)
/* This flag means the descriptor was used by the device */
#define VRING_PACKED_DESC_F_USED	(1U << 15U)

/* Frequently used combinations */
#define VRING_PACKED_DESC_F_AVAIL_USED	(VRING_PACKED_DESC_F_AVAIL | \
					 VRING_PACKED_DESC_F_USED)

#define VRING_FLE_SIZE 32

#define VRING_USED_F_NO_NOTIFY  1
#define VRING_AVAIL_F_NO_INTERRUPT  1
#define VRING_ELEM_CACHE_SIZE 64
#define VRING_CTX_CACHE_SIZE 16
#define VRING_INDIR_CACHE_SIZE 16

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE	0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE	0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC	0x2

#define MAX_IOV_SIZE 16

#define MS_PER_S 1000
#define VRING_CANBE_CACHE_THRESHOLD 10 //1us

#define VRING_F_CACHE_PREDICT	1
#define VRING_F_CACHE_FORCE	2
#define VRING_F_ELEM_RING	4
#define VRING_F_RING_PREDICT	8
#define VRING_F_NO_NOTIFY	0x0010

#define INTERRUPT_NO	0
#define INTERRUPT_PRE	1
#define INTERRUPT_RAISE	2

#define VRING_SPLIT_MAX_FLAG (VRING_DESC_F_NEXT | \
		VRING_DESC_F_WRITE             | \
                VRING_DESC_F_INDIRECT)
struct virtqueue;
typedef void (* virtqueue_enable_callback)(void * data);

/**
 * if vq notify equal 1 , return 1 and atomic set notify to 0
 * if vq notifu equal 0, read port notify/doorbell and return
 * **thread safe**
 */
typedef uint16_t (* virtqueue_notify_cb)(struct virtqueue *vq);

enum virtqueue_type {
	VQ_SPLIT,
	VQ_PACKED,
};

struct vring_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

struct vring_packed_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t id;
	uint16_t flags;
};

struct vring_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[];
};

struct vring_used_elem {
	uint32_t id;
	volatile uint32_t len;
};

struct vring_used {
	uint16_t flags;
	uint16_t idx;
	struct vring_used_elem ring[];
};

struct vring_packed_desc_event {
	uint16_t off_wrap;
	uint16_t flags;
};

struct vring_queue_elem {
	// 16 byte
	uint16_t id;    // avail idx
	uint16_t index; // desc index
	uint16_t ndescs;
	uint16_t len;
	uint16_t out_len;
	uint16_t in_len;
	uint16_t wrap;
	uint8_t out_num;
	uint8_t in_num;
};

struct virtqueue {
	enum virtqueue_type vq_type;
	uint16_t notify;
	uint16_t msi_vector;
	void *vring;
	int num;
	uint32_t flags;
	uint64_t err_tsc;
	struct agiep_dma *dma;
	void *priv;
	int index;
	virtqueue_enable_callback cb;
	void *cb_data;
	struct agiep_dirty_log *dlog;
	virtqueue_notify_cb notify_cb;
}__rte_cache_aligned;

/**
 * Create virtio virtqueue
 * @param idx virtqueue idx
 * @param num
 * @param vq_type VQ_SPLIT or VQ_PACKED
 * @param flags virtqueue init flags as VRING_F_*
 * @return virtqueue pointer
 */
struct virtqueue *virtqueue_create(int idx, uint16_t num,
	enum virtqueue_type vq_type, uint32_t flags);
/**
 * free virtqueue
 * @param vq
 */
void virtqueue_free(struct virtqueue *vq);

void virtqueue_set_addr(struct virtqueue *vq, uint64_t avail, uint64_t used, uint64_t desc);
void virtqueue_set_pci_addr(struct virtqueue *vq,uint64_t desc);
void virtqueue_clear_addr(struct virtqueue *vq);
int virtqueue_enabled(struct virtqueue *vq);
void virtqueue_set_dma(struct virtqueue *vq, struct agiep_dma *dma);
uint32_t virtqueue_desc_num(struct virtqueue *vq);
uint32_t virtqueue_interruptable(struct virtqueue *vq);

void virtqueue_set_predict_size(struct virtqueue *vq, uint32_t size);
void virtqueue_read_event(struct virtqueue *vq);
void virtqueue_write_event(struct virtqueue *vq);



uint16_t virtqueue_num(struct virtqueue *vq);
uint16_t virtqueue_avail_idx(struct virtqueue *vq);
// Before virtqueue_pop, must call virtqueue_num to confirm the avail num.
int virtqueue_pop(struct virtqueue *vq, struct vring_queue_elem **elems, uint32_t len);
void virtqueue_unpop(struct virtqueue *vq, int num);

int virtqueue_push(struct virtqueue *vq, struct vring_queue_elem **elems, uint32_t len);
void virtqueue_idx_pop(struct virtqueue *vq, uint32_t len);
int virtqueue_idx_push(struct virtqueue *vq, uint16_t last_avail_idx, uint16_t len);
int virtqueue_flush(struct virtqueue *vq);
void virtqueue_flush_synchronize(struct virtqueue *vq);
uint16_t virtqueue_flush_idx(struct virtqueue *vq);
uint16_t virtqueue_flags(struct virtqueue *vq);

int virtqueu_canbe_cache(struct virtqueue *vq);
int virtqueue_cache(struct virtqueue *vq, int notify);
int virtqueue_cache_error(struct virtqueue *vq);
void virtqueue_indir_cache(struct virtqueue *vq);

void virtqueue_dma_rejob(struct virtqueue *vq);
struct vring_queue_elem *virtqueue_elems(struct virtqueue *vq, uint16_t *last_avail_idx, uint16_t *avail_idx);

struct iovec *virtqueue_inv(struct virtqueue *vq, int eid, int id);
struct iovec *virtqueue_outv(struct virtqueue *vq, int eid, int id);

unsigned virtqueue_elem_mc_dequeue_bulk(struct virtqueue *vq,
	struct vring_queue_elem **elems,
	unsigned int n, unsigned int *available);

unsigned int virtqueue_elem_count(struct virtqueue *vq);

void virtqueue_scan_avail(struct virtqueue *vq);

size_t virtqueue_out_len(struct virtqueue *vq);

uint16_t virtqueue_get_last_avail(struct virtqueue *vq);
void virtqueue_set_last_avail(struct virtqueue *vq, uint16_t last_avail);
uint16_t virtqueue_get_last_used(struct virtqueue *vq);
void virtqueue_set_last_used(struct virtqueue *vq, uint16_t last_used);

void virtqueue_set_predict_mode(struct virtqueue *vq, uint16_t mode);
uint16_t virtqueue_get_predict_mode(struct virtqueue *vq);

void virtqueue_set_interrupt(struct virtqueue *vq, uint16_t interrupt);
uint16_t virtqueue_get_interrupt(struct virtqueue *vq);
#endif
