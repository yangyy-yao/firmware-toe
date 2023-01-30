#include <assert.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>

#include "agiep_dma.h"
#include "agiep_vring_split.h"
#include "agiep_vring.h"

#define PAGE_SIZE_ALIGN 4096

void vring_split_scan_used_idx(struct vring_split *ring);
void vring_split_flush_done1(struct agiep_async_dma_job *job);
void vring_split_flush_done2(struct agiep_async_dma_group *group);
void vring_split_flush_done3(struct agiep_async_dma_job *job);
void vring_split_flush_head(struct vring_split *ring);
struct vring_split *vring_split_create(int idx, uint16_t num, uint32_t *flags)
{
	int i;
	struct vring_split *vring = NULL;
	struct vring_avail *avail = NULL;
	struct vring_used *used = NULL;
	struct vring_desc *desc = NULL;
	struct vring_split_cache *cache = NULL;
	struct vring_queue_elem *elems = NULL;
	struct iovec **inv = NULL;
	struct iovec **outv = NULL;
	uint32_t flag = *flags;
	uint64_t desc_phy = 0;

	vring = rte_calloc(NULL, 1, sizeof(struct vring_split), RTE_CACHE_LINE_SIZE);
	if (vring == NULL)
		goto error;
	elems = rte_calloc(NULL, num, sizeof(struct vring_queue_elem), RTE_CACHE_LINE_SIZE);

	if (!elems) {
		AGIEP_LOG_ERR("split elems alloc error %d", rte_errno);
		goto error;
	}

	desc = rte_calloc(NULL, 1, vring_size(num, PAGE_SIZE_ALIGN),
			  PAGE_SIZE_ALIGN);
	if (!desc){
		AGIEP_LOG_ERR("split desc ring calloc fail: %p %d\n", desc, rte_errno);
		goto error;
	}

	avail = RTE_PTR_ADD(desc, sizeof(struct vring_desc) * num);
	used = RTE_PTR_ALIGN(RTE_PTR_ADD(avail,sizeof(uint16_t) *
		(num + VRING_SPLIT_RING_IDX_NUM)), PAGE_SIZE_ALIGN);
	desc_phy = rte_malloc_virt2iova(desc);

	vring->elems = elems;

	for (i = 0; i < num; i++) {
		vring->elems[i].id = i;
	}

	cache = vring_split_cache_create(idx, desc, desc_phy, num, flag);

	if (!cache)
		goto error;

	inv = rte_calloc(NULL, num * MAX_IOV_SIZE, sizeof(struct iovec), RTE_CACHE_LINE_SIZE);
	outv = rte_calloc(NULL, num * MAX_IOV_SIZE, sizeof(struct iovec), RTE_CACHE_LINE_SIZE);
	if (inv == NULL || outv == NULL)
		goto error;

	for (i = 0; i < MAX_IOV_SIZE; i++) {
		vring->inv[i] = RTE_PTR_ADD(inv, sizeof(struct iovec) * num * i);
		vring->outv[i] = RTE_PTR_ADD(outv, sizeof(struct iovec) * num * i);
	}

	cache->desc.predict_size = 8;
	vring->flags = flags;
	vring->cache = cache;
	vring->dma = NULL;
	vring->num = num;
	vring->mask = num - 1;

	vring->avail = avail;
	vring->used = used;
	vring->desc = desc;
	return vring;

error:
	if (inv)
		rte_free(inv);
	if (outv)
		rte_free(outv);
	if (desc)
		rte_free(desc);
	if (cache)
		vring_split_cache_free(cache);
	if (elems) {
		rte_free(elems);
	}
	if (vring) {
		for (i = 0; i < MAX_IOV_SIZE; i++) {
			if(vring->inv[i])
				rte_free(vring->inv[i]);
			if(vring->outv[i])
				rte_free(vring->outv[i]);
		}
		rte_free(vring);
	}
	return NULL;
}

void vring_split_free(struct vring_split *vring)
{
	if (!vring)
		return;
	if (vring->inv[0])
		rte_free(vring->inv[0]);
	if (vring->outv[0])
		rte_free(vring->outv[0]);
	rte_free(vring->desc);
	vring_split_cache_free(vring->cache);
	rte_free(vring->elems);
	rte_free(vring);
}

void vring_split_set_addr(struct vring_split *vring, uint64_t apci, uint64_t upci, uint64_t dpci)
{
	struct vring_split_cache *cache = vring->cache;
	cache->avail.hpci = apci;
	cache->avail.pci = apci + sizeof(uint32_t);

	cache->used.hpci = upci;
	cache->used.pci = upci + sizeof(uint32_t);

	// Make sure desc.pci is last.
	rte_mb();
	cache->desc.pci = dpci;
}
void vring_split_set_pci_addr(struct vring_split *vring, uint64_t desc)
{
	struct vring_split_cache *cache = vring->cache;
	uint64_t apci;
	uint64_t upci;
	apci = desc + vring->num * sizeof(struct vring_desc);
	upci = RTE_ALIGN(apci + (3 + vring->num) *
				 sizeof(uint16_t), VIRTIO_PCI_VRING_ALIGN);

	cache->avail.hpci = apci;
	cache->avail.pci = apci + sizeof(uint32_t);

	cache->used.hpci = upci;
	cache->used.pci = upci + sizeof(uint32_t);

	// Make sure desc.pci is last.
	rte_mb();
	cache->desc.pci = desc;
}

void vring_split_clear_addr(struct vring_split *vring)
{
	vring_split_cache_clear_addr(vring->cache);
}

inline int vring_split_enabled(struct vring_split *vring)
{
	// Reduce the number of judgment variables.  desc.pci must be last.
	return (int)vring->cache->desc.pci;
}

void vring_split_set_predict_size(struct vring_split *vring, uint32_t size)
{
	struct vring_split_cache *cache = vring->cache;
	cache->desc.predict_size = size;
}

inline int vring_split_cache(struct vring_split *ring, int notify)
{
	return vring_cache_pipeline(ring->cache, notify);
}

void vring_split_indir_cache(struct vring_split *ring)
{
	struct vring_split_cache *cache = ring->cache;
	return vring_split_cache_indir_cache(cache);
}

static __rte_always_inline struct iovec *
vring_split_fetch_iov(struct iovec **iov, int id, int iov_id)
{
	return &iov[iov_id][id];
}

__rte_always_inline struct iovec *
vring_split_inv(struct vring_split *vring, int eid, int id)
{
	return vring_split_fetch_iov(vring->inv, eid, id);
}

__rte_always_inline struct iovec *
vring_split_outv(struct vring_split *vring, int eid, int id)
{
	return vring_split_fetch_iov(vring->outv, eid, id);
}

int
vring_split_pop_indir(struct vring_split *vring, struct vring_desc *descs, struct vring_queue_elem *elem,
		uint16_t len)
{
	struct vring_desc *desc;
	struct iovec *outv;
	struct iovec *inv;
	int i;

	for (i = 0; i < len; i++) {
		desc = &descs[i];
		elem->ndescs++;

		if (desc->flags & VRING_DESC_F_WRITE) {
			outv = vring_split_fetch_iov(vring->outv, elem->id, elem->out_num);
			outv->iov_base = (void *)desc->addr;
			outv->iov_len = desc->len;
			elem->out_num++;
			elem->out_len += desc->len;
		} else {
			inv = vring_split_fetch_iov(vring->inv, elem->id, elem->in_num);
			inv->iov_base = (void *)desc->addr;
			inv->iov_len = desc->len;
			elem->in_num++;
			elem->in_len += desc->len;
		}
	}

	return 0;
}

void vring_split_scan_avail(struct vring_split *vring)
{
	struct vring_queue_elem *elems;
	struct vring_desc *desc;
	struct iovec *outv;
	struct iovec *inv;
	struct vring_desc *ring_desc;
	uint16_t *ring;
	uint64_t avail_state;
	int avail_state_idx;
	int desc_idx;
	int rlen;
	int i;
	uint16_t avail_idx;
	uint16_t last_avail_idx;
	uint16_t out_len;
	uint16_t in_len;
	uint16_t ndescs;
	uint16_t mask;
	uint16_t out_num;
	uint16_t in_num;

	elems = vring->elems;
	avail_idx = vring->avail_idx;

	rlen = vring->cache->desc.last_avail_idx - avail_idx;
	if (!rlen)
		return;
	if (rlen < 0)
		rlen = rlen + UINT16_MAX + 1;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(rlen <= vring->num);
#endif
	mask = vring->mask;
	ring = vring->avail->ring;
	ring_desc = vring->desc;

	avail_state_idx = (avail_idx & mask ) / 64;
	avail_state = vring->cache->avail_state[avail_state_idx];
	outv = NULL;
	for (i = 0; i < rlen; i++) {
		last_avail_idx = avail_idx & mask;
		if (unlikely(last_avail_idx / 64 != avail_state_idx)) {
			vring->cache->avail_state[avail_state_idx] = avail_state;
			avail_state_idx = last_avail_idx / 64;
			avail_state = vring->cache->avail_state[avail_state_idx];
		}
		if (!(avail_state & (1ULL << (last_avail_idx % 64))))
			break;
		avail_state &= ~(1ULL << (last_avail_idx % 64));
		desc_idx = ring[last_avail_idx];

		elems[last_avail_idx].index = desc_idx;
		elems[last_avail_idx].len = 0;
//		elems[last_avail_idx].wrap = 0;

		ndescs = 0;
		out_num = 0;
		out_len = 0;
		in_num = 0;
		in_len = 0;

		do {
			desc = &ring_desc[desc_idx];
			if (unlikely(desc->flags & VRING_DESC_F_INDIRECT)) {
				if (!vring->cache->desc_state[desc_idx].indir_desc)
					return;
				vring_split_pop_indir(vring,
						vring->cache->desc_state[desc_idx].indir_desc, &elems[last_avail_idx],
						desc->len / sizeof(struct vring_desc));
				rte_free(vring->cache->desc_state[desc_idx].indir_desc);
				vring->cache->desc_state[desc_idx].indir_desc = NULL;
				break;
			}

			ndescs++;

			// TODO: Need check that all read desc must after write desc.
			if (desc->flags & VRING_DESC_F_WRITE) {
				outv = vring_split_fetch_iov(vring->outv, last_avail_idx, out_num);
				outv->iov_base = (void *)desc->addr;
				outv->iov_len = desc->len;
				out_num++;
				out_len += desc->len;
			} else {
				inv = vring_split_fetch_iov(vring->inv, last_avail_idx, in_num);
				inv->iov_base = (void *)desc->addr;
				inv->iov_len = desc->len;
				in_num++;
				in_len += desc->len;
			}

			desc_idx = desc->next;
		} while (desc->flags & VRING_DESC_F_NEXT);
		elems[last_avail_idx].ndescs = ndescs;
		elems[last_avail_idx].out_num = out_num;
		elems[last_avail_idx].out_len = out_len;
		elems[last_avail_idx].in_num = in_num;
		elems[last_avail_idx].in_len = in_len;
		avail_idx++;
	}

	vring->cache->avail_state[avail_state_idx] = avail_state;
	vring->avail_idx = avail_idx;
}

__rte_always_inline size_t vring_split_out_len(struct vring_split *ring)
{
	return ring->out_len;
}

static __rte_always_inline uint16_t vring_split_avail_num(struct vring_split *vring)
{
	int size;
	size = vring->avail_idx - vring->last_avail_idx;
	if (size < 0)
		size = size + UINT16_MAX + 1;
	return (uint16_t)size;
}

uint16_t vring_split_num(struct vring_split *vring)
{
	vring_split_scan_avail(vring);
	return vring_split_avail_num(vring);
}

__rte_always_inline uint16_t vring_split_avail_idx(struct vring_split *vring)
{
	return vring->avail->idx;
}

int vring_split_pops(struct vring_split *vring, struct vring_queue_elem **elems,
		uint32_t len)
{
	uint32_t num;
	uint32_t i;
	uint16_t last_avail_idx;
	uint16_t nb_desc = vring->num;
	num = vring_split_avail_num(vring);

	if (num == 0)
		return 0;
	if (unlikely(num < len))
		len = num;

	for (i = 0; i < len; i++) {
		last_avail_idx = vring->last_avail_idx % nb_desc;
		elems[i] = &vring->elems[last_avail_idx];
		if (vring->last_avail_idx % 2 == 0) {
			last_avail_idx = (vring->last_avail_idx + 2) % nb_desc;
			rte_prefetch0(&vring->elems[last_avail_idx]);
		}
		vring->last_avail_idx++;
	}
	return len;
}

struct vring_queue_elem *vring_split_elems(struct vring_split *vring, uint16_t *last_avail_idx, uint16_t *avail_idx)
{
	*last_avail_idx = vring->last_avail_idx;
	if (avail_idx)
		*avail_idx = vring->avail_idx;
	return vring->elems;
}

void vring_split_rewind(struct vring_split *vring, uint16_t num)
{
	int i;
	uint16_t last_avail_idx;
	uint16_t nb_desc = vring->num;
	vring->last_avail_idx -= num;
	last_avail_idx = vring->last_avail_idx;

	for (i = 0; i < num; i++) {
		vring->elems[last_avail_idx].len = 0;
		last_avail_idx = (last_avail_idx + 1) % nb_desc;
	}
}

int vring_split_pushs(struct vring_split *ring, struct vring_queue_elem **elems,
		uint32_t len)
{
	uint i;
	struct vring_used_elem *elem;

	for (i = 0; i < len; i++) {
		elem = &ring->used->ring[elems[i]->id];
		elem->id = elems[i]->index;
		elem->len = elems[i]->len;
		rte_wmb();
	}
	return len;
}

void vring_split_idx_pop(struct vring_split *ring, uint32_t len)
{
	ring->last_avail_idx += len;
}

int vring_split_idx_pushs(struct vring_split *ring, uint16_t last_avail_idx,
		uint16_t len)
{
	uint16_t i;
	uint16_t avail_idx;
	uint16_t nb_desc = ring->num;
	struct vring_queue_elem *qelem;
	struct vring_used_elem *elem;

	for (i = 0; i < len; i++) {
		avail_idx = last_avail_idx % nb_desc;
		last_avail_idx ++;
		qelem = &ring->elems[avail_idx];
		elem = &ring->used->ring[avail_idx];
		elem->id = qelem->index;
		elem->len = qelem->len;
		rte_wmb();
	}
	return len;
}
__rte_always_inline static int vring_split_used_fulled(struct vring_split *ring)
{
	const uint16_t mask = ring->mask;
	/* 解决used ring 可能出现情况:
	 * 在vring_split_flush_job() (1) 与下一次vring_split_scan_used_idx() (2)
	 * 的间隙中，used_ring 被一次性填充满，此时在 vring_split_flush_done1/2 未执行，
	 * ring[x].len未被置0，在下一次执行vring_split_scan_used_idx时，
	 * ring->used_idx将会越过used.used_clean_idx在ring中的位置，使used_idx 比实际
	 * 大 (used.used_flush_idx - used.used_clean_idx)，可能造成未知错误
	 */
	/* 判断条件:
	 * 1. 正常情况总是used.used_clean_idx追赶used_idx，如果追上了说明队列已空，
	 *    返回1交由下一个判断条件；
	 * 2. 如果used_idx在ring中的位置追上了used.used_clean_idx，
	 *    代表队列已满，此时返回0退出循环；
	 * 3. 常规条件下 返回1；
	 * 4. 启动时与队列为空时情况相同 返回1
	 */
	// TODO: 修改判断条件，避免歧义
		/* ring 已满 */
	return (((ring->used_idx & mask) != (ring->cache->used.used_clean_idx & mask))
		/* ring 为空 */
		|| (ring->used_idx == ring->cache->used.used_clean_idx));
}
void vring_split_scan_used_idx(struct vring_split *ring)
{
	const uint16_t nb_desc = ring->num;
	const uint16_t mask = ring->mask;
	uint16_t nb_used = 0;
	while (nb_used < nb_desc && vring_split_used_fulled(ring) &&
		ring->used->ring[ring->used_idx & mask].len)
	{
		ring->used_idx ++;
		nb_used ++;
	}
}

void vring_split_flush_done1(struct agiep_async_dma_job *job) 
{
	uint16_t i;
	uint16_t used_flush_idx;
	uint16_t used_idx;
	struct vring_used_elem *elem;
	struct vring_split *ring;
	uint16_t nb_desc;
	ring = job->priv;
	nb_desc = ring->num;
	used_idx = job->user_args & 0xFFFF;
	used_flush_idx = (job->user_args & 0xFFFF0000) >> 16;
	i = used_flush_idx;
	while(i != used_idx) {
		elem = &ring->used->ring[i % nb_desc];
		elem->len = 0;
		i++;
	}

	rte_mempool_put(job->dma->jpool, job);
}

void vring_split_flush_done2(struct agiep_async_dma_group *group) 
{
	uint16_t i;
	uint16_t used_flush_idx;
	uint16_t used_idx;
	struct vring_split *ring = group->priv;
	uint16_t nb_desc = ring->num;
	struct vring_used_elem *elem;

	used_idx = group->user_args & 0xFFFF;
	used_flush_idx = (group->user_args & 0xFFFF0000) >> 16;
	i = used_flush_idx;
	while(i != used_idx) {
		elem = &ring->used->ring[i % nb_desc];
		elem->len = 0;
		i++;
	}

	rte_mempool_put(group->dma->jpool, group);
}


int vring_split_flush_job(struct vring_split *ring) 
{
	uint16_t used_flush_idx;
	uint16_t used_idx;
	uint16_t rused_flush_idx;
	uint16_t rused_idx;
	int size;
	struct agiep_async_dma_job *job;
	struct agiep_async_dma_job *jobs[2];
	struct agiep_async_dma_group *group;
	uint16_t nb_desc = ring->num;
	int ret;

	if (unlikely(ring->cache->used_flushing >= CACHE_USED_FLUSHING_INITED))
		return 0;

	vring_split_scan_used_idx(ring);
	vring_split_flush_head(ring);


	used_flush_idx = ring->cache->used.used_flush_idx;
	used_idx = ring->used_idx;
	if (used_idx == used_flush_idx)
		return 0;

	size = used_idx - used_flush_idx;
	if (unlikely(size < 0))
		size = UINT16_MAX + size + 1;

	rused_flush_idx = used_flush_idx % nb_desc;
	rused_idx = used_idx % nb_desc;

	if (rused_flush_idx + (uint16_t)size > nb_desc) {
		if (rte_mempool_get(ring->dma->jpool, (void **) &group))
			goto failed;
		group->cb = (void *) vring_split_flush_done2;
		group->priv = ring;
		group->user_args = (used_idx | (used_flush_idx << 16));
		if (unlikely(rte_mempool_get_bulk(ring->dma->jpool, (void **) jobs, 2))) {
			rte_mempool_put(ring->dma->jpool, group);
			goto failed;
		}
		job = jobs[0];
		job->src = ring->cache->used.phy +
			sizeof(struct vring_used_elem) * rused_flush_idx;
		job->dst = ring->cache->used.pci +
			sizeof(struct vring_used_elem) * rused_flush_idx;
		job->len = (nb_desc - rused_flush_idx) *
			sizeof(struct vring_used_elem);

		job = jobs[1];
		job->src = ring->cache->used.phy;
		job->dst = ring->cache->used.pci;
		job->len = rused_idx * sizeof(struct vring_used_elem);

		ret = agiep_dma_group_enqueue(ring->dma, group, jobs , 2, DMA_JOB_F_TO_PCI);
		if (unlikely(ret != 2)) {
			rte_mempool_put_bulk(ring->dma->jpool,
					     (void *const *) &jobs[ret], 2 - ret);
			goto failed;
		}
		goto success;
	}
	if (unlikely(rte_mempool_get(ring->dma->jpool, (void **) &job))) {
		goto failed;
	}
	job->cb = (void *) vring_split_flush_done1;
	job->priv = ring;
	job->user_args = (used_idx | (used_flush_idx << 16));
	job->src = ring->cache->used.phy +
		sizeof(struct vring_used_elem) * rused_flush_idx;
	job->dst = ring->cache->used.pci +
		sizeof(struct vring_used_elem) * rused_flush_idx;

	job->len = size * sizeof(struct vring_used_elem);

	ret = agiep_dma_enqueue_buffers(ring->dma, &job, 1, DMA_JOB_F_TO_PCI);
	if (unlikely(!ret)) {
		rte_mempool_put(ring->dma->jpool, job);
		goto failed;
	}
	goto success;
failed:
	AGIEP_LOG_WARN("split: flush job failed: %d\n", used_idx);
	return -1;
success:
	ring->cache->used.used_flush_idx = ring->used_idx;
	return ret;
}

void vring_split_flush_done3(struct agiep_async_dma_job *job)
{
	struct vring_split *ring;
	ring = job->priv;
	ring->cache->used_flushing = 0;
	ring->cache->used.used_clean_idx = job->user_args;
	rte_mempool_put(job->dma->jpool, job);
}

void vring_split_flush_head(struct vring_split *ring)
{
	struct vring_used_elem *elem;
	uint16_t i;
	struct agiep_async_dma_job *job;
	uint16_t nb_desc = ring->num;
	if (ring->cache->used_flushing)
		return;
	if (ring->cache->used.used_flush_idx == ring->cache->used.used_clean_idx)
		return;
	if (unlikely(rte_mempool_get(ring->dma->jpool, (void **) &job)))
		return;
	ring->cache->used_flushing = 1;
	i = ring->cache->used.used_clean_idx;
	while(i != ring->cache->used.used_flush_idx) {
		elem = &ring->used->ring[i % nb_desc];
		if (elem->len != 0)
			break;
		i++;
	}
	ring->used->idx = i;
	job->src = ring->cache->used.hphy;
	job->dst = ring->cache->used.hpci;
	job->len = sizeof(struct vring_used);
	job->cb = (void *) vring_split_flush_done3;
	job->user_args = i;
	job->priv = ring;
	if (unlikely(agiep_dma_enqueue(ring->dma, job, DMA_JOB_F_TO_PCI))){
		AGIEP_LOG_WARN("common: split set job enqueue failed");
		rte_mempool_put(ring->dma->jpool, job);
		ring->cache->used_flushing = 0;
	}
}

void vring_split_flush_synchronize(struct vring_split *ring)
{
	while (ring->used->idx != ring->cache->used.used_clean_idx) {
		cpu_relax();
	}
}

inline void vring_init_split(struct vring_split *ring, void *p, unsigned long align,
		unsigned int num) 
{
	ring->num = num;
	ring->desc = (struct vring_desc *) p;
	ring->avail = (struct vring_avail *) ((uint8_t *)p + num * sizeof(struct vring_desc));
	ring->used = (void *)
		RTE_ALIGN_CEIL((uintptr_t) (&ring->avail->ring[num]), align);
}

int vring_split_cache_error(struct vring_split *vring)
{
	struct vring_split_cache *cache = vring->cache;
	return cache->cache_error;
}

void vring_split_set_dma(struct vring_split *vring, struct agiep_dma *dma)
{
	vring->dma = dma;
	vring->cache->dma = dma;
}

uint16_t vring_split_flush_idx(struct vring_split *ring)
{
	return ring->cache->used.used_clean_idx;
}

uint16_t vring_split_get_flags(struct vring_split *ring)
{
	return ring->avail->flags;
}

uint32_t vring_split_get_idx(struct vring_split *ring)
{
	return ring->cache->desc.last_desc_idx;
}

int vring_split_canbe_cache(struct vring_split *vring)
{
	int rlen;
	rlen = vring->cache->avail.avail_idx - vring->used->idx;
	if (!rlen)
		return 1;
	if (rlen < 0)
		rlen = rlen + UINT16_MAX + 1;
	return (uint32_t)(rlen) < (vring->num / 2);
}
