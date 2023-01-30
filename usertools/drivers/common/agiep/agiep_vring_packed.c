#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include "agiep_dma.h"
#include "agiep_vring.h"
#include "agiep_vring_packed.h"

#define PACKED_MAX_FLUSH_JOB 2

void vring_packed_scan_used_idx(struct vring_packed *vring);
static void vring_packed_flush_done1(struct agiep_async_dma_job *job);
static void vring_packed_flush_done2(struct agiep_async_dma_group *group);
static void vring_packed_flush_done3(struct agiep_async_dma_job *job);
static int vring_packed_used_set_job(struct flush_context *ctx);

/**
 * Create and init vring_packed
 * @param num
 * 	desc cache num
 * @return
 * 	pointer to vring_packed
 */
struct vring_packed *vring_packed_create(int idx, uint16_t num, uint32_t *flags)
{
	int i;
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	struct vring_packed_cache *cache = NULL;
	struct vring_packed_desc *desc = NULL;
	struct vring_packed_desc *used = NULL;
	struct vring_packed *vring = NULL;
	struct vring_packed_desc_event *device = NULL;
	struct vring_packed_desc_event *driver = NULL;
	struct vring_queue_elem *elems = NULL;
	struct iovec * inv;
	struct iovec * outv;
	uint64_t used_phy;

	vring = rte_calloc(NULL, 1, sizeof(struct vring_packed), RTE_CACHE_LINE_SIZE);
	if (vring == NULL)
		return NULL;

	desc = rte_calloc(NULL, num, sizeof(struct vring_packed_desc),
			RTE_CACHE_LINE_SIZE);
	used = rte_calloc(NULL, num, sizeof(struct vring_packed_desc),
			RTE_CACHE_LINE_SIZE);

	device = rte_calloc(NULL, 1, sizeof(struct vring_packed_desc_event), RTE_CACHE_LINE_SIZE);
	driver = rte_calloc(NULL, 1, sizeof(struct vring_packed_desc_event), RTE_CACHE_LINE_SIZE);

	if (!desc || !device || !driver || !used)
		goto err_desc;
	used_phy = rte_malloc_virt2iova(used);
	for (i = 0; i < num; ++i) {
		used[i].id = 0xfefe;
	}
	cache = vring_packed_cache_create(idx, desc, device, driver, num);

	if (cache == NULL)
		goto err_desc;

	vring->inv = rte_calloc(NULL, num, sizeof(struct iovec *), RTE_CACHE_LINE_SIZE);
	if (vring->inv == NULL)
		goto err_iov;

	inv = rte_calloc(NULL, num * MAX_IOV_SIZE, sizeof(struct iovec), RTE_CACHE_LINE_SIZE);
	outv = rte_calloc(NULL, num * MAX_IOV_SIZE, sizeof(struct iovec), RTE_CACHE_LINE_SIZE);

	if (!inv || !outv)
		goto err_iov_data;

	for (i = 0; i < num; ++i) {
		vring->inv[i] = RTE_PTR_ADD(inv, i * (MAX_IOV_SIZE * sizeof(struct iovec)));
	}

	for (i = 0; i < MAX_IOV_SIZE; ++i) {
		vring->outv[i] = RTE_PTR_ADD(outv, i * (num * sizeof(struct iovec)));
	}

	elems = rte_calloc(NULL, num, sizeof(struct vring_queue_elem), RTE_CACHE_LINE_SIZE);
	if (elems == NULL)
		goto err_iov_data;
	snprintf(name, sizeof(name),
			"flush_ctx_%d_%ld", idx, rte_rdtsc());

	mp = rte_mempool_create(name, num, sizeof(struct flush_context),
				VRING_CTX_CACHE_SIZE, 0, NULL, NULL, NULL,
			NULL, 0, 0);

	if (mp == NULL)
		goto err_elem;

	// TODO: There is no elems init in packed create. *** Packed not working Now! ***

	cache->desc.predict_size = PACKED_PREDICT_SIZE;
	cache->desc.ring = vring;
	vring->flags = flags;
	vring->flush_ctx_pool = mp;
	vring->cache = cache;
	vring->dma = NULL;
	vring->num = num;
	vring->mask = num - 1;
	vring->avail_idx = (uint16_t *) &cache->desc.last_avail_idx;
	vring->desc = desc;
	vring->used.desc = used;
	vring->used.phy = used_phy;
	vring->driver = driver;
	vring->device = device;
	vring->elems = elems;

	vring->used_wrap_counter = 1;
	vring->scan_used_wrap_counter = 1;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	vring->idx = idx;
	cache->idx = idx;
#endif
	return vring;
err_elem:
	rte_free(elems);
err_iov_data:
	if (inv)
		rte_free(inv);
	if (outv)
		rte_free(outv);
err_iov:
	if(vring->inv)
		rte_free(vring->inv);

	vring_packed_cache_free(cache);
err_desc:
	if (desc)
		rte_free(desc);
	if (used)
		rte_free(used);
	if (device)
		rte_free(device);
	if (driver)
		rte_free(driver);
	if (vring)
		rte_free(vring);
	return NULL;
}

void vring_packed_free(struct vring_packed *vring)
{
	if (!vring)
		return;
	if(vring->inv){
		rte_free(vring->inv[0]);
		rte_free(vring->inv);
	}
	if(vring->outv[0]){
		rte_free(vring->outv[0]);
	}

	vring_packed_cache_free(vring->cache);
	rte_free(vring->device);
	rte_free(vring->driver);
	rte_free(vring->desc);
	rte_free(vring->used.desc);
	rte_mempool_free(vring->flush_ctx_pool);
	rte_free(vring);
}

void vring_packed_set_addr(struct vring_packed *vring, 
		uint64_t apci, uint64_t upci, uint64_t dpci)
{
	struct vring_packed_cache *cache = vring->cache;
	cache->driver.pci = apci;
	cache->device.pci = upci;
	rte_compiler_barrier();
	cache->desc.pci = dpci;
}
void vring_packed_set_pci_addr(struct vring_packed *vring, uint64_t desc)
{
	struct vring_packed_cache *cache = vring->cache;
	uint64_t apci;
	uint64_t upci;
	upci = desc + vring->num * sizeof(struct vring_packed_desc);
	apci = RTE_ALIGN_CEIL(upci + sizeof(struct vring_packed_desc_event),
			      VIRTIO_PCI_VRING_ALIGN);

	cache->device.pci = apci;
	cache->driver.pci = upci;
	rte_compiler_barrier();
	cache->desc.pci = desc;
}

void vring_packed_clear_addr(struct vring_packed *vring)
{
	struct vring_packed_cache *cache = vring->cache;
	cache->desc.pci = 0;
	rte_compiler_barrier();
	cache->device.pci = 0;
	cache->driver.pci = 0;
}

int vring_packed_enabled(struct vring_packed *vring)
{
	return vring->cache->desc.pci;
}

void vring_packed_set_predict_size(struct vring_packed *vring,
		uint32_t size)
{
	struct vring_packed_cache *cache = vring->cache;
	cache->desc.predict_size = size;
}

int vring_packed_cache(struct vring_packed *ring) 
{
	struct vring_packed_cache *cache = ring->cache;
	if (cache->interrupt == INTERRUPT_PRE)
		vring_packed_read_event(ring);
	return vring_packed_desc_cache(cache);
}

void vring_packed_indir_cache(struct vring_packed *ring)
{
	struct vring_packed_cache *cache = ring->cache;
	return vring_packed_cache_indir_cache(cache);
}

static __rte_always_inline struct iovec *
vring_packed_fetch_iov(struct iovec **iov, int eid, int iov_id)
{
	return &iov[eid][iov_id];
}

__rte_always_inline struct iovec *
vring_packed_inv(struct vring_packed *vring, int eid, int id)
{
	return vring_packed_fetch_iov(vring->inv, eid, id);
}

__rte_always_inline struct iovec *
vring_packed_outv(struct vring_packed *vring, int eid, int id)
{
	return vring_packed_fetch_iov(vring->outv, id, eid);
}

int vring_packed_pop_indir(struct vring_packed *vring,
	struct vring_packed_desc *descs, struct vring_queue_elem *elem, int len)
{
	struct vring_packed_desc *desc;
	struct iovec *outv;
	struct iovec *inv;
	int i;

	for (i = 0; i < len; i++) {
		desc = &descs[i];
		elem->ndescs++;

		if (desc->flags & VRING_DESC_F_WRITE) {
			outv = vring_packed_outv(vring, elem->id, elem->out_num);
			outv->iov_base = (void *)desc->addr;
			outv->iov_len = desc->len;
			elem->out_num++;
			elem->out_len += desc->len;
		} else {
			inv = vring_packed_inv(vring, elem->id, elem->in_num);
			inv->iov_base = (void *)desc->addr;
			inv->iov_len = desc->len;
			elem->in_num++;
			elem->in_len += desc->len;
		}
	}

	return i;
}

static void vring_packed_scan_avail(struct vring_packed *vring)
{
	struct vring_queue_elem *elems;
	struct vring_packed_desc *desc;
	struct iovec *outv;
	struct iovec *inv;
	uint16_t desc_idx;
	int rlen;
	uint32_t idx;
	int i;
	int ret;
	int avail, used;
	int ndescs, out_len, in_len, len, wrap, out_num, in_num;

	const uint mask = vring->mask;

	elems = vring->elems;

	rlen = (int)(*vring->avail_idx - vring->last_avail_idx);

	if (!rlen)
		return;
	if (rlen < 0)
		rlen = (int)(rlen + UINT16_MAX + 1);


	idx = vring->avail_elem_idx & mask;

	ndescs = 0;
	out_len = 0;
	in_len = 0;
	len = 0;
	wrap = 0;
	out_num = 0;
	in_num = 0;

	for (i = 0; i < rlen; i++) {
		desc_idx = vring->last_avail_idx & mask;
		desc = &vring->desc[desc_idx];

		used = !!(desc->flags & VRING_PACKED_DESC_F_USED);
		avail = !!(desc->flags & VRING_PACKED_DESC_F_AVAIL);
		if (avail != vring->used_wrap_counter || used == vring->used_wrap_counter)
			break;

		if (ndescs == 0) {
			wrap = vring->used_wrap_counter;
			elems[idx].index = desc_idx;
			elems[idx].id = desc_idx;
		}

		vring->last_avail_idx ++;
		if ((vring->last_avail_idx & mask) == 0) {
			vring->used_wrap_counter ^= 1U;
		}

		if (desc->flags & VRING_DESC_F_INDIRECT) {
			if (!vring->cache->desc_state[desc_idx].indir_desc)
				break;
			ret = vring_packed_pop_indir(vring,
				vring->cache->desc_state[desc_idx].indir_desc,
				&elems[idx],
				(int)(desc->len / sizeof(struct vring_packed_desc)));

			rte_free(vring->cache->desc_state[desc_idx].indir_desc);
			vring->cache->desc_state[desc_idx].indir_desc = NULL;
			
			if (ret)
				break;
			elems[idx].ndescs = ndescs;
			elems[idx].out_len = out_len;
			elems[idx].in_len = in_len;
			elems[idx].len = len;
			elems[idx].wrap = wrap;
			elems[idx].out_num = out_num;
			elems[idx].in_num = in_num;
			vring->avail_elem_idx++;
			idx = vring->avail_elem_idx & mask;
			ndescs = 0;
			out_num = 0;
			out_len = 0;
			in_num = 0;
			in_len = 0;
			len = 0;
			wrap = 0;
			continue;
		}

		ndescs++;

		// TODO: Need check that all read desc must after write desc.
		if (desc->flags & VRING_DESC_F_WRITE) {
			outv = vring_packed_outv(vring, elems[idx].id, out_num);
			outv->iov_base = (void *)desc->addr;
			outv->iov_len = desc->len;
			out_num++;
			out_len += desc->len;
		} else {
			inv = vring_packed_inv(vring, elems[idx].id, in_num);
			inv->iov_base = (void *)desc->addr;
			inv->iov_len = desc->len;
			in_num++;
			in_len += desc->len;
		}

		if (!(desc->flags & VRING_DESC_F_NEXT)) {
			elems[idx].wrap = wrap;
			elems[idx].ndescs = ndescs;
			elems[idx].out_len = out_len;
			elems[idx].in_len = in_len;
			elems[idx].len = len;
			elems[idx].out_num = out_num;
			elems[idx].in_num = in_num;

			vring->avail_elem_idx++;
			idx = vring->avail_elem_idx & mask;

			ndescs = 0;
			out_len = 0;
			out_num = 0;
			in_len = 0;
			in_num = 0;
			len = 0;
			wrap = 0;
		}
	}

}

static inline uint16_t vring_packed_get_num(struct vring_packed *vring)
{
	int size;
	size = vring->avail_elem_idx - vring->last_avail_elem_idx;
	if (size < 0)
		size = size + UINT16_MAX + 1;
	return (uint16_t)size;
}

uint16_t vring_packed_num(struct vring_packed *vring)
{
	vring_packed_scan_avail(vring);
	return vring_packed_get_num(vring);
}

int vring_packed_pops(struct vring_packed *vring, struct vring_queue_elem **elems,
		uint32_t len)
{
	uint32_t num;
	uint i;
	uint16_t idx;
	const int mask = vring->mask;
	num = vring_packed_get_num(vring);
	if (num == 0)
		return 0;

	if (unlikely(num < len))
		len = num;

	for (i = 0; i < len; i++) {
		idx = vring->last_avail_elem_idx & mask;
		elems[i] = &vring->elems[idx];
		vring->last_avail_elem_idx++;
	}
	return len;
}


int vring_packed_idx_pushs(struct vring_packed *vring ,
	uint16_t last_avail_idx , uint16_t len)
{
	struct vring_queue_elem *elems[len];
	int i;
	uint16_t last = last_avail_idx;
	for (i = 0; i < len; ++i) {
		elems[i] = &vring->elems[last & vring->mask];
		last ++;
	}
	return vring_packed_pushs(vring, elems, len);
}

void vring_packed_idx_pop(struct vring_packed *vring, uint32_t len)
{
	vring->last_avail_elem_idx += len;
}

struct vring_queue_elem *vring_packed_elems(struct vring_packed *vring,
	uint16_t *last_avail_idx, uint16_t *avail_idx)
{
	*last_avail_idx = vring->last_avail_elem_idx;
	if (avail_idx)
		*avail_idx = vring->avail_elem_idx;
	return vring->elems;
}

void vring_packed_rewind(struct vring_packed *vring, int num)
{
	int i;
	uint16_t last_avail_elem_idx;

	vring->last_avail_elem_idx -= num;
	last_avail_elem_idx = vring->last_avail_elem_idx;
	last_avail_elem_idx &= vring->mask;

	for (i =  0; i < num; i++) {
		vring->elems[last_avail_elem_idx & vring->mask].len = 0;
		last_avail_elem_idx ++;
	}
}

int vring_packed_pushs(struct vring_packed *vring, struct vring_queue_elem **elems,
		uint32_t len)
{
	struct vring_packed_desc *desc;
	struct vring_packed_desc *used;
	struct vring_packed_desc *descs;
	struct vring_packed_desc *useds;
	struct vring_packed_desc *fdesc;
	uint16_t idx;
	uint32_t i;
	uint8_t oidx;
	uint8_t iidx;
	struct iovec *outv;
	struct iovec *inv;
	uint16_t flags;
	int used_wrap_counter;
	const uint nb_desc = vring->num;
	const uint16_t mask = vring->mask;

	useds = vring->used.desc;
	descs = vring->cache->desc.desc;
	for (i = 0; i < len; i++) {
		idx = elems[i]->index;
		fdesc = NULL;
		used_wrap_counter = elems[i]->wrap;
		for (oidx = 0; oidx < elems[i]->out_num; oidx++) {
			if (idx >= nb_desc) {
				used_wrap_counter ^= 1;
				idx &= mask;
			}
			desc = &descs[idx];
			used = &useds[idx];

			used->addr = desc->addr;
			if (fdesc == NULL) {
				fdesc = used;
				fdesc->len = elems[i]->len;
			} else {
				outv = vring_packed_outv(vring, elems[i]->id, oidx);
				used->len = outv->iov_len;
			}
			used->id = desc->id;
			flags = desc->flags;
			if (used_wrap_counter) {
				flags |= VRING_PACKED_DESC_F_AVAIL_USED;
			} else {
				flags &= ~VRING_PACKED_DESC_F_AVAIL_USED;
			}
			used->flags = flags;
			idx++;
		}
		for (iidx = 0; iidx < elems[i]->in_num; iidx++) {
			if (idx >= nb_desc) {
				used_wrap_counter ^= 1;
				idx &= mask;
			}
			used = &useds[idx];
			desc = &descs[idx];

			inv = vring_packed_inv(vring, i, iidx);
			used->addr = desc->addr;
			used->len = inv->iov_len;
			used->id = desc->id;
			flags = desc->flags;
			if (used_wrap_counter) {
				flags |= VRING_PACKED_DESC_F_AVAIL_USED;
			} else {
				flags &= ~VRING_PACKED_DESC_F_AVAIL_USED;
			}
			used->flags = flags;
			idx++;
		}
	}

	return i;
}

void vring_packed_scan_used_idx(struct vring_packed *vring)
{
	int used;
	int avail;
	const uint mask = vring->mask;
	uint16_t next = vring->used_idx;
	struct vring_packed_desc *useds;

	useds = vring->used.desc;
	while (next != vring->last_avail_idx) {
		used = !!(useds[next & mask].flags & VRING_PACKED_DESC_F_USED);
		avail = !!(useds[next & mask].flags & VRING_PACKED_DESC_F_AVAIL);
		if (used != avail || used != vring->scan_used_wrap_counter){
			break;
		}

		next++;
		if ((next & mask) == 0) {
			vring->scan_used_wrap_counter ^= 1;
		}
	}
	vring->used_idx = next;
}

static void vring_packed_flush_done1(struct agiep_async_dma_job *job)
{
	struct flush_context *ctx = job->priv;

	if (ctx->flush_head){
		if (vring_packed_used_set_job(ctx) != -1)
			ctx->ring->flush_idx = ctx->used_idx;
	}else {
		ctx->ring->flush_idx = ctx->used_idx;
		ctx->ring->flushing = 0;
	}
	rte_mempool_put(ctx->ring->flush_ctx_pool, ctx);
	rte_mempool_put(job->dma->jpool, job);
}

static void vring_packed_flush_done2(struct agiep_async_dma_group *group)
{
	struct flush_context *ctx = group->priv;

	if (ctx->flush_head){
		if (vring_packed_used_set_job(ctx) != -1)
			ctx->ring->flush_idx = ctx->used_idx;
	} else {
		ctx->ring->flush_idx = ctx->used_idx;
		ctx->ring->flushing = 0;
	}
	rte_mempool_put(ctx->ring->flush_ctx_pool, ctx);
	rte_mempool_put(group->dma->jpool, group);
}

static void vring_packed_flush_done3(struct agiep_async_dma_job *job)
{
	struct vring_packed *ring = job->priv;
	ring->flushing = 0;
	rte_mempool_put(job->dma->jpool, job);
}

int vring_packed_flush_job(struct vring_packed  *ring)
{
	int flush_idx;
	struct agiep_async_dma_group *group = NULL;
	struct agiep_async_dma_job *jobs[2];
	struct agiep_async_dma_job *job = NULL;
	struct flush_context *ctx;
	int size;
	int ret;


	vring_packed_scan_used_idx(ring);

	if (ring->flush_idx == ring->used_idx)
		return 0;
	if (ring->flushing)
		return 1;
	ring->flushing = 1;

	rte_mempool_get(ring->flush_ctx_pool, (void **) &ctx);
	if (unlikely(ctx == NULL))
		return 0;

	size = ring->used_idx - ring->flush_idx;
	if (size < 0)
		size += UINT16_MAX + 1;

	ctx->ring = ring;
	ctx->used_idx = ring->used_idx;
	ctx->flush_idx = ring->flush_idx;
	ctx->flush_head = 0;

	flush_idx = (int)(ctx->flush_idx & ring->mask);

	if (size > 1) {
		size -= 1;
		flush_idx ++;
		flush_idx &= ring->mask;
		ctx->flush_head = 1;
	}
	if (flush_idx + size <= ring->num) {
		if (rte_mempool_get(ring->dma->jpool, (void **) &job)) {
			goto failed_out;
		}

		job->cb = (void *) vring_packed_flush_done1;
		job->priv = ctx;
		job->src = ring->used.phy +
			sizeof(struct vring_packed_desc) * flush_idx;
		job->dst = ring->cache->desc.pci +
			sizeof(struct vring_packed_desc) * flush_idx;
		job->len = size * sizeof(struct vring_packed_desc);
		if (unlikely(!agiep_dma_enqueue_buffers(ring->dma, &job, 1,
					  DMA_JOB_F_TO_PCI))) {
			rte_mempool_put(ring->dma->jpool, job);
			return 0;
		}
		ring->flushing = 1;
		return 1;
	}

	if (unlikely(rte_mempool_get(ring->dma->jpool, (void **) &group))) {
		goto failed_out;
	}

	if (unlikely(rte_mempool_get_bulk(ring->dma->jpool, (void **) jobs,
				PACKED_MAX_FLUSH_JOB))) {
		goto failed_out;
	}

	job = jobs[0];
	job->src = ring->used.phy +
		sizeof(struct vring_packed_desc) * flush_idx;
	job->dst = ring->cache->desc.pci +
		sizeof(struct vring_packed_desc) * flush_idx;
	job->len = (ring->num - flush_idx) * sizeof(struct vring_packed_desc);

	job = jobs[1];
	job->src = ring->used.phy;
	job->dst = ring->cache->desc.pci;
	job->len = sizeof(struct vring_packed_desc) * (ctx->used_idx & ring->mask);

	group->cb = vring_packed_flush_done2;
	group->priv = ctx;
	ret = agiep_dma_group_enqueue(ring->dma, group, jobs,
		PACKED_MAX_FLUSH_JOB, DMA_JOB_F_TO_PCI);
	if (unlikely(ret != PACKED_MAX_FLUSH_JOB)){
		rte_mempool_put_bulk(ring->dma->jpool,
			(void *const *) &jobs[ret], PACKED_MAX_FLUSH_JOB - ret);
		return ret;
	}
	ring->flushing = 1;
	return ret;
failed_out:
	if (group)
		rte_mempool_put(ring->dma->jpool, group);

	if (ctx)
		rte_mempool_put(ring->flush_ctx_pool, ctx);
	return 0;
}

static int vring_packed_used_set_job(struct flush_context *ctx)
{
	struct vring_packed *ring = ctx->ring;
	struct agiep_async_dma_job *job;
	int idx = (ctx->flush_idx) & ring->mask;

	if (unlikely(rte_mempool_get(ring->dma->jpool, (void **) &job))) {
		ring->flushing = 0;
		return -1;
	}
	job->src = ring->used.phy + sizeof(struct vring_packed_desc) * idx;
	job->dst = ring->cache->desc.pci + sizeof(struct vring_packed_desc) * idx;
	job->len = sizeof(struct vring_packed_desc);

	job->cb = vring_packed_flush_done3;
	job->priv = ring;
	if (agiep_dma_enqueue(ring->dma, job, DMA_JOB_F_TO_PCI)){
		rte_mempool_put(ring->dma->jpool, job);
		ring->flushing = 0;
		return -1;
	}
	return 0;
}
void vring_packed_set_dma(struct vring_packed *vring, struct agiep_dma *dma)
{
	vring->dma = dma;
	vring->cache->dma = dma;
}

uint16_t vring_packed_flush_idx(struct vring_packed *ring)
{
	return ring->flush_idx;
}

uint16_t vring_packed_get_flags(struct vring_packed *ring)
{
	return ring->driver->flags;
}

int vring_packed_canbe_cache(struct vring_packed *vring)
{
	int rlen;
	rlen = vring_packed_get_num(vring);
	return (uint32_t)(rlen) < (vring->num / 4);
}
uint16_t vring_packed_avail_idx(struct vring_packed *vring)
{
	return vring->last_avail_idx;
}