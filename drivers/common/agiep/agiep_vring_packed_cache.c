#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include "agiep_vring_packed.h"
#include "agiep_vring.h"
#include "agiep_dma.h"

int vring_packed_indir_cache_job(struct vring_packed_cache *cache, int start,
	int end, int len);
static void vring_packed_indir_done(struct agiep_async_dma_job *job);

static void vring_packed_desc_done1(struct agiep_async_dma_job *job);

static void vring_packed_desc_done2(struct agiep_async_dma_group *group);

struct vring_packed_cache *
vring_packed_cache_create(int idx, struct vring_packed_desc *desc,
	struct vring_packed_desc_event *device,
	struct vring_packed_desc_event *driver, uint16_t num)
{
	struct vring_packed_cache *cache = NULL;
	struct vring_desc_state_packed *desc_state = NULL;
	struct vring_packed_desc_indir *indir_ctx = NULL;
	struct rte_ring *pring = NULL;
	uint64_t desc_phy;
	uint64_t device_phy = 0;
	uint64_t driver_phy = 0;
	char ring_name[RTE_RING_NAMESIZE];

	snprintf(ring_name, sizeof(ring_name), "packed_pring_%d_%lx", idx, rte_rdtsc());

	cache = rte_calloc(NULL, 1, sizeof(struct vring_packed_cache), RTE_CACHE_LINE_SIZE);

	if (cache == NULL)
		goto error;

	desc_state = rte_calloc(NULL, num, sizeof(struct vring_desc_state_packed), RTE_CACHE_LINE_SIZE);

	if (desc_state == NULL)
		goto error;

	indir_ctx = rte_calloc(NULL, num, sizeof(struct vring_packed_desc_indir), RTE_CACHE_LINE_SIZE);

	if (indir_ctx == NULL)
		goto error;

	pring = rte_ring_create(ring_name, 2 * num, 0, 0);

	if (pring == NULL)
		goto error;

	desc_phy = rte_malloc_virt2iova(desc);
	if (device && driver){
		device_phy = rte_malloc_virt2iova(device);
		driver_phy = rte_malloc_virt2iova(driver);
	}


	cache->num = num;
	cache->mask = num - 1;
	cache->dma = NULL;
	cache->pring = pring;
	cache->desc_state = desc_state;
	cache->indir_ctx = indir_ctx;
	cache->desc.desc = desc;
	cache->desc.phy = desc_phy;
	cache->device.phy = device_phy;
	cache->driver.phy = driver_phy;
	cache->desc_ctx.cache = cache;
	cache->avail_wrap_counter = 1;
	return cache;
error:
	if (cache)
		rte_free(cache);
	if (desc_state)
		rte_free(desc_state);
	if (indir_ctx)
		rte_free(indir_ctx);
	if (pring)
		rte_ring_free(pring);
	return NULL;
}

void vring_packed_cache_free(struct vring_packed_cache *cache)
{
	rte_free(cache->indir_ctx);
	rte_ring_free(cache->pring);
	rte_free(cache->desc_state);
	rte_free(cache);
}

int vring_packed_desc_cache(struct vring_packed_cache *cache)
{
	struct agiep_async_dma_job *job = NULL;
	struct agiep_async_dma_group *group = NULL;
	struct agiep_async_dma_job *jobs[2];
	struct desc_dma_context *ctx;
	int ndesc;
	uint offset, dma_off;
	uint16_t avail_idx;
	int ret;
	const int mask = cache->mask;

	if (cache->caching)
		return 1;
//	cache->caching = 1;

	ctx = &cache->desc_ctx;

	ctx->prev_avail_idx = cache->desc.last_avail_idx;

	avail_idx = cache->next_desc_idx & mask;
	ctx->next_desc_idx = cache->next_desc_idx;

	ctx->avail_wrap_counter = cache->avail_wrap_counter;
	if (avail_idx + cache->desc.predict_size > cache->num) {
		//cache->avail_wrap_counter ^= 1;
		if (rte_mempool_get(cache->dma->jpool, (void **) &group)) {
			return -1;
		}

		if (rte_mempool_get_bulk(cache->dma->jpool, (void **) jobs, 2)) {
			rte_mempool_put(cache->dma->jpool, group);
			return -1;
		}

		job = jobs[0];
		offset = avail_idx * sizeof(struct vring_packed_desc);
		dma_off = ALIGN_DMA_CALC_OFFSET(cache->desc.pci + offset);
		job->src = cache->desc.pci + offset - dma_off;

		job->dst = cache->desc.phy + offset - dma_off;
		job->len = (cache->num - avail_idx) *
			sizeof(struct vring_packed_desc) + dma_off;

		job = jobs[1];

		job->src = cache->desc.pci;
		job->dst = cache->desc.phy;
		ndesc = avail_idx + cache->desc.predict_size - cache->num;
		job->len = ndesc * sizeof(struct vring_packed_desc);


		ctx->last_avail_idx = cache->next_desc_idx + cache->desc.predict_size;
		group->priv = ctx;
		group->cb = vring_packed_desc_done2;
		ret = agiep_dma_group_enqueue(cache->dma, group, jobs, 2, DMA_JOB_F_FROM_PCI);
		if (unlikely(ret != 2)) {
			rte_mempool_put_bulk(cache->dma->jpool,
					     (void **) &jobs[ret], 2 - ret);
			return -1;
		}
		cache->caching = 1;
		return 0;
	}

	if (unlikely(rte_mempool_get(cache->dma->jpool, (void **) &job)))
		return -1;

	offset = avail_idx * sizeof(struct vring_packed_desc);
	dma_off = ALIGN_DMA_CALC_OFFSET(cache->desc.pci  + offset);
	job->src = cache->desc.pci + offset - dma_off;
	job->dst = cache->desc.phy + offset - dma_off;
	job->len = cache->desc.predict_size * sizeof(struct vring_packed_desc) + dma_off;
	job->priv = ctx;
	job->cb = vring_packed_desc_done1;

	ctx->last_avail_idx = cache->next_desc_idx + cache->desc.predict_size;

	ret = agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_FROM_PCI);

	if (unlikely(!ret)) {
		rte_mempool_put(cache->dma->jpool, job);
		return -1;
	}
	cache->caching = 1;
	return 0;
}

int vring_packed_indir_cache_job(struct vring_packed_cache *cache, int start,
		int end, int len) 
{
	struct vring_packed_desc *desc;
	struct vring_packed_desc_indir *indir_ctx;
	struct agiep_async_dma_job *jobs[len];
	struct agiep_async_dma_job *job;
	int dma_off ;
	int nb_jobs = 0;
	int ret;

	if (rte_mempool_get_bulk(cache->dma->jpool, (void **)jobs, len)) {
		return -1;
	}

	for (; start != end ; start++) {
		desc = &cache->desc.desc[start & cache->mask];
		if (!(desc->flags & VRING_DESC_F_INDIRECT)) {
			continue;
		}
		indir_ctx = &cache->indir_ctx[start & cache->mask];
		indir_ctx->indir_desc = rte_malloc(NULL,
			desc->len + AGIEP_DMA_ALIGN,
					RTE_CACHE_LINE_SIZE);
		if (!indir_ctx->indir_desc) {
			break;
		}
		cache->indir_idx = start;

		indir_ctx->cache = cache;
		indir_ctx->idx = start & cache->mask;
		job = jobs[nb_jobs];
		nb_jobs ++;
		dma_off = ALIGN_DMA_CALC_OFFSET(desc->addr);
		job->src = desc->addr - dma_off;
		job->dst = rte_malloc_virt2iova(indir_ctx->indir_desc) +
			   sizeof(struct vring_packed_desc_indir) - dma_off;
		job->flags = DMA_JOB_F_FROM_PCI;
		job->len = desc->len + dma_off;
		job->priv = indir_ctx;
		job->cb = vring_packed_indir_done;
	}

	if (nb_jobs < len) {
		rte_mempool_put_bulk(cache->dma->jpool, (void *const *) &jobs[nb_jobs],
				len - nb_jobs);
	}

	ret = agiep_dma_enqueue_buffers(cache->dma, jobs, nb_jobs, DMA_JOB_F_FROM_PCI);

	if (ret < nb_jobs) {
		rte_ring_enqueue_burst(cache->pring, (void *const *) &jobs[ret],
				nb_jobs - ret, NULL);
	}

	return ret;
}

void vring_packed_cache_indir_cache(struct vring_packed_cache *cache)
{
	uint i;
	uint num;
	struct agiep_async_dma_job *jobs[32];

	if (likely(rte_ring_count(cache->pring) == 0))
		return;

	num = rte_ring_dequeue_burst(cache->pring, (void **) &jobs, 32 , NULL);
	if (!num)
		return;
	i = agiep_dma_enqueue_buffers(cache->dma, &jobs[num], num, DMA_JOB_F_FROM_PCI);
	if (unlikely(i < num))
		rte_ring_enqueue_burst(cache->pring, (void *const *) jobs[i], num - i, NULL);
}

static void vring_packed_indir_done(struct agiep_async_dma_job *job) 
{
	struct vring_packed_desc_indir *indir_ctx;
	struct vring_packed_cache *cache;
	struct vring_desc_state_packed *state;

	indir_ctx = job->priv;
	cache = indir_ctx->cache;
	state = &cache->desc_state[indir_ctx->idx];
	state->indir_desc = (struct vring_packed_desc *) &indir_ctx->indir_desc;
	rte_mempool_put(job->dma->jpool, job);
}


static void vring_packed_desc_done(struct desc_dma_context *ctx)
{
	uint16_t i;
	int used;
	int avail;
	int wrap;
	int indir;
	int gap;

	struct vring_packed_desc *desc;
	struct vring_packed_cache *cache;
	struct vring_packed *ring;

	cache = ctx->cache;
	ring = cache->desc.ring;

	const int mask = cache->mask;
	indir = 0;

	i = ctx->next_desc_idx;
	wrap = ctx->avail_wrap_counter;

	do {
		gap = i - ring->flush_idx;
		if (0 > gap) {
			gap += UINT16_MAX + 1;
		}
		if (gap == ring->num) {
			cache->avail_wrap_counter = wrap;
			break;
		}
		desc = &cache->desc.desc[i & mask];
		used = !!(desc->flags & VRING_PACKED_DESC_F_USED);
		avail = !!(desc->flags & VRING_PACKED_DESC_F_AVAIL);
		if (used == avail || avail != wrap || used == wrap) {
			cache->avail_wrap_counter = wrap;
			cache->caching = 0;
			break;
		}
		if (desc->flags & VRING_DESC_F_INDIRECT) {
			indir++;
		}

		i++;
		if (!(desc->flags & VRING_DESC_F_NEXT)) {
			cache->desc.last_avail_idx = i;
		}
		if ((i & mask) == 0) {
			wrap ^= 1;
		}
		if (i == ctx->last_avail_idx)
			cache->avail_wrap_counter = wrap;

	} while (i != ctx->last_avail_idx);

	if (indir) {
		vring_packed_indir_cache_job(cache, ctx->next_desc_idx, i, indir);
	}

	cache->next_desc_idx = i;
	if (i == (uint16_t)(ctx->last_avail_idx)) {
		cache->caching = 0;
		vring_packed_desc_cache(cache);
		return;
	}
	cache->caching = 0;
}

static void vring_packed_desc_done1(struct agiep_async_dma_job *job)
{
	vring_packed_desc_done(job->priv);
	rte_mempool_put(job->dma->jpool, job);
}

static void vring_packed_desc_done2(struct agiep_async_dma_group *group)
{
	vring_packed_desc_done(group->priv);
	rte_mempool_put(group->dma->jpool, group);
}

static void vring_packed_event_done(struct agiep_async_dma_job *job)
{
	struct vring_packed_cache *cache = (struct vring_packed_cache *) job->priv;
	if (cache->interrupt == INTERRUPT_PRE)
		cache->interrupt = INTERRUPT_RAISE;
	rte_mempool_put(job->dma->jpool, job);
}

int vring_packed_read_event(struct vring_packed *vring)
{
	struct vring_packed_cache *cache = vring->cache;
	struct agiep_async_dma_job *job;
	if (rte_mempool_get(cache->dma->jpool, (void **) &job)) {
		return -ENOMEM;
	}
	job->src = cache->driver.pci;
	job->dst = cache->driver.phy;
	job->priv = cache;
	job->len = sizeof(*cache->driver.driver);
	job->flags = DMA_JOB_F_FROM_PCI;
	job->cb = vring_packed_event_done;
	return agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_FROM_PCI);
}

int vring_packed_write_event(struct vring_packed_cache *cache)
{
	struct agiep_async_dma_job *job;
	if (rte_mempool_get(cache->dma->jpool, (void **) &job)) {
		return -ENOMEM;
	}
	job->src = cache->device.phy;
	job->dst = cache->device.pci;
	job->priv = cache;
	job->len = sizeof(*cache->device.device);
	job->cb = vring_packed_event_done;
	return agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_FROM_PCI);
}
