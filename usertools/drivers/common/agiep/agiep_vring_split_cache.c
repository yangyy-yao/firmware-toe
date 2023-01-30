#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <assert.h>

#include "agiep_vring_split.h"
#include "agiep_dma.h"
#include "agiep_vring_split_predict.h"

#define PAGE_SIZE_ALIGN 4096

/**
 * used to job/group->user_args, don not overtake sizeof(uint64_t)
 */
struct split_user_ctx_args {
	union {
		struct {
			uint16_t idx;
			uint16_t avail_idx;
			uint16_t num;
			uint16_t last_avail_idx;
		};
		uint64_t user_args;
	};
};

static void vring_avail_head_done(struct agiep_async_dma_job *job);

static void vring_avail_done1(struct agiep_async_dma_job *job);

static void vring_desc_done(struct agiep_async_dma_job *job);

static void vring_desc_cache_predict_next(struct vring_split_cache *cache, uint16_t avail_idx, int desc_idx);

static int vring_desc_cache_predict(struct vring_split_cache *cache);

static int vring_desc_cache_indir_single(struct agiep_async_dma_job *job);

static void vring_split_cache_abort(struct vring_split_cache *cache);

void vring_desc_cache_predict_next_done(struct agiep_async_dma_group *group);

__rte_always_inline static
int vring_desc_cache_wraper(struct vring_split_cache *cache)
{
	if (cache->flags & VRING_F_RING_PREDICT) {
		return vring_desc_cache_predict(cache);
	} else {
		return vring_desc_cache(cache);
	}
}

struct vring_split_cache *vring_split_cache_create(int idx,
	struct vring_desc *desc, uint64_t desc_phy, uint16_t num,
		uint32_t flags)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	struct vring_split_cache *cache = NULL;
	struct vring_desc_state_split *desc_state = NULL;
	uint64_t *avail_state = NULL;
	struct rte_ring *pring = NULL;
	struct rte_ring *iring = NULL;
	char ring_name[RTE_RING_NAMESIZE];
	uint64_t avail_phy;
	uint64_t used_phy;
	struct vring_avail *avail = NULL;
	struct vring_used *used = NULL;


	cache = rte_calloc(NULL, 1, sizeof(struct vring_split_cache), RTE_CACHE_LINE_SIZE);

	if (cache == NULL)
		goto error;
	cache->num = num;
	if (vring_split_predict_init(&cache->predict, cache->num))
		goto error;
	desc_state = rte_calloc(NULL, num, sizeof(struct vring_desc_state_split), RTE_CACHE_LINE_SIZE);

	if (desc_state == NULL)
		goto error;

	avail_state = rte_calloc(NULL, num / (sizeof(uint64_t) * 8), sizeof(uint64_t), RTE_CACHE_LINE_SIZE);

	if (avail_state == NULL)
		goto error;

	snprintf(ring_name, sizeof(ring_name), "split_pr_%d_%lx", idx, rte_rdtsc());
	pring = rte_ring_create(ring_name, 2 * num, 0, 0);

	if (pring == NULL)
		goto error;
	snprintf(ring_name, sizeof(ring_name), "split_ir_%d_%lx", idx, rte_rdtsc());
	iring = rte_ring_create(ring_name, num * 2, 0, 0);
	if (iring == NULL)
		goto error;

	snprintf(name, sizeof(name),
			"split_ctx_%d_%lx", idx, rte_rdtsc());

	mp = rte_mempool_create(name, num * 2,
			sizeof(struct split_desc_context),
				VRING_CTX_CACHE_SIZE, 0, NULL, NULL, NULL,
			NULL, 0, 0);

	if (mp == NULL)
		goto error;

	avail_phy = desc_phy + sizeof(struct vring_desc) * num;
	used_phy = RTE_ALIGN(avail_phy + sizeof(uint16_t) *
			(num + VRING_SPLIT_RING_IDX_NUM), PAGE_SIZE_ALIGN);

	avail = RTE_PTR_ADD(desc, sizeof(struct vring_desc) * num);
	used = RTE_PTR_ALIGN(RTE_PTR_ADD(avail, sizeof(uint16_t) *
			(num + VRING_SPLIT_RING_IDX_NUM)), PAGE_SIZE_ALIGN);

#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	cache->idx = idx;
#endif
	cache->ctx_pool = mp;
	cache->num = num;
	cache->dma = NULL;
	cache->avail.hphy = avail_phy;
	cache->avail.phy = avail_phy + sizeof(uint32_t);
	cache->used.hphy = used_phy ;
	cache->used.phy = used_phy + sizeof(uint32_t);
	cache->desc.phy = desc_phy;
	
	cache->avail.avail = avail;
	cache->used.used = used;
	cache->desc.desc = desc;

	cache->desc_state = desc_state;
	cache->avail_state = avail_state;
	cache->pring = pring;
	cache->iring = iring;
	cache->flags = flags;
	cache->used_flushing = CACHE_USED_FLUSHING_INIT;
	return cache;
error:
	if (pring)
		rte_ring_free(pring);
	if (desc_state)
		rte_free(desc_state);
	if (avail_state)
		rte_free(avail_state);
	if (cache) {
		rte_free(cache);
	}
	return NULL;
}

void vring_split_cache_clear_addr(struct vring_split_cache *cache)
{
	cache->desc.pci = 0;
	// Make sure desc.pci is first to zero.
	rte_mb();
	cache->avail.pci = 0;
	cache->used.pci = 0;
}

static void vring_split_cache_abort(struct vring_split_cache *cache)
{
	vring_split_cache_clear_addr(cache);
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	AGIEP_LOG_ERR("check cache %d %p fatal error",cache->idx, cache);
	assert(0);
#else
	AGIEP_LOG_ERR("check cache %p fatal error", cache);
#endif
}

void vring_split_cache_free(struct vring_split_cache *cache)
{
	rte_free(cache->desc_state);
	rte_ring_free(cache->pring);
	rte_ring_free(cache->iring);
	rte_mempool_free(cache->ctx_pool);
	rte_free(cache->avail_state);
	rte_free(cache);
}

int vring_cache_pipeline(struct vring_split_cache *cache, int notify)
{
	int ret = 0;
	if (unlikely(cache->used_flushing == CACHE_USED_FLUSHING_INIT)) {
		cache->used_flushing = CACHE_USED_FLUSHING_INITED;
		ret = vring_used_head_cache(cache);
		if (ret)
			return ret;
	}
	if (unlikely(cache->used_flushing >= CACHE_USED_FLUSHING_INITED))
		return 0;

	if (notify || (cache->interrupt == INTERRUPT_PRE))
		ret = vring_avail_head_cache(cache);

	vring_avail_cache(cache);

	vring_desc_cache_wraper(cache);
	return ret;
}

int vring_avail_head_cache(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *job;
	if (unlikely(agiep_dma_job_get(cache->dma, &job)))
		return -1;
	// not need align addr, addr set align by 0x1000
	job->src = cache->avail.hpci;
	job->dst = cache->avail.hphy;
	job->len = sizeof(struct vring_avail);
	job->cb = (void *)vring_avail_head_done;
	job->priv = cache;

	if (unlikely(agiep_dma_enqueue(cache->dma, job, DMA_JOB_F_FROM_PCI))){
		rte_mempool_put(cache->dma->jpool, job);
		return -ENOBUFS;
	}
	return 0;
}

static void vring_avail_head_done(struct agiep_async_dma_job *job) 
{
	struct vring_split_cache *cache = (struct vring_split_cache *) job->priv;
	if (cache->interrupt == INTERRUPT_PRE)
		cache->interrupt = INTERRUPT_RAISE;
	rte_mempool_put(job->dma->jpool, job);
}

static void vring_avail_done1(struct agiep_async_dma_job *job)
{
	struct vring_split_cache *cache = (struct vring_split_cache *) job->priv;
	uint16_t avail_idx;
	struct split_user_ctx_args ctx_args;
	ctx_args.user_args = job->user_args;
	avail_idx = ctx_args.avail_idx;
	if (avail_idx > cache->avail.avail_idx ||
			(avail_idx - cache->avail.avail_idx) < -(int)cache->num) {
		cache->avail.avail_idx = avail_idx;
	}
	rte_mempool_put(job->dma->jpool, job);
}

static void vring_avail_done2(struct agiep_async_dma_group *group)
{
	struct vring_split_cache *cache = (struct vring_split_cache *) group->priv;
	struct split_user_ctx_args ctx_args;
	uint16_t avail_idx;
	ctx_args.user_args = group->user_args;
	avail_idx = ctx_args.avail_idx;
	if (avail_idx > cache->avail.avail_idx ||
	    (avail_idx - cache->avail.avail_idx) < -(int)cache->num) {
		cache->avail.avail_idx = avail_idx;
	}
	rte_mempool_put(group->dma->jpool, group);
}

int vring_avail_cache(struct vring_split_cache *cache)
{
	int size, osize;
	struct agiep_async_dma_job *job = NULL;
	struct agiep_async_dma_job *jobs[2];
	struct agiep_async_dma_group *group = NULL;
	struct split_user_ctx_args ctx_args;
	uint64_t offset;
	int ret;
	uint16_t nb_desc = cache->num;
	uint16_t align_offset;
	uint16_t cur_idx;
	uint16_t cur_last_idx;

	cur_idx = cache->avail.avail->idx;
	cur_last_idx = cache->avail.avail_idx;

	if (cur_idx == cache->avail.last_avail_idx)
		return 1;

	size = (int)(cur_idx - cur_last_idx);
	if (size == 0)
		return 1;

	if (size < 0)
		size += UINT16_MAX + 1;

	if (unlikely((int)size > nb_desc)) {
		return -1;
	}
	offset = (cur_last_idx % nb_desc) * sizeof(uint16_t);

	if (cur_last_idx % nb_desc + size <= cache->num) {
		if (rte_mempool_get(cache->dma->jpool, (void **) &job))
			return -1;
		ctx_args.avail_idx = cur_idx;
		ctx_args.last_avail_idx = cur_last_idx;
		job->user_args = ctx_args.user_args;

		align_offset = ALIGN_DMA_CALC_OFFSET(cache->avail.pci + offset);
		job->src = cache->avail.pci + offset - align_offset;
		job->dst = cache->avail.phy + offset - align_offset;
		job->len = size * sizeof(uint16_t) + align_offset;
		job->cb = (void *)vring_avail_done1;
		job->priv = cache;
		ret = agiep_dma_enqueue(cache->dma, job, DMA_JOB_F_FROM_PCI);
		if (unlikely(ret)) {
			rte_mempool_put(cache->dma->jpool, job);
			return -1;
		}
	} else {
		if (unlikely(rte_mempool_get(cache->dma->jpool, (void **) &group)))
			return -1;

		if (unlikely(agiep_dma_job_get_bulk(cache->dma, jobs, 2))) {
			rte_mempool_put(cache->dma->jpool, group);
			return -1;
		}
		ctx_args.avail_idx = cur_idx;
		ctx_args.last_avail_idx = cur_last_idx;
		group->user_args = ctx_args.user_args;

		osize = (cache->num - cur_last_idx % nb_desc);

		job = jobs[0];

		align_offset = ALIGN_DMA_CALC_OFFSET(cache->avail.pci + offset);
		job->src = cache->avail.pci + offset - align_offset;
		job->dst = cache->avail.phy + offset - align_offset;
		job->len = osize * sizeof(uint16_t) + align_offset;

		osize = cur_idx % nb_desc;

		job = jobs[1];
		job->src = cache->avail.pci;
		job->dst = cache->avail.phy;
		job->len = osize * sizeof(uint16_t);
		group->cb = (void *)vring_avail_done2;
		group->priv = cache;
		ret = agiep_dma_group_enqueue(cache->dma, group, jobs, 2, DMA_JOB_F_FROM_PCI);
		if (ret != 2) {
			rte_ring_enqueue_bulk(cache->pring,
				(void *const *) &jobs[ret], 2 - ret, NULL);
			return -1;
		}
	}
	cache->avail.last_avail_idx = cur_idx;
	return 0;
}

static void vring_avail_done3(struct agiep_async_dma_job *job)
{
	struct vring_split_cache *cache = job->priv;
	cache->avail.avail_idx = cache->avail.avail->idx;
	rte_mempool_put(job->dma->jpool, job);
	if (cache->used_flushing == CACHE_USED_FLUSHING_INITED) {
		cache->used_flushing = 0;
	}
}

int vring_avail_cache_all(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *job = NULL;
	uint16_t nb_desc = cache->num;
	int ret;

	if (unlikely(agiep_dma_job_get(cache->dma, &job)))
		return -1;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(ALIGN_DMA_CALC_OFFSET(cache->avail.hpci) == 0);
#endif
	job->src = cache->avail.hpci;
	job->dst = cache->avail.hphy;
	job->len = sizeof(struct vring_avail) + nb_desc * sizeof(uint16_t);
	job->cb = (void *)vring_avail_done3;
	job->priv = cache;
	ret = agiep_dma_enqueue(cache->dma, job, DMA_JOB_F_FROM_PCI);
	if (unlikely(ret)) {
		rte_mempool_put(cache->dma->jpool, job);
		return -2;
	}
	return 0;
}
static void vring_used_head_done(struct agiep_async_dma_job *job)
{
	struct vring_split_cache *cache = (struct vring_split_cache *) job->priv;
	cache->used.used_clean_idx = cache->used.used->idx;
	if (cache->flags & VRING_F_NO_NOTIFY)
		cache->used.used->flags |= VRING_USED_F_NO_NOTIFY;
	else
		cache->used.used->flags = 0;

	rte_mempool_put(job->dma->jpool, job);
	//TODO: need to handle failure
	vring_avail_cache_all(cache);
}
int vring_used_head_cache(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *job = NULL;
	int ret;

	if (unlikely(agiep_dma_job_get(cache->dma, &job)))
		return -1;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(ALIGN_DMA_CALC_OFFSET(cache->used.hpci) == 0);
#endif
	job->src = cache->used.hpci;
	job->dst = cache->used.hphy;
	job->len = sizeof(struct vring_used);
	job->cb = (void *)vring_used_head_done;
	job->priv = cache;
	ret = agiep_dma_enqueue(cache->dma, job, DMA_JOB_F_FROM_PCI);
	if (unlikely(ret)){
		rte_mempool_put(cache->dma->jpool, job);
		return -1;
	}
	return 0;
}

void vring_desc_cache_predict_next_done(struct agiep_async_dma_group *group)
{
	struct vring_split_cache *cache = group->priv;
	struct split_user_ctx_args ctx_args;
	struct vring_desc *desc;
	int len = 0;
	uint16_t desc_idx;
	uint16_t avail_idx;
	uint16_t nb_desc = cache->num;

	ctx_args.user_args = group->user_args;
	desc_idx = ctx_args.idx;

	avail_idx = ctx_args.avail_idx;
	do {

		if (unlikely(desc_idx >= nb_desc))
			goto fatal;
		if (len >= cache->predict.avg_size){
			vring_desc_cache_predict_next(cache, avail_idx, desc_idx);
			rte_mempool_put(group->dma->jpool, group);
			return;
		}
		desc = &cache->desc.desc[desc_idx];
		if (unlikely(desc->flags > VRING_SPLIT_MAX_FLAG))
			goto fatal;
		desc_idx = desc->next;
		len ++;
	} while(desc->flags & VRING_DESC_F_NEXT);
	rte_mempool_put(group->dma->jpool, group);
	avail_idx %= cache->num;
	cache->avail_state[avail_idx / 64] |= 1ULL << (avail_idx % 64);
	return;
fatal:
	rte_mempool_put(group->dma->jpool, group);
	vring_split_cache_abort(cache);
}

static void vring_desc_cache_predict_next(struct vring_split_cache *cache, uint16_t avail_idx, int desc_idx)
{
	struct agiep_async_dma_job *jobs[128];
	struct desc_seg segs[2];
	struct agiep_async_dma_group *group = NULL;
	struct agiep_async_dma_job *job = NULL;
	struct split_user_ctx_args ctx_args;
	uint32_t offset;
	int ret;
	int nb_seg;
	int i;

	ret = vring_split_predict_next(&cache->predict, desc_idx, segs);
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(ret == 1 || ret == 2);
#endif

	nb_seg = ret;
	if (unlikely(rte_mempool_get(cache->dma->jpool, (void **) &group)))
		goto failed;

	if (unlikely(rte_mempool_get_bulk(cache->dma->jpool, (void **) jobs, nb_seg))) {
		goto failed_free;
	}
	ctx_args.idx = desc_idx;
	ctx_args.avail_idx = avail_idx;
	for (i = 0; i < nb_seg; i++) {
		offset = segs[i].id * sizeof(struct vring_desc);
		job = jobs[i];
		job->src = cache->desc.pci + offset;
		job->dst = cache->desc.phy + offset;
		job->len = sizeof(struct vring_desc) * segs[i].len;
		AGIEP_DMA_ALIGN_JOB_ADDR(job);
	}

	group->priv = cache;
	group->user_args = ctx_args.user_args;
	group->cb = vring_desc_cache_predict_next_done;

	i = agiep_dma_group_enqueue_no_pending(cache->dma, group, jobs, nb_seg, DMA_JOB_F_FROM_PCI);
	if (unlikely(i < nb_seg)) {
		rte_ring_enqueue_burst(cache->pring, (void **) &jobs[i], nb_seg - i,
				       NULL);
	}
	return;
failed_free:
	rte_mempool_put(cache->dma->jpool, group);
failed:
	cache->cache_error = 1;
}

static void vring_desc_cache_predict_done(struct agiep_async_dma_group *group)
{
	struct vring_split_cache *cache;
	struct agiep_async_dma_job *job;
	struct split_desc_context *indir_ctx;
	struct split_user_ctx_args ctx_args;
	struct vring_desc *desc;
	uint64_t avail_state;
	int avail_state_idx;
	int desc_idx;
	int nb;
	int next;
	uint16_t avail_idx;
	uint16_t nb_desc;
	uint16_t i;

	cache = group->priv;
	ctx_args.user_args = group->user_args;
	nb_desc = cache->num;
	avail_idx =  ctx_args.last_avail_idx % nb_desc;

	avail_state_idx = avail_idx / 64;
	avail_state = cache->avail_state[avail_state_idx];
	for (i = ctx_args.last_avail_idx; i != ctx_args.avail_idx; i++) {
		desc_idx = cache->avail.avail->ring[i % nb_desc];
		nb = 0;
		next = 0;
		do {
			if (unlikely(desc_idx >= nb_desc))
				goto fatal;
			desc = &cache->desc.desc[desc_idx];
			if (unlikely(desc->flags > VRING_SPLIT_MAX_FLAG))
				goto fatal;
			if ((uint16_t)(i + 1) == ctx_args.avail_idx && nb == cache->predict.avg_size){
				vring_desc_cache_predict_next(cache, i, desc_idx);
				next = 1;
				break;
			}
			if (!nb && desc->flags & VRING_DESC_F_INDIRECT) {
				// FIXME: 这里需要异步逻辑处理indirect，同步无法处理资源不足的情况。
				rte_mempool_get(cache->dma->jpool, (void **) &job);
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
				assert(job != NULL);
#endif
				rte_mempool_get(cache->ctx_pool, (void **) &indir_ctx);
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
				assert(indir_ctx != NULL);
#endif
				job->priv = indir_ctx;
				indir_ctx->avail_idx = i;
				indir_ctx->idx = desc_idx;
				indir_ctx->cache = cache;
				if (vring_desc_cache_indir_single(job)) {
					rte_ring_enqueue_burst(cache->iring, (void **) &job, 1, NULL);
				}
				break;
			}
			desc_idx = desc->next;
			nb++;
		} while (desc->flags & VRING_DESC_F_NEXT);
		
		avail_idx = i % nb_desc;
		if (avail_idx / 64 != avail_state_idx) {
			cache->avail_state[avail_state_idx] = avail_state;
			avail_state_idx = avail_idx / 64;
			avail_state = cache->avail_state[avail_state_idx];
		}
		if (!next){
			avail_state |= 1ULL << (avail_idx % 64);
			cache->desc.last_desc_idx++;
		}
	}

	cache->avail_state[avail_state_idx] = avail_state;
	rte_mempool_put(group->dma->jpool, group);
	return;
fatal:
	rte_mempool_put(group->dma->jpool, group);
	vring_split_cache_abort(cache);
}

/**
 * desc cache with predict
 * @param cache
 * @return
 * 	0: maybe ok, <0: some error
 */
static int vring_desc_cache_predict(struct vring_split_cache *cache)
{
	struct desc_seg segs[4096];
	struct agiep_async_dma_job *jobs[4096];
	struct agiep_async_dma_job *job = NULL;
	struct agiep_async_dma_group *group = NULL;
	struct split_user_ctx_args ctx_args;
	uint64_t offset;
	uint64_t dma_off;
	int nb_seg;
	int i;
	uint16_t cur_idx;

	cur_idx = cache->avail.avail_idx;
	if (cur_idx == cache->desc.last_avail_idx){
		return 0;
	}
	nb_seg = vring_split_predict_desc(&cache->predict,
				   	  cache->avail.avail->ring,
					  cur_idx,
				   	  cache->desc.last_avail_idx,
				   	  segs);
	if (unlikely(nb_seg < 0))
		goto fatal;

	if (unlikely(rte_mempool_get(cache->dma->jpool, (void **) &group)))
		return -1;

	if (unlikely(rte_mempool_get_bulk(cache->dma->jpool, (void **) jobs, nb_seg))) {
		rte_mempool_put(cache->dma->jpool, group);
		return -1;
	}

	ctx_args.last_avail_idx = cache->desc.last_avail_idx;
	ctx_args.avail_idx = cur_idx;

	for (i = 0; i < nb_seg; i++) {
		offset = segs[i].id * sizeof(struct vring_desc);
		dma_off = ALIGN_DMA_CALC_OFFSET(offset);
		job = jobs[i];
		job->src = cache->desc.pci + offset - dma_off;
		job->dst = cache->desc.phy + offset - dma_off;
		job->len = sizeof(struct vring_desc) * segs[i].len + dma_off;
	}

	group->priv = cache;
	group->user_args = ctx_args.user_args;
	group->cb = vring_desc_cache_predict_done;

	i = agiep_dma_group_enqueue_no_pending(cache->dma, group, jobs, nb_seg, DMA_JOB_F_FROM_PCI);
	if (unlikely(i < nb_seg)) {
		rte_ring_enqueue_burst(cache->pring, (void **) &jobs[i], nb_seg - i,
				       NULL);
	}
	cache->desc.last_avail_idx = cur_idx;
	return 0;
fatal:
	vring_split_cache_abort(cache);
	return -1;
}

/*
static int sort_jobs_bigthan(const void * p1, const void *p2)
{
	return  ((const struct agiep_async_dma_job *)p1)->src >
		((const struct agiep_async_dma_job *)p2)->src;
}
 */
// TODO: Delete all the normal cache code when predict cache test finished.
int vring_desc_cache(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *jobs[4096];
	struct agiep_async_dma_job *job = NULL;
	struct split_user_ctx_args args;
	uint16_t avail_idx;
	uint16_t desc_idx;
	uint16_t pre_idx;
	uint16_t last_avail_idx;
	int size;
	uint64_t offset;
	int i;
	const int mask = cache->num - 1;

	avail_idx = cache->avail.avail_idx;
	if (avail_idx == cache->desc.last_avail_idx)
		return 0;
	
	last_avail_idx = cache->desc.last_avail_idx & mask;
	size = avail_idx - cache->desc.last_avail_idx;
	if (size == 0) {
		return 1;
	}
	if (size < 0)
		size += UINT16_MAX + 1;

	if (unlikely(agiep_dma_job_get_bulk(cache->dma, jobs, size))) {
		return -1;
	}

	i = 0;
	args.user_args = 0;
	pre_idx = cache->avail.avail->ring[last_avail_idx];
	do {
		desc_idx = cache->avail.avail->ring[last_avail_idx];
		if (desc_idx == pre_idx + 1 && (pre_idx + 1) < cache->num) {
			job->len += sizeof(struct vring_desc);
			args.user_args = job->user_args;
			args.num ++;
			job->user_args = args.user_args;
			last_avail_idx ++;
			last_avail_idx = last_avail_idx & mask;
			pre_idx = desc_idx;
			continue;
		}
		args.user_args = 0;
		pre_idx = desc_idx;
		offset = desc_idx * sizeof(struct vring_desc);
		job = jobs[i];
		job->src = cache->desc.pci + offset;
		job->dst = cache->desc.phy + offset;
		job->len = sizeof(struct vring_desc);
		AGIEP_DMA_ALIGN_JOB_ADDR(job);
		args.idx = desc_idx;
		args.avail_idx = last_avail_idx;
		args.num = 1;
		job->user_args = args.user_args;
		job->priv = cache;
		job->cb = (void *)vring_desc_done;
		i++;
		last_avail_idx ++;
		last_avail_idx = last_avail_idx & mask;
	} while (last_avail_idx != (avail_idx & mask));
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(i <= size);
#endif
	cache->desc.last_avail_idx = avail_idx;
	if (i < size){
		agiep_dma_job_put_bulk(cache->dma, &jobs[i], size - i);
	}
//	qsort(jobs, i, sizeof(struct agiep_async_dma_job *), sort_jobs_bigthan);

	size = agiep_dma_enqueue_buffers(cache->dma, jobs, i, DMA_JOB_F_FROM_PCI);

	if (size < i) {
		rte_ring_enqueue_burst(cache->pring, (void **) &jobs[size], i - size,
				NULL);
	}
	return 0;
}

static int vring_desc_cache_next(struct vring_split_cache *cache,
	struct split_user_ctx_args ctx_args, uint16_t idx)
{
	struct agiep_async_dma_job *job;
	struct vring_desc *desc;
	uint64_t offset;
	int ret;
	uint16_t next_idx;

	job = NULL;
	if (unlikely(agiep_dma_job_get(cache->dma, &job)))
		return -1;

	desc = &cache->desc.desc[idx];
	next_idx = desc->next;
	offset = next_idx * sizeof(struct vring_desc);
	job->src = cache->desc.pci + offset;
	job->dst = cache->desc.phy + offset;
	job->len = sizeof(struct vring_desc);
	AGIEP_DMA_ALIGN_JOB_ADDR(job);
	job->cb = vring_desc_done;
	job->priv = cache;
	ctx_args.idx = next_idx;
	ctx_args.num = 1;
	job->user_args = ctx_args.user_args;

	ret = agiep_dma_enqueue(cache->dma, job, DMA_JOB_F_FROM_PCI);

	if (ret)
		rte_ring_enqueue(cache->pring, job);
	return 0;
}

static void vring_desc_cache_indir_done(struct agiep_async_dma_job *job)
{
	struct split_desc_context *ctx = job->priv;
	struct vring_split_cache *cache = ctx->cache;
	uint16_t avail_idx;

	cache->desc_state[ctx->idx].indir_desc = ctx->indir_desc;
	avail_idx = ctx->avail_idx % cache->num;
	cache->avail_state[avail_idx / 64] |= 1ULL << (avail_idx % 64);
	rte_mempool_put(job->dma->jpool, job);
	rte_mempool_put(cache->ctx_pool, ctx);
}

static int vring_desc_cache_indir_single(struct agiep_async_dma_job *job)
{
	struct split_desc_context *ctx = job->priv;
	struct vring_split_cache *cache = ctx->cache;
	struct vring_desc *desc = &cache->desc.desc[ctx->idx];
	struct vring_desc *indir_desc = NULL;
	int ret;

	indir_desc = rte_malloc(NULL, desc->len, 0);
	if (!indir_desc)
		return -1;
	ctx->indir_desc = indir_desc;

	job->src = desc->addr;
	job->dst = rte_malloc_virt2iova(indir_desc);
	job->len = desc->len;
	AGIEP_DMA_ALIGN_JOB_ADDR(job);
	job->cb = vring_desc_cache_indir_done;
	job->priv = ctx;

	ret = agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_FROM_PCI);
	if (!ret) {
		rte_ring_enqueue(cache->pring, job);
	}
	return 0;
}

void vring_split_cache_indir_cache(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *jobs[32];
	uint16_t num;
	uint16_t i;

	if (likely(!rte_ring_count(cache->iring)))
		return;
	num = rte_ring_dequeue_burst(cache->iring, (void **)jobs, 32, NULL);

	if (!num)
		return;

	for (i = 0; i < num; i++) {
		if (vring_desc_cache_indir_single(jobs[i])) {
			rte_ring_enqueue_burst(cache->iring, (void *const *) &jobs[i], num - i, NULL);
			break;
		}
	}
}

static void vring_desc_done(struct agiep_async_dma_job *job) 
{
	struct vring_split_cache *cache = job->priv;
	struct split_desc_context *ctx;
	struct split_user_ctx_args ctx_args;
	struct split_user_ctx_args ctx_next;
	struct vring_desc *desc;
	struct agiep_async_dma_job *indir_job;
	int i;
	uint16_t desc_idx;
	uint16_t avail_idx;

	ctx_args.user_args = job->user_args;

	for (i = 0; i < (int)ctx_args.num; ++i) {
		desc_idx = (ctx_args.idx + i) % cache->num;
		desc = &cache->desc.desc[desc_idx];
		if (desc->flags & VRING_DESC_F_NEXT) {
			ctx_next.user_args = ctx_args.user_args;
			ctx_next.avail_idx += i;
			vring_desc_cache_next(cache, ctx_next, desc_idx);
		} else if (unlikely(desc->flags & VRING_DESC_F_INDIRECT)) {
			if (cache->desc_state[desc_idx].indir_desc != NULL) {
				continue;
			}
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			assert(agiep_dma_job_get(cache->dma, &indir_job) == 0);
			assert(rte_mempool_get(cache->ctx_pool, (void **) &ctx));
#else
			agiep_dma_job_get(cache->dma, &indir_job);
			rte_mempool_get(cache->ctx_pool, (void **) &ctx);
#endif
			ctx->cache = cache;
			ctx->idx = ctx_args.idx;
			ctx->avail_idx = ctx_args.avail_idx;
			indir_job->priv = ctx;
			if (vring_desc_cache_indir_single(indir_job)) {
				rte_ring_enqueue_burst(cache->iring, (void **) &indir_job, 1,
						       NULL);
			}
		} else {
			avail_idx = (ctx_args.avail_idx + i) % cache->num;
			cache->avail_state[avail_idx / 64] |= 1ULL << (avail_idx % 64);
		}
	}
	rte_mempool_put(job->dma->jpool, job);
}

static void vring_split_event_done(struct agiep_async_dma_job *job)
{
	rte_mempool_put(job->dma->jpool, job);
}

int vring_split_read_event(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *job;
	if (rte_mempool_get(cache->dma->jpool, (void **) &job)) {
		return -1;
	}
	job->src = cache->avail.pci + sizeof(uint16_t) * cache->num;
	job->dst = cache->avail.phy + sizeof(uint16_t) * cache->num;
	job->priv = cache;
	job->cb = vring_split_event_done;
	return agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_FROM_PCI);
}

int vring_split_write_event(struct vring_split_cache *cache)
{
	struct agiep_async_dma_job *job;
	if (rte_mempool_get(cache->dma->jpool, (void **) &job)) {
		return -1;
	}
	job->src = cache->used.phy + sizeof(uint16_t) * cache->num;
	job->dst = cache->used.pci + sizeof(uint16_t) * cache->num;
	job->priv = cache;
	job->cb = vring_split_event_done;
	return agiep_dma_enqueue_buffers(cache->dma, &job, 1, DMA_JOB_F_TO_PCI);
}
