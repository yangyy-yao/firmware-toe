#ifndef RTE_AGIEP_DMA_H_
#define RTE_AGIEP_DMA_H_

#include <stdint.h>
#include <sys/queue.h>
#include <rte_rawdev.h>
#include <rte_mempool.h>
#include <rte_pmd_dpaa2_qdma.h>
#include "agiep_pci.h"

/* define DPAA2 qdma API */
#define rte_qdma_vq_destroy(id, qid) rte_rawdev_queue_release(id, qid)
#define rte_qdma_stop(id) rte_rawdev_stop(id)
#define rte_qdma_info rte_rawdev_info
#define rte_qdma_start(id) rte_rawdev_start(id)
#define rte_qdma_reset(id) rte_rawdev_reset(id)
#define rte_qdma_configure(id, cf) rte_rawdev_configure(id, cf)
#define rte_qdma_dequeue_buffers(id, buf, num, ctxt) \
	rte_rawdev_dequeue_buffers(id, buf, num, ctxt)
#define rte_qdma_enqueue_buffers(id, buf, num, ctxt) \
	rte_rawdev_enqueue_buffers(id, buf, num, ctxt)
#define rte_qdma_queue_setup(id, qid, cfg) \
	rte_rawdev_queue_setup(id, qid, cfg)


#define JOB_ENQ_NUM 64
#define JOB_DEQ_NUM 64
#define DMA_JOB_ENQ_MAX_NUM 64
#define DMA_JOB_DNQ_MAX_NUM 64

#define JOB_POOL_NUM (1024 * 8)
#define JOB_RING_NUM JOB_POOL_NUM
#define MAX_QUEUE_NUMBER 64
#define DMA_JOB_CACHE_SIZE 64

#define DMA_JOB_F_TO_PCI  1
#define DMA_JOB_F_FROM_PCI 2

#define AGIEP_DMA_ALIGN 64
/**
 * dma host copy data to endpoint pci addr must aligned 64 byte
 * @param addr
 * 	pci bus address
 */
#define ALIGN_DMA_CALC_OFFSET(addr)   ((addr) & (AGIEP_DMA_ALIGN - 1))

#define AGIEP_DMA_ALIGN_ADDR(addr) ((addr) - ALIGN_DMA_CALC_OFFSET(addr))

/**
 * helper for align dma job
 *
 * @param job
 * 	dma job
 * @warning
 * 	the memory before job->dst may be overwritten
 */
#define AGIEP_DMA_ALIGN_JOB_ADDR(job) ({ \
	(job)->dst = (job)->dst - ALIGN_DMA_CALC_OFFSET((job)->src); \
	(job)->len = (job)->len + ALIGN_DMA_CALC_OFFSET((job)->src);  \
	(job)->src = AGIEP_DMA_ALIGN_ADDR((job)->src); \
	})

#define AGIEP_GET_CACHE_SIZE(num) (RTE_MIN(1 << (agiep_fls_u16(((num) * 2 / 3))-1), \
		RTE_MEMPOOL_CACHE_MAX_SIZE))

/*  --  */
struct agiep_async_dma_group;
struct agiep_async_dma_job;
struct agiep_async_dma_batch;
typedef void (*async_dma_callback)(struct agiep_async_dma_job *job);

typedef void (*async_dma_group_callback)(struct agiep_async_dma_group *group);

typedef void (*async_dma_batch_callback)(struct agiep_async_dma_batch *batch);

typedef void (*async_dma_GC_callback)(void *data);

struct agiep_dma_hwq {
	int enable;
	int lcore_id;
	int id;
	int vq;
	struct rte_qdma_rbp R_rbp[MAX_PF][MAX_VF];
	struct rte_qdma_rbp W_rbp[MAX_PF][MAX_VF];
};

struct agiep_dma {
	uint16_t id;
	uint16_t pf;
	uint16_t vf;
	uint16_t job_cnt;
	// job count
	volatile uint32_t enqueue_jobs;
	volatile uint32_t dequeue_jobs;
	volatile uint32_t discard_jobs[RTE_MAX_LCORE];
	// job pool
	struct rte_mempool *jpool;
	struct rte_mempool *bpool;
	struct rte_qdma_job *qjobs;
	void *GC_data;
	struct rte_ring *dq;
	async_dma_GC_callback GC_cb;
	volatile int ref;
	TAILQ_ENTRY(agiep_dma) next;
};

struct agiep_async_dma_job {
	struct agiep_dma *dma;
	uint16_t GC;
	uint16_t flags;
	uint32_t len;
	uint64_t src;
	uint64_t dst;
	void *priv;
	uint64_t user_args;
	async_dma_callback cb;
	struct rte_qdma_job *job;
	// ---  cache line ---
}__rte_cache_aligned;

struct agiep_async_dma_group {
	struct agiep_dma *dma;
	uint16_t GC;
	uint16_t nb_jobs;
	int nb_pending;
	int doing;
	uint32_t reserved1;
	uint64_t reserved2;  /* other args offset must equal to job */
	void *priv;
	uint64_t user_args;
	async_dma_group_callback cb;
} __rte_cache_aligned;

struct agiep_async_dma_batch {
	struct agiep_dma *dma;
	async_dma_batch_callback cb;
	uint16_t GC;
	uint16_t nb_jobs;
	uint32_t total_jobs;
	void *priv;
	uint64_t user_args;
	uint64_t reserved1[3];
	// 8 - cache-line
	struct agiep_async_dma_job *pjobs[DMA_JOB_ENQ_MAX_NUM];
	// 64 cache-line
	struct agiep_async_dma_job jobs[DMA_JOB_ENQ_MAX_NUM];
	// 64 cache-line
	struct rte_qdma_job *pqjobs[DMA_JOB_ENQ_MAX_NUM];
	struct rte_qdma_job qjobs[DMA_JOB_ENQ_MAX_NUM];
} __rte_cache_aligned;

int agiep_dma_init(void);

void agiep_dma_fini(void);

struct agiep_dma *agiep_dma_create(int pf, int vf);

void agiep_dma_free(struct agiep_dma *dma, async_dma_GC_callback cb, void *priv);
void agiep_dma_free_syn(struct agiep_dma *dma, async_dma_GC_callback cb, void *priv);
void agiep_dma_synchronize(struct agiep_dma *dma);

int agiep_dma_enqueue_buffers(struct agiep_dma *dma,
		struct agiep_async_dma_job **ajobs, int num_jobs, int flags);

/**
 * Enqueue one job on a dma.
 * @param dma
 *   A pointer to the dma structure.
 * @param job
 *   A pointer to the dma job to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: dma job enqueue error; no job is enqueued.
 */
static __rte_always_inline int agiep_dma_enqueue(struct agiep_dma *dma,
	struct agiep_async_dma_job *job, int flags)
{
	return agiep_dma_enqueue_buffers(dma, &job, 1, flags) ? 0 : -ENOBUFS;
}

static __rte_always_inline void
agiep_dma_job_put_bulk(struct agiep_dma *dma, struct agiep_async_dma_job **jobs, unsigned int n)
{
	return rte_mempool_put_bulk(dma->jpool, (void *const *) jobs, n);
}

static __rte_always_inline int
agiep_dma_job_get_bulk(struct agiep_dma *dma, struct agiep_async_dma_job **jobs, unsigned int n)
{
	return rte_mempool_get_bulk(dma->jpool, (void **) jobs, n);
}
/**
 * Get one job from the dma.
 *
 * @param dma
 *   A pointer to the mempool structure.
 * @param jobs
 *   A pointer to a struct agiep_async_dma_job * pointer that will be filled.
 * @return
 *   - 0: Success; objects taken.
 *   - -ENOENT: Not enough entries in the mempool; no object is retrieved.
 */
static __rte_always_inline int
agiep_dma_job_get(struct agiep_dma *dma, struct agiep_async_dma_job **jobs)
{
	return rte_mempool_get(dma->jpool, (void **) jobs);
}

int agiep_dma_group_enqueue(struct agiep_dma *dma,
		struct agiep_async_dma_group *group,
		struct agiep_async_dma_job **ajobs, int nb_jobs, int flags);

int agiep_dma_group_enqueue_no_pending(struct agiep_dma *dma,
		struct agiep_async_dma_group *group,
		struct agiep_async_dma_job **ajobs, int nb_jobs, int flags);

int agiep_dma_dequeue_buffers(struct agiep_dma *dma,
		struct agiep_async_dma_job **ajobs, int nb_jobs);



void agiep_dma_group_attach(struct agiep_dma *dma,
		struct agiep_async_dma_group *group,
		struct agiep_async_dma_job **ajobs, int nb_jobs);

void agiep_dma_group_pending(struct agiep_async_dma_job **ajobs, int nb_jobs);

int agiep_dma_batch_enqueue(struct agiep_dma *dma,
		struct agiep_async_dma_batch *batch,
		struct agiep_async_dma_job **ajobs, int nb_jobs);

struct rte_qdma_rbp *agiep_dma_rbp(struct agiep_dma *dma, int flags);

void agiep_dma_dequeue_process(void *param __rte_unused);
#endif
