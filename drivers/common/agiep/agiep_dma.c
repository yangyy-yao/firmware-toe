#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev_driver.h>
#include "agiep_dma.h"
#include "agiep_lib.h"
#include "agiep_pci.h"
#include "agiep_logs.h"


#define AGIEP_QDMA_MAX_HW_QUEUES_PER_CORE      2
#define AGIEP_QDMA_FLE_POOL_QUEUE_COUNT        4096
#define AGIEP_QDMA_MAX_VQS                     2048

#define QDMA_MAP_SIZE (4096)
#define QDMA_REG_BASE (0x8380000)

#define REG_DMR (0x00)
#define REG_DSRP (0x04)
#define REG_DEWQAR0 (0x60)
#define REG_DWQBWCR0 (0x70)
#define REG_DWQBWCR1 (0x74)
#define REG_DPWQAR (0x78)
#define REG_DSRM (0x10004)
#define REG_DGBTR (0x10040)

#define GC_RING_SIZE 2048

int agiep_logtype_common;

struct rte_ring *GC_ring;
TAILQ_HEAD(agiep_dma_GC, agiep_dma) agiep_dma_gcs =
	TAILQ_HEAD_INITIALIZER(agiep_dma_gcs);

struct agiep_dma_hwq dma_hwq[RTE_MAX_LCORE];

static int qdma_dev_id = 0;

#define QDMA_GC_DMA_DQ 16
#define QDMA_GC_JOB_DQ 4096

//#define MIG_RING_LEN (QDMA_GC_JOB_DQ * 2)

static void agiep_dma_job_pool_free(struct agiep_dma *dma);
static void agiep_dma_hwq_init(const int *pfs, int pf_num, const int* vf_num);
void agiep_dma_hwq_destroy(void);
static void agiep_dma_release(struct agiep_dma *dma);

static pthread_t GC_thread;

uint16_t dpni_rx_callback_process(uint16_t port_id __rte_unused,
	uint16_t queue __rte_unused, struct rte_mbuf *pkts[] __rte_unused,
	uint16_t nb_pkts, uint16_t max_pkts __rte_unused,
	void *user_param __rte_unused);

__rte_always_inline uint32_t
sum_array(const volatile uint32_t array[RTE_MAX_LCORE], int num)
{
	uint32_t nb = 0;
	for (int i = 0; i < num; ++i) {
		nb += array[i];
	}
	return nb;
}

_Noreturn static void *agiep_dma_GC(void *arg __rte_unused)
{
	struct agiep_dma *dmas[QDMA_GC_DMA_DQ];
	struct agiep_dma *dma, *next;
	struct agiep_async_dma_job *jobs[QDMA_GC_JOB_DQ];
	int dcount;
	int i;
	while (1){
		if (rte_ring_count(GC_ring)) {
			dcount = rte_ring_dequeue_burst(GC_ring, (void **) dmas,
							QDMA_GC_DMA_DQ, NULL);
			for (i = 0; i < dcount; i++) {
				dma = dmas[i];
				TAILQ_INSERT_HEAD(&agiep_dma_gcs, dma, next);
			}
		}

		dma = TAILQ_FIRST(&agiep_dma_gcs);
		while(dma) {
			next = TAILQ_NEXT(dma, next);
			// FIXME: discard_jobs loopback
			if ((dma->ref == 0) && (dma->enqueue_jobs == (dma->dequeue_jobs +
				sum_array(dma->discard_jobs, RTE_MAX_LCORE))))
			{
				TAILQ_REMOVE(&agiep_dma_gcs, dma, next);
				agiep_dma_release(dma);
			}
			dma = next;
		}

		TAILQ_FOREACH(dma, &agiep_dma_gcs, next) {
			if (dma->enqueue_jobs != (dma->dequeue_jobs +
				sum_array(dma->discard_jobs, RTE_MAX_LCORE)))
				agiep_dma_dequeue_buffers(dma, jobs, QDMA_GC_JOB_DQ);
		}
		sleep(1);
	}
}

// specially for LX2160A
static int qdma_reg_init(void)
{
	int retfd = 0;
	void *ret_addr;
	void *map_addr = NULL;
	uint64_t addr = QDMA_REG_BASE;

	ret_addr = agiep_mmap(NULL, QDMA_MAP_SIZE,
			PROT_WRITE, MAP_SHARED,
			(off_t)addr, &map_addr, &retfd);
	if (!ret_addr) {
		RTE_LOG(ERR, PMD, "lsinic_dma_read_reg mmap error!\n");
		return -1;
	}

	*(uint32_t *)(((uint8_t*)map_addr + REG_DMR) 	 ) = 0x11000;
	*(uint32_t *)(((uint8_t*)map_addr + REG_DWQBWCR0)) = 0x11111111;
	*(uint32_t *)(((uint8_t*)map_addr + REG_DWQBWCR1)) = 0x11111110;

	agiep_ummap(ret_addr, QDMA_MAP_SIZE, retfd);
	return 0;
}

static int qdma_init(int qdma_dev_id)
{
	struct rte_qdma_config qdma_config;
	struct rte_qdma_info dev_conf;
	char name[RTE_MEMPOOL_NAMESIZE];
	int ret;
	int i = 0;

	ret = qdma_reg_init();

	if (ret < 0)
		goto qdma_error;


	snprintf(name, sizeof(name), "dma_gc_ring_%d",i);
	GC_ring = rte_ring_create(name, GC_RING_SIZE, SOCKET_ID_ANY, 0);
	if (GC_ring == NULL)
		goto error;

	/* Configure QDMA to use HW resource - no virtual queues */
	qdma_config.max_hw_queues_per_core = AGIEP_QDMA_MAX_HW_QUEUES_PER_CORE;
	qdma_config.fle_queue_pool_cnt = AGIEP_QDMA_FLE_POOL_QUEUE_COUNT;
	qdma_config.max_vqs = AGIEP_QDMA_MAX_VQS;

	dev_conf.dev_private = (void *)&qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);

	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
		goto error;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to start DMA\n");
		goto error;
	}

	return qdma_dev_id;
error:
	rte_ring_free(GC_ring);
qdma_error:
	return -EINVAL;
}

static void qdma_fini(int qdma_dev_id)
{
	rte_rawdev_stop(qdma_dev_id);
	rte_rawdev_close(qdma_dev_id);
}

int agiep_dma_init(void)
{
	int pf[MAX_PF];
	int vf_num[MAX_PF];
	int ret;
	int pf_num = agiep_pci_get_pf(pf, vf_num);
	const char *thread_name = "agiep_gc";

	qdma_dev_id = qdma_init(qdma_dev_id);
	assert(qdma_dev_id >= 0);

	assert(GC_thread == 0);

	ret = pthread_create(&GC_thread, NULL, agiep_dma_GC, NULL);

	if (ret) {
		RTE_LOG(ERR, PMD, "AGIEP: DMA GC thread create failed\n");
		return -1;
	}
	ret = pthread_setname_np(GC_thread, thread_name);
	if (ret)
		return ret;
	agiep_dma_hwq_init(pf, pf_num, vf_num);
	return 0;
}

void agiep_dma_fini(void)
{
	agiep_dma_hwq_destroy();
	qdma_fini(qdma_dev_id);
}

static inline int qdma_queue_setup(int dma_id,int lcore_id, uint32_t vq_flags)
{
	struct rte_qdma_queue_config qdma_config;
	qdma_config.lcore_id = lcore_id;
	qdma_config.flags = vq_flags;
	qdma_config.rbp = NULL;
	return rte_qdma_queue_setup(dma_id, -1, &qdma_config);
}

static inline void qdma_queue_relese(int dma_id, int vq_id)
{
	rte_rawdev_queue_release(dma_id, vq_id);
}

static void dma_batch_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned int idx __rte_unused)
{
	struct agiep_async_dma_batch *b = obj;
	uint32_t i;

	memset(b, 0, sizeof(struct agiep_async_dma_batch));
	b->total_jobs = DMA_JOB_ENQ_MAX_NUM;
	b->dma = opaque;
	for (i = 0; i < b->total_jobs; i++) {
		b->pjobs[i] = &b->jobs[i];
		b->pqjobs[i] = &b->qjobs[i];
		b->jobs[i].dma = opaque;
		b->jobs[i].job = &b->qjobs[i];
		b->qjobs[i].flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
		b->jobs[i].user_args = (uint64_t)b;
	}
}

static int agiep_dma_batch_pool_init(struct agiep_dma *dma) 
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	uint32_t elt_size;

	snprintf(name, sizeof(name),
			"agiep_dma_b_%d_%lx", dma->vf, rte_rdtsc());

	elt_size = sizeof(struct agiep_async_dma_batch);

	// FIXME: fix bpool core migrate local cache problem
	mp = rte_mempool_create(name, 256,
			elt_size,
			0, 0, NULL, NULL, dma_batch_init,
			dma, SOCKET_ID_ANY, 0);

	if (mp == NULL) {
		RTE_LOG(ERR, PMD,
				"mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	dma->bpool = mp;
	return 0;
}

static void dma_job_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned int idx)
{
	struct agiep_async_dma_job *job = obj;
	struct agiep_dma *dma = opaque;
	memset(job, 0, sizeof(*job));
	job->dma = dma;
	job->job = &dma->qjobs[idx];
	job->job->flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
}

static int agiep_dma_job_pool_init(struct agiep_dma *dma) 
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	uint32_t elt_size;

	dma->qjobs = rte_calloc(NULL, dma->job_cnt, sizeof(struct rte_qdma_job), RTE_CACHE_LINE_SIZE);

	if (!dma->qjobs)
		return -rte_errno;

	snprintf(name, sizeof(name),
			"agiep_dma_j_%d_%lx", dma->vf, rte_rdtsc());

	elt_size = sizeof(struct agiep_async_dma_job);

	if (elt_size < sizeof(struct agiep_async_dma_group))
		elt_size = sizeof(struct agiep_async_dma_group);

	// 目前只有一个NUMA: 0
	mp = rte_mempool_create(name, dma->job_cnt,
			elt_size,
			DMA_JOB_CACHE_SIZE, 0, NULL, NULL, dma_job_init,
			dma, SOCKET_ID_ANY, 0);

	if (mp == NULL) {
		RTE_LOG(ERR, PMD,
				"mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	dma->jpool = mp;
	return 0;
}

static void agiep_dma_job_pool_free(struct agiep_dma *dma) 
{
	if (dma->qjobs)
		rte_free(dma->qjobs);
	if (dma->jpool) {
		rte_mempool_free(dma->jpool);
		dma->jpool = NULL;
	}
}

int agiep_dma_dequeue_buffers(struct agiep_dma *dma,
		struct agiep_async_dma_job **ajobs, int nb_jobs)
{
	uint32_t ret;
	agiep_dma_dequeue_process(NULL);
	if (!rte_ring_count(dma->dq))
		return 0;
	ret = rte_ring_sc_dequeue_burst(dma->dq, (void **) ajobs, nb_jobs, NULL);
	__sync_fetch_and_add(&dma->dequeue_jobs, (uint32_t)ret);
	return (int)ret;
}

void agiep_dma_dequeue_process(void *param __rte_unused)
{
	struct rte_qdma_job *jobs[JOB_DEQ_NUM];
	struct agiep_async_dma_job *ajobs[JOB_DEQ_NUM];
	struct agiep_async_dma_job *ajob = NULL;
	struct agiep_dma_hwq *hwq;
	struct agiep_dma *dma;
	struct rte_qdma_enqdeq e_context;
	uint32_t lcore_id;
	int i;
	int nb;
	int nb_enq;

	lcore_id = rte_lcore_id();
	if (unlikely(lcore_id == LCORE_ID_ANY))
		return;

	hwq = &dma_hwq[lcore_id];
	if (unlikely(!hwq->enable))
		return;
	e_context.vq_id = hwq->vq;
	e_context.job = jobs;

	do {
		nb = rte_qdma_dequeue_buffers(hwq->id, NULL,
				      JOB_DEQ_NUM, &e_context);
		if (!nb)
			break;
		nb_enq = 0;
		for (i = 0; i < nb; i++) {
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			if (unlikely(jobs[i]->status))
				AGIEP_LOG_DEBUG("dma job error %04x", jobs[i]->status);
#endif
			ajob = (struct agiep_async_dma_job *) jobs[i]->cnxt;
			if (likely(!ajob))
				continue;
			jobs[i]->cnxt = 0;
			ajobs[nb_enq] = ajob;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			assert(ajob->dma == ajobs[0]->dma && ajob->dma != NULL);
#endif
			nb_enq++;
		}
		if (nb_enq){
			dma = ajobs[0]->dma;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			int ret =
#endif
			rte_ring_mp_enqueue_burst(dma->dq,
					(void *const *) ajobs, nb_enq, NULL);
			dma->discard_jobs[lcore_id] += nb - nb_enq;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			assert(ret == nb_enq);
#endif
		} else {
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
			assert(ajob != NULL);
#endif
			dma = ajob->dma;
			dma->discard_jobs[lcore_id] += nb;
		}
	} while(nb);
}

int agiep_dma_enqueue_buffers(struct agiep_dma *dma,
		struct agiep_async_dma_job **ajobs, int num_jobs, int flags) 
{
	struct rte_qdma_job *jobs[JOB_ENQ_NUM];
	struct rte_qdma_enqdeq e_context;
	struct agiep_async_dma_job *ajob;
	struct rte_qdma_rbp *rbp;
	struct agiep_dma_hwq *hwq;
	int nb_jobs;

	uint32_t lcore_id;
	int i;
	int ret;

	lcore_id = rte_lcore_id();

	hwq = &dma_hwq[lcore_id];

	if (flags & DMA_JOB_F_FROM_PCI) {
		rbp = &hwq->R_rbp[dma->pf][dma->vf];
	} else {
		rbp = &hwq->W_rbp[dma->pf][dma->vf];
	}
	nb_jobs = 0;
	for (i = 0; i < num_jobs; i++) {
		ajob = ajobs[i];
		ajob->job->cnxt = (uint64_t) ajob;
		ajob->job->src = ajob->src;
		ajob->job->dest = ajob->dst;
		ajob->job->len = ajob->len;
		ajob->job->rbp = rbp;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
		assert(ajob->len != 0);
#endif
		jobs[nb_jobs] = ajob->job;
		nb_jobs++;

		if (nb_jobs == JOB_ENQ_NUM) {
			e_context.vq_id = hwq->vq;
			e_context.job = jobs;
			ret = rte_qdma_enqueue_buffers(dma->id, NULL,  nb_jobs, &e_context);
			__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
			if (ret != JOB_ENQ_NUM)
				return (i + 1 - (nb_jobs - ret));
			nb_jobs = 0;
		}
	}
	if (nb_jobs != 0) {
		e_context.vq_id = hwq->vq;
		e_context.job = jobs;
		ret = rte_qdma_enqueue_buffers(dma->id, NULL, nb_jobs, &e_context);
		__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
		return num_jobs - (nb_jobs - ret);
	}

	return num_jobs;
}

struct rte_qdma_rbp *agiep_dma_rbp(struct agiep_dma *dma, int flags)
{
	struct agiep_dma_hwq *hwq;
	hwq = &dma_hwq[rte_lcore_id()];
	if (flags & DMA_JOB_F_FROM_PCI) {
		return &hwq->R_rbp[dma->pf][dma->vf];
	} else {
		return &hwq->W_rbp[dma->pf][dma->vf];
	}
}

static __rte_always_inline int agiep_dma_enqueue_batch(struct agiep_dma *dma,
	struct agiep_async_dma_batch *batch)
{
	struct rte_qdma_enqdeq e_context;
	struct rte_qdma_job *job;
	struct agiep_dma_hwq *hwq;

	uint32_t lcore_id;
	int ret;

	lcore_id = rte_lcore_id();

	hwq = &dma_hwq[lcore_id];

	job = &batch->qjobs[batch->nb_jobs - 1];
	job->cnxt = (uint64_t)batch->pjobs[batch->nb_jobs - 1];
	e_context.vq_id = hwq->vq;
	e_context.job = batch->pqjobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL, batch->nb_jobs, &e_context);
	__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
	return ret;
}

static void agiep_dma_group_cb(struct agiep_async_dma_job *job)
{

	struct agiep_async_dma_group *group = job->priv;
	rte_mempool_put(job->dma->jpool, job);

	group->doing--;

	if (!group->doing && !group->nb_pending) {
		if (!group->nb_pending) {
			group->GC = job->GC;
			group->cb(group);
		}

		// 在cb之后不再允许使用group指针，因为group指针有可能已经被释放了
		return;
	}
}

// 函数外部需要自己处理enqueue失败的情况，比如增加group->nb_pending
inline void agiep_dma_group_attach(struct agiep_dma *dma, struct agiep_async_dma_group *group,
		struct agiep_async_dma_job **ajobs, int nb_jobs)
{
	int i;
	group->nb_jobs += nb_jobs;
	for (i = 0; i < group->nb_jobs; i++) {
		ajobs[i]->priv = group;
		ajobs[i]->cb = agiep_dma_group_cb;
		ajobs[i]->user_args = group->user_args;
	}
	group->dma = dma;
	group->doing += nb_jobs;
}

void agiep_dma_group_pending(struct agiep_async_dma_job **ajobs, int nb_jobs)
{
	int i;
	struct agiep_async_dma_group *group;

	for (i = 0; i < nb_jobs; i++) {
		if (ajobs[i]->cb == agiep_dma_group_cb) {
			group = ajobs[i]->priv;
			group->nb_pending++;
		}
	}
}

int agiep_dma_group_enqueue(struct agiep_dma *dma,
		struct agiep_async_dma_group *group, struct agiep_async_dma_job **ajobs, int nb_jobs, int flags)
{
	int i;
	int ret;
#ifdef RTE_LIBRTE_AGIEP_COMMON_DEBUG
	assert(nb_jobs > 0);
#else
	if (unlikely(nb_jobs <= 0))
		return 0;
#endif
	group->dma = dma;
	group->nb_jobs = nb_jobs;

	for (i = 0; i < group->nb_jobs; i++) {
		ajobs[i]->priv = group;
		ajobs[i]->cb = agiep_dma_group_cb;
		ajobs[i]->user_args = group->user_args;
	}

	group->doing = nb_jobs;

	ret = agiep_dma_enqueue_buffers(dma, ajobs,
			group->nb_jobs, flags);

	group->nb_pending = group->nb_jobs - ret;

	return ret;
}

static void async_dma_batch_cb(struct agiep_async_dma_job *job)
{
	struct agiep_async_dma_batch *batch;
	batch = job->priv;
	batch->cb(batch);
}

// ajobs[x]->cb must be NULL before call this function.
int agiep_dma_batch_enqueue(struct agiep_dma *dma,
	struct agiep_async_dma_batch *batch,
	struct agiep_async_dma_job **ajobs, int nb_jobs)
{
	if (unlikely(nb_jobs == 0))
		return 0;
	ajobs[nb_jobs - 1]->cb = async_dma_batch_cb;
	ajobs[nb_jobs - 1]->priv = batch;
	return agiep_dma_enqueue_batch(dma, batch);
}

int agiep_dma_group_enqueue_no_pending(struct agiep_dma *dma,
		struct agiep_async_dma_group *group, struct agiep_async_dma_job **ajobs, int nb_jobs, int flags)
{
	int i;
	int ret;

	group->dma = dma;
	group->nb_jobs = nb_jobs;

	for (i = 0; i < group->nb_jobs; i++) {
		ajobs[i]->priv = group;
		ajobs[i]->cb = agiep_dma_group_cb;
	}

	group->doing = nb_jobs;

	ret = agiep_dma_enqueue_buffers(dma, ajobs,
			group->nb_jobs, flags);

	group->nb_pending = 0;

	return ret;
}

static void agiep_dma_hwq_init(const int *pfs, int pf_num, const int *vf_num)
{
	int lcore;
	int i;
	int pf;
	int vf;
	struct agiep_dma_hwq *hwq;
	struct rte_qdma_rbp *rbp;
	unsigned int portid = agiep_get_portid();
	uint32_t vq_flags = RTE_QDMA_VQ_EXCLUSIVE_PQ | RTE_QDMA_VQ_FD_LONG_FORMAT
		| RTE_QDMA_VQ_FD_SG_FORMAT;

	RTE_LCORE_FOREACH(lcore) {
		hwq = &dma_hwq[lcore];
		hwq->lcore_id = lcore;
		hwq->id = qdma_dev_id;
		hwq->vq = qdma_queue_setup(qdma_dev_id, lcore, vq_flags);
		assert(hwq->vq >= 0);
		
		for (i = 0; i < pf_num; i++) {
			pf = pfs[i];
			for (vf = 0; vf < vf_num[i]; vf++) {
				rbp = &hwq->R_rbp[pf][vf];
				memset(rbp, 0, sizeof(struct rte_qdma_rbp));
				rbp->enable = 1;

				if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
					rbp->use_ultrashort = 0;
				else
					rbp->use_ultrashort = 1;
				rbp->srbp = 1;
				rbp->drbp = 0;
				rbp->sportid = portid;
				rbp->spfid = pf;
				rbp->svfid = vf;

				rbp = &hwq->W_rbp[pf][vf];
				memset(rbp, 0, sizeof(struct rte_qdma_rbp));
				rbp->enable = 1;

				if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
					rbp->use_ultrashort = 0;
				else
					rbp->use_ultrashort = 1;
				rbp->srbp = 0;
				rbp->drbp = 1;
				rbp->dportid = portid;
				rbp->dpfid = pf;
				rbp->dvfid = vf;
			}
		}

		rte_compiler_barrier();
		hwq->enable = 1;
	}
}

void agiep_dma_hwq_destroy(void)
{
	int lcore;
	struct agiep_dma_hwq *hwq;
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		hwq = &dma_hwq[lcore];		
		if (!hwq->enable)
			continue;
		qdma_queue_relese(hwq->id, hwq->vq);
	}
}

struct agiep_dma *agiep_dma_create(int pf, int vf)
{
	int ret;
	struct agiep_dma *dma = NULL;
	struct rte_ring *dp = NULL;
	char name[RTE_RING_NAMESIZE];
	dma = rte_calloc(NULL, 1, sizeof(struct agiep_dma), RTE_CACHE_LINE_SIZE);

	if (dma == NULL)
		return NULL;
	snprintf(name, sizeof(name), "dma_dq_%lx", rte_rdtsc());

	dp = rte_ring_create(name, JOB_RING_NUM, 0, 0);
	if (unlikely(!dp)) {
		AGIEP_LOG_ERR("pf %d vf %d dma dp ring create error %d",
			      pf, vf, rte_errno);
		goto error;
	}
	dma->id = qdma_dev_id;
	dma->job_cnt = JOB_POOL_NUM;
	dma->pf = pf;
	dma->vf = vf;
	dma->dq = dp;
	dma->ref = 0;
	ret = agiep_dma_job_pool_init(dma);

	if (ret < 0)
		goto error;
	ret = agiep_dma_batch_pool_init(dma);
	if (ret < 0)
		goto error;
	return dma;
error:
	if (dp)
		rte_ring_free(dp);
	if (dma->jpool)
		rte_mempool_free(dma->jpool);
	if (dma->bpool)
		rte_mempool_free(dma->bpool);
	rte_free(dma);
	return NULL;
}

static void agiep_dma_release(struct agiep_dma *dma)
{
	if (!dma)
		return;
	if (dma->GC_cb)
		dma->GC_cb(dma->GC_data);
	agiep_dma_job_pool_free(dma);
	rte_mempool_free(dma->bpool);
	rte_ring_free(dma->dq);
	rte_free(dma);
}

void agiep_dma_free(struct agiep_dma *dma, async_dma_GC_callback cb, void *priv)
{
	if (dma == NULL)
		return;
	dma->GC_cb = cb;
	dma->GC_data = priv;

	if (dma->enqueue_jobs == (uint32_t)(dma->dequeue_jobs +
		sum_array(dma->discard_jobs, RTE_MAX_LCORE))) {
		agiep_dma_release(dma);
		return;
	}

	rte_ring_mp_enqueue(GC_ring, dma);
}

void agiep_dma_free_syn(struct agiep_dma *dma, async_dma_GC_callback cb, void *priv)
{
	struct agiep_dma *dma_dup;
	if (dma == NULL){
		if (cb)
			cb(priv);
		return;
	}
	dma->ref++;
	rte_mb();
	dma->GC_cb = cb;
	dma->GC_data = priv;
	dma_dup = dma;

	if (dma->enqueue_jobs != (dma->dequeue_jobs +
		sum_array(dma->discard_jobs, RTE_MAX_LCORE))) {
		rte_ring_mp_enqueue(GC_ring, dma);
		dma_dup = NULL;
	}

	while (dma->enqueue_jobs != (dma->dequeue_jobs + 
		sum_array(dma->discard_jobs, RTE_MAX_LCORE))) {
		cpu_relax();
	}
	dma->ref--;
	if (dma_dup)
		agiep_dma_release(dma_dup);
	return;
}

void agiep_dma_synchronize(struct agiep_dma *dma)
{
	if (dma == NULL)
		return;
	while (dma->enqueue_jobs != (dma->dequeue_jobs + 
		sum_array(dma->discard_jobs, RTE_MAX_LCORE))) {
		cpu_relax();
	}
}

RTE_INIT(agiep_common_init_log)
{
	agiep_logtype_common = rte_log_register("pmd.common.agiep");
	if (agiep_logtype_common >= 0)
		rte_log_set_level(agiep_logtype_common, RTE_LOG_DEBUG);
}
