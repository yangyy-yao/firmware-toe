#include <stdbool.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_malloc.h>

#include "agiep_dirty_log.h"
#include "agiep_logs.h"

static pthread_mutex_t dirty_log_tab_lock = PTHREAD_MUTEX_INITIALIZER;
static struct agiep_dirty_log *dirty_log_tab[MAX_PF][MAX_VF];

int agiep_dirty_log_enable(int pf, int vf, uint64_t log_base_pci, uint64_t log_size)
{
	struct agiep_dirty_log *dirty_log = dirty_log_tab[pf][vf];
	if (dirty_log==NULL)
		return -1;
	dirty_log->log_base = rte_calloc(NULL, 1, log_size, PAGE_SIZE_ALIGN);
	if (dirty_log->log_base == NULL) {
		return -1;
	}
	dirty_log->log_base_pci = log_base_pci;
	dirty_log->log_base_phy = rte_malloc_virt2iova(dirty_log->log_base);
	dirty_log->log_size = log_size;
	dirty_log->loging = 1;
	return 0;
}

static void agiep_dirty_log_flush_done(struct agiep_async_dma_job *job)
{
	struct agiep_dirty_log *dirty_log;
	dirty_log = job->priv;
	rte_atomic64_set(&dirty_log->log_num, 0);
	dirty_log->log_flushing = DIRTYLOG_FLUSH_STOP;
	rte_mempool_put(job->dma->jpool, job);
}

int agiep_dirty_log_disable(int pf, int vf)
{
	struct agiep_dirty_log *dirty_log = dirty_log_tab[pf][vf];
	dirty_log->loging = 0;
	if (rte_atomic64_read(&dirty_log->log_num))
		dirty_log->log_flushing = DIRTYLOG_FLUSH_START;

	while (dirty_log->log_flushing) {
		cpu_relax();
	}
	return 0;
}

static void set_bit(int nr, volatile unsigned char *addr)
{
	*addr |= (1 << nr);
}

static int agiep_dirty_log_write(uint64_t log_base, uint64_t write_address, uint64_t write_length)
{
	uint64_t write_page = write_address / AGIEP_PAGE_SIZE;

	if (!write_length)
		return 0;
	write_length += write_address % AGIEP_PAGE_SIZE;
	for (;;) {
		uint64_t log = log_base + write_page / 8;
		int bit = write_page % 8;
		if ((uint64_t)(unsigned long)log != log)
			return -1;
		set_bit(bit, (unsigned char *)log);
		if (write_length <= AGIEP_PAGE_SIZE)
			break;
		write_length -= AGIEP_PAGE_SIZE;
		write_page += 1;
	}
	return 0;
}

int agiep_dirty_log_add(struct agiep_dirty_log *dirty_log, uint64_t addr, uint64_t len)
{
	agiep_dirty_log_write((uint64_t)dirty_log->log_base, addr, len);
	rte_atomic64_inc(&dirty_log->log_num);
	return 0;
}

__rte_always_inline void
agiep_dirty_log_synchronize(struct agiep_dirty_log *dirty_log)
{
	if (!dirty_log) {
		return;
	}
	while (rte_atomic64_read(&dirty_log->log_num) > 0) {
		cpu_relax();
	}
}
struct agiep_dirty_log * agiep_dirty_log_init(struct agiep_dirty_log *dirty_log)
{
	if (dirty_log == NULL) {
		return NULL;
	}
	dirty_log->loging = 0;
	rte_atomic64_set(&dirty_log->log_num, 0);
	dirty_log->log_flushing = DIRTYLOG_FLUSH_STOP;
	if (dirty_log->log_base) {
		rte_free(dirty_log->log_base);
		dirty_log->log_base = NULL;
	}
	return dirty_log;
}

struct agiep_dirty_log * agiep_dirty_log_get(int pf, int vf)
{
	struct agiep_dirty_log *dirty_log;
	struct agiep_dma *dma;
	pthread_mutex_lock(&dirty_log_tab_lock);
	dirty_log = dirty_log_tab[pf][vf];
	if (!dirty_log) {
		dirty_log = rte_calloc(NULL, 1, sizeof(struct agiep_dirty_log), RTE_CACHE_LINE_SIZE);
		if (dirty_log == NULL) {
			AGIEP_LOG_ERR("dirty log create error %d %d", pf, vf);
			goto error;
		}
		rte_atomic64_init(&dirty_log->log_num);
		dma = agiep_dma_create(pf, vf);
		if (dma == NULL) {
			RTE_LOG(ERR, PMD, "dirty log dma create fail\n");
			goto error;
		}
		dirty_log->dma = dma;
		dirty_log_tab[pf][vf] = dirty_log;
	}
	pthread_mutex_unlock(&dirty_log_tab_lock);
	return dirty_log;
error:
	pthread_mutex_unlock(&dirty_log_tab_lock);
	if (dirty_log)
		rte_free(dirty_log);
	if (dma)
		agiep_dma_free_syn(dma, NULL, NULL);
	return NULL;
}

int agiep_dirty_log_release(int pf, int vf)
{
	struct agiep_dirty_log *dirty_log;
	dirty_log = dirty_log_tab[pf][vf];
	if (dirty_log) {
		agiep_dirty_log_synchronize(dirty_log);
		if (dirty_log->dma) {
			agiep_dma_free_syn(dirty_log->dma, NULL, NULL);
			dirty_log->dma = NULL;
		}
		if (dirty_log->log_base) {
			rte_free(dirty_log->log_base);
			dirty_log->log_base = NULL;
		}
		dirty_log_tab[pf][vf] = NULL;
		rte_free(dirty_log);
	}
	return 0;
}

static void agiep_dirty_log_dma_process(struct agiep_dirty_log *dirty_log)
{
	struct agiep_async_dma_job *jobs[4096];
	struct agiep_async_dma_job *job;
	int ret;
	int i;
	if (unlikely(!dirty_log->dma))
		return;
	do {
		ret = agiep_dma_dequeue_buffers(dirty_log->dma, jobs, 4096);
		for (i = 0; i < ret; i++) {
			job = jobs[i];
			if (job->cb)
				job->cb(job);
		}
	} while(ret);
}

int agiep_dirty_log_process(struct agiep_dirty_log *dirty_log)
{
	struct agiep_async_dma_job *job;

	agiep_dirty_log_dma_process(dirty_log);
	if (dirty_log->log_flushing == DIRTYLOG_FLUSH_ING)
		return 0;

	if (rte_atomic64_read(&dirty_log->log_num) == 0)
		return 0;
	dirty_log->log_flushing = DIRTYLOG_FLUSH_ING;
	if (unlikely(rte_mempool_get(dirty_log->dma->jpool, (void **) &job))) {
		AGIEP_LOG_INFO("agiep dirty log job get failed");
		dirty_log->log_flushing = DIRTYLOG_FLUSH_STOP;
		return -1;
	}
	job->src = dirty_log->log_base_phy;
	job->dst = dirty_log->log_base_pci;
	job->len = dirty_log->log_size;
	job->cb = (void *) agiep_dirty_log_flush_done;
	job->priv = dirty_log;
	job->flags = DMA_JOB_F_TO_PCI;

	if (unlikely(agiep_dma_enqueue_buffers(dirty_log->dma, &job, 1, DMA_JOB_F_TO_PCI) != 1)) {
		AGIEP_LOG_INFO("agiep dirty log job enqueue failed");
		dirty_log->log_flushing = DIRTYLOG_FLUSH_STOP;
		return -1;
	}
	return 0;
}