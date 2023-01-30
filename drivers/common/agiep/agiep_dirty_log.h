#ifndef RTE_AGIEP_DLOG_H_
#define RTE_AGIEP_DLOG_H_

#include <sys/queue.h>
#include <stdint.h>
#include <rte_common.h>
#include <rte_atomic.h>

#include "agiep_dma.h"
#include "agiep_lib.h"

#define AGIEP_PAGE_SIZE 0x1000
#define DIRTYLOG_FLUSH_STOP 0
#define DIRTYLOG_FLUSH_START 1
#define DIRTYLOG_FLUSH_ING 2

struct agiep_dirty_log {
	void* log_base;
	uint64_t log_base_pci;
	uint64_t log_base_phy;
	uint64_t log_size;

	uint16_t loging;
	rte_atomic64_t log_num;
	uint16_t log_flushing;
	struct agiep_dma *dma;
};

struct agiep_dirty_log* agiep_dirty_log_get(int pf, int vf);
struct agiep_dirty_log * agiep_dirty_log_init(struct agiep_dirty_log *dirty_log);
int agiep_dirty_log_enable(int pf, int vf, uint64_t dlog_base, uint64_t dlog_size);
int agiep_dirty_log_disable(int pf, int vf);
int agiep_dirty_log_add(struct agiep_dirty_log *dirty_log, uint64_t addr, uint64_t len);
void agiep_dirty_log_synchronize(struct agiep_dirty_log *dirty_log);
int agiep_dirty_log_release(int pf, int vf);
int agiep_dirty_log_process(struct agiep_dirty_log *dirty_log);
#endif