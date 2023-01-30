#ifndef RTE_PMD_TOE_DMA_H_
#define RTE_PMD_TOE_DMA_H_

#include <stdint.h>
#include <sys/queue.h>
#include <rte_rawdev.h>
#include <rte_mempool.h>
#include <rte_pmd_dpaa2_qdma.h>
#include <agiep_pci.h>
#include <tcp_stream.h>
#include <toe_engine.h>
#include <toe_dev.h>

/* define DPAA2 qdma API */
#define rte_qdma_vq_destroy(id, qid)                    rte_rawdev_queue_release(id, qid)
#define rte_qdma_stop(id)                               rte_rawdev_stop(id)
#define rte_qdma_info                                   rte_rawdev_info
#define rte_qdma_start(id)                              rte_rawdev_start(id)
#define rte_qdma_reset(id)                              rte_rawdev_reset(id)
#define rte_qdma_configure(id, cf)                      rte_rawdev_configure(id, cf)
#define rte_qdma_dequeue_buffers(id, buf, num, ctxt)    rte_rawdev_dequeue_buffers(id, buf, num, ctxt)
#define rte_qdma_enqueue_buffers(id, buf, num, ctxt)    rte_rawdev_enqueue_buffers(id, buf, num, ctxt)
#define rte_qdma_queue_setup(id, qid, cfg)              rte_rawdev_queue_setup(id, qid, cfg)

#define TOE_JOB_ENQ_NUM 64
#define TOE_JOB_DEQ_NUM 64
#define JOB_POOL_NUM (1024 * 8)
#define DMA_JOB_CACHE_SIZE 64
#define TOE_DMA_JOB_F_TO_PCI  1
#define TOE_DMA_JOB_F_FROM_PCI 2

typedef void (*toe_sync_dma_callback)(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg);
typedef void (*toe_dma_priv_free)(void* paddr);

enum {
	TOE_DMA_READ,
	TOE_DMA_WRITE,
};
struct toe_dma_info {
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
	//struct rte_mempool *bpool;
	struct rte_qdma_job *qjobs;
	//void *GC_data;
	//struct rte_ring *dq;
	//async_dma_GC_callback GC_cb;
	//volatile int ref;
	//TAILQ_ENTRY(toe_dma_info) next;
};

struct toe_sync_dma_job {
	//struct toe_dma_info *t_dma;
	struct rte_qdma_job *job;
	int qid;
  int meb_num;
  void *vaddr; /*local buffer address*/
  void *priv_addr;
  void *cnxt;
  uint64_t extra;
	uint64_t extra2;
	uint64_t extra3;
	uint64_t extra4;
	uint64_t extra5;
	//void *rq_info;
  toe_sync_dma_callback cb;
  toe_dma_priv_free priv_free;
};

struct toe_dma_hwq {
	int enable;
	int lcore_id;
	int id;
	int vq;
	//struct rte_qdma_rbp R_rbp[MAX_PF][MAX_VF];
	//struct rte_qdma_rbp W_rbp[MAX_PF][MAX_VF];
	struct rte_qdma_rbp R_rbp;
	struct rte_qdma_rbp W_rbp;
};

uint64_t toe_irq_addr(struct toe_engine *toe_eg, uint16_t vector);
uint32_t toe_irq_data(struct toe_engine *toe_eg, uint16_t vector);

int toe_rxctl_cq_tail_update(struct toe_ctl_cq_info *ctl_cq, uint16_t pre_tail);
int toe_rxctl_rq_head_update(struct toe_ctl_rq_info *ctl_rq, uint16_t rq_pre_head);
int toe_dma_dequeue(struct toe_engine *toe_eg);
int toe_rx_data_dma_enqueue(struct toe_engine *toe_eg, int idx);
int toe_rx_databuf_dma_enqueue(struct toe_engine *toe_eg, int idx);

int toe_tx_data_dma_enqueue(struct toe_engine *toe_eg, int idx);
void toe_tx_databuf_dma_enqueue(struct toe_engine *toe_eg, int idx);

int toe_dma_init(struct toe_engine *toe_eg);
void toe_dma_fini(void);

int toe_sys_ctl_rq_dma_enqueue(struct toe_engine *toe_eg);
int toe_sys_ctl_cq_dma_enqueue(struct toe_engine *toe_eg);

int toe_ctl_data_rq_dma_enqueue(struct toe_engine *toe_eg, int idx);
int toe_ctl_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx);
void toe_tx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx);

void toe_rxctl_rqcq_update(struct toe_ctl_rq_info *ctl_rq, struct toe_ctl_cq_info *ctl_cq);

int toe_tx_data_buf_send_to_host(struct toe_tx_data_queue *node, struct toe_engine *toe_eg, int qid);

void toe_dma_reset(struct toe_engine *toe_eg);
void toe_rx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx);
struct rte_qdma_job * toe_tx_databuf_to_job(struct rte_mbuf *pkt, uint64_t buf_addr, int len, int final_len, uint64_t host_dataptr, uint64_t host_list_addr, struct toe_engine *toe_eg, int qid, tcp_stream *stream, int stream_mbuf_head);
void toe_tx_data_job_enq(struct rte_qdma_job **jobs, int job_num, struct toe_engine *toe_eg);

#endif
