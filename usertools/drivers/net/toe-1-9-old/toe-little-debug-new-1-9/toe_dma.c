
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include <rte_net.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_pmd_dpaa2_qdma.h>
#include <rte_rawdev.h>
#include <rte_mempool.h>
#include <rte_io_64.h>

#include <../../../lib/librte_tcpstack/mtcp.h>
#include <tcp_out.h>
#include <agiep_pci.h>

//#include "toe_dev.h"
//#include "toe_engine.h"
#include <toe_pcie.h>
#include <toe_dma.h>
#include <tcp_in.h>

#define TOE_QDMA_MAX_HW_QUEUES_PER_CORE      2
#define TOE_QDMA_FLE_POOL_QUEUE_COUNT        4096
#define TOE_QDMA_MAX_VQS                     2048

static int tqdma_dev_id = 0;
static struct toe_dma_hwq tdma_hwq[RTE_MAX_LCORE];
static pthread_t TOE_CTRL_thread;
static pthread_t TOE_DATA_CQ_thread;

extern uint64_t loop_count;

extern uint64_t timestamp[LOG_NUM + 1];
char timestamp_str[LOG_NUM + 1][40];

extern uint16_t log_count;

__rte_always_inline uint64_t toe_irq_addr(struct toe_engine *toe_eg, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;

	if (toe_eg->irq_addr[vector] == NULL)
		toe_eg->irq_addr[vector] = (void *)pci_ep_get_irq_addr(toe_eg->ep,
				toe_eg->pf, toe_eg->vf, irq_type, vector);
	return (uint64_t)toe_eg->irq_addr[vector];
}

__rte_always_inline uint32_t toe_irq_data(struct toe_engine *toe_eg, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;
	if (toe_eg->irq_data[vector] == 0xFFFFFFFF) {
		toe_eg->irq_data[vector] = pci_ep_get_irq_data(toe_eg->ep, 
				toe_eg->pf, toe_eg->vf, irq_type, vector);
	}
	return toe_eg->irq_data[vector];
}

__rte_always_inline static void toe_irq_raise(struct toe_engine *toe_eg, uint16_t vector)
{
	uint64_t addr = toe_irq_addr(toe_eg, vector);
	uint32_t data = toe_irq_data(toe_eg, vector);
	if (addr == 0)
		return;
	rte_write32(data, (void *)addr);
}

static uint64_t toe_addr32_to_addr64(uint32_t hi, uint32_t lo)
{
	uint64_t addr;

	addr = hi;
	addr = lo | addr << 32;
	return addr;
}

static int toe_host_buffer_insert(tcp_stream *stream, struct toe_data_host_to_dpu_req *data_msg, int m_num)
{
	struct tcp_prepare_read *node;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int rc;
	if (stream->sndvar->pre_read_list.head != NULL) {
		rc = rte_mempool_get(mtcp->hostbuf_pool, (void **)&node);
		if (unlikely(rc != 0)) {
			RTE_LOG(ERR, PMD, "%s-%d: tcp prepare nod get failed! \n", __func__, __LINE__);
      return -1;
		}
		node->host_buffer_phyaddr = data_msg->send_buffer_addr;
		node->host_buffer_viraddr = data_msg->send_list_addr;
		node->len = data_msg->data_len;
		stream->sndvar->pre_read_list.tail->next = node;
		stream->sndvar->pre_read_list.tail = node;
		return 1;
	}

	if (stream->sndvar->snd_wnd < data_msg->data_len
		|| stream->sndvar->tcp_data_ring.free_num < m_num) {
		rc = rte_mempool_get(mtcp->hostbuf_pool, (void **)&node);
		if (unlikely(rc != 0)) {
			RTE_LOG(ERR, PMD, "%s-%d: tcp prepare nod get failed! \n", __func__, __LINE__);
			return -1;
		}
		
		node->host_buffer_phyaddr = data_msg->send_buffer_addr;
		node->host_buffer_viraddr = data_msg->send_list_addr;
		node->len = data_msg->data_len;
		stream->sndvar->pre_read_list.head = node;
		stream->sndvar->pre_read_list.tail = node;
		
		return 1;
	}

	return 0;
}

void toe_prepare_list_remove_head(struct tcp_prepare_read_list *list, struct tcp_prepare_read *read_head)
{
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	
	list->head = read_head->next;
	read_head->next = NULL;

	if (read_head == list->tail)
		list->tail = NULL;

	rte_mempool_put(mtcp->hostbuf_pool, read_head);
}

int toe_dma_dequeue(struct toe_engine *toe_eg)
{
	struct toe_dma_hwq *hwq;
	struct rte_qdma_enqdeq e_context;
	struct rte_qdma_job *jobs[TOE_JOB_DEQ_NUM];
	struct toe_sync_dma_job *sync_job;
	struct toe_dma_info *dma = toe_eg->t_dma;
	int nb, i;
	
	hwq = &tdma_hwq[rte_lcore_id()];

	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	nb = rte_qdma_dequeue_buffers(hwq->id, NULL, TOE_JOB_DEQ_NUM, &e_context);

	if (!nb)
		return 0;
	
	for (i = 0; i < nb; i++) {
		sync_job = (struct toe_sync_dma_job *) jobs[i]->cnxt;

		if (sync_job->cb)
			sync_job->cb(sync_job, toe_eg);
		else
			rte_mempool_put(dma->jpool, sync_job);
	}
    
	return nb;
}

static int toe_dma_enqueue(struct toe_dma_info *dma, int dir, uint16_t tail, uint16_t *local_head, 
										uint16_t q_size, uint64_t q_phy_base_addr, uint16_t offset_base, 
										char *q_local_base_addr, int idx, toe_sync_dma_callback fun)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;
	
	nb_meb[0] = tail - *local_head;
	if (!nb_meb[0])
		return 0;
	
	nb_meb[1] = 0;
	head[0] = *local_head;
	head[1] = 0;

	if (nb_meb[0] < 0) {
		nb_meb[0] = q_size - *local_head;
		nb_meb[1] = tail;
	
		num_jobs = 2;
	}
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	if (dir == TOE_DMA_READ)
		rbp = &hwq->R_rbp;
	else
		rbp = &hwq->W_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = fun;
		sjob[i]->qid = idx;

		if (dir == TOE_DMA_READ) {
			src_addr = q_phy_base_addr + head[i] * offset_base;
		
			dst_addr = (uint64_t)(q_local_base_addr + offset_base * head[i]);
			sjob[i]->vaddr = (void *)dst_addr;
			dst_addr = rte_mem_virt2iova((void *)dst_addr);
		} else {
			src_addr = (uint64_t)(q_local_base_addr + offset_base * head[i]);
			dst_addr = q_phy_base_addr + head[i] * offset_base;
			sjob[i]->vaddr = (void *)src_addr;
			src_addr = rte_mem_virt2iova((void *)src_addr);
		}
		
		job_len = nb_meb[i] * offset_base;

		sjob[i]->job->cnxt = (uint64_t) sjob[i];
		sjob[i]->job->src = src_addr;
		sjob[i]->job->dest = dst_addr;
		sjob[i]->job->len = job_len;
		sjob[i]->job->rbp = rbp;

		jobs[i] = sjob[i]->job;
	}
	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL,  num_jobs, &e_context);
	if (unlikely(ret < num_jobs)) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		*local_head = (*local_head + nb_meb[i]) % q_size;
	
	return ret;

}

static void toe_sys_ctl_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int i, meb_num = sjob->meb_num;
	void *vaddr;
	uint64_t srcaddr = 0;
	struct toe_sys_ctl_rq_info *ctl_rq = &toe_eg->sys_ctl_vring->rq_info;
	
	for (i = 0; i < meb_num; i++) {
			vaddr = (char *)sjob->vaddr + i * TOE_SYS_CTRL_RQ_MSG_SIZE;
			ctl_rq->pre_head = (ctl_rq->pre_head + 1) % ctl_rq->rq_size;
			toe_sys_ctl_recv(vaddr, toe_eg);
	}
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

int toe_sys_ctl_rq_dma_enqueue(struct toe_engine *toe_eg)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sys_ctl_rq_info *ctl_rq = &toe_eg->sys_ctl_vring->rq_info;
	uint64_t rq_phy_base_addr;
	int ret;
	
	if (likely (*ctl_rq->tail == ctl_rq->local_head)) {
		return 0;
	}

	rq_phy_base_addr = toe_addr32_to_addr64(ctl_rq->rbc->queue_desc_h, ctl_rq->rbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_READ, *ctl_rq->tail, &ctl_rq->local_head, ctl_rq->rq_size, rq_phy_base_addr, TOE_SYS_CTRL_RQ_MSG_SIZE, (char *)ctl_rq->rq_local, -1, toe_sys_ctl_dma_process);
	return ret;
}

static void toe_sys_ctl_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	if (toe_eg->sys_ctl_vring->cq_info.cbc->msi_switch == 1)
		toe_irq_raise(toe_eg, toe_eg->sys_ctl_vring->cq_info.cbc->msi_vector);
	return;
}

int toe_sys_ctl_cq_dma_enqueue(struct toe_engine *toe_eg)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sys_ctl_cq_info *ctl_cq = &toe_eg->sys_ctl_vring->cq_info;
	uint64_t cq_phy_base_addr;
	int ret;
	
	if (likely (ctl_cq->tail == ctl_cq->pre_head)) {
		return 0;
	}

	cq_phy_base_addr = toe_addr32_to_addr64(ctl_cq->cbc->queue_desc_h, ctl_cq->cbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_WRITE, ctl_cq->tail, &ctl_cq->pre_head, ctl_cq->cq_size, cq_phy_base_addr, 
					TOE_SYS_CTRL_CQ_MSG_SIZE, (char *)ctl_cq->cq_local, -1, toe_sys_ctl_reply_dma_process);
	return ret;
}

static void toe_ctl_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int i, meb_num = sjob->meb_num;
	void *vaddr;
	int qid = sjob->qid;
	uint64_t srcaddr = 0;
	struct toe_ctl_rq_info *ctl_rq = &toe_eg->ctl_rx_vring[qid]->rq_info;
	
	for (i = 0; i < meb_num; i++) {
			vaddr = (char *)sjob->vaddr + i * TOE_CTRL_RQ_MSG_SIZE;
			srcaddr = sjob->job->src + i * TOE_CTRL_RQ_MSG_SIZE;
	
			toe_ctl_recv(vaddr, toe_eg, qid);
			ctl_rq->pre_head = (ctl_rq->pre_head + 1) % ctl_rq->rq_size;
	}
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);

	return;
}

int toe_ctl_data_rq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_ctl_rq_info *ctl_rq = &toe_eg->ctl_rx_vring[idx]->rq_info;
	uint64_t rq_phy_base_addr;
	int ret;

	if (likely(*ctl_rq->tail == ctl_rq->local_head)) {
		return 0;
	}

	printf("!! %s-%d: doorbell:%u, now:%lu\n",__func__,__LINE__,*ctl_rq->tail, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "ctrl-rq-enq-start"); 
				log_count ++;
			} 
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
		
	rq_phy_base_addr = toe_addr32_to_addr64(ctl_rq->rbc->queue_desc_h, ctl_rq->rbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_READ, *ctl_rq->tail, &ctl_rq->local_head, ctl_rq->rq_size, rq_phy_base_addr, 
					TOE_CTRL_RQ_MSG_SIZE, (char *)ctl_rq->rq_local, idx, toe_ctl_data_dma_process);
/*
	if (ret > 0) {
	//printf("!! %s-%d:  now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "ctrl-rq-enq-end"); 
				log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	}
*/
	return ret;
}

static void toe_ctl_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int qid = sjob->qid;

	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	if (toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_switch == 1)
		toe_irq_raise(toe_eg, toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector);
	printf("##$$ %s-%d: msi_vector:%d, qid:%d,now:%lu\n",__func__,__LINE__,toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector,qid,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (TOE_LOG_ON) {
		if (log_count < LOG_NUM) {
					timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
			sprintf(timestamp_str[log_count], "ctrl-irq-%s",(toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_switch==1)?"on":"off"); 
					log_count ++;
		}
		else {
			timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
			sprintf(timestamp_str[log_count], "log restart");
			log_count = 0;	
		}
	}

	return;
}

int toe_ctl_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_ctl_cq_info *ctl_cq = &toe_eg->ctl_rx_vring[idx]->cq_info;
	uint64_t cq_phy_base_addr;
	int ret;

	if (likely(ctl_cq->tail == ctl_cq->pre_head)) {
		return 0;
	}

		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "ctrl-cq-enq-start"); 
				log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}

	cq_phy_base_addr = toe_addr32_to_addr64(ctl_cq->cbc->queue_desc_h, ctl_cq->cbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_WRITE, ctl_cq->tail, &ctl_cq->pre_head, ctl_cq->cq_size, cq_phy_base_addr, 
					TOE_CTRL_CQ_MSG_SIZE, (char *)ctl_cq->cq_local, idx, toe_ctl_reply_dma_process);
	if (ret > 0) {
	//printf("!! %s-%d:now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "ctrl-cq-enq-end"); 
				log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	}
	return ret;
}

static void toe_rx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	//struct toe_data_host_to_dpu_req *data_msg = (struct toe_data_host_to_dpu_req *)sjob->cnxt;
	struct toe_data_host_to_dpu_res *cq_msg;
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[sjob->qid]->cq_info;
	struct toe_data_rx_rq_info *rq_info = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
#ifdef TOE_TSO
	struct rte_mbuf **buff;
#endif
	tcp_stream *stream = (tcp_stream *)sjob->priv_addr;
	int qid = sjob->qid;
	
	if (!sjob->meb_num)
		goto done;

	stream->ref_count --;

#ifdef TOE_TSO
	buff = sjob->vaddr;
	stream->sndvar->tcp_data_ring.m[stream->sndvar->tcp_data_ring.tail] = buff[0];
	stream->sndvar->tcp_data_ring.mbuf_data_len[stream->sndvar->tcp_data_ring.tail] = buff[0]->pkt_len;
	rte_mempool_put(toe_eg->data_rx_vring[sjob->qid]->mbuf_save_pool, buff);
#endif

	stream->sndvar->tcp_data_ring.tail = (stream->sndvar->tcp_data_ring.tail + sjob->meb_num) % TCP_SEND_DATA_BUFFER_MAX_NUM;
/*
  if (toe_sendbuf_update(stream, data_msg->data_len) < 0) {
		printf("%s-%d: sendbuf update failed\n");
		return;
	}
	*/
	toe_tcp_datapkt_send(stream, toe_eg, qid);
	/*
	cq_info->head = cq_info->cbc->doorbell;
	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == cq_info->head)) {
		printf("%s-%d: cq full\n",__func__, __LINE__);
		return;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->compl = cq_info->cq_compl;
	cq_msg->rq_head = sjob->extra;
	cq_msg->send_list_virtaddr = data_msg->send_list_addr;
	cq_msg->sent_len = sjob->extra2;
	cq_msg->identification.host_dataptr = data_msg->identification.host_dataptr;
	cq_msg->identification.card_stream_addr = (uint64_t)stream;

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
*/
	done:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

static void toe_prepare_buffer_fill_cq_msg(struct toe_data_rx_rq_info *data_rq, uint16_t len, uint8_t result, struct toe_engine *toe_eg, struct tcp_prepare_read *node, int qid)
{
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[qid]->cq_info;
	struct toe_data_host_to_dpu_res *cq_msg;
	uint16_t cq_rq_head;

	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == *cq_info->head)) {
		printf("%s-%d: cq full\n",__func__, __LINE__);
		return;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->compl = cq_info->cq_compl;
	cq_msg->result = result;
	if (data_rq->head == 0)
		cq_rq_head = data_rq->rq_size;
	else
		cq_rq_head = data_rq->head - 1;
	cq_msg->rq_head = cq_rq_head;
	cq_msg->send_list_virtaddr = node->host_buffer_viraddr;
	cq_msg->sent_len = len;

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

}

int toe_prepare_host_buffer_enqueue(struct toe_engine *toe_eg, tcp_stream *stream, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_sync_dma_job *sjob[TOE_JOB_ENQ_NUM];
	struct rte_qdma_job *jobs[TOE_JOB_ENQ_NUM];
	struct rte_qdma_enqdeq e_context;
	struct tcp_prepare_read *read_head;
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[idx]->rq_info;
	struct toe_rx_queue *data_q = toe_eg->t_dev->data_rxq[idx];
	struct rte_mbuf **mbufs = NULL, **mbufs2 = NULL, *pre_mbuf, *head_mbuf, *d_mbuf;
	uint16_t m_num, m_final_num, m_final_num2, count = 0, en_num = 0;
	uint16_t *mbuf_data_len, *mbuf_data_len2, *m_data_len;
	uint32_t data_len, job_len, en_len = 0;
	uint64_t src_addr, dst_addr;
	int i, allow_data_len, ret;

	read_head = stream->sndvar->pre_read_list.head;
	if (!read_head)
		return 0;
	
	if (!stream->sndvar->tcp_data_ring.free_num || !stream->sndvar->snd_wnd) {
		return 0;
	}
#ifdef TOE_TSO
	data_len = RTE_MBUF_DEFAULT_DATAROOM;
#else 
	data_len = stream->sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
#endif
	hwq = &tdma_hwq[rte_lcore_id()];
	rbp = &hwq->R_rbp;

	while (read_head) {
		allow_data_len = RTE_MIN(read_head->len, stream->sndvar->snd_wnd);
		m_num = allow_data_len / data_len;
		m_num += (allow_data_len % data_len) ? 1 : 0;

		m_num = RTE_MIN(stream->sndvar->tcp_data_ring.free_num, m_num);
		
		if (m_num > TOE_JOB_ENQ_NUM) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf too more!\n", __func__, __LINE__);
			goto err;
		}	

		m_final_num = 0;
		m_final_num2 = 0;

#ifdef TOE_TSO
		m_final_num = 1;
		if (unlikely(rte_mempool_get(toe_eg->data_rx_vring[idx]->mbuf_save_pool, (void **)&mbufs)))
			goto err;

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}
#else

		m_final_num = m_num;
		mbufs = &stream->sndvar->tcp_data_ring.m[stream->sndvar->tcp_data_ring.prev_tail];
		mbuf_data_len = &stream->sndvar->tcp_data_ring.mbuf_data_len[stream->sndvar->tcp_data_ring.prev_tail];

		if (stream->sndvar->tcp_data_ring.prev_tail >= stream->sndvar->tcp_data_ring.una_head) {
			if (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail < m_final_num) {
				mbufs2 = &stream->sndvar->tcp_data_ring.m[0];
				mbuf_data_len2 = &stream->sndvar->tcp_data_ring.mbuf_data_len[0];
			
				m_final_num2 = m_final_num - (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail);
				m_final_num = TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail;
			}
		}

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_final_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}

		if (mbufs2) {
			if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs2, m_final_num2))) {
				RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
				goto err;
			}

		}
#endif
		if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **)sjob, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: sjob alloc failed!\n", __func__, __LINE__);
			goto err;
		}

		en_len = 0;
		pre_mbuf = NULL;
		head_mbuf = mbufs[0];
		for (i = 0; i < m_num; i++) {
#ifdef TOE_TSO
			d_mbuf = mbufs[i];
#else
			if (i < m_final_num) {
				d_mbuf = mbufs[i];
				m_data_len = &mbuf_data_len[i];
			} else {
				d_mbuf = mbufs2[i - m_final_num];
				m_data_len = &mbuf_data_len2[i - m_final_num];
			}
#endif
			sjob[i]->meb_num = 0;
			sjob[i]->cb = NULL;
			sjob[i]->qid = idx;
			sjob[i]->priv_addr = (void *)d_mbuf;
			sjob[i]->vaddr = NULL;
			sjob[i]->cnxt = NULL;

						
			src_addr = read_head->host_buffer_phyaddr + en_len;
			dst_addr = rte_pktmbuf_iova(d_mbuf);
			job_len = RTE_MIN(allow_data_len - en_len, data_len);
			sjob[i]->job->cnxt = (uint64_t)sjob[i];
			sjob[i]->job->src = src_addr;
			sjob[i]->job->dest = dst_addr;
			sjob[i]->job->len = job_len;
			sjob[i]->job->rbp = rbp;

			jobs[count] = sjob[i]->job;
			
			en_len += job_len;
			count ++;
			d_mbuf->data_len = job_len;
			d_mbuf->pkt_len = job_len;
			d_mbuf->next = NULL;
			d_mbuf->nb_segs = 1;	
			*m_data_len = job_len;
			
#ifdef TOE_TSO
			if (pre_mbuf) {
				pre_mbuf->next = d_mbuf;
				head_mbuf->nb_segs ++;
			}
			pre_mbuf = d_mbuf;		
			head_mbuf->pkt_len = en_len;
#endif

			if (i == m_num - 1) {
				sjob[i]->meb_num = m_final_num + m_final_num2;
				sjob[i]->cb = toe_rx_databuf_dma_process;
				//sjob[i]->cnxt = (void *)data_msg;
				sjob[i]->vaddr = (void *)mbufs;
				sjob[i]->priv_addr = (void *)stream;
				//sjob[i]->extra = data_rq->head;
				//sjob[i]->extra2 = en_len;				
			}
			if (count == TOE_JOB_ENQ_NUM) {
				e_context.vq_id = hwq->vq;
				e_context.job = jobs;
				ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
				en_num += ret;
				if (unlikely(ret < TOE_JOB_ENQ_NUM)) {
					printf("%s-%d:qdma enqueue failed!! ret:%d\n",__func__,__LINE__,ret);		
					goto done;
				}
				count = 0;
			}
		}
		stream->ref_count ++;

		toe_sendbuf_update(stream, en_len);
		if (en_len >= read_head->len) {
			toe_prepare_buffer_fill_cq_msg(data_rq, en_len, TOE_DMA_SUCCESS, toe_eg, read_head, idx);
			toe_prepare_list_remove_head(&stream->sndvar->pre_read_list, read_head);
		} else {
				read_head->host_buffer_phyaddr += en_len;
				read_head->len -= en_len;
		}
		stream->sndvar->tcp_data_ring.prev_tail = (stream->sndvar->tcp_data_ring.prev_tail + m_num) % TCP_SEND_DATA_BUFFER_MAX_NUM;
		stream->sndvar->tcp_data_ring.free_num -= m_num;
		if (stream->sndvar->snd_wnd == 0)
			break;

		read_head = stream->sndvar->pre_read_list.head;
	}
	
	if (count > 0) {
		e_context.vq_id = hwq->vq;
		e_context.job = jobs;
		ret = rte_qdma_enqueue_buffers(dma->id, NULL,  count, &e_context);
		en_num += ret;
		if (ret < count) {
			goto done;
		}
	}

done:
	if (unlikely(ret < count)) { //这个地方不对，应该判断 en_num < count,但要释放之前的sjob和mbuf
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], count - ret);
	
		printf("%s-%d: free mbuf bulk: %p, n:%d,dont should\n",__func__,__LINE__,mbufs[en_num], m_num - en_num);
		rte_pktmbuf_free_bulk(&mbufs[en_num], m_num - en_num);//这不对，上一个循环m_num未达到64情况时，无法释放，内存泄露
	}
	return en_num;

err:
#ifdef TOE_TSO
	if (mbufs) {
		if (m_num > 0)
			rte_pktmbuf_free_bulk(mbufs, m_num);
		rte_free(mbufs);
	}
#else
	if (mbufs) {
		if (m_final_num > 0)
			rte_pktmbuf_free_bulk(mbufs, m_final_num);
	}
	if (mbufs2) {
		if (m_final_num2 > 0)
			rte_pktmbuf_free_bulk(mbufs2, m_final_num2);
	}
#endif
	return en_num;
}

static void toe_rx_data_fill_cq_msg(struct toe_data_rx_rq_info *data_rq, uint16_t len, uint8_t result, struct toe_engine *toe_eg, struct toe_data_host_to_dpu_req *rq_msg, void *stream, int qid)
{
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[qid]->cq_info;
	struct toe_data_host_to_dpu_res *cq_msg;
	uint16_t cq_rq_head;

	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == *cq_info->head)) {
		printf("%s-%d: cq full\n",__func__, __LINE__);
		return;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->compl = cq_info->cq_compl;
	cq_msg->result = result;

	if (data_rq->head == 0)
		cq_rq_head = data_rq->rq_size;
	else
		cq_rq_head = data_rq->head - 1;
	cq_msg->rq_head = cq_rq_head;
	cq_msg->send_list_virtaddr = rq_msg->send_list_addr;
	if (!len) {
		cq_msg->send_list_virtaddr = 0;
	}
	cq_msg->sent_len = len;
	cq_msg->identification.host_dataptr = rq_msg->identification.host_dataptr;
	cq_msg->identification.card_stream_addr = (uint64_t)stream;

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

}

int toe_rx_databuf_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_data_host_to_dpu_req *data_msg;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[idx]->rq_info;
	struct toe_sync_dma_job *sjob[TOE_JOB_ENQ_NUM];
	struct rte_qdma_job *jobs[TOE_JOB_ENQ_NUM];
	struct rte_qdma_enqdeq e_context;
	struct toe_rx_queue *data_q = toe_eg->t_dev->data_rxq[idx];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	int i, j,num, m_num = 0, m_final_num = 0, m_final_num2 = 0, en_num = 0, count = 0, ret = 0;
	//char *data_buf;
	tcp_stream *stream;
	uint32_t data_len;
	struct rte_mbuf **mbufs = NULL;
	struct rte_mbuf **mbufs2 = NULL;
	struct rte_mbuf *d_mbuf;
	struct rte_mbuf *pre_mbuf;
	struct rte_mbuf *head_mbuf;
	uint16_t *mbuf_data_len;
	uint16_t *mbuf_data_len2;
	uint16_t *m_data_len;
	uint64_t src_addr, dst_addr;
	uint32_t job_len, en_len = 0;
	uint32_t lcore_id;
	int allow_data_len;

	  //printf("%s-%d: data_rq->real_tail:%d, data_rq->head:%d,  Doorbell:%u,loop_count:%llu,now:%llu \n", __func__, __LINE__, data_rq->real_tail,data_rq->head, data_rq->rbc->doorbell,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (TOE_LOG_ON) {

		if (log_count < LOG_NUM) {
						timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
						sprintf(timestamp_str[log_count], "channel2-databuf-enq"); 
						log_count ++;
		}
		else {
			timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
			sprintf(timestamp_str[log_count], "log restart");
			log_count = 0;	
		}
	}

	num = data_rq->real_tail - data_rq->head;
	if (unlikely(num == 0))
		return 0;
	if (num < 0)
		num += data_rq->rq_size;

	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->R_rbp;

	for (j = 0; j < num; j++) {
		data_msg = data_rq->rq_local + data_rq->head;

		stream = (tcp_stream*)data_msg->identification.card_stream_addr;

		if (!stream->sndvar->sndbuf) {
			if (toe_sendbuf_create(stream) < 0) {
				goto err;
			}
		}
		
#ifdef TOE_TSO
		data_len = RTE_MBUF_DEFAULT_DATAROOM;
#else 
		data_len = stream->sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
#endif

		//allow_data_len = RTE_MIN(data_msg->data_len, stream->sndvar->snd_wnd);
		allow_data_len = data_msg->data_len;
		m_num = allow_data_len / data_len;
		m_num += (allow_data_len % data_len) ? 1 : 0;
		
		if (unlikely(m_num > TOE_JOB_ENQ_NUM)) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf too more!\n", __func__, __LINE__);
			goto err;
		}	

		m_final_num = 0;
		m_final_num2 = 0;

#ifdef TOE_TSO
		m_final_num = 1;
		if (unlikely(rte_mempool_get(toe_eg->data_rx_vring[idx]->mbuf_save_pool, (void **)&mbufs)))
			goto err;

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}
#else

		ret = toe_host_buffer_insert(stream, data_msg, m_num);
		if (ret > 0) {
			RTE_LOG(ERR, PMD, "%s-%d: host buffer insert list! snd_wnd:%u stream->sndvar->tcp_data_ring.free_num:%d,m_num:%d\n", __func__, __LINE__,stream->sndvar->snd_wnd,stream->sndvar->tcp_data_ring.free_num,m_num);
	
			toe_rx_data_fill_cq_msg(data_rq, 0, TOE_DMA_PENDING, toe_eg, data_msg, stream, idx);	
			data_rq->head = (data_rq->head + 1) % data_rq->rq_size;
			m_num = 0;
			continue;
		}

		if (unlikely(ret < 0)) {
			goto err;
		}

		m_final_num = m_num;
		mbufs = &stream->sndvar->tcp_data_ring.m[stream->sndvar->tcp_data_ring.prev_tail];
		mbuf_data_len = &stream->sndvar->tcp_data_ring.mbuf_data_len[stream->sndvar->tcp_data_ring.prev_tail];

		if (stream->sndvar->tcp_data_ring.prev_tail >= stream->sndvar->tcp_data_ring.una_head) {
			if (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail < m_final_num) {
				mbufs2 = &stream->sndvar->tcp_data_ring.m[0];
				mbuf_data_len2 = &stream->sndvar->tcp_data_ring.mbuf_data_len[0];
			
				m_final_num2 = m_final_num - (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail);
				m_final_num = TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.prev_tail;
			}
		}

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_final_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}

		if (mbufs2) {
			if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs2, m_final_num2))) {
				RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
				goto err;
			}

		}
#endif

		if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: sjob alloc failed!\n", __func__, __LINE__);
			goto err;
		}

		en_len = 0;
		pre_mbuf = NULL;
		head_mbuf = mbufs[0];
		for (i = 0; i < m_num; i++) {
#ifdef TOE_TSO
			d_mbuf = mbufs[i];
#else
			if (i < m_final_num) {
				d_mbuf = mbufs[i];
				m_data_len = &mbuf_data_len[i];
			} else {
				d_mbuf = mbufs2[i - m_final_num];
				m_data_len = &mbuf_data_len2[i - m_final_num];
			}
#endif
			sjob[i]->meb_num = 0;
			sjob[i]->cb = NULL;
			sjob[i]->qid = idx;
			sjob[i]->priv_addr = (void *)d_mbuf;
			sjob[i]->vaddr = NULL;
			sjob[i]->cnxt = NULL;

						
			src_addr = data_msg->send_buffer_addr + en_len;
			//dst_addr = rte_mem_virt2iova((void *)data_buf);
			dst_addr = rte_pktmbuf_iova(d_mbuf);
			job_len = RTE_MIN(allow_data_len - en_len, data_len);
			sjob[i]->job->cnxt = (uint64_t)sjob[i];
			sjob[i]->job->src = src_addr;
			sjob[i]->job->dest = dst_addr;
			sjob[i]->job->len = job_len;
			sjob[i]->job->rbp = rbp;

			jobs[count] = sjob[i]->job;
			
			en_len += job_len;
			count ++;
			d_mbuf->data_len = job_len;
			d_mbuf->pkt_len = job_len;
			d_mbuf->next = NULL;
			d_mbuf->nb_segs = 1;	
			*m_data_len = job_len;
			
#ifdef TOE_TSO
			if (pre_mbuf) {
				pre_mbuf->next = d_mbuf;
				head_mbuf->nb_segs ++;
			}
			pre_mbuf = d_mbuf;		
			head_mbuf->pkt_len = en_len;
#endif

			if (i == m_num - 1) {
				sjob[i]->meb_num = m_final_num + m_final_num2;
				sjob[i]->cb = toe_rx_databuf_dma_process;
				//sjob[i]->cnxt = (void *)data_msg;
				sjob[i]->vaddr = (void *)mbufs;
				sjob[i]->priv_addr = (void *)stream;
				//sjob[i]->extra = data_rq->head;
				//sjob[i]->extra2 = en_len;
			}
			if (count == TOE_JOB_ENQ_NUM) {
				e_context.vq_id = hwq->vq;
				e_context.job = jobs;
				ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
				//__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
				en_num += ret;
				if (unlikely(ret < TOE_JOB_ENQ_NUM)) {
					printf("%s-%d:qdma enqueue failed!! ret:%d\n",__func__,__LINE__,ret);
					goto done;
				}
				count = 0;
			}
		}
		stream->ref_count ++;
		
		toe_rx_data_fill_cq_msg(data_rq, en_len, TOE_DMA_SUCCESS, toe_eg, data_msg, stream, idx);
		data_rq->head = (data_rq->head + 1) % data_rq->rq_size; //默认dma全部成功
		toe_sendbuf_update(stream, en_len);
		stream->sndvar->tcp_data_ring.prev_tail = (stream->sndvar->tcp_data_ring.prev_tail + m_num) % TCP_SEND_DATA_BUFFER_MAX_NUM;
		stream->sndvar->tcp_data_ring.free_num -= m_num;
	}

	if (count > 0) {
		e_context.vq_id = hwq->vq;
		e_context.job = jobs;
		ret = rte_qdma_enqueue_buffers(dma->id, NULL,  count, &e_context);
		en_num += ret;
		if (ret < count) {
			goto done;
		}
	}

	done:
	if (unlikely(en_num < m_num )) { //这个地方不对，应该判断 en_num < count,但要释放之前的sjob和mbuf
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[en_num], m_num - en_num);
	
		printf("%s-%d: free mbuf bulk: %p, n:%d,dont should\n",__func__,__LINE__,mbufs[en_num], m_num - en_num);
		rte_pktmbuf_free_bulk(&mbufs[en_num], m_num - en_num);
	}
	return en_num;

	err:
#ifdef TOE_TSO
	if (mbufs) {
		if (m_num > 0)
			rte_pktmbuf_free_bulk(mbufs, m_num);
		rte_free(mbufs);
	}
#else
	if (mbufs) {
		if (m_final_num > 0)
			rte_pktmbuf_free_bulk(mbufs, m_final_num);
	}
	if (mbufs2) {
		if (m_final_num2 > 0)
			rte_pktmbuf_free_bulk(mbufs2, m_final_num2);
	}
#endif
	return en_num;
}

static void toe_rx_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
	
	data_rq->real_tail = (data_rq->real_tail + sjob->meb_num) % data_rq->rq_size;

	toe_rx_databuf_dma_enqueue(toe_eg, sjob->qid);
	
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);

	return;
}

int toe_rx_data_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[idx]->rq_info;
	uint64_t rq_phy_base_addr;
	int ret;

	if (likely(*data_rq->tail == data_rq->pre_head)) {
		return 0;
	}
		//printf("!! %s-%d:now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "channel2-rq-enq-start"); 
				log_count ++;
			} 
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	rq_phy_base_addr = toe_addr32_to_addr64(data_rq->rbc->queue_desc_h, data_rq->rbc->queue_desc_lo);
	ret = toe_dma_enqueue(dma, TOE_DMA_READ, *data_rq->tail, &data_rq->pre_head, data_rq->rq_size, rq_phy_base_addr, 
					TOE_DATA_RXRQ_MSG_SIZE, (char *)data_rq->rq_local, idx, toe_rx_data_dma_process);
	if (ret > 0) {
		//printf("!! %s-%d:now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
						timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
						sprintf(timestamp_str[log_count], "channel2-rq-enq-end"); 
						log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	}
	return ret;
}

static void toe_rx_data_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	if (toe_eg->data_rx_vring[sjob->qid]->cq_info.cbc->msi_switch == 1)
		toe_irq_raise(toe_eg, toe_eg->data_rx_vring[sjob->qid]->cq_info.cbc->msi_vector);
	
	return;
}

void toe_rx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_rx_cq_info *data_cq = &toe_eg->data_rx_vring[idx]->cq_info;
	uint64_t cq_phy_base_addr;
	int ret;
	
	if (data_cq->tail == data_cq->pre_head) {
		return;
	}	
		//printf("!! %s-%d:now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {
			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "channel2-cq-enq-start"); 
				log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	cq_phy_base_addr = toe_addr32_to_addr64(data_cq->cbc->queue_desc_h, data_cq->cbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_WRITE, data_cq->tail, &data_cq->pre_head, data_cq->cq_size, cq_phy_base_addr, 
					TOE_DATA_RXCQ_MSG_SIZE, (char *)data_cq->cq_local, idx, toe_rx_data_reply_dma_process);
	if (ret > 0) {
	//printf("!! %s-%d:now:%lu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {

			if (log_count < LOG_NUM) {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
				sprintf(timestamp_str[log_count], "channel2-cq-enq-end"); 
				log_count ++;
			}
			else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
			}
		}
	}
	return;
}

static void toe_tx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	struct toe_data_dpu_to_host_req *rq = sjob->vaddr;
	struct toe_mbuf_recovery *rec_ring = &toe_eg->data_tx_vring[sjob->qid]->recovery_ring;
	struct toe_data_dpu_to_host_res *cq_msg;
	struct toe_data_tx_cq_info *cq_info = &toe_eg->data_tx_vring[sjob->qid]->cq_info;
	tcp_stream *stream;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int stream_mbuf_head , num[2];
	uint16_t cq_rq_head;	

	if (sjob->extra == 0)
		goto free;
	
	printf("%s-%d: final_len:%llu,host_list_virtaddr:0x%llx,,loop_count:%llu,now:%llu\n",__func__, __LINE__, sjob->extra, sjob->extra3, loop_count, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
	
	if ((cq_info->tail + 1) % cq_info->cq_size == *cq_info->head) {
		printf("%s-%d: tx databuf cq full\n",__func__, __LINE__);
		goto free;
	}

	stream = sjob->cnxt;
	stream_mbuf_head = sjob->extra4;

	num[0] = stream_mbuf_head - rec_ring->head;
	num[1] = 0;

	RTE_ASSERT(num[0] != 0);
	if (num[0] < 0) {
		num[0] = rec_ring->size - rec_ring->head;
		num[1] = stream_mbuf_head;
	}

	rte_pktmbuf_free_bulk(&rec_ring->m_data[rec_ring->head], num[0]);
	if (num[1] > 0)
		rte_pktmbuf_free_bulk(rec_ring->m_data, num[1]);

	rec_ring->head = stream_mbuf_head;

	stream->ref_count --;
	toe_destory_stream_check(stream);
#if 0
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	if (stream->need_wnd_adv) {
		if (rcvvar->rcv_wnd > stream->sndvar->eff_mss) {
			if (!stream->sndvar->on_ackq) {
				stream->sndvar->on_ackq = TRUE;
				//StreamEnqueue(mtcp->ackq, cur_stream); /* this always success */
			
				EnqueueACK(mtcp, stream, 0, ACK_OPT_AGGREGATE);
				stream->need_wnd_adv = FALSE;
			}
		}
	}
#endif
	if (sjob->extra5 + 1 == rq->buffer_num)
		rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
/*
	if (rq_info->head == 0)
		cq_rq_head = rq_info->rq_size;
	else
		cq_rq_head = rq_info->head - 1;

	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->qid = sjob->qid;
	cq_msg->data_len = sjob->extra;
	cq_msg->recv_list_virtaddr = sjob->extra3;
	cq_msg->complete = cq_info->cq_compl;
	cq_msg->identification.host_dataptr = sjob->extra2;
	cq_msg->rq_head = cq_rq_head;

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
*/	
		//printf("%s-%d: loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (TOE_LOG_ON) {

		if (log_count < LOG_NUM) {
						timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
						sprintf(timestamp_str[log_count], "channel3-databuff-process"); 
						log_count ++;
		}
		else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
		}
	}
free:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

struct rte_qdma_job * toe_tx_databuf_to_job(struct rte_mbuf *pkt, uint64_t buf_addr, int len, int final_len, uint64_t host_dataptr, uint64_t host_list_addr, struct toe_engine *toe_eg, int qid, tcp_stream *stream, int stream_mbuf_head)
{
	struct toe_sync_dma_job *sjob = NULL;
	struct toe_dma_info *dma = toe_eg->t_dma;
	//struct rte_qdma_job **jobs = toe_eg->data_tx_vring[idx]->rq_info.jobs;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[qid]->rq_info;
	struct toe_data_dpu_to_host_req *rq = data_rq->rq_local + data_rq->pre_head;
	struct toe_data_dpu_to_host_res *cq_msg;
	struct toe_data_tx_cq_info *cq_info = &toe_eg->data_tx_vring[qid]->cq_info;
	uint32_t lcore_id;
	uint16_t rq_head;

	if (unlikely(rte_mempool_get(dma->jpool, (void **)&sjob))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		goto err;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;

	sjob->meb_num = 1;
	sjob->cb = NULL;
	sjob->vaddr = NULL;
	sjob->cb = NULL;
	sjob->extra = 0;
	sjob->extra2 = 0;
	sjob->qid = qid;
	if (final_len) {
		sjob->cnxt = (void *)stream;
		sjob->vaddr = (void *)rq;
		sjob->cb = toe_tx_databuf_dma_process;
		sjob->extra = final_len;
		sjob->extra2 = host_dataptr;
		sjob->extra3 = host_list_addr;
		sjob->extra4 = stream_mbuf_head;
		sjob->extra5 = rq->use_idx;
	}

	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = rte_pktmbuf_iova(pkt);
	sjob->job->dest = buf_addr;
	sjob->job->len = len;
	sjob->job->rbp = rbp;

		//printf("%s-%d: final_len:%u,loop_count:%llu,now:%llu \n",__func__,__LINE__,final_len,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (TOE_LOG_ON) {

			if (log_count < LOG_NUM) {
						timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
						sprintf(timestamp_str[log_count], "channel3-databuff-enq"); 
						log_count ++;
			}
			else {
					timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
					sprintf(timestamp_str[log_count], "log restart");
					log_count = 0;	
			}
		}
	if (final_len) {
			rq_head = data_rq->pre_head;
			//if (sjob->extra5 + 1 == rq->buffer_num)
				//rq_head = (data_rq->pre_head + 1) % data_rq->rq_size;

		if (rq_head == 0)
			rq_head = data_rq->rq_size;
		else
			rq_head = rq_head - 1;

		cq_msg = cq_info->cq_local + cq_info->tail;
		cq_msg->qid = sjob->qid;
		cq_msg->data_len = sjob->extra;
		cq_msg->recv_list_virtaddr = sjob->extra3;
		cq_msg->complete = cq_info->cq_compl;
		cq_msg->identification.host_dataptr = sjob->extra2;
		cq_msg->rq_head = rq_head;

		printf("%s-%d: cq_msg->rq_head:%d\n",__func__,__LINE__,cq_msg->rq_head);
		cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
		if (cq_info->tail == 0)
			cq_info->cq_compl = cq_info->cq_compl ^ 1;
	}
	return sjob->job;
err:
	if (sjob) {
		rte_mempool_put(dma->jpool, sjob);
	}
	return NULL;
}

void toe_tx_data_job_enq(struct rte_qdma_job **jobs, int job_num, struct toe_engine *toe_eg)
{
	struct rte_qdma_enqdeq e_context;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sync_dma_job *sjob = NULL;
	int ret, j;
	
	hwq = &tdma_hwq[rte_lcore_id()];

	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL,  job_num, &e_context);
	if (unlikely(ret < job_num)) {
		for (j = ret; j < job_num; j ++) {
			sjob = (struct toe_sync_dma_job *)jobs[j]->cnxt;
			
			rte_pktmbuf_free((struct rte_mbuf *)sjob->vaddr);//存在重复释放问题
			rte_mempool_put(toe_eg->t_dma->jpool, sjob);
		}
	}

	return;
}

static void toe_tx_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	struct toe_data_dpu_to_host_req *rq = sjob->vaddr;

	int i;
		printf("%s-%d:rq->buffer_num:%d,rq_info->rq_local->identification.host_dataptr:%d,rq_info->tail:%d\n", __func__,__LINE__,rq->buffer_num, rq->identification.host_dataptr,rq_info->tail);

	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

	rq->use_idx = 0;
	rq_info->real_tail = (rq_info->real_tail + sjob->meb_num) % rq_info->rq_size;
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

int toe_tx_data_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[idx]->rq_info;
	uint64_t rq_phy_base_addr;
	int ret;
	
	if (*data_rq->tail == data_rq->enq_tail)
		return 0;
		
	printf("!! %s-%d:doorbell:%u, now:%lu\n",__func__,__LINE__,*data_rq->tail, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
	rq_phy_base_addr = toe_addr32_to_addr64(data_rq->rbc->queue_desc_h, data_rq->rbc->queue_desc_lo);

	ret = toe_dma_enqueue(dma, TOE_DMA_READ, *data_rq->tail, &data_rq->enq_tail, data_rq->rq_size, rq_phy_base_addr, TOE_DATA_TXRQ_MSG_SIZE, (char *)data_rq->rq_local, idx, toe_tx_data_dma_process);
	return ret;
}

static void toe_tx_data_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	if (unlikely(!sjob->meb_num))
		return;

	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	if (toe_eg->data_tx_vring[sjob->qid]->cq_info.cbc->msi_switch == 1)
		toe_irq_raise(toe_eg, toe_eg->data_tx_vring[sjob->qid]->cq_info.cbc->msi_vector);
	printf("%s-%d:irq send,toe_eg->data_tx_vring[%d]->cq_info.cbc->msi_switch:%d ,loop_count:%llu,now:%llu \n",__func__,__LINE__,sjob->qid,toe_eg->data_tx_vring[sjob->qid]->cq_info.cbc->msi_switch,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (TOE_LOG_ON) {
		if (log_count < LOG_NUM) {
						timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();
						sprintf(timestamp_str[log_count], "channel3-irq-%s", (toe_eg->data_tx_vring[sjob->qid]->cq_info.cbc->msi_switch == 1)?"on":"off"); 
						log_count ++;
		}
		else {
				timestamp[log_count] = (rte_rdtsc()*1000000)/rte_get_tsc_hz();                                
				sprintf(timestamp_str[log_count], "log restart");
				log_count = 0;	
		}
	}
	return;
}

void toe_tx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_tx_cq_info *data_cq = &toe_eg->data_tx_vring[idx]->cq_info;
	uint64_t cq_phy_base_addr;
	
	if (data_cq->tail == data_cq->pre_head) {
		return;
	}

	printf("!! %s-%d:data_cq->tail:%u, data_cq->pre_head:%u,now:%lu\n",__func__,__LINE__, data_cq->tail, data_cq->pre_head, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
	cq_phy_base_addr = toe_addr32_to_addr64(data_cq->cbc->queue_desc_h, data_cq->cbc->queue_desc_lo);

	toe_dma_enqueue(dma, TOE_DMA_WRITE, data_cq->tail, &data_cq->pre_head, data_cq->cq_size, cq_phy_base_addr, TOE_DATA_TXCQ_MSG_SIZE, (char *)data_cq->cq_local, idx, toe_tx_data_reply_dma_process);
	return;
}

#define dma_init

static void toe_dma_job_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned int idx)
{
	struct toe_sync_dma_job *job = obj;
	struct toe_dma_info *dma = opaque;
	memset(job, 0, sizeof(*job));
	job->job = &dma->qjobs[idx];
	job->job->flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
}

static int toe_dma_job_pool_init(struct toe_dma_info *dma) 
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	uint32_t elt_size;

	dma->qjobs = rte_calloc(NULL, dma->job_cnt, sizeof(struct rte_qdma_job), RTE_CACHE_LINE_SIZE);

	if (!dma->qjobs)
		return -rte_errno;

	snprintf(name, sizeof(name),
			"toe_dma_j_%d_%lx", dma->vf, rte_rdtsc());

	elt_size = sizeof(struct toe_sync_dma_job);
	// 目前只有一个NUMA: 0
	mp = rte_mempool_create(name, dma->job_cnt,
			elt_size,
			DMA_JOB_CACHE_SIZE, 0, NULL, NULL, toe_dma_job_init,
			dma, SOCKET_ID_ANY, 0);

	if (mp == NULL) {
		RTE_LOG(ERR, PMD,
				"mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	dma->jpool = mp;
	return 0;
}

static void toe_dma_job_pool_free(struct toe_dma_info *dma) 
{
	if (dma->qjobs)
		rte_free(dma->qjobs);
	if (dma->jpool) {
		rte_mempool_free(dma->jpool);
		dma->jpool = NULL;
	}
}

static int toe_qdma_init(int qdma_dev_id)
{
	struct rte_qdma_config qdma_config;
	struct rte_qdma_info dev_conf;
	char name[RTE_MEMPOOL_NAMESIZE];
	int ret;
	int i = 0;

	/* Configure QDMA to use HW resource - no virtual queues */
	qdma_config.max_hw_queues_per_core = TOE_QDMA_MAX_HW_QUEUES_PER_CORE;
	qdma_config.fle_queue_pool_cnt = TOE_QDMA_FLE_POOL_QUEUE_COUNT;
	qdma_config.max_vqs = TOE_QDMA_MAX_VQS;

	dev_conf.dev_private = (void *)&qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);

	if (ret && ret != -EBUSY) {
		RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
		goto done;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to start DMA\n");
		goto done;
	}

done:
	return qdma_dev_id;
	/*
error:
	//rte_ring_free(GC_ring);
qdma_error:
	return -EINVAL;
	*/
}

static inline int toe_qdma_queue_setup(int dma_id,int lcore_id, uint32_t vq_flags)
{
	struct rte_qdma_queue_config qdma_config;
	qdma_config.lcore_id = lcore_id;
	qdma_config.flags = vq_flags;
	qdma_config.rbp = NULL;
	return rte_qdma_queue_setup(dma_id, -1, &qdma_config);
}

static void toe_dma_hwq_init(int pf, int vf)
{
	int lcore;
	int i;
	struct toe_dma_hwq *hwq;
	struct rte_qdma_rbp *rbp;
	unsigned int portid = agiep_get_portid();
	uint32_t vq_flags = RTE_QDMA_VQ_EXCLUSIVE_PQ | RTE_QDMA_VQ_FD_LONG_FORMAT
		| RTE_QDMA_VQ_FD_SG_FORMAT;

	RTE_LCORE_FOREACH(lcore) {
		hwq = &tdma_hwq[lcore];
		hwq->lcore_id = lcore;
		hwq->id = tqdma_dev_id;
		hwq->vq = toe_qdma_queue_setup(tqdma_dev_id, lcore, vq_flags);
		assert(hwq->vq >= 0);

		rbp = &hwq->R_rbp;
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

		rbp = &hwq->W_rbp;
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

		rte_compiler_barrier();
		hwq->enable = 1;
	}
}

int toe_dma_init(struct toe_engine *toe_eg)
{
	struct toe_dma_info *dma;

	dma = rte_calloc(NULL, 1, sizeof(struct toe_dma_info), RTE_CACHE_LINE_SIZE);
	if (dma == NULL)
		return -1;
	toe_eg->t_dma = dma;
	dma->id = tqdma_dev_id;
	dma->job_cnt = JOB_POOL_NUM;
	dma->pf = toe_eg->pf;
	dma->vf = toe_eg->vf;

	if (toe_dma_job_pool_init(dma))
		goto failed;
	
	tqdma_dev_id = toe_qdma_init(tqdma_dev_id);
	assert(tqdma_dev_id >= 0);

	toe_dma_hwq_init(toe_eg->pf, toe_eg->vf);

	return 0;

failed:

	if (dma)
		rte_free(dma);
	return -1;
}

static void toe_qdma_fini(int qdma_dev_id)
{
	rte_rawdev_stop(qdma_dev_id);
	rte_rawdev_close(qdma_dev_id);
}

void toe_dma_hwq_destroy(void)
{
	int lcore;
	struct toe_dma_hwq *hwq;
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		hwq = &tdma_hwq[lcore];		
		if (!hwq->enable)
			continue;
		rte_rawdev_queue_release(hwq->id, hwq->vq);
	}
}

void toe_dma_fini(void)
{
	toe_dma_hwq_destroy();
	toe_qdma_fini(tqdma_dev_id);
}

void toe_dma_reset(struct toe_engine *toe_eg)
{
	int i, ret = 0;
	uint64_t now = rte_rdtsc()/rte_get_tsc_hz();
	uint64_t last = now;
	do {
		now = rte_rdtsc()/rte_get_tsc_hz();
		ret = toe_dma_dequeue(toe_eg);
		if (ret > 0)
			last = now;
	}while ((now - last) < 2);

	
	toe_eg->sys_ctl_vring->rq_info.local_head = 0;
	toe_eg->sys_ctl_vring->rq_info.pre_head = 0;
	toe_eg->sys_ctl_vring->rq_info.head = 0;
	//toe_eg->sys_ctl_vring->rq_info.tail = 0;
	
	toe_eg->sys_ctl_vring->cq_info.pre_head = 0;
	//toe_eg->sys_ctl_vring->cq_info.head = 0;
	toe_eg->sys_ctl_vring->cq_info.pre_tail = 0;
	toe_eg->sys_ctl_vring->cq_info.tail = 0;
	toe_eg->sys_ctl_vring->cq_info.cq_compl = 1;

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {

		toe_eg->ctl_rx_vring[i]->rq_info.local_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.head = 0;
		//toe_eg->ctl_rx_vring[i]->rq_info.tail = 0;


		toe_eg->ctl_rx_vring[i]->cq_info.pre_head = 0;
		//toe_eg->ctl_rx_vring[i]->cq_info.head = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.cq_compl = 1;
		printf("%s-%d: ctrl rq cq set 0!\n",__func__,__LINE__);
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		toe_eg->data_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_rx_vring[i]->rq_info.head = 0;
		toe_eg->data_rx_vring[i]->rq_info.real_tail = 0;
		//toe_eg->data_rx_vring[i]->rq_info.tail = 0;

		toe_eg->data_rx_vring[i]->cq_info.pre_head = 0;
		//toe_eg->data_rx_vring[i]->cq_info.head = 0;
		toe_eg->data_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.cq_compl = 1;

		toe_eg->data_tx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_tx_vring[i]->rq_info.head = 0;
		toe_eg->data_tx_vring[i]->rq_info.real_tail = 0;
		//toe_eg->data_tx_vring[i]->rq_info.tail = 0;
		toe_eg->data_tx_vring[i]->rq_info.enq_tail = 0;

		//toe_eg->data_tx_vring[i]->cqad = 0;
		toe_eg->data_tx_vring[i]->cq_info.tail = 0;
		toe_eg->data_tx_vring[i]->cq_info.cq_compl = 1;
		
	}

	return;
}

