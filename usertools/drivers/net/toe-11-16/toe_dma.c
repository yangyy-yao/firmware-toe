
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

int toe_rxctl_rq_head_update(struct toe_ctl_rq_info *ctl_rq, uint16_t rq_pre_head)
{
	int i, num = 0;

	
	printf("*** %s-%d: ctl_rq->pre_head:%d, rq_pre_head:%d, ctl_rq->head:%d\n",__func__,__LINE__,ctl_rq->pre_head,rq_pre_head, ctl_rq->head);
	if (rte_atomic16_read(&ctl_rq->wait_head_num) == 0) {
		num = rq_pre_head - ctl_rq->head;
		num = (num > 0) ? num : (num + ctl_rq->rq_size);
	
		ctl_rq->head = rq_pre_head;
		return num;
	}

	if (rq_pre_head < ctl_rq->head) {
		for (i = ctl_rq->head; i < ctl_rq->rq_size; i++) {
			num++;
			
			printf("**8 22 %s-%d: ctl_rq->wait_head[%d]:%d\n",__func__,__LINE__,i,ctl_rq->wait_head[i]);
			if (ctl_rq->wait_head[i] == 1)
				return num;
			ctl_rq->head = i;
		}
		ctl_rq->head = 0;
		for (i = 0; i <= rq_pre_head; i++) { 
			num++;
			
			printf("**8 33 %s-%d: ctl_rq->wait_head[%d]:%d\n",__func__,__LINE__,i,ctl_rq->wait_head[i]);
			if (ctl_rq->wait_head[i] == 1)
				return num;
			ctl_rq->head = i;
		}
	} else {
		for(i = ctl_rq->head; i <= rq_pre_head; i++) {
			num++;
			
			printf("**8 44 %s-%d: ctl_rq->wait_head[%d]:%d\n",__func__,__LINE__,i,ctl_rq->wait_head[i]);
			if (ctl_rq->wait_head[i] == 1)
				return num;
			ctl_rq->head = i;
		}
	}
	return num;
}

int toe_rxctl_cq_tail_update(struct toe_ctl_cq_info *ctl_cq, uint16_t pre_tail)
{
		int i, num = 0;

		
	printf("%s-%d:ctl_cq->tail:%d,ctl_cq->pre_tail:%d,pre_tail:%d, ctl_cq->pre_head:%d,ctl_cq->head:%d\n",__func__,__LINE__,ctl_cq->tail,ctl_cq->pre_tail, pre_tail,ctl_cq->pre_head,ctl_cq->head);
	if (rte_atomic16_read(&ctl_cq->wait_tail_num) == 0) {
		num = pre_tail - ctl_cq->tail;
		num = (num > 0) ? num : (num + ctl_cq->cq_size);
	
		ctl_cq->tail = pre_tail;
		return num;
	}

	if (pre_tail < ctl_cq->tail) {
		for (i = ctl_cq->tail; i < ctl_cq->cq_size; i++) {
			num++;
			if (ctl_cq->wait_tail[i] == 1)
				return num;
			ctl_cq->tail++;
		}

		for (i = 0; i <= pre_tail; i++) {
			num++;
			if (ctl_cq->wait_tail[i] == 1)
				return num;
			ctl_cq->tail = (ctl_cq->tail + 1) % ctl_cq->cq_size;
		}
	} else {
		for(i = ctl_cq->tail; i <= pre_tail; i++) {
			num++;
			if (ctl_cq->wait_tail[i] == 1)
				return num;
			ctl_cq->tail++;
		}
	}
	printf("%s-%d:ctl_cq->tail:%d,ctl_cq->pre_tail:%d,ctl_cq->pre_head:%d,ctl_cq->head:%d\n",__func__,__LINE__,ctl_cq->tail,pre_tail,ctl_cq->pre_head,ctl_cq->head);
	return num;
}

/*
void toe_rxctl_rqcq_update(struct toe_ctl_rx_rq_info *ctl_rq, struct toe_ctl_rx_cq_info *ctl_cq)
{
	toe_rxctl_rq_head_update(ctl_rq);
	toe_rxctl_cq_tail_update(ctl_cq);
}
*/

#if 0
static void toe_socketopt_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_ctrl_rxcq_msg *cq_msg = sjob->cnxt;
	struct toe_ctrl_rxrq_msg *local_msg = (struct toe_ctrl_rxrq_msg *)sjob->priv_addr;
	int qid = sjob->qid;
	printf("$$ %s-%d: opcode:%d,\n",__func__,__LINE__,local_msg->opcode);
	if(local_msg->opcode == TOE_MSG_SOCKET_SETSOCKOPT) {
	
		printf("$$22 %s-%d: rq_info.wait_head[%ld]:%d, num:%d\n",__func__,__LINE__,sjob->extra, toe_eg->ctl_rx_vring[qid]->rq_info.wait_head[sjob->extra],rte_atomic16_read(&toe_eg->ctl_rx_vring[qid]->rq_info.wait_head_num));
		printf("$$33 %s-%d: cq_info.wait_tail[%ld]:%d, num:%d\n",__func__,__LINE__,sjob->extra2, toe_eg->ctl_rx_vring[qid]->cq_info.wait_tail[sjob->extra2],rte_atomic16_read(&toe_eg->ctl_rx_vring[qid]->cq_info.wait_tail_num));

		toe_sk_setsocketopt(sjob->priv_addr, cq_msg, toe_eg, sjob->extra, qid);
		toe_eg->ctl_rx_vring[qid]->rq_info.wait_head[sjob->extra] = 0;
		rte_atomic16_dec(&toe_eg->ctl_rx_vring[qid]->rq_info.wait_head_num);

		toe_eg->ctl_rx_vring[qid]->cq_info.wait_tail[sjob->extra2] = 0;
		rte_atomic16_dec(&toe_eg->ctl_rx_vring[qid]->cq_info.wait_tail_num);
	}

	//toe_rxctl_rqcq_update(&toe_eg->ctl_rx_vring->rq_info, &toe_eg->ctl_rx_vring->cq_info);
	
	//rte_free(sjob->vaddr);
	//rte_free(sjob->priv_addr);

	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}


int toe_set_sockoptval_dma_enqueue(struct toe_ctrl_rxrq_msg *rq_msg, 
																												struct toe_ctrl_rxcq_msg *cq_msg,
																												struct toe_engine *toe_eg, int idx)
{
	struct toe_ctrl_req_setsockopt_hdr *sk_opt = &rq_msg->setsockopt;
	struct toe_ctrl_rxrq_msg *local_msg;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sync_dma_job *sjob;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	uint32_t lcore_id;
	struct rte_qdma_job *job;
	struct rte_qdma_enqdeq e_context;
	int ret = 0;
	uint64_t dst_addr;

	printf("%s-%d: set option %d\n",__func__,__LINE__,sk_opt->optname);
	local_msg = rte_calloc(NULL, 1, sizeof(struct toe_ctrl_req_setsockopt_hdr), RTE_CACHE_LINE_SIZE);
	if (local_msg == NULL) {
		ret =  TOE_RET_FAIL;
		goto fail;
	}
	local_msg->opcode = rq_msg->opcode;
	local_msg->fd = rq_msg->fd;
	local_msg->setsockopt.optval_addr = (uint64_t)rte_calloc(NULL, 1, sk_opt->optlen, RTE_CACHE_LINE_SIZE);
	if (local_msg->setsockopt.optval_addr == 0) {
		ret = TOE_RET_FAIL;
		goto fail;
	}
	local_msg->setsockopt.level = sk_opt->level;
	local_msg->setsockopt.optname = sk_opt->optname;
	local_msg->setsockopt.optlen = sk_opt->optlen;
	
	if (unlikely(rte_mempool_get(dma->jpool, (void **) &sjob))) {
		
		printf("$$%s-%d: sjob malloc failed\n",__func__,__LINE__);
		ret =  TOE_RET_FAIL;
		goto fail;
	}
	
	lcore_id = rte_lcore_id();
	hwq = &tdma_hwq[lcore_id];
	rbp = &hwq->R_rbp;

	sjob->meb_num = 1;
	sjob->cb = toe_socketopt_dma_process;
	sjob->qid = idx;

	sjob->vaddr = (void *)local_msg->setsockopt.optval_addr;
	sjob->priv_addr = (void *)local_msg;
	sjob->extra= toe_eg->ctl_rx_vring[idx]->rq_info.pre_head;
	sjob->extra2= toe_eg->ctl_rx_vring[idx]->cq_info.pre_tail;
	sjob->cnxt = cq_msg;
	
	dst_addr = rte_mem_virt2iova((void *)local_msg->setsockopt.optval_addr);
	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = sk_opt->optval_addr;
	sjob->job->dest = dst_addr;
	sjob->job->len = sk_opt->optlen;
	sjob->job->rbp = rbp;

	job = sjob->job;

	e_context.vq_id = hwq->vq;
	e_context.job = &job;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL,  1, &e_context);
	if (!ret) {
		ret =  TOE_RET_FAIL;
		goto fail;
	}
	
	return TOE_RET_NEED_DMA;

	fail:
	if (local_msg) {
		if (local_msg->setsockopt.optval_addr)
			rte_free((void *)local_msg->setsockopt.optval_addr);
		rte_free(local_msg);
	}

	if (sjob)
		rte_mempool_put(dma->jpool, sjob);
	
	return ret;
}
#endif

static uint64_t toe_addr32_to_addr64(uint32_t hi, uint32_t lo)
{
	uint64_t addr;

	addr = hi;
	addr = lo | addr << 32;
	return addr;
}

static void toe_rx_ctl_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int i, meb_num = sjob->meb_num;
	void *vaddr;
	int qid = sjob->qid;
	uint64_t srcaddr = 0;
	struct toe_ctl_rq_info *ctl_rq = &toe_eg->ctl_rx_vring[qid]->rq_info;
	
	printf("@# %s-%d: meb_num:%d \n",__func__,__LINE__,meb_num);
	for (i = 0; i < meb_num; i++) {
			vaddr = (char *)sjob->vaddr + i * TOE_CTRL_RQ_MSG_SIZE;
			srcaddr = sjob->job->src + i * TOE_CTRL_RQ_MSG_SIZE;
			printf("@# %s-%d: srcaddr:0x%lx, i:%d, qid:%d\n",__func__,__LINE__,srcaddr, i, qid);
	
			toe_ctl_recv(vaddr, toe_eg, qid);

			ctl_rq->pre_head = (ctl_rq->pre_head + 1) % ctl_rq->rq_size;
	}
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);

#if 0
	toe_rxctl_rq_head_update(ctl_rq);

	toe_rx_ctl_reply(toe_eg);
#endif
	return;
}

static void toe_ctl_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int qid = sjob->qid;
	struct toe_ctrl_host_to_dpu_res *cq_local = sjob->vaddr;
	int num = sjob->meb_num;
	int i;
	uint64_t dstaddr = sjob->job->dest;

	for(i = 0; i < num; i ++) {

		dstaddr += i * TOE_CTRL_CQ_MSG_SIZE;
		
		cq_local++;
	}
	
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	toe_irq_raise(toe_eg, toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector);
	printf("##$$ %s-%d: msi_vector:%d, qid:%d,now:%lu\n",__func__,__LINE__,toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector,qid,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	return;
}

static void toe_rx_data_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
//	int qid = sjob->qid;

	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	toe_irq_raise(toe_eg, toe_eg->data_rx_vring[sjob->qid]->cq_info.cbc->msi_vector);
	
	return;
}

void toe_rx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_rx_cq_info *data_cq = &toe_eg->data_rx_vring[idx]->cq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;

	if (data_cq->tail == data_cq->pre_head)
		return;
	
	nb_meb[0] = data_cq->tail - data_cq->pre_head;
	nb_meb[1] = 0;
	head[0] = data_cq->pre_head;
	head[1] = 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = data_cq->cq_size - data_cq->pre_head;
		nb_meb[1] = data_cq->tail;
	
		num_jobs = 2;
	}
	
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		printf("$$%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return;
	}
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_rx_data_reply_dma_process;
		//sjob[i]->rq_info = (void *)ctl_rq;
		sjob[i]->qid = idx;

		src_addr = (uint64_t)(data_cq->cq_local + head[i]);
		
		dst_addr = toe_addr32_to_addr64(data_cq->cbc->queue_desc_h, data_cq->cbc->queue_desc_lo)
								+ head[i] * TOE_DATA_RXCQ_MSG_SIZE;
		
		//sjob[i]->vaddr = (void *)dst_addr;
		src_addr = rte_mem_virt2iova((void *)src_addr);
		job_len = nb_meb[i] * TOE_DATA_RXCQ_MSG_SIZE;

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
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		data_cq->pre_head = (data_cq->pre_head + nb_meb[i]) % data_cq->cq_size;
	
	return;
}
#if 1
static void toe_rx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
//	struct toe_data_host_to_dpu_req *data_msg = (struct toe_data_host_to_dpu_req *)sjob->cnxt;
	struct toe_data_host_to_dpu_res *cq_msg;
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[sjob->qid]->cq_info;
//	struct toe_data_rx_rq_info *rq_info = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
	//void *buff = sjob->vaddr;
#ifdef TOE_TSO
	struct rte_mbuf **buff;
#endif
	tcp_stream *stream;
	int qid = sjob->qid;

	//rte_pktmbuf_dump(stdout,buff, buff->pkt_len);
	
	if (!sjob->meb_num)
		goto done;

	stream = sjob->priv_addr;
#ifdef TOE_TSO
	buff = sjob->vaddr;
	stream->sndvar->tcp_data_ring.m[stream->sndvar->tcp_data_ring.tail] = buff[0];
	rte_free(buff);
#endif

	stream->sndvar->tcp_data_ring.tail = (stream->sndvar->tcp_data_ring.tail + sjob->meb_num) % TCP_SEND_DATA_BUFFER_MAX_NUM;

	toe_tcp_datapkt_send(stream, toe_eg, qid);
	
	cq_info->head = cq_info->cbc->doorbell;
	if ((cq_info->pre_tail + 1) % cq_info->cq_size == cq_info->head) {
		printf("%s-%d: cq full\n",__func__, __LINE__);
		return;
	}
	cq_msg = cq_info->cq_local + cq_info->pre_tail;
	cq_msg->compl = cq_info->cq_compl;
	cq_msg->rq_head = sjob->extra;
	
	//buff->pkt_len = sjob->job->len;
	//buff->data_len = buff->pkt_len;
	
	//toe_sk_sendmsg(data_msg, buff, cq_msg);

	cq_info->pre_tail = (cq_info->pre_tail + 1) % cq_info->cq_size;
	if (cq_info->pre_tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	/*
	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
	
	rq_info->head = (rq_info->head + 1) % rq_info->rq_size;

	cq_msg->rq_head = rq_info->head;
	
	//rte_free(buff);
	*/
	done:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}
#else
static void toe_rx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_rxrq_msg *data_msg = (struct toe_data_rxrq_msg *)sjob->cnxt;
	struct toe_data_rxcq_msg *cq_msg;
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[sjob->qid]->cq_info;
	struct toe_data_rx_rq_info *rq_info = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
	//void *buff = sjob->vaddr;
	void *buff;
	int qid = sjob->qid;

	//rte_pktmbuf_dump(stdout,buff, buff->pkt_len);
	
	if (!sjob->meb_num)
		goto done;
	
	printf("$^^# %s-%d:old cq_info->head:%d,cq_info->cbc->doorbell:%d\n",__func__,__LINE__,cq_info->head,cq_info->cbc->doorbell);
	cq_info->head = cq_info->cbc->doorbell;
	if ((cq_info->pre_tail + 1) % cq_info->cq_size == cq_info->head) {
		printf("%s-%d: cq full\n",__func__, __LINE__);
		return;
	}
	cq_msg = cq_info->cq_local + cq_info->pre_tail;
	cq_msg->compl = cq_info->cq_compl;
	cq_msg->rq_head = sjob->extra;
	
	//buff->pkt_len = sjob->job->len;
	//buff->data_len = buff->pkt_len;
	
	//toe_sk_sendmsg(data_msg, buff, cq_msg);
	buff = sjob->vaddr;
	toe_rx_data_pkt_enq(data_msg, cq_msg, toe_eg, buff, sjob->job->len,qid);
	cq_info->pre_tail = (cq_info->pre_tail + 1) % cq_info->cq_size;
	if (cq_info->pre_tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	/*
	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
	
	rq_info->head = (rq_info->head + 1) % rq_info->rq_size;

	cq_msg->rq_head = rq_info->head;
	
	//rte_free(buff);
	*/
	done:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}
#endif
#if 1
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
	unsigned int data_len;
	struct rte_mbuf **mbufs = NULL;
	struct rte_mbuf **mbufs2 = NULL;
	struct rte_mbuf *d_mbuf;
	struct rte_mbuf *pre_mbuf;
	struct rte_mbuf *head_mbuf;
	uint64_t src_addr, dst_addr;
	uint32_t job_len, en_len = 0;
	uint32_t lcore_id;
//	uint16_t site;
	
    printf("%s:%d  data_rq[%d]  RQ  PhyAddr:%llx  Doorbell:%u\n", __func__, __LINE__, idx, (data_rq->rbc->queue_desc_lo << 32)|data_rq->rbc->queue_desc_lo, data_rq->rbc->doorbell);
	num = data_rq->real_tail - data_rq->head;
	if (num == 0)
		return 0;
	if (num < 0)
		num += data_rq->rq_size;

	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->R_rbp;

	for (j = 0; j < num; j++) {
		data_msg = data_rq->rq_local + data_rq->head;

		stream = (tcp_stream*)data_msg->identification.card_stream_addr;
/*		
		data_buf = rte_calloc(NULL, 1, data_msg->data_len, RTE_CACHE_LINE_SIZE);
		if (data_buf == NULL)
			break;
*/	
		
#ifdef TOE_TSO
		data_len = RTE_MBUF_DEFAULT_DATAROOM;
#else 
		data_len = stream->sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
#endif

		m_num = data_msg->data_len / data_len;
		m_num += (data_msg->data_len % data_len) ? 1 : 0;
		
		if (m_num > TOE_JOB_ENQ_NUM) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf too more!\n", __func__, __LINE__);
			goto err;
		}	

#ifdef TOE_TSO
		m_final_num = 1;
		mbufs = rte_calloc(NULL, m_num, sizeof(struct rte_mbuf *), RTE_CACHE_LINE_SIZE);
		if (mbufs == NULL) {

			goto err;
		}

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}
#else
		m_final_num = m_num;
		if (stream->sndvar->tcp_data_ring.free_num < m_final_num) {
				RTE_LOG(ERR, PMD, "%s-%d: tcp data ring is full!\n", __func__, __LINE__);
				goto err;
		}
		mbufs = &stream->sndvar->tcp_data_ring.m[stream->sndvar->tcp_data_ring.tail];

		if (stream->sndvar->tcp_data_ring.tail >= stream->sndvar->tcp_data_ring.head) {
			if (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.tail < m_final_num) {
				mbufs2 = &stream->sndvar->tcp_data_ring.m[0];
				
				m_final_num2 = m_final_num - (TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.tail);
				m_final_num = TCP_SEND_DATA_BUFFER_MAX_NUM - stream->sndvar->tcp_data_ring.tail;
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
			if (i < m_final_num)
				d_mbuf = mbufs[i];
			else 
				d_mbuf = mbufs2[i - m_final_num];
#endif
			printf("%s-%d:head_mbuf:%p,head_mbuf->nb_seg:%d,pre_mbuf:%p,idx:%d\n", __func__,__LINE__,head_mbuf, head_mbuf->nb_segs,pre_mbuf,idx);
			sjob[i]->meb_num = 0;
			sjob[i]->cb = NULL;
			sjob[i]->qid = idx;
			sjob[i]->priv_addr = (void *)d_mbuf;
			sjob[i]->vaddr = NULL;
			sjob[i]->cnxt = NULL;

			if (i == m_num - 1) {
				sjob[i]->meb_num = m_final_num + m_final_num2;
				sjob[i]->cb = toe_rx_databuf_dma_process;
				sjob[i]->cnxt = (void *)data_msg;
				sjob[i]->vaddr = (void *)mbufs;
				sjob[i]->priv_addr = (void *)stream;
				sjob[i]->extra = data_rq->head;
			}
						
			src_addr = data_msg->send_buffer_addr + en_len;
			//dst_addr = rte_mem_virt2iova((void *)data_buf);
			dst_addr = rte_pktmbuf_iova(d_mbuf);
			job_len = RTE_MIN(data_msg->data_len - en_len, data_len);
			printf("%s-%d:data_msg->data_len:%d,mbufs[i]->buf_len:%d,job_len:%d,\n", __func__,__LINE__,data_msg->data_len, mbufs[i]->buf_len, job_len);
			sjob[i]->job->cnxt = (uint64_t) d_mbuf;
			sjob[i]->job->src = src_addr;
			sjob[i]->job->dest = dst_addr;
			sjob[i]->job->len = job_len;
			sjob[i]->job->rbp = rbp;

			jobs[count] = sjob[i]->job;
			
			en_len += job_len;
			count ++;
			d_mbuf->data_len = job_len;
			d_mbuf->pkt_len = job_len;
			
#ifdef TOE_TSO
			if (pre_mbuf) {
				pre_mbuf->next = d_mbuf;
				head_mbuf->nb_segs ++;
			}
			pre_mbuf = d_mbuf;		
			head_mbuf->pkt_len = en_len;
#endif

			if (count == TOE_JOB_ENQ_NUM) {
				e_context.vq_id = hwq->vq;
				e_context.job = jobs;
				ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
				//__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
				en_num += ret;
				if (ret < TOE_JOB_ENQ_NUM) {
					goto done;
				}
				count = 0;
			}
		}
		
		if (count == TOE_JOB_ENQ_NUM) {
			e_context.vq_id = hwq->vq;
			e_context.job = jobs;
			ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
			//__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
			en_num += ret;
			if (ret < TOE_JOB_ENQ_NUM) {
				goto done;
			}
			count = 0;
		}

		
		data_rq->head = (data_rq->head + 1) % data_rq->rq_size; //默认dma全部成功
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
	if (en_num < m_num ) { //这个地方不对，应该判断 en_num < count,但要释放之前的sjob和mbuf
		printf("+++ %s-%d: freee sjob,mbuf\n",__func__,__LINE__);
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[en_num], m_num - en_num);
	
		printf("%s-%d: free mbuf bulk: %p, n:%d,dont should\n",__func__,__LINE__,mbufs[en_num], m_num - en_num);
		rte_pktmbuf_free_bulk(&mbufs[en_num], m_num - en_num);
	}
	return en_num;

	err:
#ifdef TOE_TSO
	if (mbufs)
		rte_free(mbufs);
#endif
	return en_num;
}

#else
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
	int i, num, en_num = 0, count = 0, ret = 0;
	//char *data_buf;
	uint64_t src_addr, dst_addr;
	uint32_t lcore_id;

	num = data_rq->real_tail - data_rq->head;
	if (num == 0)
		return 0;
	if (num < 0)
		num += data_rq->rq_size;

	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->R_rbp;
	printf("**^^ %s-%d:data_rq->tail:%d,data_rq->real_tail:%d,data_rq->head:%d, num:%d\n",__func__,__LINE__,data_rq->tail,data_rq->real_tail,data_rq->head,num);

	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num))) {
		RTE_LOG(ERR, PMD, "%s-%d: sjob alloc failed!\n", __func__, __LINE__);
		goto err;
	}

	for (i = 0; i < num; i++) {
		data_msg = data_rq->rq_local + data_rq->head;

		if (data_msg->kernel_fd != toe_eg->fd_save_kernel[data_msg->fd]) {
			printf("$$%s-%d: rx data process close fd rq, fd:%d, old kernel fd:%lu, new kernel fd:%lu\n",__func__,__LINE__,data_msg->fd, data_msg->kernel_fd, toe_eg->fd_save_kernel[data_msg->fd]);
			data_rq->head = (data_rq->head + 1) % data_rq->rq_size;
			continue;
		}
		
/*		
		data_buf = rte_calloc(NULL, 1, data_msg->data_len, RTE_CACHE_LINE_SIZE);
		if (data_buf == NULL)
			break;
*/		
	
	char *data_buff = rte_calloc(NULL, 1, data_msg->data_len, RTE_CACHE_LINE_SIZE);
	if (data_buff == NULL) {
		printf("%s-%d:malloc failed! data_msg->data_len:%u\n", __func__,__LINE__,data_msg->data_len);
		goto err;
	}
	
			printf("%s-%d:i:%d,data_buff:%p, data_msg->data_len:%u\n", __func__,__LINE__,i,data_buff,data_msg->data_len);
			sjob[i]->meb_num = 1;
			sjob[i]->cb = toe_rx_databuf_dma_process;
			sjob[i]->qid = idx;
			sjob[i]->priv_addr = NULL;
			sjob[i]->vaddr = data_buff;
			sjob[i]->cnxt = data_msg;
			sjob[i]->extra = data_rq->head;
/*
			if (i == m_num - 1) {
				sjob[i]->meb_num = 1;
				sjob[i]->cnxt = (void *)data_msg;
				sjob[i]->vaddr = (void *)head_mbuf;
				sjob[i]->extra = data_rq->head;
			}
*/						
			src_addr = data_msg->data_buffer_addr;
			//dst_addr = rte_mem_virt2iova((void *)data_buf);
			dst_addr = rte_mem_virt2iova((void *)data_buff);
			
		//	job_len = RTE_MIN(data_msg->data_len - en_len, RTE_MBUF_DEFAULT_DATAROOM);
		//	printf("%s-%d:data_msg->data_len:%d,mbufs[i]->buf_len:%d,job_len:%d,\n", __func__,__LINE__,data_msg->data_len, mbufs[i]->buf_len, job_len);
			sjob[i]->job->cnxt = (uint64_t) sjob[i];
			sjob[i]->job->src = src_addr;
			sjob[i]->job->dest = dst_addr;
			sjob[i]->job->len = data_msg->data_len;
			sjob[i]->job->rbp = rbp;

			jobs[count] = sjob[i]->job;

			count ++;
	
			if (count == TOE_JOB_ENQ_NUM) {
				e_context.vq_id = hwq->vq;
				e_context.job = jobs;
				ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
				//__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
				en_num += ret;
				if (ret < TOE_JOB_ENQ_NUM) {
					goto done;
				}
				count = 0;
			}

			
			data_rq->head = (data_rq->head + 1) % data_rq->rq_size; //默认dma全部成功
		}
		/*
		if (count == TOE_JOB_ENQ_NUM) {
			e_context.vq_id = hwq->vq;
			e_context.job = jobs;
			ret = rte_qdma_enqueue_buffers(dma->id, NULL,  TOE_JOB_ENQ_NUM, &e_context);
			//__sync_fetch_and_add(&dma->enqueue_jobs, (uint32_t)ret);
			en_num += ret;
			if (ret < TOE_JOB_ENQ_NUM) {
				goto done;
			}
			count = 0;
		}
*/
		

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
	if (ret < count ) {
		printf("+++ %s-%d: freee sjob,mbuf,en_num:%d,num:%d\n",__func__,__LINE__,en_num,num);
		rte_mempool_put_bulk(dma->jpool, &sjob[en_num], num - en_num);
	}

	err:

	return en_num;
}

#endif


static void toe_rx_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
//	void *vaddr;
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
	
	data_rq->real_tail = (data_rq->real_tail + sjob->meb_num) % data_rq->rq_size;


	toe_rx_databuf_dma_enqueue(toe_eg, sjob->qid);
	
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);

	return;
}

static void toe_tx_data_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_cq_info *data_cq = (struct toe_data_tx_cq_info *)sjob->cnxt;

	if (!sjob->meb_num)
		return;
	data_cq->head = (data_cq->head + sjob->meb_num) % data_cq->cq_size;
	printf("%s-%d:sjob->qid:%d,sjob->meb_num:%d, data_cq->head:%d,  data_cq->tail:%d,data_cq->cq_local->rq_head:%d\n",__func__,__LINE__,sjob->qid,sjob->meb_num, data_cq->head, data_cq->tail, data_cq->cq_local->rq_head);
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	toe_irq_raise(toe_eg, toe_eg->data_tx_vring[sjob->qid]->cq_info.cbc->msi_vector);
	return;
}

void toe_tx_data_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_tx_cq_info *data_cq = &toe_eg->data_tx_vring[idx]->cq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;

	if (data_cq->tail == data_cq->pre_head)
		return;
	printf("%s-%d:data_cq->tail:%d,data_cq->pre_head:%d, data_cq->head:%d\n",__func__,__LINE__,data_cq->tail, data_cq->pre_head,data_cq->head);
	nb_meb[0] = data_cq->tail - data_cq->pre_head;
	nb_meb[1] = 0;
	head[0] = data_cq->pre_head;
	head[1] = 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = data_cq->cq_size - data_cq->pre_head;
		nb_meb[1] = data_cq->tail;
	
		num_jobs = 2;
	}
	
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_tx_data_reply_dma_process;
		sjob[i]->cnxt = (void *)data_cq;

		printf("2222 %s-%d: data_cq head[i]:%d\n",__func__,__LINE__,head[i]);

		src_addr = (uint64_t)(data_cq->cq_local + head[i]);
		
		dst_addr = toe_addr32_to_addr64(data_cq->cbc->queue_desc_h, data_cq->cbc->queue_desc_lo)
								+ head[i] * TOE_DATA_TXCQ_MSG_SIZE;
		
		src_addr = rte_mem_virt2iova((void *)src_addr);
		job_len = nb_meb[i] * TOE_DATA_TXCQ_MSG_SIZE;

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
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, (void *const *)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		data_cq->pre_head = (data_cq->pre_head + nb_meb[i]) % data_cq->cq_size;
	
	return;
}

#if 0
int toe_tx_databuf_to_job(void *pkt_buf, uint64_t buf_addr, int len, int final_len, void *data_msg, int idx, void *t_eg)
{
	struct toe_engine *toe_eg = (struct toe_engine *)t_eg;
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[idx]->rq_info;
	struct toe_sync_dma_job *sjob;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct rte_qdma_job **jobs = toe_eg->data_tx_vring[idx]->rq_info.jobs;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	uint64_t src_addr;
	uint32_t lcore_id;

	if (((rq_info->jobs_tail + 1) % TOE_JOB_DATABUF_NUM) == rq_info->head) {
		printf("%s-%d: tx data jobs queue full!\n", __func__, __LINE__);
		goto err;
	}
	if (unlikely(rte_mempool_get(dma->jpool, (void **)&sjob)))
		goto err;

	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;

	sjob->meb_num = 1;
	sjob->cb = NULL;
	if (final_len) {
		sjob->cb = toe_tx_databuf_dma_process;
	//sjob[i]->vaddr = (void *)data_buf;
		sjob->cnxt = (void *)data_msg;
		sjob->extra = final_len;
	}
	src_addr = rte_mem_virt2iova((void *)pkt_buf);

	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = src_addr;
	sjob->job->dest = buf_addr;
	sjob->job->len = len;
	sjob->job->rbp = rbp;

	jobs[rq_info->jobs_tail] = sjob->job;
	rq_info->jobs_tail++;
	rq_info->jobs_tail %= TOE_JOB_DATABUF_NUM;
	rq_info->jobs_num++;
	
	return 0;
err:
	if (sjob) {
		rte_free(sjob);
	}
	return -1;
}

static struct rte_qdma_job * toe_tx_databuf_to_job(struct rte_mbuf *pkt, uint64_t buf_addr, int len, int final_len, void *rq_msg, struct toe_engine *toe_eg)
{
	struct toe_sync_dma_job *sjob = NULL;
	struct toe_dma_info *dma = toe_eg->t_dma;
	//struct rte_qdma_job **jobs = toe_eg->data_tx_vring[idx]->rq_info.jobs;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	uint64_t src_addr;
	uint32_t lcore_id;

	if (unlikely(rte_mempool_get(dma->jpool, (void **)&sjob)))
		goto err;

	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;
	printf("%s-%d:len:%d,final_len:%d\n",__func__,__LINE__,len,final_len);

	sjob->meb_num = 1;
	sjob->cb = NULL;
	//sjob->extra2 = (uint64_t)pkt;
	sjob->vaddr = (void *)pkt;
	sjob->cb = toe_tx_databuf_dma_process;
	sjob->extra = 0;
	if (final_len) {
		sjob->cnxt = (void *)rq_msg;
		sjob->extra = final_len;
	}

	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = rte_pktmbuf_iova(pkt);
	sjob->job->dest = buf_addr;
	sjob->job->len = len;
	sjob->job->rbp = rbp;

	return sjob->job;
err:
	if (sjob) {
		rte_free(sjob);
	}
	return NULL;
}
#endif
#if 0
static int toe_tx_mbuf_deq(struct toe_tx_data_queue *node, uint64_t buf_addr, int max_len, struct toe_data_txrq_msg *rq_msg, struct toe_engine *toe_eg, struct rte_qdma_job **jobs)
{
	struct rte_mbuf *pkt_mbuf[MAX_PKT_BURST];
	struct rte_mbuf *mbuf = NULL;
//	struct toe_tx_data_queue *node;
	int i = 0, pkt_num, ret = 0, len = 0, final_len = 0;
	uint16_t jobs_num = 0;
/*
	node = toe_tx_data_node_find(fd);
	if (node == NULL) {
		if (!rq_msg->first) {
			printf("%s-%d:fd:%d not find data node!\n",__func__,__LINE__,fd);
			ret = -1;
			goto err;
		}
		
		node = toe_tx_data_queue_node_create(fd);
		if (node == NULL) {
			printf("%s-%d: fd:%d,create node failed\n",__func__,__LINE__,fd);
			ret = -1;
			goto err;
		}
	}

	if (rte_ring_count(node->ring) == 0)
		goto err;
*/
	pkt_num = max_len / TOE_RECVBUF_SEND_MAX_LEN;
	if (pkt_num == 0) {
		printf("%s-%d:max_len:%d is less than %d\n",__func__,__LINE__,max_len,TOE_RECVBUF_SEND_MAX_LEN);
		RTE_ASSERT(0);
		goto err;
	}
	pkt_num = RTE_MIN(pkt_num, MAX_PKT_BURST);
	ret = rte_ring_mc_dequeue_burst(node->ring, (void **)pkt_mbuf, pkt_num, NULL);
	if (ret == 0) {
		printf("%s-%d:fd:%d,not find pkt in ring!\n",__func__,__LINE__, node->fd);
		goto err;
	}
	printf("%s-%d:pkt_num:%d,ret:%d,max_len:%d\n",__func__,__LINE__,pkt_num,ret,max_len);
	for (i = 0; i < ret; i++) {
		mbuf = pkt_mbuf[i];
		do {
			buf_addr += len;
			len += mbuf->data_len;
						printf("%s-%d:mbuf:%p,data_len:%d,data_len_w:%ld,mbuf->data_off:%d,mbuf->l2_len:%d, mbuf->l3_len:%d,mbuf->l4_len:%d\n",__func__,__LINE__,mbuf,data_len,data_len_w,mbuf->data_off,mbuf->l2_len,mbuf->l3_len,mbuf->l4_len);

			if (i == ret - 1 && !mbuf->next)
				final_len = len;
			if (i < ret - 1 && mbuf == pkt_mbuf[i+1] && data_len_w == (mbuf->dynfield1[0] >> 32)) {
				final_len = len;
			}

			jobs[jobs_num] = toe_tx_databuf_to_job(mbuf, buf_addr, mbuf->data_len, final_len, rq_msg, toe_eg);
			if (!jobs[jobs_num]) {
				ret = jobs_num;
				goto err;
			}
			jobs_num++;
			mbuf = mbuf->next;
		}while(mbuf);
	}

	return jobs_num;
err:
	if (mbuf) {
		
		printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,mbuf);
		rte_pktmbuf_free(mbuf);
		if (i < ret - 1) {
			
			printf("%s-%d: free mbuf bulk: %p, n:%d\n",__func__,__LINE__,pkt_mbuf[i + 1],ret - 1 - i);
			rte_pktmbuf_free_bulk(&pkt_mbuf[i + 1], ret - 1 - i);
		}
	}
	
	return ret;
}
#endif


static void toe_tx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	//struct toe_data_txrq_msg *data_msg = (struct toe_data_txrq_msg *)sjob->cnxt;
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	struct toe_data_dpu_to_host_res *cq_msg;
	struct toe_data_tx_cq_info *cq_info = &toe_eg->data_tx_vring[sjob->qid]->cq_info;
	tcp_stream *stream;
	struct tcp_recv_vars *rcvvar = stream->rcvvar;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int stream_mbuf_head;
	
	if (sjob->extra == 0)
		goto free;
		
	printf("%s-%d: final_len:%ld\n",__func__, __LINE__, sjob->extra);

	if ((cq_info->tail + 1) % cq_info->cq_size == cq_info->head) {
		printf("%s-%d: tx databuf cq full\n",__func__, __LINE__);
		goto free;
	}

	stream = sjob->cnxt;
	stream_mbuf_head = sjob->extra4;
	while((stream->rcvvar->rcvbuf->data_buf.head + 1) % stream->rcvvar->rcvbuf->data_buf.size != stream_mbuf_head) {
		rte_pktmbuf_free(stream->rcvvar->rcvbuf->data_buf.m_data[stream->rcvvar->rcvbuf->data_buf.head]);
		stream->rcvvar->rcvbuf->data_buf.head = (stream->rcvvar->rcvbuf->data_buf.head + 1) % stream->rcvvar->rcvbuf->data_buf.size;
	}

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

	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->data_len = sjob->extra;
	cq_msg->recv_list_virtaddr = sjob->extra3;
	cq_msg->complete = cq_info->cq_compl;
	cq_msg->identification.host_dataptr = sjob->extra2;
	cq_msg->rq_head = rq_info->head;

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
	
	//rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
	
free:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

/*
static struct rte_qdma_job * toe_tx_databuf_to_job(struct rte_mbuf *pkt, uint64_t buf_addr, int len, int final_len, int fd, uint64_t hst_recv_buf, struct toe_engine *toe_eg, int qid)
{
	struct toe_sync_dma_job *sjob = NULL;
	struct toe_dma_info *dma = toe_eg->t_dma;
	//struct rte_qdma_job **jobs = toe_eg->data_tx_vring[idx]->rq_info.jobs;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	uint64_t src_addr;
	uint32_t lcore_id;

	if (unlikely(rte_mempool_get(dma->jpool, (void **)&sjob))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		goto err;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;
	printf("%s-%d:pkt:%p,pkt->data_len:%d,(pkt->dynfield1[0] >> 32):%lulen:%d,final_len:%d\n",__func__,__LINE__,pkt,pkt->data_len,(pkt->dynfield1[0] >> 32),len,final_len);

	sjob->meb_num = 1;
	sjob->cb = NULL;
	sjob->vaddr = (void *)pkt;
	sjob->cb = toe_tx_databuf_dma_process;
	sjob->extra = 0;
	sjob->extra2 = 0;
	sjob->qid = qid;
	if (final_len) {
		//sjob->cnxt = (void *)site;
		sjob->extra = final_len;
		sjob->extra2 = fd;
		//sjob->extra2 = (sjob->extra2 << 32) | site;
		sjob->extra3 = hst_recv_buf;
	}

	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = rte_pktmbuf_iova(pkt);
	sjob->job->dest = buf_addr;
	sjob->job->len = len;
	sjob->job->rbp = rbp;

	return sjob->job;
err:
	if (sjob) {
		rte_mempool_put(dma->jpool, sjob);
	}
	return NULL;
}
*/
struct rte_qdma_job * toe_tx_databuf_to_job(struct rte_mbuf *pkt, uint64_t buf_addr, int len, int final_len, uint32_t host_dataptr, uint64_t host_list_addr, struct toe_engine *toe_eg, int qid, tcp_stream *stream, int stream_mbuf_head)
{
	struct toe_sync_dma_job *sjob = NULL;
	struct toe_dma_info *dma = toe_eg->t_dma;
	//struct rte_qdma_job **jobs = toe_eg->data_tx_vring[idx]->rq_info.jobs;
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
//	uint64_t src_addr;
	uint32_t lcore_id;

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
		//sjob->vaddr = (void *)stream;
		sjob->cb = toe_tx_databuf_dma_process;
		sjob->extra = final_len;
		sjob->extra2 = host_dataptr;
		//sjob->extra2 = (sjob->extra2 << 32) | site;
		sjob->extra3 = host_list_addr;
		sjob->extra4 = stream_mbuf_head;
	}

	sjob->job->cnxt = (uint64_t) sjob;
	sjob->job->src = rte_pktmbuf_iova(pkt);
	sjob->job->dest = buf_addr;
	sjob->job->len = len;
	sjob->job->rbp = rbp;

	return sjob->job;
err:
	if (sjob) {
		rte_mempool_put(dma->jpool, sjob);
	}
	return NULL;
}

static int toe_tx_mbuf_deq(struct toe_tx_data_queue *node, uint64_t buf_addr, int max_len, int site, struct toe_engine *toe_eg, struct rte_qdma_job **jobs, int qid)
{
	struct rte_mbuf *pkt_mbuf[MAX_PKT_BURST];
	struct rte_mbuf *mbuf = NULL;
//	struct toe_tx_data_queue *node;
	int i = 0, pkt_num, ret = 0, len = 0,final_len = 0;
	uint64_t data_len_w, count;
	uint16_t data_len;
	uint16_t jobs_num = 0;

	pkt_num = max_len / TOE_RECVBUF_SEND_PER_MAX_LEN;
	if (pkt_num == 0) {
		printf("%s-%d:max_len:%d is less than %d\n",__func__,__LINE__,max_len,TOE_RECVBUF_SEND_PER_MAX_LEN);
		RTE_ASSERT(0);
		goto err;
	}
	pkt_num = RTE_MIN(pkt_num, MAX_PKT_BURST);
	ret = rte_ring_mc_dequeue_burst(node->ring, (void **)pkt_mbuf, pkt_num, NULL);
	if (ret == 0) {
		printf("%s-%d:fd:%d,not find pkt in ring!\n",__func__,__LINE__, node->fd);
		goto err;
	}
	printf("%s-%d:pkt_num:%d,ret:%d,max_len:%d\n",__func__,__LINE__,pkt_num,ret,max_len);
	for (i = 0; i < ret; i++) {
		mbuf = pkt_mbuf[i];

		data_len_w = (mbuf->dynfield1[1] & 0xffffffff);
		data_len = data_len_w - (mbuf->data_off - RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)mbuf->buf_len) - mbuf->l2_len - mbuf->l3_len - mbuf->l4_len);
		printf("%s-%d:mbuf:%p,data_len:%d,data_len_w:%ld,mbuf->data_off:%d,mbuf->l2_len:%d, mbuf->l3_len:%d,mbuf->l4_len:%d\n",__func__,__LINE__,mbuf,data_len,data_len_w,mbuf->data_off,mbuf->l2_len,mbuf->l3_len,mbuf->l4_len);

		if (data_len > 0) {
			len += data_len;
			if (i == ret - 1)
				final_len = len;

			if (ret > 1) {
					if (i == ret - 2 && mbuf == pkt_mbuf[i+1] && data_len_w == (mbuf->dynfield1[0] >> 32)) {
						final_len = len;
				}
			}

			jobs[jobs_num] = toe_tx_databuf_to_job(mbuf, buf_addr, data_len, final_len, node->fd, node->host_buf[site].host_recv_buf_addr, toe_eg, qid, NULL, 0);
			if (!jobs[jobs_num]) {
				ret = jobs_num;
				goto err;
			}
			mbuf->data_off += data_len;
			buf_addr += data_len;
			jobs_num++;
		} else {
			count = (mbuf->dynfield1[1] >> 32) & 0xffffffff;
			mbuf->dynfield1[1] -= 0x100000000;
			printf("%s-%d: (mbuf->dynfield1[0] >> 32):%lu\n",__func__,__LINE__,(mbuf->dynfield1[0] >> 32));
			if (data_len_w == (mbuf->dynfield1[0] >> 32) && count <= 1) {
				printf("%s-%d:data is 0, count:%ld\n",__func__,__LINE__,count);
				mbuf->dynfield1[0] = 0;
				mbuf->dynfield1[1] = 0;
				printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,mbuf);
				rte_pktmbuf_free(mbuf);
			}
		}

/*
		do {
			data_len_w = (mbuf->dynfield1[1] & 0xffffffff);
			data_len = data_len_w - (mbuf->data_off - RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)mbuf->buf_len) - mbuf->l2_len - mbuf->l3_len - mbuf->l4_len);
			printf("%s-%d:mbuf:%p,data_len:%d,data_len_w:%ld,mbuf->data_off:%d,mbuf->l2_len:%d, mbuf->l3_len:%d,mbuf->l4_len:%d\n",__func__,__LINE__,mbuf,data_len,data_len_w,mbuf->data_off,mbuf->l2_len,mbuf->l3_len,mbuf->l4_len);

			if (data_len > 0) {
				len += data_len;
				if (i == ret - 1 && !mbuf->next)
					final_len = len;

				if (ret > 1) {
						if (i == ret - 2 && mbuf == pkt_mbuf[i+1] && data_len_w == (mbuf->dynfield1[0] >> 32)) {
							final_len = len;
					}
				}

				jobs[jobs_num] = toe_tx_databuf_to_job(mbuf, buf_addr, data_len, final_len, node->fd, node->host_buf[site].host_recv_buf_addr, toe_eg, qid);
				if (!jobs[jobs_num]) {
					ret = jobs_num;
					goto err;
				}
				mbuf->data_off += data_len;
				buf_addr += data_len;
				jobs_num++;
			} else {
				count = (mbuf->dynfield1[1] >> 32) & 0xffffffff;
				mbuf->dynfield1[1] -= 0x100000000;
				printf("%s-%d: (mbuf->dynfield1[0] >> 32):%lu\n",__func__,__LINE__,(mbuf->dynfield1[0] >> 32));
				if (data_len_w == (mbuf->dynfield1[0] >> 32) && count <= 1) {
					printf("%s-%d:data is 0, count:%d\n",__func__,__LINE__,count);
					mbuf->dynfield1[0] = 0;
					mbuf->dynfield1[1] = 0;
					printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,mbuf);
					rte_pktmbuf_free(mbuf);
				}
			}
			mbuf = mbuf->next;
		}while(mbuf);
		*/
	}

	return jobs_num;
err:
	if (mbuf) {
		
		printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,mbuf);
		rte_pktmbuf_free(mbuf);
		if (i < ret - 1) {
			
			printf("%s-%d: free mbuf bulk: %p, n:%d\n",__func__,__LINE__,pkt_mbuf[i + 1],ret - 1 - i);
			rte_pktmbuf_free_bulk(&pkt_mbuf[i + 1], ret - 1 - i);
		}
	}
	
	return ret;
}

#if 0 /* not use*/
void toe_tx_databuf_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[idx]->rq_info;
	struct toe_data_txrq_msg *data_msg;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct rte_qdma_enqdeq e_context;
	struct toe_dma_hwq *hwq;
	struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
	struct toe_sync_dma_job *sjob = NULL;
	struct toe_tx_data_queue *node = NULL;
	uint32_t lcore_id;
	int num, i, j, site, ret, job_num;

	num = rq_info->real_tail - rq_info->head;
	if (num == 0)
		return;
		
	//printf("%s-%d: rq_info->local_tail:%d,pre_tx_head:%d\n",__func__,__LINE__,rq_info->local_tail,rq_info->pre_tx_head);
	if (num < 0)
		num += rq_info->rq_size;

	lcore_id = rte_lcore_id();
	hwq = &tdma_hwq[lcore_id];

	for (i = 0; i < num; i++) {
		site = rq_info->head;
		data_msg = rq_info->rq_local + site;

		if (data_msg->kernel_fd != toe_eg->fd_save_kernel[data_msg->fd]) {
			printf("$$%s-%d:idx:%d tx data process close fd rq, fd:%d, old kernel fd:0x%lx, new kernel fd:0x%lx\n",__func__,__LINE__,idx,data_msg->fd, data_msg->kernel_fd, toe_eg->fd_save_kernel[data_msg->fd]);
			rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
			continue;
		}
		node = toe_tx_data_node_find(data_msg->fd, idx);
		if (node == NULL) {
			
			printf("___ %s-%d: NULL!! idx:%d, site:%d,data_msg->fd:%d,data_msg->first:%d,rq_info->local_tail:%d,pre_tx_head:%d, data_msg->host_recv_buf_addr:0x%lx, data_msg->data_buffer_addr:0x%lx\n",
				__func__,__LINE__,idx,site,data_msg->fd,data_msg->first,rq_info->real_tail,rq_info->head,data_msg->host_recv_buf_addr, data_msg->data_buffer_addr);
			if (data_msg->first == 1) {
				printf("^^^ %s-%d:data_msg->first,site:%d,data_msg->fd:%d,rq_info->local_tail:%d,pre_tx_head:%d, data_msg->host_recv_buf_addr:0x%lx\n",
					__func__,__LINE__,site,data_msg->fd,rq_info->real_tail,rq_info->head,data_msg->host_recv_buf_addr);
				if (toe_tx_data_first_process(data_msg->fd, &node, toe_eg, idx) < 0) { 
					rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
					continue;
				} else {
					node->host_buf[node->host_buf_tail].data_buffer_addr = data_msg->data_buffer_addr;
					node->host_buf[node->host_buf_tail].data_len = data_msg->data_len;
					node->host_buf[node->host_buf_tail].host_recv_buf_addr = data_msg->host_recv_buf_addr;
					node->host_buf_tail = (node->host_buf_tail + 1) % TOE_MAX_HOST_BUF_NUM;
				}
			} else {					
				rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
				continue;
			}
			
		}else {
		
				printf("___ %s-%d: site:%d,qid:%d,data_msg->fd:%d,data_msg->first:%d,rq_info->local_tail:%d,pre_tx_head:%d, data_msg->host_recv_buf_addr:0x%lx,data_msg->data_buffer_addr:0x%lx,node->host_buf_tail:%d,node->host_buf_head:%d\n",
					__func__,__LINE__,site,idx,data_msg->fd,data_msg->first,rq_info->real_tail,rq_info->head,data_msg->host_recv_buf_addr,data_msg->data_buffer_addr,node->host_buf_tail,node->host_buf_head);
				RTE_ASSERT(((node->host_buf_tail + 1) % TOE_MAX_HOST_BUF_NUM) != node->host_buf_head);
				node->host_buf[node->host_buf_tail].data_buffer_addr = data_msg->data_buffer_addr;
				node->host_buf[node->host_buf_tail].data_len = data_msg->data_len;
				node->host_buf[node->host_buf_tail].host_recv_buf_addr = data_msg->host_recv_buf_addr;
				node->host_buf_tail = (node->host_buf_tail + 1) % TOE_MAX_HOST_BUF_NUM;
		}

		if (toe_tx_data_rq_to_cq(data_msg->fd, rq_info->head, idx, toe_eg))
			break;
		rq_info->head = (rq_info->head + 1) % rq_info->rq_size;

/**************************************************		
		if (rte_ring_count(node->ring) == 0)
				continue;
		
		printf("%s-%d:site:%d,data_msg:fd:%d,data_buffer_addr:0x%lx,data_len:%u,host_recv:0x%lx,data_msg->first:%d\n",__func__,__LINE__,site,
			data_msg->fd,data_msg->data_buffer_addr,data_msg->data_len,data_msg->host_recv_buf_addr,data_msg->first);
		ret = toe_tx_mbuf_deq(node, data_msg->data_buffer_addr, data_msg->data_len, data_msg, toe_eg, &jobs);

		if (ret == 0)
			continue;

		job_num = ret;
		printf("%s-%d:job_num:%d\n",__func__,__LINE__,job_num);
		rq_info->pre_tx_head = (rq_info->pre_tx_head + 1) % rq_info->rq_size;
		
		printf("%s-%d: rq_info->pre_tx_head add: %d\n",__func__,__LINE__,rq_info->pre_tx_head);
		e_context.vq_id = hwq->vq;
		e_context.job = jobs;
		ret = rte_qdma_enqueue_buffers(dma->id, NULL,  job_num, &e_context);
		if (ret < job_num) {
			for (j = ret; j < job_num; j ++) {
				sjob = (struct toe_sync_dma_job *)jobs[j]->cnxt;
				
				printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,sjob->vaddr);
				rte_pktmbuf_free((struct rte_mbuf *)sjob->vaddr);
				rte_mempool_put(toe_eg->t_dma->jpool, sjob);
			}
		}

*****************************************************/
	}
	
	return;
}
#endif
static void toe_tx_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	printf("%s-%d: sjob->qid:%d ,sjob->meb_num:%d\n", __func__,__LINE__, sjob->qid,sjob->meb_num);
	printf("%s-%d: rq_info->rq_local->opcode:%d,rq_info->rq_local->identification.host_dataptr:%d\n", __func__,__LINE__, rq_info->rq_local->opcode,rq_info->rq_local->identification.host_dataptr);

	int i;
	for (i = 0; i < TOE_RECV_BUFFER_COUNT_RESERVED; i++) {
		printf("%s-%d:rq_info->rq_local->recv_buffer[i].recv_buffer_len:%d,rq_info->rq_local->recv_buffer[i].recv_buffer_addr:0x%lx,rq_info->rq_local->recv_buffer[i].host_list_addr:0x%lx\n", __func__,__LINE__, rq_info->rq_local->recv_buffer[i].recv_buffer_len,rq_info->rq_local->recv_buffer[i].recv_buffer_phyaddr,rq_info->rq_local->recv_buffer[i].host_list_virtaddr);
	}
	rq_info->real_tail = (rq_info->real_tail + sjob->meb_num) % rq_info->rq_size;
	
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
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


int toe_rx_ctl_rq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_ctl_rq_info *ctl_rq = &toe_eg->ctl_rx_vring[idx]->rq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;
//	int tail_num;
	uint16_t doorbell = ctl_rq->rbc->doorbell;

	if (ctl_rq->tail == doorbell)
		return 0;
	
	ctl_rq->tail = doorbell % ctl_rq->rq_size;
	
	nb_meb[0] = ctl_rq->tail - ctl_rq->local_head;
	nb_meb[1] = 0;
	head[0] = ctl_rq->local_head;
	head[1] = 0;

	if (nb_meb[0] < 0) {
		nb_meb[0] = ctl_rq->rq_size - ctl_rq->local_head;
		nb_meb[1] = ctl_rq->tail;
	
		num_jobs = 2;
	}
		printf("$$$%s-%d: nb_meb[0]:%d,nb_meb[1]:%d,head[0]:%d\n",__func__,__LINE__,nb_meb[0],nb_meb[1],head[0]);
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();
	//lcore_id = rte_get_master_lcore();

	hwq = &tdma_hwq[lcore_id];
	printf("*&& %s-%d: hwq:%p,lcore_id:%d\n",__func__,__LINE__,hwq,lcore_id);
	rbp = &hwq->R_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_rx_ctl_dma_process;
		//sjob[i]->rq_info = (void *)ctl_rq;
		sjob[i]->qid = idx;
		src_addr = toe_addr32_to_addr64(ctl_rq->rbc->queue_desc_h, ctl_rq->rbc->queue_desc_lo)
								+ head[i] * TOE_CTRL_RQ_MSG_SIZE;
	
		dst_addr = (uint64_t)(ctl_rq->rq_local + head[i]);

		sjob[i]->vaddr = (void *)dst_addr;
		//printf("^^##%s-%d: ctl_rq->rq_local:0x%p,head[i]:%d,dst_addr:0x%lx,sjob[i]->vaddr:%p, src_addr:0x%lx,TOE_CTRL_RXRQ_MSG_SIZE:%d\n",__func__,__LINE__,ctl_rq->rq_local,head[i],dst_addr,sjob[i]->vaddr,src_addr,TOE_CTRL_RXRQ_MSG_SIZE);
		//rte_hexdump(stdout, "ctrl cq ", (const void *)(ctl_rq->rq_local + head[i]),TOE_CTRL_RXRQ_MSG_SIZE * nb_meb[i]);


		dst_addr = rte_mem_virt2iova((void *)dst_addr);
		job_len = nb_meb[i] * TOE_CTRL_RQ_MSG_SIZE;

		sjob[i]->job->cnxt = (uint64_t) sjob[i];
		sjob[i]->job->src = src_addr;
		sjob[i]->job->dest = dst_addr;
		sjob[i]->job->len = job_len;
		sjob[i]->job->rbp = rbp;

		jobs[i] = sjob[i]->job;
		printf("#@# %s-%d:sjob[i]->job:%p\n",__func__,__LINE__,sjob[i]->job);
	}
	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL,  num_jobs, &e_context);
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		ctl_rq->local_head = (ctl_rq->local_head + nb_meb[i]) % ctl_rq->rq_size;
	
	return ret;
}

int toe_rx_ctl_cq_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_ctl_cq_info *ctl_cq = &toe_eg->ctl_rx_vring[idx]->cq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;

	if (ctl_cq->pre_head == ctl_cq->tail)
		return 0;
	
	printf("!! %s-%d: old ctl_cq->tail:%d,ctl_cq->head:%d ,ctl_cq->pre_head:%d, ctl_cq->pre_tail:%d, now:%lu\n",__func__,__LINE__,ctl_cq->tail,ctl_cq->head,ctl_cq->pre_head,ctl_cq->pre_tail, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
	nb_meb[0] = ctl_cq->tail - ctl_cq->pre_head;
	nb_meb[1] = 0;
	head[0] = ctl_cq->pre_head;
	head[1] = 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = ctl_cq->cq_size - ctl_cq->pre_head;
		nb_meb[1] = ctl_cq->tail;
	
		num_jobs = 2;
	}
	
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->W_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_ctl_reply_dma_process;
		sjob[i]->qid = idx;
 

		src_addr = (uint64_t)(ctl_cq->cq_local + head[i]);
		sjob[i]->vaddr = (void*)src_addr;
			
		dst_addr = toe_addr32_to_addr64(ctl_cq->cbc->queue_desc_h, ctl_cq->cbc->queue_desc_lo)
								+ head[i] * TOE_CTRL_CQ_MSG_SIZE;

		//printf("%s-%d:num_jobs:%d i:%d, sjob[i]->meb_num:%d, dst_addr:0x%lx, TOE_CTRL_RXCQ_MSG_SIZE:%d\n",__func__,__LINE__,num_jobs,i,sjob[i]->meb_num,dst_addr,TOE_CTRL_RXCQ_MSG_SIZE);
		//sjob[i]->vaddr = (void *)dst_addr;
		src_addr = rte_mem_virt2iova((void *)src_addr);
		job_len = nb_meb[i] * TOE_CTRL_CQ_MSG_SIZE;

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
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		ctl_cq->pre_head = (ctl_cq->pre_head + nb_meb[i]) % ctl_cq->cq_size;
	
	return ret;
}

int toe_rx_data_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_rx_rq_info *data_rq = &toe_eg->data_rx_vring[idx]->rq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;

	if (data_rq->tail == data_rq->rbc->doorbell)
		return 0;
	
	data_rq->tail = data_rq->rbc->doorbell % data_rq->rq_size;
	nb_meb[0] = data_rq->tail - data_rq->pre_head;
	nb_meb[1] = 0;
	head[0] = data_rq->pre_head;
	head[1] = 0;

	if (nb_meb[0] == 0)
		return 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = data_rq->rq_size - data_rq->pre_head;
		nb_meb[1] = data_rq->tail;
	
		num_jobs = 2;
	}
	
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->R_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_rx_data_dma_process;
		sjob[i]->qid = idx;
		
		src_addr = toe_addr32_to_addr64(data_rq->rbc->queue_desc_h, data_rq->rbc->queue_desc_lo)
								+ head[i] * TOE_DATA_RXRQ_MSG_SIZE;

		dst_addr = data_rq->rq_local + head[i];
		sjob[i]->vaddr = (void *)dst_addr;
		dst_addr = rte_mem_virt2iova((void *)dst_addr);
		job_len = nb_meb[i] * TOE_DATA_RXRQ_MSG_SIZE;

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
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, &sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		data_rq->pre_head = (data_rq->pre_head + nb_meb[i]) % data_rq->rq_size;

	return ret;

}

int toe_tx_data_dma_enqueue(struct toe_engine *toe_eg, int idx)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[idx]->rq_info;
	int nb_meb[2], num_jobs = 1, head[2];
	uint64_t src_addr, dst_addr;
	uint32_t job_len;
	uint32_t lcore_id;
	int i;
	int ret;
	
	//ctl_rq->tail = toe_rq_doorbell_get((uint8_t *)t_ring->toe_eg->bar, TOE_CTRL_RX);
	if (data_rq->tail == data_rq->rbc->doorbell)
		return 0;
	
	printf("^^ %s-%d: old data_rq->tail:%d,data_rq->head:%d,data_rq->pre_head:%d,data_rq->rbc->doorbell:%d \n",
	__func__,__LINE__,data_rq->tail,data_rq->head,data_rq->pre_head,data_rq->rbc->doorbell);
	data_rq->tail = data_rq->rbc->doorbell % data_rq->rq_size;
	nb_meb[0] = data_rq->tail - data_rq->pre_head;
	nb_meb[1] = 0;
	head[0] = data_rq->pre_head;
	head[1] = 0;
	
	if (nb_meb[0] == 0)
		return 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = data_rq->rq_size - data_rq->pre_head;
		nb_meb[1] = data_rq->tail;
	
		num_jobs = 2;
	}
	
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();

	hwq = &tdma_hwq[lcore_id];

	rbp = &hwq->R_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_tx_data_dma_process;
		sjob[i]->qid = idx;
		
		src_addr = toe_addr32_to_addr64(data_rq->rbc->queue_desc_h, data_rq->rbc->queue_desc_lo)
								+ head[i] * TOE_DATA_TXRQ_MSG_SIZE;

		dst_addr = data_rq->rq_local + head[i];
		sjob[i]->vaddr = (void *)dst_addr;
		dst_addr = rte_mem_virt2iova((void *)dst_addr);
		job_len = nb_meb[i] * TOE_DATA_TXRQ_MSG_SIZE;

		sjob[i]->job->cnxt = (uint64_t) sjob[i];
		sjob[i]->job->src = src_addr;
		sjob[i]->job->dest = dst_addr;
		sjob[i]->job->len = job_len;
		sjob[i]->job->rbp = rbp;

		jobs[i] = sjob[i]->job;
	}
	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL, num_jobs, &e_context);
	if (ret < num_jobs) {
		rte_mempool_put_bulk(dma->jpool, &sjob[ret], num_jobs - ret);
		
	}
	
	for (i = 0; i < ret; i++)
		data_rq->pre_head = (data_rq->pre_head + nb_meb[i]) % data_rq->rq_size;

	return ret;
}


#define dma_init

static void toe_dma_job_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned int idx)
{
	struct toe_sync_dma_job *job = obj;
	struct toe_dma_info *dma = opaque;
	memset(job, 0, sizeof(*job));
	//job->t_dma = dma;
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
/*
	if (elt_size < sizeof(struct agiep_async_dma_group))
		elt_size = sizeof(struct agiep_async_dma_group);
*/
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
		printf("%s-%d: hwq->vq:%d\n",__func__,__LINE__,hwq->vq);
		//for (i = 0; i < pf_num; i++) {
			//pf = pfs[i];
			//for (vf = 0; vf < vf_num[i]; vf++) {
				//rbp = &hwq->R_rbp[pf][vf];
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
			//}
		//}

		rte_compiler_barrier();
		hwq->enable = 1;
	}
}

int toe_dma_init(struct toe_engine *toe_eg)
{
	struct toe_dma_info *dma;
	//cpu_set_t mask;
	//uint16_t lcoreid = 0;
	const char *thread_name = "toe_ctrl_loop";
	const char *cq_thread_name = "toe_cq_loop";
	int ret;

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
#if 0
	assert(TOE_CTRL_thread == 0);
	ret = pthread_create(&TOE_CTRL_thread, NULL, toe_ctrl_dma_loop, toe_eg);
	if (ret) {
		printf("%s-%d toe ctrl thread create failed!\n", __func__, __LINE__);
		goto failed;
	}
	ret = pthread_setname_np(TOE_CTRL_thread, thread_name);
	if (ret)
		goto failed;
	#endif
/*
	lcoreid = rte_lcore_id();
	CPU_ZERO(&mask);
	CPU_SET(lcoreid, &mask);
	printf("@@@ %s-%d: lcore:%d\n",__func__,__LINE__,lcoreid);
	ret = pthread_setaffinity_np(TOE_CTRL_thread, sizeof(mask), &mask);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "toe: set TOE_CTRL_thread cpu id fail: %d\n", ret);
*/

	#if 0
	assert(TOE_DATA_CQ_thread == 0);
	ret = pthread_create(&TOE_DATA_CQ_thread, NULL, toe_data_cq_dma_loop, toe_eg);
	if (ret) {
		printf("%s-%d toe data cq thread create failed!\n", __func__, __LINE__);
		goto failed;
	}
	ret = pthread_setname_np(TOE_DATA_CQ_thread, cq_thread_name);
	if (ret)
		goto failed;
#endif

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
	printf("~~ %s-%d: dma reset start \n", __func__,__LINE__);
	do {
		now = rte_rdtsc()/rte_get_tsc_hz();
		ret = toe_dma_dequeue(toe_eg);
		if (ret > 0)
			last = now;
	}while ((now - last) < 2);

	for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {

		toe_eg->ctl_rx_vring[i]->rq_info.local_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.tail = 0;


		toe_eg->ctl_rx_vring[i]->cq_info.pre_head = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.head = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.cq_compl = 1;
		printf("%s-%d: ctrl rq cq set 0!\n",__func__,__LINE__);

		ret = rte_atomic16_read(&toe_eg->ctl_rx_vring[i]->rq_info.wait_head_num);
		if (ret != 0) {
			printf("%s-%d: ctrl rq vring wait_head_num:%d, it's should be 0!\n",__func__,__LINE__,ret);
			
			rte_atomic16_set(&toe_eg->ctl_rx_vring[i]->rq_info.wait_head_num, 0);
		}
		
		ret = rte_atomic16_read(&toe_eg->ctl_rx_vring[i]->cq_info.wait_tail_num);
		if (ret != 0) {
			printf("%s-%d: ctrl cq vring wait_tail_num:%d, it's should be 0!\n",__func__,__LINE__,ret);
			
			rte_atomic16_set(&toe_eg->ctl_rx_vring[i]->cq_info.wait_tail_num, 0);
		}
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		toe_eg->data_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_rx_vring[i]->rq_info.head = 0;
		toe_eg->data_rx_vring[i]->rq_info.real_tail = 0;
		toe_eg->data_rx_vring[i]->rq_info.tail = 0;

		toe_eg->data_rx_vring[i]->cq_info.pre_head = 0;
		toe_eg->data_rx_vring[i]->cq_info.head = 0;
		toe_eg->data_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.cq_compl = 1;

		toe_eg->data_tx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_tx_vring[i]->rq_info.head = 0;
		toe_eg->data_tx_vring[i]->rq_info.real_tail = 0;
		toe_eg->data_tx_vring[i]->rq_info.tail = 0;

		//toe_eg->data_tx_vring[i]->cqad = 0;
		toe_eg->data_tx_vring[i]->cq_info.tail = 0;
		toe_eg->data_tx_vring[i]->cq_info.cq_compl = 1;
		
	//printf("%s-%d: data rq set 0!\n",__fu	printf("%s-%d: data	printf("%s-%d: data rq set 0!\n",__func__,__LINE__);
	}

	return;
}

