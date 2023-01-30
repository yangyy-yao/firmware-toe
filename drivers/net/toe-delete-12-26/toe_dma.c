
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

extern uint64_t loop_count;

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
	
	//printf("@# %s-%d: meb_num:%d \n",__func__,__LINE__,meb_num);
	for (i = 0; i < meb_num; i++) {
			vaddr = (char *)sjob->vaddr + i * TOE_CTRL_RQ_MSG_SIZE;
			srcaddr = sjob->job->src + i * TOE_CTRL_RQ_MSG_SIZE;
			//printf("@# %s-%d: srcaddr:0x%lx, i:%d, qid:%d\n",__func__,__LINE__,srcaddr, i, qid);
	
			ctl_rq->pre_head = (ctl_rq->pre_head + 1) % ctl_rq->rq_size;
			toe_ctl_recv(vaddr, toe_eg, qid);
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
	//struct toe_ctrl_host_to_dpu_res *cq_local = sjob->vaddr;
	//int num = sjob->meb_num;
	//int i;
	//uint64_t dstaddr = sjob->job->dest;
/*
	for(i = 0; i < num; i ++) {

		dstaddr += i * TOE_CTRL_CQ_MSG_SIZE;
		
		cq_local++;
	}
	*/
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	toe_irq_raise(toe_eg, toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector);
	//printf("##$$ %s-%d: msi_vector:%d, qid:%d,now:%lu\n",__func__,__LINE__,toe_eg->ctl_rx_vring[qid]->cq_info.cbc->msi_vector,qid,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
        //printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);
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
	if (unlikely(ret < num_jobs)) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		data_cq->pre_head = (data_cq->pre_head + nb_meb[i]) % data_cq->cq_size;
	
	return;
}

static void toe_rx_data_fill_cq_msg(struct toe_data_rx_rq_info *data_rq, uint16_t len, uint8_t result, struct toe_engine *toe_eg, struct toe_data_host_to_dpu_req *rq_msg, void *stream, int qid)
{
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[qid]->cq_info;
	struct toe_data_host_to_dpu_res *cq_msg;
	uint16_t cq_rq_head;

	cq_info->head = cq_info->cbc->doorbell;
	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == cq_info->head)) {
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

static void toe_prepare_buffer_fill_cq_msg(struct toe_data_rx_rq_info *data_rq, uint16_t len, uint8_t result, struct toe_engine *toe_eg, struct tcp_prepare_read *node, int qid)
{
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[qid]->cq_info;
	struct toe_data_host_to_dpu_res *cq_msg;
	uint16_t cq_rq_head;

	cq_info->head = cq_info->cbc->doorbell;
	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == cq_info->head)) {
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

static void toe_rx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	//struct toe_data_host_to_dpu_req *data_msg = (struct toe_data_host_to_dpu_req *)sjob->cnxt;
	struct toe_data_host_to_dpu_res *cq_msg;
	struct toe_data_rx_cq_info *cq_info = &toe_eg->data_rx_vring[sjob->qid]->cq_info;
	struct toe_data_rx_rq_info *rq_info = &toe_eg->data_rx_vring[sjob->qid]->rq_info;
	//void *buff = sjob->vaddr;
#ifdef TOE_TSO
	struct rte_mbuf **buff;
#endif
	tcp_stream *stream = (tcp_stream *)sjob->priv_addr;
	int qid = sjob->qid;

	//rte_pktmbuf_dump(stdout,buff, buff->pkt_len);
	
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
    //printf("%s-%d: !!! stream->sndvar->tcp_data_ring.tail=%u  free_num=%u\n",__func__, __LINE__, stream->sndvar->tcp_data_ring.tail, stream->sndvar->tcp_data_ring.free_num);
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

static int toe_host_buffer_insert(tcp_stream *stream, struct toe_data_host_to_dpu_req *data_msg, int m_num)
{
	struct tcp_prepare_read *node;
	int rc;
	if (stream->sndvar->pre_read_list.head != NULL) {
		rc = rte_mempool_get(stream->sndvar->pre_read_list.poor, (void **)&node);
		if (unlikely(rc != 0)) {
			RTE_LOG(ERR, PMD, "%s-%d: tcp prepare nod get failed! \n", __func__, __LINE__);
      return -1;
		}
		//printf("%s-%d: insert list head:%p tail:%p,node:%p\n",__func__,__LINE__,stream->sndvar->pre_read_list.head, stream->sndvar->pre_read_list.tail, node);
		node->host_buffer_phyaddr = data_msg->send_buffer_addr;
		node->host_buffer_viraddr = data_msg->send_list_addr;
		node->len = data_msg->data_len;
		stream->sndvar->pre_read_list.tail->next = node;
		stream->sndvar->pre_read_list.tail = node;
		return 1;
	}

	if (stream->sndvar->snd_wnd < data_msg->data_len
		|| stream->sndvar->tcp_data_ring.free_num < m_num) {
		rc = rte_mempool_get(stream->sndvar->pre_read_list.poor, (void **)&node);
		if (unlikely(rc != 0)) {
			RTE_LOG(ERR, PMD, "%s-%d: tcp prepare nod get failed! \n", __func__, __LINE__);
			return -1;
		}
		
		node->host_buffer_phyaddr = data_msg->send_buffer_addr;
		node->host_buffer_viraddr = data_msg->send_list_addr;
		node->len = data_msg->data_len;
		stream->sndvar->pre_read_list.head = node;
		stream->sndvar->pre_read_list.tail = node;
		
		//printf("%s-%d: insert list head:%p\n",__func__,__LINE__,stream->sndvar->pre_read_list.head);
		return 1;
	}

	return 0;
}

void toe_prepare_list_remove_head(struct tcp_prepare_read_list *list, struct tcp_prepare_read *read_head)
{
	
	list->head = read_head->next;
	read_head->next = NULL;

	if (read_head == list->tail)
		list->tail = NULL;
	//printf("%s-%d: remove list head:%p,new head:%p,tail:%p\n",__func__,__LINE__,read_head,list->head,list->tail);

	rte_mempool_put(list->poor, read_head);
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
	//printf("%s-%d:read_head:%p\n",__func__,__LINE__,read_head);
	if (!read_head)
		return 0;
	
	if (!stream->sndvar->tcp_data_ring.free_num || !stream->sndvar->snd_wnd) {
		//printf("%s-%d: tcp_data_ring free_num:%u is 0 or stream->sndvar->snd_wnd:%u is 0\n",__func__,__LINE__,stream->sndvar->tcp_data_ring.free_num,stream->sndvar->snd_wnd);
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
		//printf("%s-%d:read_head:%p,read_head->len:%u\n",__func__,__LINE__,read_head,read_head->len);
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
		//printf("%s-%d:stream->sndvar->tcp_data_ring.prev_tail:%d\n",__func__,__LINE__,stream->sndvar->tcp_data_ring.prev_tail);
#endif
		if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **)sjob, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: sjob alloc failed!\n", __func__, __LINE__);
			goto err;
		}

		//printf("%s-%d: en_num:%d,m_num:%d,count:%d,m_final_num:%d,m_final_num2:%d\n",__func__,__LINE__,en_num,m_num,count,m_final_num,m_final_num2);
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
			//printf("%s-%d:sjob[%d]:%p,head_mbuf:%p,head_mbuf->nb_seg:%d,d_mbuf:%p,idx:%d\n", __func__,__LINE__,i,sjob[i],head_mbuf, head_mbuf->nb_segs,d_mbuf,idx);
			sjob[i]->meb_num = 0;
			sjob[i]->cb = NULL;
			sjob[i]->qid = idx;
			sjob[i]->priv_addr = (void *)d_mbuf;
			sjob[i]->vaddr = NULL;
			sjob[i]->cnxt = NULL;

						
			src_addr = read_head->host_buffer_phyaddr + en_len;
			dst_addr = rte_pktmbuf_iova(d_mbuf);
			job_len = RTE_MIN(allow_data_len - en_len, data_len);
			//printf("%s-%d:allow_data_len:%d,mbufs[i]->buf_len:%d,job_len:%d,en_len:%d\n", __func__,__LINE__,allow_data_len, mbufs[i]->buf_len, job_len,en_len);
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
			
			//printf("%s-%d:d_mbuf:%p,d_mbuf->data_len:%d,job_len:%d,i:%d\n", __func__,__LINE__,d_mbuf,d_mbuf->data_len, job_len,i);
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
				//printf("%s-%d:read_head->len:%u, en_len:%u\n",__func__,__LINE__,read_head->len,en_len);		

		}
		//printf("%s-%d: en_num:%d,m_num:%d,count:%d,m_final_num:%d,m_final_num2:%d\n",__func__,__LINE__,en_num,m_num,count,m_final_num,m_final_num2);
		//printf("%s-%d: stream->sndvar->tcp_data_ring.prev_tail:%d,en_num:%d,en_len:%u,stream->sndvar->snd_wnd:%u\n",__func__,__LINE__,stream->sndvar->tcp_data_ring.prev_tail,en_num,en_len,stream->sndvar->snd_wnd);
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
		printf("+++ %s-%d: freee sjob,mbuf\n",__func__,__LINE__);
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
		//printf("%s-%d:data_msg->data_len:%d,data_msg->send_buffer_addr:0x%llx \n",__func__,__LINE__,data_msg->data_len,data_msg->send_buffer_addr);

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
		}

		if (unlikely(rte_pktmbuf_alloc_bulk(data_q->pkt_pool, mbufs, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: mbuf alloc failed!\n", __func__, __LINE__);
			goto err;
		}
#else
		//printf("%s-%d: m_num:%d, tcp_data_ring.free_num:%d,data_msg->data_len:%u,stream->sndvar->snd_wnd:%u\n",__func__,__LINE__,m_num,stream->sndvar->tcp_data_ring.free_num,data_msg->data_len,stream->sndvar->snd_wnd);

		ret = toe_host_buffer_insert(stream, data_msg, m_num);
		if (ret > 0) {
			RTE_LOG(ERR, PMD, "%s-%d: host buffer insert list! snd_wnd:%u stream->sndvar->tcp_data_ring.free_num:%d,m_num:%d\n", __func__, __LINE__,stream->sndvar->snd_wnd,stream->sndvar->tcp_data_ring.free_num,m_num);
	
			data_rq->head = (data_rq->head + 1) % data_rq->rq_size;
			toe_rx_data_fill_cq_msg(data_rq, 0, TOE_DMA_PENDING, toe_eg, data_msg, stream, idx);
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
		//printf("%s-%d:stream->sndvar->tcp_data_ring.prev_tail:%d\n",__func__,__LINE__,stream->sndvar->tcp_data_ring.prev_tail);
#endif

		if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, m_num))) {
			RTE_LOG(ERR, PMD, "%s-%d: sjob alloc failed!\n", __func__, __LINE__);
			goto err;
		}

	//printf("%s-%d: en_num:%d,m_num:%d,count:%d,m_final_num:%d,m_final_num2:%d\n",__func__,__LINE__,en_num,m_num,count,m_final_num,m_final_num2);
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
			//printf("%s-%d:sjob[%d]:%p,head_mbuf:%p,head_mbuf->nb_seg:%d,d_mbuf:%p,idx:%d\n", __func__,__LINE__,i,sjob[i],head_mbuf, head_mbuf->nb_segs,d_mbuf,idx);
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
			//printf("%s-%d:allow_data_len:%d,mbufs[i]->buf_len:%d,job_len:%d,en_len:%d\n", __func__,__LINE__,allow_data_len, mbufs[i]->buf_len, job_len,en_len);
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
			
			//printf("%s-%d:d_mbuf:%p,d_mbuf->data_len:%d,job_len:%d,i:%d\n", __func__,__LINE__,d_mbuf,d_mbuf->data_len, job_len,i);
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
		
		data_rq->head = (data_rq->head + 1) % data_rq->rq_size; //默认dma全部成功
		toe_sendbuf_update(stream, en_len);
		toe_rx_data_fill_cq_msg(data_rq, en_len, TOE_DMA_SUCCESS, toe_eg, data_msg, stream, idx);
		//printf("%s-%d: en_num:%d,m_num:%d,count:%d,m_final_num:%d,m_final_num2:%d\n",__func__,__LINE__,en_num,m_num,count,m_final_num,m_final_num2);
		//printf("%s-%d: stream->sndvar->tcp_data_ring.prev_tail:%d,en_num:%d\n",__func__,__LINE__,stream->sndvar->tcp_data_ring.prev_tail,en_num);
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
		//printf("+++ %s-%d: freee sjob,mbuf\n",__func__,__LINE__);
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[en_num], m_num - en_num);
	
		//printf("%s-%d: free mbuf bulk: %p, n:%d,dont should\n",__func__,__LINE__,mbufs[en_num], m_num - en_num);
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

	if (unlikely(!sjob->meb_num))
		return;
	//data_cq->head = (data_cq->head + sjob->meb_num) % data_cq->cq_size;
	//printf("%s-%d:sjob->qid:%d,sjob->meb_num:%d, data_cq->head:%d,  data_cq->tail:%d,loop_count:%llu\n",__func__,__LINE__,sjob->qid,sjob->meb_num, data_cq->head, data_cq->tail,loop_count);
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
	//printf("%s-%d:data_cq->tail:%d,data_cq->pre_head:%d, data_cq->head:%d,loop_count:%llu\n",__func__,__LINE__,data_cq->tail, data_cq->pre_head,data_cq->head,loop_count);
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
        //printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);
		sjob[i]->cnxt = (void *)data_cq;

		//printf("2222 %s-%d: data_cq head[i]:%d\n",__func__,__LINE__,head[i]);

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
	if (unlikely(ret < num_jobs)) {
		rte_mempool_put_bulk(dma->jpool, (void *const *)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		data_cq->pre_head = (data_cq->pre_head + nb_meb[i]) % data_cq->cq_size;
	
	return;
}

#if 0
static void toe_tx_databuf_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	struct toe_data_dpu_to_host_req *rq = sjob->vaddr;
	struct toe_data_dpu_to_host_res *cq_msg;
	struct toe_data_tx_cq_info *cq_info = &toe_eg->data_tx_vring[sjob->qid]->cq_info;
	tcp_stream *stream;
	struct tcp_recv_vars *rcvvar;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int stream_mbuf_head;
	uint16_t cq_rq_head;	

	if (sjob->extra == 0)
		goto free;
		
	printf("%s-%d: final_len:%llu,host_list_virtaddr:0x%llx,,loop_count:%llu,now:%llu\n",__func__, __LINE__, sjob->extra, sjob->extra3, loop_count, (rte_rdtsc()*1000000)/rte_get_tsc_hz());

	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if ((cq_info->tail + 1) % cq_info->cq_size == cq_info->head) {
		printf("%s-%d: tx databuf cq full\n",__func__, __LINE__);
		goto free;
	}

	stream = sjob->cnxt;
	rcvvar = stream->rcvvar;
	stream_mbuf_head = sjob->extra4;
	while((stream->rcvvar->rcvbuf->data_buf.head + 1) % stream->rcvvar->rcvbuf->data_buf.size != stream_mbuf_head) {
		rte_pktmbuf_free(stream->rcvvar->rcvbuf->data_buf.m_data[stream->rcvvar->rcvbuf->data_buf.head]);
		stream->rcvvar->rcvbuf->data_buf.head = (stream->rcvvar->rcvbuf->data_buf.head + 1) % stream->rcvvar->rcvbuf->data_buf.size;
	}

	stream->ref_count --;
	toe_destory_stream_check(stream);
#if 0
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;
	printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);

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

	if (rq_info->head == 0)
		cq_rq_head = rq_info->rq_size;
	else
		cq_rq_head = rq_info->head - 1;

	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->data_len = sjob->extra;
	cq_msg->recv_list_virtaddr = sjob->extra3;
	cq_msg->complete = cq_info->cq_compl;
	cq_msg->identification.host_dataptr = sjob->extra2;
	cq_msg->rq_head = cq_rq_head;
	printf("%s-%d: cq_msg->rq_head:%d\n",__func__,__LINE__,cq_msg->rq_head);

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
	
	//rq_info->head = (rq_info->head + 1) % rq_info->rq_size;
	
free:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}
#else
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
		
	//printf("%s-%d: final_len:%llu,host_list_virtaddr:0x%llx,,loop_count:%llu,now:%llu\n",__func__, __LINE__, sjob->extra, sjob->extra3, loop_count, (rte_rdtsc()*1000000)/rte_get_tsc_hz());

	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	cq_info->head = cq_info->cbc->doorbell;
	if ((cq_info->tail + 1) % cq_info->cq_size == cq_info->head) {
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
	printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);

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
	printf("%s-%d: cq_msg->rq_head:%d\n",__func__,__LINE__,cq_msg->rq_head);

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;
*/	
free:
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	return;
}

#endif
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

	//printf("%s-%d:pkt:%p,buf_addr:0x%llx,len:%d,final_len:%d,host_dataptr:0x%x,host_list_addr:0x%llx,stream_mbuf_head:%d\n",__func__,__LINE__,pkt,buf_addr,len,final_len,host_dataptr,host_list_addr,stream_mbuf_head);
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (unlikely(rte_mempool_get(dma->jpool, (void **)&sjob))) {
		
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		goto err;
	}
	
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	lcore_id = rte_lcore_id();

	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
	        //printf("%s-%d  rq->use_idx:%u,data_rq->head:%u,data_rq->pre_head:%u\n",__func__,__LINE__, rq->use_idx,data_rq->head,data_rq->pre_head);
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
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

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
		//printf("%s-%d: cq_msg->rq_head:%d\n",__func__,__LINE__,cq_msg->rq_head);

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
//	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (unlikely(ret < job_num)) {
		for (j = ret; j < job_num; j ++) {
			sjob = (struct toe_sync_dma_job *)jobs[j]->cnxt;
			
			//printf("%s-%d: free mbuf: %p\n",__func__,__LINE__,sjob->vaddr);
			rte_pktmbuf_free((struct rte_mbuf *)sjob->vaddr);//存在重复释放问题
			rte_mempool_put(toe_eg->t_dma->jpool, sjob);
		}
	}

	return;
}

static void toe_tx_data_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	struct toe_data_tx_rq_info *rq_info = &toe_eg->data_tx_vring[sjob->qid]->rq_info;
	struct toe_data_dpu_to_host_req *rq = sjob->cnxt;
	//printf("%s-%d: sjob->qid:%d ,sjob->meb_num:%d,loop_count:%llu\n", __func__,__LINE__, sjob->qid,sjob->meb_num,loop_count);
	//printf("%s-%d:rq->buffer_num:%d,rq_info->rq_local->opcode:%d,rq_info->rq_local->identification.host_dataptr:%d,rq_info->tail:%d\n", __func__,__LINE__,rq->buffer_num, rq->opcode,rq->identification.host_dataptr,rq_info->tail);

	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
#if 0
	int i;
	for (i = 0; i < TOE_RECV_BUFFER_COUNT_RESERVED; i++) {
		printf("%s-%d:rq_info->rq_local->recv_buffer[i].recv_buffer_len:%d,rq_info->rq_local->recv_buffer[i].recv_buffer_addr:0x%lx,rq_info->rq_local->recv_buffer[i].host_list_addr:0x%lx\n",
			__func__,__LINE__, rq->recv_buffer[i].recv_buffer_len,rq->recv_buffer[i].recv_buffer_phyaddr,rq->recv_buffer[i].host_list_virtaddr);
	}
#endif
	rq->use_idx = 0;
	rq_info->real_tail = (rq_info->real_tail + sjob->meb_num) % rq_info->rq_size;
	//printf("%s-%d: rq_info->real_tail:%d\n",__func__,__LINE__,rq_info->real_tail);	
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

int toe_sys_ctrl_dma_dequeue(struct toe_engine *toe_eg)
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

static void toe_sys_ctl_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{
	int i, meb_num = sjob->meb_num;
	void *vaddr;
	uint64_t srcaddr = 0;
	struct toe_sys_ctl_rq_info *ctl_rq = &toe_eg->sys_ctl_vring->rq_info;
	
	printf("@# %s-%d: meb_num:%d \n",__func__,__LINE__,meb_num);
	for (i = 0; i < meb_num; i++) {
			vaddr = (char *)sjob->vaddr + i * TOE_SYS_CTRL_RQ_MSG_SIZE;
			ctl_rq->pre_head = (ctl_rq->pre_head + 1) % ctl_rq->rq_size;
			toe_sys_ctl_recv(vaddr, toe_eg);
	}
	rte_mempool_put(toe_eg->t_dma->jpool, sjob);

#if 0
	toe_rxctl_rq_head_update(ctl_rq);

	toe_rx_ctl_reply(toe_eg);
#endif
	return;
}

int toe_sys_ctl_rq_dma_enqueue(struct toe_engine *toe_eg)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sys_ctl_rq_info *ctl_rq = &toe_eg->sys_ctl_vring->rq_info;
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
		sjob[i]->cb = toe_sys_ctl_dma_process;
        printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);
		src_addr = toe_addr32_to_addr64(ctl_rq->rbc->queue_desc_h, ctl_rq->rbc->queue_desc_lo)
								+ head[i] * TOE_SYS_CTRL_RQ_MSG_SIZE;
	
		dst_addr = (uint64_t)(ctl_rq->rq_local + head[i]);

		sjob[i]->vaddr = (void *)dst_addr;
		//printf("^^##%s-%d: ctl_rq->rq_local:0x%p,head[i]:%d,dst_addr:0x%lx,sjob[i]->vaddr:%p, src_addr:0x%lx,TOE_CTRL_RXRQ_MSG_SIZE:%d\n",__func__,__LINE__,ctl_rq->rq_local,head[i],dst_addr,sjob[i]->vaddr,src_addr,TOE_CTRL_RXRQ_MSG_SIZE);
		//rte_hexdump(stdout, "ctrl cq ", (const void *)(ctl_rq->rq_local + head[i]),TOE_CTRL_RXRQ_MSG_SIZE * nb_meb[i]);

		dst_addr = rte_mem_virt2iova((void *)dst_addr);
		job_len = nb_meb[i] * TOE_SYS_CTRL_RQ_MSG_SIZE;

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
	if (unlikely(ret < num_jobs)) {
		rte_mempool_put_bulk(dma->jpool, (void**)&sjob[ret], num_jobs - ret);
	}

	for (i = 0; i < ret; i++)
		ctl_rq->local_head = (ctl_rq->local_head + nb_meb[i]) % ctl_rq->rq_size;
	
	return ret;
}

static void toe_sys_ctl_reply_dma_process(struct toe_sync_dma_job *sjob, struct toe_engine *toe_eg)
{

	rte_mempool_put(toe_eg->t_dma->jpool, sjob);
	toe_irq_raise(toe_eg, toe_eg->sys_ctl_vring->cq_info.cbc->msi_vector);
	printf("##$$ %s-%d: msi_vector:%d,now:%lu\n",__func__,__LINE__,toe_eg->sys_ctl_vring->cq_info.cbc->msi_vector,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	return;
}

int toe_sys_ctl_cq_dma_enqueue(struct toe_engine *toe_eg)
{
	struct rte_qdma_job *jobs[2];
	struct rte_qdma_enqdeq e_context;
	struct toe_sync_dma_job *sjob[2];
	struct rte_qdma_rbp *rbp;
	struct toe_dma_hwq *hwq;
	struct toe_dma_info *dma = toe_eg->t_dma;
	struct toe_sys_ctl_cq_info *ctl_cq = &toe_eg->sys_ctl_vring->cq_info;
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
		sjob[i]->cb = toe_sys_ctl_reply_dma_process;
        printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);

		src_addr = (uint64_t)(ctl_cq->cq_local + head[i]);
		sjob[i]->vaddr = (void*)src_addr;
			
		dst_addr = toe_addr32_to_addr64(ctl_cq->cbc->queue_desc_h, ctl_cq->cbc->queue_desc_lo)
								+ head[i] * TOE_SYS_CTRL_CQ_MSG_SIZE;

		//printf("%s-%d:num_jobs:%d i:%d, sjob[i]->meb_num:%d, dst_addr:0x%lx, TOE_CTRL_RXCQ_MSG_SIZE:%d\n",__func__,__LINE__,num_jobs,i,sjob[i]->meb_num,dst_addr,TOE_CTRL_RXCQ_MSG_SIZE);
		//sjob[i]->vaddr = (void *)dst_addr;
		src_addr = rte_mem_virt2iova((void *)src_addr);
		job_len = nb_meb[i] * TOE_SYS_CTRL_CQ_MSG_SIZE;

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
		ctl_cq->pre_head = (ctl_cq->pre_head + nb_meb[i]) % ctl_cq->cq_size;
	
	return ret;
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
		//printf("$$$%s-%d: nb_meb[0]:%d,nb_meb[1]:%d,head[0]:%d\n",__func__,__LINE__,nb_meb[0],nb_meb[1],head[0]);
	if (unlikely(rte_mempool_get_bulk(dma->jpool, (void **) sjob, num_jobs))) {
		printf("%s-%d: sjob malloc failed\n",__func__,__LINE__);
		return -1;
	}
	
	lcore_id = rte_lcore_id();
	//lcore_id = rte_get_master_lcore();

	hwq = &tdma_hwq[lcore_id];
	//printf("*&& %s-%d: hwq:%p,lcore_id:%d\n",__func__,__LINE__,hwq,lcore_id);
	rbp = &hwq->R_rbp;

	for (i = 0; i < num_jobs; i++) {

		sjob[i]->meb_num = nb_meb[i];
		sjob[i]->cb = toe_rx_ctl_dma_process;
        //printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);
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
		//printf("#@# %s-%d:sjob[i]->job:%p\n",__func__,__LINE__,sjob[i]->job);
	}
	e_context.vq_id = hwq->vq;
	e_context.job = jobs;
	ret = rte_qdma_enqueue_buffers(dma->id, NULL,  num_jobs, &e_context);
	if (unlikely(ret < num_jobs)) {
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
	
	//printf("!! %s-%d: old ctl_cq->tail:%d,ctl_cq->head:%d ,ctl_cq->pre_head:%d, ctl_cq->pre_tail:%d, now:%lu\n",__func__,__LINE__,ctl_cq->tail,ctl_cq->head,ctl_cq->pre_head,ctl_cq->pre_tail, (rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
        //printf("%s-%d  CheckPoint 5  sync_job->cb = %p\n",__func__,__LINE__, sjob[i]->cb);
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
	if (unlikely(ret < num_jobs)) {
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
	//printf("%s-%d:data_rq->rbc->doorbell:%d,data_rq->tai:%d,data_rq->pre_head:%d,loop_count:%llu,now:%llu \n",__func__,__LINE__,data_rq->rbc->doorbell,data_rq->tail,data_rq->pre_head,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

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
	if (unlikely(ret < num_jobs)) {
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
	
	if (data_rq->tail == data_rq->rbc->doorbell)
		return 0;
	
	//printf("^^ %s-%d: old data_rq->tail:%d,data_rq->head:%d,data_rq->enq_tail:%d,data_rq->rbc->doorbell:%d,loop_count:%llu,now:%llu \n",__func__,__LINE__,data_rq->tail,data_rq->head,data_rq->enq_tail,data_rq->rbc->doorbell,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	data_rq->tail = data_rq->rbc->doorbell % data_rq->rq_size;
	nb_meb[0] = data_rq->tail - data_rq->enq_tail;
	nb_meb[1] = 0;
	head[0] = data_rq->enq_tail;
	head[1] = 0;
	
	if (nb_meb[0] == 0)
		return 0;
	
	if (nb_meb[0] < 0) {
		nb_meb[0] = data_rq->rq_size - data_rq->enq_tail;
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
		sjob[i]->cnxt = (void *)(data_rq->rq_local + head[i]);

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
	if (unlikely(ret < num_jobs)) {
		rte_mempool_put_bulk(dma->jpool, &sjob[ret], num_jobs - ret);
		
	}
	
	for (i = 0; i < ret; i++)
		data_rq->enq_tail = (data_rq->enq_tail + nb_meb[i]) % data_rq->rq_size;

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
		//printf("%s-%d: hwq->vq:%d\n",__func__,__LINE__,hwq->vq);
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
	//printf("~~ %s-%d: dma reset start \n", __func__,__LINE__);
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
		//printf("%s-%d: ctrl rq cq set 0!\n",__func__,__LINE__);
/*
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
		*/
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
		toe_eg->data_tx_vring[i]->rq_info.enq_tail = 0;

		//toe_eg->data_tx_vring[i]->cqad = 0;
		toe_eg->data_tx_vring[i]->cq_info.tail = 0;
		toe_eg->data_tx_vring[i]->cq_info.cq_compl = 1;
		
	}

	return;
}

