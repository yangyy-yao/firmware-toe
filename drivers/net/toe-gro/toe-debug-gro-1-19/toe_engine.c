
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_bus_vdev.h>
#include <rte_kvargs.h>
#include <rte_net.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_cycles.h>

#include <agiep_pci.h>

#include <netinet/in.h>
//#include <ff_api.h>
//#include <mtcp.h>
#include <ip_out.h>
#include <tcp_in.h>
#include <tcp_out.h>
#include <eth_out.h>

#include <toe_engine.h>
#include <toe_pcie.h>
#include <toe_dma.h>
#include <toe_dev.h>

struct toe_engine *t_eg;
uint64_t loop_count = 0;
uint64_t last = 0;
uint64_t prev_tsc = 0;

uint64_t rte_initial_rdtsc;
uint32_t sys_absolute_time;
static pthread_t ctrl_thread = 0;
#define toe_irq

#define ip_uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)
static void toe_reset_process(struct toe_engine *toe_eg);
static void toe_bar_printf(struct toe_engine *toe_eg, int once)
{
	//struct toe_bar_cfg *bar0;
	int i;
	char name[20] = {0};
	char *bar0;
	if (once) {
		//bar0 = (struct toe_bar_cfg *)toe_base_bar_get(toe_eg->bar);
		bar0 = (char *)toe_base_bar_get(toe_eg->bar);
		printf("************************bar0***********************************************\n");
		rte_hexdump(stdout, "bar0-base",bar0,sizeof(struct toe_bar_base_cfg));
		bar0 += sizeof(struct toe_bar_base_cfg);
		rte_hexdump(stdout, "bar0-sys-ctrl",bar0,sizeof(struct toe_bar_queue_cfg));
		bar0 += sizeof(struct toe_bar_queue_cfg);
		for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
			sprintf(name, "bar0-ctrl-%d", i);
			rte_hexdump(stdout, name, bar0,sizeof(struct toe_bar_queue_cfg));
			bar0 += sizeof(struct toe_bar_queue_cfg);
		}
		for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
			sprintf(name, "bar0-rxdata-%d", i);
			rte_hexdump(stdout, name, bar0, sizeof(struct toe_bar_queue_cfg));
			bar0 += sizeof(struct toe_bar_queue_cfg);
		}
		for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
			sprintf(name, "bar0-txdata-%d", i);
			rte_hexdump(stdout, name, bar0, sizeof(struct toe_bar_queue_cfg));
			bar0 += sizeof(struct toe_bar_queue_cfg);
		}
	printf("************************done***********************************************\n\n");
	}
}

static uint32_t toe_get_sys_time_ms(void)
{
	
	struct timeval cur_ts = {0};
	uint32_t ts=0;

	gettimeofday(&cur_ts, NULL);
    	ts = TIMEVAL_TO_TS(&cur_ts);
	return ts;
	
	//return sys_absolute_time + (uint32_t)(((rte_rdtsc() - rte_initial_rdtsc)*1000)/rte_get_tsc_hz()); 
}

void toe_destory_stream_check(tcp_stream *tcp_s)
{
	if (tcp_s->ref_count > 0)
		return;
	if (tcp_s->connect_state == TOE_CLOSED) {
		printf("%s-%d: tcp stream free!\n",__func__,__LINE__);
		TOE_DestroyTCPStream(tcp_s);
	}
	return;
}
int toe_send_tcppkt_to_ring(tcp_stream *tcp_s, uint8_t tcpflag, void *data, int data_len)
{
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	uint32_t ts;
	int ret;

	ts = toe_get_sys_time_ms();
	
	ret = SendTCPPacket(mtcp, tcp_s, ts, tcpflag, data, data_len, 0);
	printf("%s-%d:parse done,loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

	return ret;
}

static void toe_cq_common_msg( struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	tcp_stream *tcp_s,
																	int idx)
{
	uint16_t rq_head = toe_eg->ctl_rx_vring[idx]->rq_info.pre_head;
	printf("%s-%d: rq_head:%d\n",__func__,__LINE__,rq_head);
	if (rq_head == 0)
		rq_head = toe_eg->ctl_rx_vring[idx]->rq_info.rq_size;
	else
		rq_head = rq_head - 1;

	printf("%s-%d: rq_head:%d\n",__func__,__LINE__,rq_head);
	cq_msg->rq_head = rq_head;
	cq_msg->qid = idx;
	cq_msg->identification.card_stream_addr = (uint64_t)tcp_s;
	cq_msg->identification.host_dataptr = rq_msg->id.host_dataptr;

}

int toe_get_ipmac(struct toe_sys_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	int idx)
{
	struct toe_h2d_msg_ipmac_notification_hdr *ipmac_nf = &rq_msg->ipmac_notify;	
	uint8_t a, b, c, d;

	ip_uint32_t_to_char(ipmac_nf->ip, &a, &b, &c, &d);

	rte_memcpy(toe_eg->t_dev->ip, &ipmac_nf->ip, sizeof(ipmac_nf->ip));
	
	rte_memcpy(toe_eg->t_dev->mac, ipmac_nf->mac, sizeof(ipmac_nf->mac));
	rte_memcpy(toe_eg->t_dev->addr->addr_bytes, ipmac_nf->mac, sizeof(ipmac_nf->mac));

    printf("%s:%d  InterfaceIndex:%u  IP:%hhu.%hhu.%hhu.%hhu  MAC:%02X-%02X-%02X-%02X-%02X-%02X\n", __func__, __LINE__, ipmac_nf->ifindex, a, b, c, d, toe_eg->t_dev->mac[0], toe_eg->t_dev->mac[1], toe_eg->t_dev->mac[2], toe_eg->t_dev->mac[3], toe_eg->t_dev->mac[4], toe_eg->t_dev->mac[5]);

	toe_rte_flow_destroy(toe_eg->t_dev);

	if (toe_rte_flow_set(toe_eg->t_dev)) {
		RTE_LOG(ERR, PMD, "%s-%d: ret_flow set failed!\n", __func__, __LINE__);
	}
	
	toe_cq_common_msg(rq_msg, cq_msg, toe_eg, NULL, idx);
	return 0;
}

int toe_h2d_ctrl_msg(struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	int idx)
{
	struct toe_h2d_ctrl_packet_msg *ctrl_msg = &rq_msg->ctrl_pkt_msg;
	uint8_t flags = ctrl_msg->tcp_info.tcp_params.tcp_flags;
	uint8_t send_ctlpkt = 1;
	tcp_stream *tcp_s;
	tcp_stream s_stream;
	int ret;

	printf("%s-%d:idx:%d, tcp ctrl flags:0x%x!\n",__func__,__LINE__,idx,flags);	
	printf("%s-%d: now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	tcp_s = (tcp_stream *)rq_msg->id.card_stream_addr;
	if (!tcp_s && flags != TCP_FLAG_SYN) {
		printf("%s-%d: tcp stream is null!\n",__func__,__LINE__);
		return -1;
	}

	if (tcp_s && unlikely(tcp_s->connect_state == TOE_CLOSED)) {
		printf("%s-%d: tcp stream is closed!\n",__func__,__LINE__);
		return 0;
	}

	switch (flags) {
		case TCP_FLAG_SYN:
			s_stream.saddr = ctrl_msg->tcp_info.tcp_tuples.local_ip;
			s_stream.daddr = ctrl_msg->tcp_info.tcp_tuples.remote_ip;
			s_stream.sport = ctrl_msg->tcp_info.tcp_tuples.local_port;
			s_stream.dport = ctrl_msg->tcp_info.tcp_tuples.remote_port;
			tcp_s = StreamHTSearch_by_stream(&s_stream);
			if (likely(!tcp_s)) {
				tcp_s = CreateTCPStream_by_port(0, ctrl_msg->tcp_info.tcp_params.sequence, ctrl_msg->tcp_info.tcp_tuples.local_ip, ctrl_msg->tcp_info.tcp_tuples.local_port, ctrl_msg->tcp_info.tcp_tuples.remote_ip, ctrl_msg->tcp_info.tcp_tuples.remote_port);
				if (!tcp_s) {
					printf("%s-%d: tcp stream create failed!\n",__func__,__LINE__);
					return -1;
				}
				tcp_s->daddr = ctrl_msg->tcp_info.tcp_tuples.remote_ip;
				tcp_s->saddr = ctrl_msg->tcp_info.tcp_tuples.local_ip;
				rte_memcpy(tcp_s->dst_mac, ctrl_msg->tcp_info.tcp_tuples.remote_mac, sizeof(tcp_s->dst_mac));
				rte_memcpy(tcp_s->src_mac, ctrl_msg->tcp_info.tcp_tuples.local_mac, sizeof(tcp_s->src_mac));		
				tcp_s->host_dataptr = rq_msg->id.host_dataptr;
			}
			
			tcp_s->sndvar->mss = ctrl_msg->tcp_info.tcp_params.mss;
			tcp_s->snd_nxt = ctrl_msg->tcp_info.tcp_params.sequence;
			tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_info.tcp_params.window;
			tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_info.tcp_params.window_scale;
			
			printf("%s-%d,tcp_s:%p,tcp_s->state:%d,tcp_s->host_dataptr:%llx,acr->tcp_params.sequence:%u,tcp_s->rcvvar->rcv_wnd:%u,tcp_s->sndvar->wscale_mine:%u \n", __func__, __LINE__,tcp_s,tcp_s->state,tcp_s->host_dataptr,ctrl_msg->tcp_info.tcp_params.sequence,tcp_s->rcvvar->rcv_wnd,tcp_s->sndvar->wscale_mine);
			break;
		case (TCP_FLAG_SYN | TCP_FLAG_ACK):
			if (ctrl_msg->status != 0)
				tcp_s->connect_state = ctrl_msg->status;
			tcp_s->sndvar->iss = ctrl_msg->tcp_info.tcp_params.sequence;
			tcp_s->host_dataptr = rq_msg->id.host_dataptr;
		case TCP_FLAG_RST:
		case (TCP_FLAG_RST | TCP_FLAG_ACK):
			if (tcp_s->connect_state != TOE_ESTABLISHED) {
				printf("%s-%d: tcp_s->connect_state:%d,tcp_s->sndvar->iss:%u\n",__func__,__LINE__,tcp_s->connect_state,tcp_s->sndvar->iss);			
				tcp_s->snd_nxt = ctrl_msg->tcp_info.tcp_params.sequence;
				tcp_s->rcv_nxt = ctrl_msg->tcp_info.tcp_params.acknowledge;
				tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_info.tcp_params.window;
				tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_info.tcp_params.window_scale;
			}
			
			if (flags == TCP_FLAG_RST)	
				tcp_s->connect_state = TOE_CLOSED;
			break;
		case TCP_FLAG_ACK:
			if (ctrl_msg->status != 0)
				tcp_s->connect_state = ctrl_msg->status;
			printf("%s-%d: tcp_s->connect_state:%d\n",__func__,__LINE__,tcp_s->connect_state);			
			tcp_s->snd_nxt = ctrl_msg->tcp_info.tcp_params.sequence;
			tcp_s->rcv_nxt = ctrl_msg->tcp_info.tcp_params.acknowledge;
			if (tcp_s->connect_state == TOE_ESTABLISHED) {
				printf("%s-%d: ctrl_msg->tcp_params.window:%u\n",__func__,__LINE__,ctrl_msg->tcp_info.tcp_params.window);
				if (ctrl_msg->tcp_info.tcp_params.window) {
					tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_info.tcp_params.window << tcp_s->sndvar->wscale_mine;
					//tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_params.window_scale;
				}
				tcp_s->state = TCP_ST_ESTABLISHED;
			}
			break;
		case (TCP_FLAG_FIN | TCP_FLAG_ACK):

			if (tcp_s->sndvar->tcp_data_ring.free_num < TCP_SEND_DATA_BUFFER_MAX_NUM) {
				send_ctlpkt = 0;
				tcp_s->send_fin_masg.is_fin = 1;
				tcp_s->send_fin_masg.tcp_flag = flags;
				tcp_s->send_fin_masg.connect_state = ctrl_msg->status;
				break;
			}
			
			if (ctrl_msg->status != 0)
				tcp_s->connect_state = ctrl_msg->status;
			printf("%s-%d:send fin_ack connect_state:%u!\n",__func__,__LINE__,tcp_s->connect_state);
			if (tcp_s->connect_state == TOE_CLOSING) {
				tcp_s->snd_nxt = ctrl_msg->tcp_info.tcp_params.sequence;
				tcp_s->rcv_nxt = ctrl_msg->tcp_info.tcp_params.acknowledge;
			}

			if (tcp_s->sndvar->sndbuf) {
				tcp_s->sndvar->fss = tcp_s->sndvar->sndbuf->head_seq + tcp_s->sndvar->sndbuf->len;
			} else {
				tcp_s->sndvar->fss = tcp_s->snd_nxt;
			}
			break;
		default:
			break;
	}
	toe_cq_common_msg(rq_msg, cq_msg, toe_eg, tcp_s, idx);

	if (send_ctlpkt) {
		ret = toe_send_tcppkt_to_ring(tcp_s, flags, NULL, 0);

		if (likely(ret >= 0)) {
			if (tcp_s->connect_state == TOE_CLOSED) {
				toe_destory_stream_check(tcp_s);
			}
			cq_msg->result = TOE_DMA_SUCCESS;
		} else {
			cq_msg->result = TOE_DMA_FAILED;
		}
	} else {
		cq_msg->result = TOE_DMA_REFUSED;
	}
	return ret;
}

struct toe_ctrl_host_to_dpu_res * toe_sys_ctl_avail_cq_msg(struct toe_sys_ctl_cq_info *cq_info)
{
	struct toe_sys_ctrl_dpu_to_host_res *cq_msg;
	/*cq full*/
	printf("%s-%d:cq_info->pre_tail:%d,cq_info->cq_size:%d,cq_info->head:%d\n",__func__,__LINE__,cq_info->pre_tail,cq_info->cq_size,*cq_info->head);

	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == *cq_info->head)) {
		printf("%s-%d: ctl rx cq is full!\n", __func__, __LINE__);
		return NULL;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->complete = cq_info->cq_compl;
	return cq_msg;
}

struct toe_ctrl_host_to_dpu_res * toe_avail_cq_msg(struct toe_ctl_cq_info *cq_info)
{
	struct toe_ctrl_host_to_dpu_res *cq_msg;
	/*cq full*/

	printf("%s-%d:cq_info->pre_tail:%d,cq_info->cq_size:%d,cq_info->head:%d\n",__func__,__LINE__,cq_info->pre_tail,cq_info->cq_size,*cq_info->head);

	if (unlikely((cq_info->tail + 1) % cq_info->cq_size == *cq_info->head)) {
		printf("%s-%d: ctl rx cq is full!\n", __func__, __LINE__);
		return NULL;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->compl = cq_info->cq_compl;
	return cq_msg;
}

int toe_sys_ctl_recv(void *vaddr, struct toe_engine *toe_eg)
{
	struct toe_sys_ctrl_host_to_dpu_req *rq_msg = vaddr;
	struct toe_sys_ctrl_dpu_to_host_res *cq_msg = NULL;
	struct toe_sys_ctl_cq_info *cq_info = &toe_eg->sys_ctl_vring->cq_info;
	int ret = 0;

	cq_msg = toe_sys_ctl_avail_cq_msg(cq_info);
	if (unlikely(!cq_msg)) {
		printf("%s-%d:cq is full!\n", __func__, __LINE__);
		return 0;
	}
     
	ret = toe_get_ipmac(rq_msg, cq_msg, toe_eg, 0);

	if (unlikely(ret != 0))
		return ret;
	
	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	return ret;
}

int toe_ctl_recv(void *vaddr, struct toe_engine *toe_eg, int idx)
{
	struct toe_ctrl_host_to_dpu_req *rq_msg = vaddr;
	struct toe_ctrl_host_to_dpu_res *cq_msg = NULL;
	struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[idx]->cq_info;
	int ret = 0;

	cq_msg = toe_avail_cq_msg(cq_info);
	if (unlikely(!cq_msg)) {
		printf("%s-%d:cq is full!\n", __func__, __LINE__);
		return 0;
	}
     
	ret = toe_h2d_ctrl_msg(rq_msg, cq_msg, toe_eg, idx);

	if (unlikely(ret != 0))
		return ret;
	
	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	return ret;
}

#define tcp_pkt_process

uint8_t *toe_get_wptr(struct mtcp_thread_context *ctx, uint16_t len)
{
	struct rte_mbuf *mbuf;
	void *m_data;
	struct toe_rx_queue *data_q = ctx->io_private_context;

	mbuf = rte_pktmbuf_alloc(data_q->pkt_pool);
	if (unlikely(mbuf == NULL)) {
		return NULL;
	}
	m_data = rte_pktmbuf_mtod(mbuf, void *);
	mbuf->data_len = mbuf->pkt_len = len;
	mbuf->nb_segs = 1;
	mbuf->next = NULL;

	printf("%s-%d:mbuf:%p, data_q->rxq:%p,qid:%d,len:%d\n",__func__,__LINE__, mbuf,data_q->rxq,data_q->idx,len);
	if (!rte_ring_sp_enqueue_burst(data_q->rxq, (void *const *)&mbuf, 1, NULL)) {
		printf("%s-%d: enqueue failed \n",__func__,__LINE__);
		return NULL;
	}

	return m_data;
}

uint8_t *toe_get_wptr_datapkt(struct mtcp_thread_context *ctx, uint16_t len, void *st, int data_posit)
{
	struct rte_mbuf *mbuf;
	void *m_data;
	tcp_stream *stream = st;
	struct toe_rx_queue *data_q = ctx->io_private_context;
	int diff_len;

	mbuf = stream->sndvar->tcp_data_ring.m[data_posit];
	if (unlikely(mbuf == NULL)) {
		return NULL;
	}
	diff_len = mbuf->data_len - stream->sndvar->tcp_data_ring.mbuf_data_len[data_posit];
	printf("%s-%d:mbuf:%p,mbuf->data_len:%d,stream->sndvar->tcp_data_ring.mbuf_data_len[%d]:%u\n",__func__,__LINE__,mbuf,mbuf->data_len,data_posit, stream->sndvar->tcp_data_ring.mbuf_data_len[data_posit]);
	if (!diff_len)
		m_data = rte_pktmbuf_prepend(mbuf, len - mbuf->data_len);
	else if (diff_len > 0 && mbuf->data_len == len)
		m_data = rte_pktmbuf_mtod(mbuf, void *);
	else if (diff_len > 0 && mbuf->data_len > len) {
		m_data = rte_pktmbuf_adj(mbuf, mbuf->data_len - len);
	} else {
		printf("%s-%d:data len err!!mbuf:%p len:%u,mbuf->data_len:%u,stream->sndvar->tcp_data_ring.mbuf_data_len[%d]:%u\n",__func__,__LINE__,mbuf,len, mbuf->data_len, data_posit,stream->sndvar->tcp_data_ring.mbuf_data_len[data_posit]);
		rte_pktmbuf_free(mbuf);
		return NULL;
	}
	rte_mbuf_refcnt_update(mbuf, 1);
	printf("%s-%d:qid:%d,mbuf:%p,mbuf->data:%p,m_data:%p,len:%d,mbuf->data_len:%d,mbuf_refcnt:%u\n",__func__,__LINE__,data_q->idx,mbuf,mbuf->buf_addr+mbuf->data_off,m_data,len,mbuf->data_len,rte_mbuf_refcnt_read(mbuf));	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	rte_ring_sp_enqueue_burst(data_q->rxq, (void *const *)&mbuf, 1, NULL);

	return m_data;

}

int toe_sendbuf_create(tcp_stream *stream)
{
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];

	stream->sndvar->sndbuf = SBInit_no_copy(mtcp->rbm_snd, stream->sndvar->iss + 1);
	if (unlikely(!stream->sndvar->sndbuf)) {
		stream->close_reason = TCP_NO_MEM;
		printf("%s-%d:stream->sndvar->sndbuf malloc failed\n ",__func__,__LINE__);
		return -1;
	}

	return 0;
}
void toe_sendbuf_update(tcp_stream *stream, int data_len)
{
	struct tcp_send_buffer *buf;

	buf = stream->sndvar->sndbuf;

	buf->len += data_len;
	buf->cum_len += data_len;
	stream->sndvar->snd_wnd = buf->size - buf->len;
	if (stream->sndvar->snd_wnd == 0) {
		stream->sndvar->wnd_to_host = 1;
	}
	return 0;
}

int toe_tcp_datapkt_send(tcp_stream *stream, struct toe_engine *toe_eg,
																		int idx)
{
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		
    printf("%s-%d  stream->sndvar->sndbuf=%p,loop_count:%llu,now:%llu \n",__func__,__LINE__, stream->sndvar->sndbuf,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		AddtoSendList(mtcp, stream);
		return 0;
}

void toe_close_to_host(tcp_stream *stream, struct toe_engine *toe_eg)
{
		struct toe_ctrl_host_to_dpu_res *cq_msg;
		int qid = stream->qid;
		struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[qid]->cq_info;
		
		
		cq_msg = toe_avail_cq_msg(cq_info);

		cq_msg->qid = qid;
		cq_msg->compl = toe_eg->ctl_rx_vring[qid]->cq_info.cq_compl;
		cq_msg->identification.card_stream_addr = (uint64_t)stream;
		cq_msg->identification.host_dataptr = stream->host_dataptr;

		//cq_msg->opcode = TOE_MSG_OPCODE_D2H_ABNORMAL_CLOSE;

		cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
		if (cq_info->tail == 0)
			cq_info->cq_compl = cq_info->cq_compl ^ 1;

	return;
}

static void toe_msi_init(struct toe_engine *toe_eg)
{
	struct cq_bar_cfg *cbc;
	uint64_t addr;
	int i;

	cbc = &toe_eg->sys_ctl_vring->cq_info.cbc;
	toe_eg->vector_map |= (1UL << cbc->msi_vector);
	
	addr = toe_irq_addr(toe_eg, cbc->msi_vector);
	toe_irq_data(toe_eg, cbc->msi_vector);

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		cbc = &toe_eg->ctl_rx_vring[i]->cq_info.cbc;
		toe_eg->vector_map |= (1UL << cbc->msi_vector);

		addr = toe_irq_addr(toe_eg, cbc->msi_vector);
		toe_irq_data(toe_eg, cbc->msi_vector);

	
		cbc = &toe_eg->data_rx_vring[i]->cq_info.cbc;
			toe_eg->vector_map |= (1UL << cbc->msi_vector);

		addr = toe_irq_addr(toe_eg, cbc->msi_vector);
		toe_irq_data(toe_eg, cbc->msi_vector);

		cbc = &toe_eg->data_tx_vring[i]->cq_info.cbc;
		toe_eg->vector_map |= (1UL << cbc->msi_vector);

		addr = toe_irq_addr(toe_eg, cbc->msi_vector);
		toe_irq_data(toe_eg, cbc->msi_vector);
	}
	return;
}

static int toe_bar_msg_sync(struct toe_engine *toe_eg)
{
	struct toe_bar_base_cfg *base_cfg;
	struct toe_device *toe_dev = toe_eg->t_dev;
	uint8_t active = 0;
	int i;

	base_cfg = (struct toe_bar_base_cfg *)toe_eg->bar;

	/**********/
	if (toe_dev->reset != (base_cfg->status & TOE_CARD_RESET)) {
		toe_dev->reset = (base_cfg->status & TOE_CARD_RESET);
		//base_cfg->status &= ~TOE_CARD_RESET;
		if (toe_dev->reset)
			toe_dev->reset_done = 0;
	}
	/***********/

	if (toe_dev->active == (base_cfg->status & TOE_DRIVER_ACTIVE))
		return 0;

	active = (base_cfg->status & TOE_DRIVER_ACTIVE);

	if (active) {
	printf("%s-%d: active now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

		toe_msi_init(toe_eg);
		toe_dev->active = active;
		return 1;
	}
	
	toe_dev->active = active;
	return 0;
}
#if 0
#if 1
int toe_dma_data_to_host(tcp_stream *stream, struct toe_engine *toe_eg, int qid, int timeout_send)
{
		struct tcp_recv_vars *rcvvar = stream->rcvvar;
		struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[qid]->rq_info;
		struct toe_data_dpu_to_host_req *rq = data_rq->rq_local + data_rq->pre_head;
		struct toe_mbuf_recovery *rec_ring = &toe_eg->data_tx_vring[qid]->recovery_ring;
		struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
		uint16_t jobs_num = 0;
		struct rte_mbuf *m, *prev_m;
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		int head, merged_len = -1, free_len, en_len = 0, en_len_total = 0, dma_final_len = 0;
		uint64_t h_buffer_addr;
		uint64_t host_list_addr = 0;

		if (data_rq->pre_head == data_rq->real_tail) {
			printf("%s-%d: no buffer!\n",__func__,__LINE__);
			goto done;
		}
	//	printf("%s-%d: timeout_send:%d,loop_count:%llu\n",__func__,__LINE__,timeout_send,loop_count);	
		merged_len = rcvvar->rcvbuf->merged_len;
		if (merged_len == 0) {
			printf("%s-%d: merged_len is 0!\n",__func__,__LINE__);
			goto done;
		}
		m = rcvvar->rcvbuf->fctx->head_mbuf;
		
	//	printf("%s-%d: merged_len:%d, m:%p,rq->recv_buffer[rq->use_idx].recv_buffer_len:%d,data_rq:%p data_rq->pre_head:%d,data_rq->real_tail:%d,rq:%p\n",__func__,__LINE__,merged_len, m,rq->recv_buffer[rq->use_idx].recv_buffer_len,data_rq,data_rq->pre_head,data_rq->real_tail,rq);
		while (m && merged_len && (merged_len > rq->recv_buffer.recv_buffer_len || timeout_send)) {
			dma_final_len = 0;
			en_len_total = 0;
			host_list_addr = 0;
			while(m) {
	//			printf("%s-%d:m:%p,m->data_len:%d,m->next:%p\n",__func__,__LINE__,m,m->data_len,m->next);
				if (m->data_len == 0) {
					rec_ring->m_data[rec_ring->tail] = m;
					prev_m = m;
					m = m->next;
					prev_m->next = NULL;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					continue;
				}
				
				h_buffer_addr = rq->recv_buffer.recv_buffer_phyaddr + en_len_total;
				//m = rcvvar->rcvbuf->data_buf.m_data[head];

				printf("%s-%d,m:%p,en_len:%d,dma_final_len:%d,en_len_total:%d,merged_len:%d,h_buffer_addr:0x%llx\n",__func__,__LINE__,m,m?m->data_len:-1,dma_final_len,en_len_total,merged_len,h_buffer_addr);

				en_len = m->data_len;
				if (en_len_total + m->data_len >= rq->recv_buffer.recv_buffer_len) {
					en_len = rq->recv_buffer.recv_buffer_len - en_len_total;
					dma_final_len = en_len_total + en_len;

					host_list_addr = rq->recv_buffer.host_list_virtaddr;
					
	//				printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				} else if (timeout_send && (merged_len - en_len == 0)) {
					dma_final_len = en_len_total + en_len;
					host_list_addr = rq->recv_buffer.host_list_virtaddr;
		//			printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				}
				
				prev_m = m;
				if (dma_final_len > 0) { //写完一个buffer
					if (en_len == m->data_len) {
						rec_ring->m_data[rec_ring->tail] = m;
						m = m->next;
						prev_m->next = NULL;
						rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
						
						rcvvar->rcvbuf->fctx->head_mbuf = m;
						//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
					} else {
						rcvvar->rcvbuf->fctx->head_mbuf = m;
					}
		//			printf("%s-%d: en_len:%d,prev_m->data_len:%d,head:%d\n",__func__,__LINE__,en_len,prev_m->data_len,head);
					//rcvvar->rcvbuf->data_buf.prev_head = head;
					stream->ref_count ++;
				} else {
					rec_ring->m_data[rec_ring->tail] = m;
					m = m->next;
					prev_m->next = NULL;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
				}
				
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				jobs[jobs_num] = toe_tx_databuf_to_job(prev_m, h_buffer_addr, en_len, dma_final_len, stream->host_dataptr, host_list_addr,toe_eg,qid, stream, rec_ring->tail);
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				if (!jobs[jobs_num]) {
					goto done;
				}
				
				jobs_num ++;
				if (unlikely(jobs_num == TOE_JOB_DATABUF_NUM)) {
						toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
						jobs_num = 0;
				}
				en_len_total += en_len;
				merged_len -= en_len;
				if (dma_final_len > 0) {
					if (en_len < prev_m->data_len) {
						//m->data_off += en_len;
						//m->data_len -= en_len;
						rte_pktmbuf_adj(prev_m, en_len);
					}
					break;
				}
			};

			//rq中所有buffer写完，换下一个rq
			data_rq->pre_head = (data_rq->pre_head + 1) % data_rq->rq_size;
			printf("%s-%d: data_rq->pre_head:%d,data_rq->real_tail:%d,data_rq->enq_tail:%d\n",__func__,__LINE__,data_rq->pre_head,data_rq->real_tail,data_rq->enq_tail);
			if (data_rq->pre_head == data_rq->real_tail) { //没有可用的rq
//				printf("%s-%d: no host buffer\n",__func__,__LINE__);
				break;
			}
			rq = data_rq->rq_local + data_rq->pre_head;
			
			m = rcvvar->rcvbuf->fctx->head_mbuf;
			RTE_ASSERT(!(m == NULL && merged_len > 0));
		}

		if (likely(jobs_num > 0)) {
				toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
				jobs_num = 0;
		}

		free_len = rcvvar->rcvbuf->merged_len - merged_len;
		if (likely(free_len > 0)) {
			RBRemove_no_copy(mtcp->rbm_rcv, rcvvar->rcvbuf, free_len, AT_MTCP);
			rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	//		printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);
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
			prev_tsc = rte_rdtsc();
		}

done:
	return merged_len;
}
#else
int toe_dma_data_to_host(tcp_stream *stream, struct toe_engine *toe_eg, int qid, int timeout_send)
{
		struct tcp_recv_vars *rcvvar = stream->rcvvar;
		struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[qid]->rq_info;
		struct toe_data_dpu_to_host_req *rq = data_rq->rq_local + data_rq->pre_head;
		struct toe_mbuf_recovery *rec_ring = &toe_eg->data_tx_vring[qid]->recovery_ring;
		struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
		uint16_t jobs_num = 0;
		struct rte_mbuf *m, *prev_m;
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		int head, merged_len = -1, free_len, en_len = 0, en_len_total = 0, dma_final_len = 0;
		uint64_t h_buffer_addr;
		uint64_t host_list_addr = 0;

		if (data_rq->pre_head == data_rq->real_tail) {
			printf("%s-%d: no buffer!\n",__func__,__LINE__);
			goto done;
		}
	//	printf("%s-%d: timeout_send:%d,loop_count:%llu\n",__func__,__LINE__,timeout_send,loop_count);	
		merged_len = rcvvar->rcvbuf->merged_len;
		if (merged_len == 0) {
			printf("%s-%d: merged_len is 0!\n",__func__,__LINE__);
			goto done;
		}
		m = rcvvar->rcvbuf->fctx->head_mbuf;
		
		printf("%s-%d: loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		while (m && merged_len && (merged_len > rq->recv_buffer[rq->use_idx].recv_buffer_len || timeout_send)) {
			//head = rcvvar->rcvbuf->data_buf.prev_head;
			dma_final_len = 0;
			en_len_total = 0;
			host_list_addr = 0;
			while(m) {
	//			printf("%s-%d:m:%p,m->data_len:%d,m->next:%p\n",__func__,__LINE__,m,m->data_len,m->next);
				if (m->data_len == 0) {
					rec_ring->m_data[rec_ring->tail] = m;
					prev_m = m;
					m = m->next;
					prev_m->next = NULL;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					continue;
				}
				
				h_buffer_addr = rq->recv_buffer[rq->use_idx].recv_buffer_phyaddr + en_len_total;
				//m = rcvvar->rcvbuf->data_buf.m_data[head];

				printf("%s-%d,m:%p,en_len:%d,dma_final_len:%d,en_len_total:%d,merged_len:%d,h_buffer_addr:0x%llx,rq->use_idx:%d\n",__func__,__LINE__,m,m?m->data_len:-1,dma_final_len,en_len_total,merged_len,h_buffer_addr,rq->use_idx);

				en_len = m->data_len;
				if (en_len_total + m->data_len >= rq->recv_buffer[rq->use_idx].recv_buffer_len) {
					en_len = rq->recv_buffer[rq->use_idx].recv_buffer_len - en_len_total;
					dma_final_len = en_len_total + en_len;

					host_list_addr = rq->recv_buffer[rq->use_idx].host_list_virtaddr;
					
	//				printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				} else if (timeout_send && (merged_len - en_len == 0)) {
					dma_final_len = en_len_total + en_len;
					host_list_addr = rq->recv_buffer[rq->use_idx].host_list_virtaddr;
		//			printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				}
				
				prev_m = m;
				if (dma_final_len > 0) { //写完一个buffer
					if (en_len == m->data_len) {
						rec_ring->m_data[rec_ring->tail] = m;
						m = m->next;
						prev_m->next = NULL;
						rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
						
						rcvvar->rcvbuf->fctx->head_mbuf = m;
						//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
					} else {
						rcvvar->rcvbuf->fctx->head_mbuf = m;
					}
		//			printf("%s-%d: en_len:%d,prev_m->data_len:%d,head:%d\n",__func__,__LINE__,en_len,prev_m->data_len,head);
					//rcvvar->rcvbuf->data_buf.prev_head = head;
					stream->ref_count ++;
				} else {
					rec_ring->m_data[rec_ring->tail] = m;
					m = m->next;
					prev_m->next = NULL;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
				}
				
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				jobs[jobs_num] = toe_tx_databuf_to_job(prev_m, h_buffer_addr, en_len, dma_final_len, stream->host_dataptr, host_list_addr,toe_eg,qid, stream, rec_ring->tail);
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				if (!jobs[jobs_num]) {
					goto done;
				}
				
				jobs_num ++;
				if (unlikely(jobs_num == TOE_JOB_DATABUF_NUM)) {
						toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
						jobs_num = 0;
				}
				en_len_total += en_len;
				merged_len -= en_len;
				if (dma_final_len > 0) {
					if (en_len < prev_m->data_len) {
						//m->data_off += en_len;
						//m->data_len -= en_len;
						rte_pktmbuf_adj(prev_m, en_len);
					}
					break;
				}
			};

			if (rq->use_idx + 1 == rq->buffer_num) { //rq中所有buffer写完，换下一个rq
				data_rq->pre_head = (data_rq->pre_head + 1) % data_rq->rq_size;
				printf("%s-%d: data_rq->pre_head:%d,data_rq->real_tail:%d,data_rq->enq_tail:%d\n",__func__,__LINE__,data_rq->pre_head,data_rq->real_tail,data_rq->enq_tail);
				if (data_rq->pre_head == data_rq->real_tail) { //没有可用的rq
	//				printf("%s-%d: no host buffer\n",__func__,__LINE__);
					break;
				}
				rq = data_rq->rq_local + data_rq->pre_head;
			} else {
				rq->use_idx += 1;
			}
			
			m = rcvvar->rcvbuf->fctx->head_mbuf;
			RTE_ASSERT(!(m == NULL && merged_len > 0));
		}

		if (likely(jobs_num > 0)) {
				toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
				jobs_num = 0;
		}

		free_len = rcvvar->rcvbuf->merged_len - merged_len;
		if (likely(free_len > 0)) {
			RBRemove_no_copy(mtcp->rbm_rcv, rcvvar->rcvbuf, free_len, AT_MTCP);
			rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	//		printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);
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
			prev_tsc = rte_rdtsc();
		}

		printf("%s-%d:done  loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
done:
	return merged_len;
}
#endif
#else
static int toe_dma_data_to_host(tcp_stream *stream, struct toe_engine *toe_eg, int qid, int timeout_send)
{
		struct tcp_recv_vars *rcvvar = stream->rcvvar;
		struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[qid]->rq_info;
		struct toe_data_dpu_to_host_req *rq = data_rq->rq_local + data_rq->pre_head;
		struct toe_mbuf_recovery *rec_ring = &toe_eg->data_tx_vring[qid]->recovery_ring;
		struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
		uint16_t jobs_num = 0;
		struct rte_mbuf *m, *prev_m;
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		int head, merged_len = -1, free_len, en_len = 0, en_len_total = 0, dma_final_len = 0;
		uint64_t h_buffer_addr;
		uint64_t host_list_addr = 0;

		if (data_rq->pre_head == data_rq->real_tail) {
			printf("%s-%d: no buffer!\n",__func__,__LINE__);
			goto done;
		}
	//	printf("%s-%d: timeout_send:%d,loop_count:%llu\n",__func__,__LINE__,timeout_send,loop_count);	
		merged_len = rcvvar->rcvbuf->merged_len;
		if (merged_len == 0) {
			printf("%s-%d: merged_len is 0!\n",__func__,__LINE__);
			goto done;
		}
		m = rcvvar->rcvbuf->fctx->head_mbuf;
		
	//	printf("%s-%d: merged_len:%d, m:%p,rq->recv_buffer[rq->use_idx].recv_buffer_len:%d,data_rq:%p data_rq->pre_head:%d,data_rq->real_tail:%d,rq:%p\n",__func__,__LINE__,merged_len, m,rq->recv_buffer[rq->use_idx].recv_buffer_len,data_rq,data_rq->pre_head,data_rq->real_tail,rq);
		while (m && merged_len && (merged_len > rq->recv_buffer.recv_buffer_len || timeout_send)) {
			dma_final_len = 0;
			en_len_total = 0;
			host_list_addr = 0;
			while(m) {
				printf("%s-%d:m:%p,m->data_len:%d,m->next:%p\n",__func__,__LINE__,m,m->data_len,m->next);
				if (m->data_len == 0) {
					rec_ring->m_data[rec_ring->tail] = m;
					prev_m = m;
					m = m->next;
					prev_m->next = NULL;
					prev_m->nb_segs = 1;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					continue;
				}
				
				h_buffer_addr = rq->recv_buffer.recv_buffer_phyaddr + en_len_total;
				//m = rcvvar->rcvbuf->data_buf.m_data[head];

				printf("%s-%d,m:%p,en_len:%d,dma_final_len:%d,en_len_total:%d,merged_len:%d,h_buffer_addr:0x%llx\n",__func__,__LINE__,m,m?m->data_len:-1,dma_final_len,en_len_total,merged_len,h_buffer_addr);

				en_len = m->data_len;
				if (en_len_total + m->data_len >= rq->recv_buffer.recv_buffer_len) {
					en_len = rq->recv_buffer.recv_buffer_len - en_len_total;
					dma_final_len = en_len_total + en_len;

					host_list_addr = rq->recv_buffer.host_list_virtaddr;
					
	//				printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				} else if (timeout_send && (merged_len - en_len == 0)) {
					dma_final_len = en_len_total + en_len;
					host_list_addr = rq->recv_buffer.host_list_virtaddr;
		//			printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
				}
				
				prev_m = m;
				if (dma_final_len > 0) { //写完一个buffer
					if (en_len == m->data_len) {
						rec_ring->m_data[rec_ring->tail] = m;
						m = m->next;
						prev_m->next = NULL;
						prev_m->nb_segs = 1;
						rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
						
						rcvvar->rcvbuf->fctx->head_mbuf = m;
						//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
					} else {
						rcvvar->rcvbuf->fctx->head_mbuf = m;
					}
		//			printf("%s-%d: en_len:%d,prev_m->data_len:%d,head:%d\n",__func__,__LINE__,en_len,prev_m->data_len,head);
					//rcvvar->rcvbuf->data_buf.prev_head = head;
					stream->ref_count ++;
				} else {
					rec_ring->m_data[rec_ring->tail] = m;
					m = m->next;
					prev_m->next = NULL;
					prev_m->nb_segs = 1;
					rec_ring->tail = (rec_ring->tail + 1) % rec_ring->size;
					//head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
				}
				
	//printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				jobs[jobs_num] = toe_tx_databuf_to_job(prev_m, h_buffer_addr, en_len, dma_final_len, stream->host_dataptr, host_list_addr,toe_eg,qid, stream, rec_ring->tail);
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				if (!jobs[jobs_num]) {
					goto done;
				}
				
				jobs_num ++;
				if (unlikely(jobs_num == TOE_JOB_DATABUF_NUM)) {
						toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
						jobs_num = 0;
				}
				en_len_total += en_len;
				merged_len -= en_len;
				if (dma_final_len > 0) {
					if (en_len < prev_m->data_len) {
						m->data_off += en_len;
						m->data_len -= en_len;
						//rte_pktmbuf_adj(prev_m, en_len);
					}
					break;
				}
			};

			//rq中所有buffer写完，换下一个rq
			data_rq->pre_head = (data_rq->pre_head + 1) % data_rq->rq_size;
			printf("%s-%d: data_rq->pre_head:%d,data_rq->real_tail:%d,data_rq->enq_tail:%d\n",__func__,__LINE__,data_rq->pre_head,data_rq->real_tail,data_rq->enq_tail);
			if (data_rq->pre_head == data_rq->real_tail) { //没有可用的rq
//				printf("%s-%d: no host buffer\n",__func__,__LINE__);
				break;
			}
			rq = data_rq->rq_local + data_rq->pre_head;
			
			m = rcvvar->rcvbuf->fctx->head_mbuf;
			RTE_ASSERT(!(m == NULL && merged_len > 0));
		}

		if (likely(jobs_num > 0)) {
				toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
				jobs_num = 0;
		}

		free_len = rcvvar->rcvbuf->merged_len - merged_len;
		if (likely(free_len > 0)) {
			RBRemove_no_copy(mtcp->rbm_rcv, rcvvar->rcvbuf, free_len, AT_MTCP);
			rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	//		printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);
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
			prev_tsc = rte_rdtsc();
		}

done:
	return merged_len;
}

#endif


int toe_process_tcp_payload(tcp_stream *stream, struct rte_tcp_hdr *tcph, int payloadlen, struct rte_mbuf *m, struct toe_engine *toe_eg)
{
	uint32_t seq = ntohl(tcph->sent_seq);
//	uint32_t rcv_ack = ntohl(tcph->recv_ack);
//	uint16_t window = ntohs(tcph->rx_win);
	struct tcp_recv_vars *rcvvar = stream->rcvvar;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	uint32_t prev_rcv_nxt;
	int ret;

	rte_pktmbuf_adj(m, m->pkt_len - payloadlen);
	
	printf("%s-%d:  m->pkt_len:%d, m->data_len:%d, now:%llu\n",__func__,__LINE__,m->pkt_len,m->data_len,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(seq + payloadlen, stream->rcv_nxt)) {
		printf("%s-%d: seq:%d and segment:%d length is lower than rcv_nxt:%d\n",__func__,__LINE__,seq, payloadlen, stream->rcv_nxt);

		return TOE_FAILED_FREE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	/* more than recv wnd */
	if (TCP_SEQ_GT(seq + payloadlen, stream->rcv_nxt + stream->rcvvar->rcv_wnd)) {
		printf("%s-%d: seq:%d and segment:%d length is more than recv wnd:(rcv_nxt:%d + rcv_wnd:%d)\n",__func__,__LINE__,seq, payloadlen, stream->rcv_nxt,stream->rcvvar->rcv_wnd);
		return TOE_FAILED_FREE;
	}

	
	//printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit_no_copy(mtcp, rcvvar->irs + 1);
		if (!rcvvar->rcvbuf) {
			printf("Stream %d: Failed to allocate receive buffer.\n", 
					stream->id);
			//cur_stream->state = TCP_ST_CLOSED;
			//cur_stream->close_reason = TCP_NO_MEM;
			//RaiseErrorEvent(mtcp, cur_stream);
			//toe_close_to_host(stream, toe_eg);
			return TOE_ERR_FREE;
		}
	}

	printf("%s-%d: payloadlen:%d,m:%p\n",__func__,__LINE__,payloadlen,m);	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	prev_rcv_nxt = stream->rcv_nxt;


	int i;
	struct rte_mbuf *mn = m;
	for(i = 0; i < m->nb_segs; i++) {
		if (!mn)
			break;
		printf("%s-%d: mbuf-%d:%p, data_len:%d\n",__func__,__LINE__,i, mn,mn->data_len);
		mn = mn->next;
	}

	ret = RBPut_no_copy(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, (uint32_t)payloadlen, seq, m);
	if (unlikely(ret < 0)) {
		printf("Cannot merge payload. reason: %d\n", ret);
		return TOE_ERR_FREE;
	}

	//int i;
	mn = m;
	for(i = 0; i < m->nb_segs; i++) {
		if (!mn)
			break;
		printf("%s-%d: mbuf-%d:%p, data_len:%d\n",__func__,__LINE__,i, mn,mn->data_len);
		mn = mn->next;
	}
	
	//printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	stream->rcv_nxt = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;
	//printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);

	if (TCP_SEQ_LEQ(stream->rcv_nxt, prev_rcv_nxt)) {
		/* There are some lost packets */
		printf("%s-%d: There are some lost packets rcv_nxt:%u,prev_rcv_nxt:%u\n",__func__,__LINE__,stream->rcv_nxt,prev_rcv_nxt);
		return TOE_FAILED_RETAIN;
	}
	//rcvvar->rcvbuf->data_buf.m_data[rcvvar->rcvbuf->data_buf.tail] = m;
	//rcvvar->rcvbuf->data_buf.tail = (rcvvar->rcvbuf->data_buf.tail + 1) % rcvvar->rcvbuf->data_buf.size;

	return TOE_SUCCESS_RETAIN;
}

void toe_deal_data_per_stream(struct toe_engine *toe_eg, int qid)
{
	struct toe_data_tx_vring *tx_vring = toe_eg->data_tx_vring[qid];
	tcp_stream *stream[TOE_TX_DATA_RING_DESC];
	int num, i, ret;

	num = rte_ring_count(tx_vring->data_ring);
	if (!num)
		return;
	
	num = rte_ring_mc_dequeue_burst(tx_vring->data_ring, (void **)stream, num, NULL);

	for (i = 0; i < num; i++) {
		printf("%s-%d: data_to_host start,loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		ret = toe_dma_data_to_host(stream[i], toe_eg, qid, 1);

		printf("%s-%d:data_to_host done, loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		if (ret < 0) {
			if(!rte_ring_enqueue(tx_vring->data_ring, (void *)stream[i]))
				continue;
		}
		stream[i]->in_data_ring = 0;
		stream[i]->ref_count --;
		toe_destory_stream_check(stream[i]);
	}
		
	return;
}

int toe_data_stream_enq(tcp_stream *stream, struct toe_engine *toe_eg, int qid)
{
	struct toe_data_tx_vring *tx_vring = toe_eg->data_tx_vring[qid];
	int ret = 0;
	if (stream->in_data_ring) {
		return ret;
	}

	stream->ref_count ++;
	ret = rte_ring_enqueue(tx_vring->data_ring, (void *)stream);
	if (ret == 0)
		stream->in_data_ring = 1;

	return ret;
}

static int toe_tcp_fin_to_host(tcp_stream *stream, struct toe_engine *toe_eg, int qid)
{
	struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[qid]->cq_info;
	struct toe_ctrl_host_to_dpu_res *cq_msg;

	cq_msg = toe_avail_cq_msg(cq_info);

	cq_msg->qid = qid;
	cq_msg->compl = toe_eg->ctl_rx_vring[qid]->cq_info.cq_compl;
	cq_msg->identification.card_stream_addr = (uint64_t)stream;
	cq_msg->identification.host_dataptr = stream->host_dataptr;

	cq_msg->tcp_info.tcp_tuples.local_ip = stream->daddr;
	cq_msg->tcp_info.tcp_tuples.remote_ip = stream->saddr;
	cq_msg->tcp_info.tcp_tuples.local_port = stream->dport;
	cq_msg->tcp_info.tcp_tuples.remote_port = stream->sport;

	cq_msg->tcp_info.tcp_params.tcp_flags = stream->fin_msg.tcp_flag;
	cq_msg->tcp_info.tcp_params.sequence = ntohl(stream->fin_msg.sequence);
	cq_msg->tcp_info.tcp_params.window = ntohl(stream->fin_msg.window);
	cq_msg->tcp_info.tcp_params.acknowledge = ntohl(stream->fin_msg.acknowledge);

	stream->fin_msg.is_fin = 0;


	stream->sndvar->snd_una++;
	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	return 0;
}

int toe_tcp_ctlpkt_to_host(struct rte_mbuf *m, struct rte_tcp_hdr *tcph, tcp_stream *stream, struct toe_engine *toe_eg, int qid)
{
	struct toe_ctrl_host_to_dpu_res *cq_msg;
	uint8_t flag = tcph->tcp_flags;
	struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[qid]->cq_info;
	uint16_t rq_head = toe_eg->ctl_rx_vring[qid]->rq_info.pre_head;

	cq_msg = toe_avail_cq_msg(cq_info);
	if (rq_head == 0)
		rq_head = toe_eg->ctl_rx_vring[qid]->rq_info.rq_size;
	else
		rq_head = rq_head - 1;

	cq_msg->rq_head = rq_head;
	cq_msg->qid = qid;
	cq_msg->compl = toe_eg->ctl_rx_vring[qid]->cq_info.cq_compl;
	cq_msg->identification.card_stream_addr = (uint64_t)stream;
	cq_msg->identification.host_dataptr = stream->host_dataptr;

	cq_msg->tcp_info.tcp_tuples.local_ip = stream->daddr;
	cq_msg->tcp_info.tcp_tuples.remote_ip = stream->saddr;
	cq_msg->tcp_info.tcp_tuples.local_port = stream->dport;
	cq_msg->tcp_info.tcp_tuples.remote_port = stream->sport;

	cq_msg->tcp_info.tcp_params.tcp_flags = tcph->tcp_flags;
	cq_msg->tcp_info.tcp_params.sequence = ntohl(tcph->sent_seq);
	cq_msg->tcp_info.tcp_params.window = ntohl(tcph->rx_win);
	cq_msg->tcp_info.tcp_params.acknowledge = ntohl(tcph->recv_ack);
	switch (flag) {
		case TCP_FLAG_SYN:
			break;
		case (TCP_FLAG_SYN | TCP_FLAG_ACK):
				//stream->sndvar->snd_una++;
				//printf("%s-%d:stream->sndvar->snd_una:%u,\n",__func__,__LINE__,stream->sndvar->snd_una);
			break;
		case (TCP_FLAG_FIN | TCP_FLAG_ACK):
				stream->sndvar->snd_una++;
				//printf("%s-%d:stream->sndvar->snd_una:%u,\n",__func__,__LINE__,stream->sndvar->snd_una);
		break;
		case TCP_FLAG_RST:
		break;
		case TCP_FLAG_ACK:
			break;
		default:
		break;
	}

	cq_info->tail = (cq_info->tail + 1) % cq_info->cq_size;
	if (cq_info->tail == 0)
		cq_info->cq_compl = cq_info->cq_compl ^ 1;

	return 0;
}

static int toe_pkt_parse_tcp(struct rte_mbuf *mbuf, struct toe_engine *toe_eg, int qid, uint32_t cur_ts)
{
	struct rte_ether_hdr *ethh = rte_pktmbuf_mtod_offset(mbuf, struct rte_ether_hdr *, 0);
	struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, mbuf->l2_len);
	struct rte_tcp_hdr *tcph = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, mbuf->l2_len + mbuf->l3_len);
	tcp_stream s_stream;
	tcp_stream *stream;
	uint8_t tcp_flag = tcph->tcp_flags;
	uint16_t window = ntohs(tcph->rx_win);
	uint8_t *payload = (uint8_t *)tcph + ((tcph->data_off & 0xf0) >> 2);
	int payloadlen = ntohs(iph->total_length) - (payload - (u_char *)iph);
	//int payloadlen = ntohs(iph->total_length) - ((tcph->data_off & 0xf0) >> 2) - ((iph->version_ihl & 0x0f) * 4);
	uint32_t seq = ntohl(tcph->sent_seq);
    uint32_t ack_seq = ntohl(tcph->recv_ack);
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int to_host = 0;
	int ret, free_mbuf = 1;
	
	s_stream.saddr = iph->dst_addr;
	s_stream.daddr = iph->src_addr;
	s_stream.sport = tcph->dst_port;
	s_stream.dport = tcph->src_port;
	printf("%s-%d:qid:%d, mbuf->pkt_len:%d,mbuf->data_len:%d, nbseg:%d,saddr:0x%x,daddr:0x%x,sport:%d,dport:%d,tcp_flag:0x%x,payloadlen:%d,iph->total_length:%d,,iph:%p\n",__func__,__LINE__,qid,mbuf->pkt_len,mbuf->data_len,mbuf->nb_segs,ntohl(iph->src_addr), ntohl(iph->dst_addr), ntohs(tcph->src_port), ntohs(tcph->dst_port), tcp_flag,payloadlen,ntohs(iph->total_length),(u_char *)iph);

	printf("%s-%d: seq:%u,ack_seq:%u\n",__func__,__LINE__,seq, ack_seq);


	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	stream = StreamHTSearch_by_stream(&s_stream);

	if (unlikely(!stream)) {
			if (likely(tcp_flag == TCP_FLAG_SYN)) {
				stream = CreateTCPStream_by_port(0, 0, iph->dst_addr, tcph->dst_port,iph->src_addr, tcph->src_port);
				if (!stream) {
					printf("%s-%d: stream create failed!\n",__func__,__LINE__);
					free_mbuf = 1;
					goto done;
				}
			//	stream->rcv_nxt++;
				stream->qid = qid;
				rte_memcpy(stream->dst_mac, ethh->s_addr.addr_bytes, sizeof(stream->dst_mac));
				rte_memcpy(stream->src_mac, ethh->d_addr.addr_bytes, sizeof(stream->src_mac));
				stream->rcvvar->irs = seq;
				stream->sndvar->peer_wnd = window;
				//stream->rcv_nxt = cur_stream->rcvvar->irs;
				stream->sndvar->cwnd = 1;
				ParseTCPOptions(stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
						(tcph->data_off << 2) - TCP_HEADER_LEN);
			} else {
				printf("%s-%d: stream not find\n",__func__,__LINE__);
				free_mbuf = 1;
				goto done;
			}
	}

	if (tcp_flag & TCP_FLAG_SYN && !stream->connect_state) {
	//	stream->state = TCP_ST_SYN_RCVD;
		stream->sndvar->peer_wnd = window;
		if (tcp_flag & TCP_FLAG_ACK) {
			HandleActiveOpen(mtcp, stream, cur_ts, tcph, seq, ack_seq, window);
			stream->sndvar->snd_una = ack_seq;
			//stream->sndvar->nrtx = 0;
			//stream->rcv_nxt = stream->rcvvar->irs + 1;
			//RemoveFromRTOList(mtcp, stream);
			//stream->state = TCP_ST_ESTABLISHED;
			//printf("%s-%d:htonl(stream->rcv_nxt):%d\n",__func__,__LINE__,htonl(stream->rcv_nxt));
		}
	} else {
		stream->sndvar->peer_wnd = 
				(uint32_t)window << stream->sndvar->wscale_peer;
	}
/*收到rst,卡应该不管，告诉主机，收到主机的close再释放
		if (tcp_flag & TCP_FLAG_RST) {
		stream->have_reset = TRUE;
		if (stream->state > TCP_ST_SYN_SENT) {
			if (ProcessRST(mtcp, stream, ack_seq)) {
				return TRUE;
			}
		}
	}
*/
	if (tcp_flag & TCP_FLAG_RST) {
		stream->connect_state = TOE_CLOSED;
		to_host = 1;
		goto dma_to_host;
	}

	if (!(tcp_flag == (TCP_FLAG_PSH | TCP_FLAG_ACK)) && !(tcp_flag == TCP_FLAG_ACK)) {
		to_host = 1;
		goto dma_to_host;
	}
	//printf("%s-%d: stream->connect_state:%d\n",__func__,__LINE__,stream->connect_state);
	//printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (stream->connect_state != TOE_ESTABLISHED) {
		to_host = 1;
		goto dma_to_host;
	}
	if ((tcp_flag & TCP_FLAG_FIN) && stream->connect_state == TOE_ESTABLISHED) {
		if (stream->rcvvar->rcvbuf->merged_len > 0) {
			to_host = 0;
			printf("%s-%d: recv fin but data not send over,stream->rcvvar->rcvbuf->merged_len:%u\n",__func__,__LINE__,stream->rcvvar->rcvbuf->merged_len);
			stream->fin_msg.is_fin = 1;
			stream->fin_msg.tcp_flag = tcp_flag;
			stream->fin_msg.window = ntohl(tcph->rx_win);
			stream->fin_msg.sequence = ntohl(tcph->sent_seq);
			stream->fin_msg.acknowledge = ntohl(tcph->recv_ack);
		}
	}
dma_to_host:
	if (stream->connect_state == TOE_ESTABLISHING && tcp_flag == TCP_FLAG_ACK) {
		//printf("%s-%d: ack_seq:%u,stream->sndvar->iss:%u\n",__func__,__LINE__,ack_seq,stream->sndvar->iss);
		if (ack_seq == stream->sndvar->iss + 1) {
				stream->connect_state = TOE_ESTABLISHED;
				
				stream->sndvar->snd_una = ack_seq;
				stream->snd_nxt = ntohl(tcph->recv_ack);
				stream->sndvar->cwnd = ((stream->sndvar->cwnd == 1)? (stream->sndvar->mss * TCP_INIT_CWND): stream->sndvar->mss);

				stream->state = TCP_ST_ESTABLISHED;
		} else {
			printf("%s-%d: this is not ack for syn_ack,ack_seq:%d, stream->sndvar->iss:%d\n",__func__,__LINE__,ack_seq, stream->sndvar->iss);
		}
	} else if (stream->connect_state == TOE_CLOSING && tcp_flag == TCP_FLAG_ACK) {
		printf("%s-%d: ack_seq:%u,stream->sndvar->iss:%u\n",__func__,__LINE__,ack_seq,stream->sndvar->iss);
		if (ack_seq == stream->sndvar->iss + 1) {
			stream->connect_state = TOE_CLOSED;
		}
	}
	

	if (to_host) {
		toe_tcp_ctlpkt_to_host(mbuf, tcph, stream, toe_eg, qid);
		if ((tcp_flag & TCP_FLAG_ACK) && payloadlen > 0) {
			goto data_deal;
		}
		free_mbuf = 1;
		printf("%s-%d:ctlpkt_to_host successful! now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		goto done;
	}

data_deal:

		ret = ValidateSequence(mtcp, stream, cur_ts, tcph, seq, ack_seq, payloadlen);
		if (!ret) {
			printf("%s-%d: ValidateSequence failed\n",__func__,__LINE__);
			free_mbuf = 1;
			goto done;
		}

	//stream->last_active_ts = mbuf->timestamp;
	//toe_update_timeout(stream, mbuf->timestamp, tcp_flag);

	if (payloadlen > 0) {
		ret = toe_process_tcp_payload(stream, tcph, 
				payloadlen, mbuf, toe_eg);
		if (ret == TOE_SUCCESS_RETAIN) {
			/* if return is TRUE, send ACK */
			EnqueueACK(mtcp, stream, cur_ts, ACK_OPT_AGGREGATE);
		} else if (ret == TOE_FAILED_RETAIN || ret == TOE_FAILED_FREE || ret == TOE_ERR_FREE) {
			EnqueueACK(mtcp, stream, cur_ts, ACK_OPT_NOW);
		}

		if (ret == TOE_SUCCESS_RETAIN || ret == TOE_FAILED_RETAIN)
			free_mbuf = 0;
		//if (ret == TOE_SUCCESS_FREE || ret == TOE_FAILED_FREE || ret == TOE_ERR_FREE)
		//	free_mbuf = 1;
#ifdef TOE_GRO
		ret = toe_dma_data_to_host(stream, toe_eg, qid, 1);
#else
		//ret = -1;
		ret = toe_dma_data_to_host(stream, toe_eg, qid, 1);
#endif
		if (ret != 0) {
		printf("%s-%d:data_stream_enq, loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
			toe_data_stream_enq(stream, toe_eg, qid);
		} else {
			if (unlikely(stream->fin_msg.is_fin == 1)) {
					toe_tcp_fin_to_host(stream, toe_eg, qid);
			}	
		}
			
	}

	if (tcp_flag & TCP_FLAG_ACK) {
		if (likely(stream->sndvar->sndbuf)) {
			printf("%s-%d:stream->sndvar->snd_wnd:%u,stream->sndvar->wnd_to_host:%d, stream->sndvar->increment_wnd:%u\n",__func__,__LINE__,stream->sndvar->snd_wnd,stream->sndvar->wnd_to_host,stream->sndvar->increment_wnd);
			ProcessACK(mtcp, stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
			//toe_prepare_host_buffer_enqueue(toe_eg, stream, qid);
			
			printf("%s-%d:stream->sndvar->wnd_to_host:%d, stream->sndvar->increment_wnd:%u,free_mbuf:%d\n",__func__,__LINE__,stream->sndvar->wnd_to_host,stream->sndvar->increment_wnd,free_mbuf);
			if (stream->sndvar->wnd_to_host && stream->sndvar->increment_wnd >= TOE_SEND_INCWND_TO_HOST_THRESHOLD) {
				toe_send_wnd_to_host(toe_eg, stream, qid);
			}
		}
	}

//rst:
		//toe_send_tcppkt_to_ring(stream, TCP_FLAG_RST, NULL, 0);

done:

	if (likely(stream))
		toe_destory_stream_check(stream);
	
	return free_mbuf;
}

uint16_t toe_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct toe_rx_queue *txq = tx_queue;
	struct toe_engine *toe_eg = txq->toe_eg;
	int i,qid, ret;
	struct rte_mbuf *mbuf;
	uint32_t cur_ts = toe_get_sys_time_ms();

	qid = txq->idx;

	printf("%s-%d: nb_pkts:%u,qid:%d,lcore:%d\n",__func__,__LINE__,nb_pkts,qid,rte_lcore_id());
	if (!toe_eg->t_dev->active || qid < 0) {
		rte_pktmbuf_free_bulk(tx_pkts, nb_pkts);
		return 0;
	}
	
	for (i = 0; i < nb_pkts; i++) {
		mbuf = tx_pkts[i];
		ret = toe_pkt_parse_tcp(mbuf, toe_eg, qid, cur_ts);
		if (ret)
			rte_pktmbuf_free(mbuf);
	}

	return nb_pkts;
}

static void 
WritePacketsToChunks(mtcp_manager_t mtcp, uint32_t cur_ts)
{
	int thresh = CONFIG.max_concurrency;
	int i;
	assert(mtcp->g_sender != NULL);

	if (mtcp->g_sender->ack_list_cnt) {
		WriteTCPACKList(mtcp, mtcp->g_sender, cur_ts, thresh);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	}
	if (mtcp->g_sender->send_list_cnt){
        	printf("%s-%d: mtcp->g_sender->send_list_cnt:%d\n",__func__,__LINE__,mtcp->g_sender->send_list_cnt);
		WriteTCPDataList(mtcp, mtcp->g_sender, cur_ts, thresh);
	}
}

static void toe_sys_ctrl_process(struct toe_engine *toe_eg)
{
	toe_sys_ctl_rq_dma_enqueue(toe_eg);
	toe_sys_ctl_cq_dma_enqueue(toe_eg);
	toe_dma_dequeue(toe_eg);
}

uint16_t toe_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct toe_rx_queue *rxq = (struct toe_rx_queue *)rx_queue;
	int idx = rxq->idx;
	struct toe_engine *toe_eg = rxq->toe_eg;
	struct toe_device *toe_dev = toe_eg->t_dev;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	uint32_t ts;
	int ret;
	uint64_t now = rte_rdtsc();
	const uint64_t drain_tsc = (rte_get_tsc_hz() + TOE_US_PER_S - 1) /
		TOE_US_PER_S * TOE_BURST_TX_DRAIN_US;

	if (!toe_eg->t_dev->enable || !toe_eg->t_dev->active)
		return 0;

	if (idx < 0) {
		toe_sys_ctrl_process(toe_eg);
		return 0;
	}

    // CHANNEL 1
	toe_ctl_data_rq_dma_enqueue(toe_eg, idx);
	toe_ctl_data_cq_dma_enqueue(toe_eg, idx);

    // CHANNEL 2
	toe_rx_data_dma_enqueue(toe_eg, idx);
	//toe_rx_databuf_dma_enqueue(toe_eg, data_rxq->idx);
	toe_rx_data_cq_dma_enqueue(toe_eg, idx);

	toe_dma_dequeue(toe_eg);
    // CHANNEL 3
	toe_tx_data_dma_enqueue(toe_eg, idx);
#ifdef TOE_GRO
	if (unlikely(now - prev_tsc > drain_tsc)) {
		toe_deal_data_per_stream(toe_eg, idx);
	}
#else
		if (unlikely(now - prev_tsc > drain_tsc)) {
			toe_deal_data_per_stream(toe_eg, idx);
		}
		//toe_deal_data_per_stream(toe_eg, idx);
#endif
	
	toe_tx_data_cq_dma_enqueue(toe_eg, idx);
	
	toe_dma_dequeue(toe_eg);

	ts = toe_get_sys_time_ms();
	//CheckRtmTimeout(mtcp, ts, 1000);	 
	WritePacketsToChunks(mtcp, ts); 
	ret = rte_ring_sc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
	if (ret > 0) {
	printf("%s-%d: rxq->rxq:%p, ret:%d\n",__func__,__LINE__,rxq->rxq,ret);
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	}
/*
	int i;
	for (i=0; i < ret; i++) {
		printf("%s-%d: toe send mbuf:%p,rx_pkts[i]->pkt_len:%d\n",__func__,__LINE__,rx_pkts[i],rx_pkts[i]->pkt_len);
		rte_pktmbuf_dump(stdout,rx_pkts[i], rx_pkts[i]->pkt_len);

	}*/
	loop_count++;
	return ret;
}

_Noreturn static void * toe_thread_sync_bar(void * reg)
{

	struct toe_device *toe_dev = (struct toe_device *)reg;
	struct toe_engine *toe_eg = toe_dev->toe_eg; 
	uint64_t now_s;
	int ret;
	
	while (true) {
		now_s = rte_rdtsc()/rte_get_tsc_hz();
		if (now_s - last > 10) {
			last = now_s;
			//toe_bar_printf(toe_eg, 1);
			//printf("%s-%d: toe_eg->t_dev->active:%d\n",__func__,__LINE__, toe_eg->t_dev->active);
		}
		if (!toe_eg->t_dev->enable)
			continue;
		
		toe_bar_msg_sync(toe_eg);
		if (!toe_dev->reset_done && toe_eg->t_dev->reset) {
			toe_reset_process(toe_eg);
			return ret;
		}		
	}
}
//#define toe_engine_init

static int toe_sys_ctrl_ring_init(struct toe_device *toe_dev)
{
	struct toe_sys_ctl_vring *ctl_vring;
	struct toe_engine *toe_eg = toe_dev->toe_eg; 
	
	ctl_vring = rte_calloc(NULL, toe_dev->ctrl_queues, sizeof(struct toe_sys_ctl_vring), RTE_CACHE_LINE_SIZE);
	if (ctl_vring == NULL)
		goto fail;

	ctl_vring->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, 0);
	ctl_vring->rq_info.rq_size = TOE_CHANNEL0_MAX_QUEUE_SIZE;
	ctl_vring->rq_info.tail = &ctl_vring->rq_info.rbc->doorbell;
	ctl_vring->rq_info.rq_local = rte_calloc(NULL, ctl_vring->rq_info.rq_size, sizeof(struct toe_sys_ctrl_host_to_dpu_req), RTE_CACHE_LINE_SIZE);
	if (ctl_vring->rq_info.rq_local == NULL)
		goto fail;

	ctl_vring->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, 0);
	ctl_vring->cq_info.cq_size = TOE_CHANNEL0_MAX_QUEUE_SIZE;
	ctl_vring->cq_info.head = &ctl_vring->cq_info.cbc->doorbell;
	ctl_vring->cq_info.cq_local = rte_calloc(NULL, ctl_vring->cq_info.cq_size, sizeof(struct toe_sys_ctrl_dpu_to_host_res), RTE_CACHE_LINE_SIZE);
	if (ctl_vring->cq_info.cq_local == NULL)
		goto fail;
	ctl_vring->cq_info.cq_compl = 1;

	toe_eg->sys_ctl_vring = ctl_vring;

	return 0;

fail:
	if (ctl_vring) {
		if (ctl_vring->rq_info.rq_local)
			rte_free(ctl_vring->rq_info.rq_local);
		if (ctl_vring->cq_info.cq_local)
			rte_free(ctl_vring->cq_info.cq_local);
		rte_free(ctl_vring);
	}
	return -1;
}

static int toe_ctrl_ring_init(struct toe_device *toe_dev)
{
	struct toe_ctl_rx_vring **ctl_rx_vring;
	struct toe_engine *toe_eg = toe_dev->toe_eg; 
	int i;
	
	ctl_rx_vring = rte_calloc(NULL, toe_dev->data_queues, sizeof(struct toe_ctl_rx_vring *), RTE_CACHE_LINE_SIZE);
	if (ctl_rx_vring == NULL)
		goto fail;

/*ctl_rx_vring->rq_info*/
	for (i = 0; i < toe_dev->data_queues; i++) {
		ctl_rx_vring[i] = rte_calloc(NULL, 1, sizeof(struct toe_ctl_rx_vring), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i] == NULL)
			goto fail;
		
		ctl_rx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, i + 1);
		ctl_rx_vring[i]->rq_info.rq_size = TOE_CHANNEL1_MAX_QUEUE_SIZE;
		ctl_rx_vring[i]->rq_info.tail = &ctl_rx_vring[i]->rq_info.rbc->doorbell;
		ctl_rx_vring[i]->rq_info.rq_local = rte_calloc(NULL, ctl_rx_vring[i]->rq_info.rq_size, sizeof(struct toe_ctrl_host_to_dpu_req), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i]->rq_info.rq_local == NULL)
			goto fail;
		
		//rte_atomic16_init(&ctl_rx_vring[i]->rq_info.wait_head_num);
		
	/*ctl_rx_vring->cq_info*/
		ctl_rx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, i + 1);
		ctl_rx_vring[i]->cq_info.cq_size = TOE_CHANNEL1_MAX_QUEUE_SIZE;
		ctl_rx_vring[i]->cq_info.head = &ctl_rx_vring[i]->cq_info.cbc->doorbell;
		ctl_rx_vring[i]->cq_info.cq_local = rte_calloc(NULL, ctl_rx_vring[i]->cq_info.cq_size, sizeof(struct toe_ctrl_host_to_dpu_res), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i]->cq_info.cq_local == NULL)
			goto fail;
		ctl_rx_vring[i]->cq_info.cq_compl = 1;
		//rte_atomic16_init(&ctl_rx_vring[i]->cq_info.wait_tail_num);
	}

	toe_eg->ctl_rx_vring = ctl_rx_vring;

	return 0;
	
	fail:
	if (ctl_rx_vring) {
		for (i = 0; i < toe_dev->data_queues; i++) {
			if (ctl_rx_vring[i]->rq_info.rq_local)
				rte_free(ctl_rx_vring[i]->rq_info.rq_local);
			if (ctl_rx_vring[i]->cq_info.cq_local)
				rte_free(ctl_rx_vring[i]->cq_info.cq_local);
		}
		rte_free(ctl_rx_vring);
	}
	
	return -1;
}

static int toe_data_ring_init(struct toe_device *toe_dev)
{
	struct toe_engine *toe_eg = toe_dev->toe_eg;
	struct toe_data_rx_vring **data_rx_vring;
	struct toe_data_tx_vring **data_tx_vring;
	char ring_name[RTE_RING_NAMESIZE];
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	int num = toe_dev->data_queues;
	int i;
	
	data_rx_vring = rte_calloc(NULL, num, sizeof(struct toe_data_rx_vring *), RTE_CACHE_LINE_SIZE);
	if (data_rx_vring == NULL)
		goto fail;

	data_tx_vring = rte_calloc(NULL, num, sizeof(struct toe_data_tx_vring *), RTE_CACHE_LINE_SIZE);
	if (data_tx_vring == NULL)
		goto fail;

	for(i = 0; i < num; i ++) {
		data_rx_vring[i] = rte_calloc(NULL, 1, sizeof(struct toe_data_rx_vring), RTE_CACHE_LINE_SIZE);
		if (data_rx_vring[i] == NULL)
			goto fail;
		data_rx_vring[i]->idx = i;
		data_rx_vring[i]->toe_dev = toe_dev->toe_eg;
		data_rx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + toe_dev->data_queues + i);
		data_rx_vring[i]->rq_info.rq_size = TOE_CHANNEL2_MAX_QUEUE_SIZE;
		data_rx_vring[i]->rq_info.tail = &data_rx_vring[i]->rq_info.rbc->doorbell;
		data_rx_vring[i]->rq_info.rq_local = rte_calloc(NULL, data_rx_vring[i]->rq_info.rq_size, sizeof(struct toe_data_host_to_dpu_req), RTE_CACHE_LINE_SIZE);
        printf("data_rx_vring[%d]  RQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_rx_vring[i]->rq_info.rbc->queue_desc_h << 32)|data_rx_vring[i]->rq_info.rbc->queue_desc_lo, data_rx_vring[i]->rq_info.rbc->doorbell);
		if (data_rx_vring[i]->rq_info.rq_local == NULL)
			goto fail;

		data_rx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + toe_dev->data_queues + i);
		data_rx_vring[i]->cq_info.cq_size = TOE_CHANNEL2_MAX_QUEUE_SIZE;
		data_rx_vring[i]->cq_info.head = &data_rx_vring[i]->cq_info.cbc->doorbell;
		data_rx_vring[i]->cq_info.cq_local = rte_calloc(NULL, data_rx_vring[i]->cq_info.cq_size, sizeof(struct toe_data_host_to_dpu_res), RTE_CACHE_LINE_SIZE);
        printf("data_rx_vring[%d]  CQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_rx_vring[i]->cq_info.cbc->queue_desc_h << 32)|data_rx_vring[i]->cq_info.cbc->queue_desc_lo, data_rx_vring[i]->cq_info.cbc->doorbell);
		if (data_rx_vring[i]->cq_info.cq_local == NULL)
			goto fail;
		data_rx_vring[i]->cq_info.cq_compl = 1;

		sprintf(pool_name, "toe_mbuf_save_pool%d", i); 
		data_rx_vring[i]->mbuf_save_pool = rte_mempool_create(pool_name, 512, sizeof(struct rte_mbuf **), 0, 0, NULL,
                0, NULL, 0, rte_socket_id(),
                MEMPOOL_F_NO_SPREAD);
		if (!data_rx_vring[i]->mbuf_save_pool)
			goto fail;

		data_tx_vring[i] = rte_calloc(NULL, 1, sizeof(struct toe_data_tx_vring), RTE_CACHE_LINE_SIZE);
		if (data_tx_vring[i] == NULL)
			goto fail;
		data_tx_vring[i]->idx = i;
		data_tx_vring[i]->toe_dev = toe_dev->toe_eg;
		data_tx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + toe_dev->data_queues + num + i);
		data_tx_vring[i]->rq_info.rq_size = TOE_CHANNEL3_MAX_QUEUE_SIZE;
		data_tx_vring[i]->rq_info.tail = &data_tx_vring[i]->rq_info.rbc->doorbell;
		data_tx_vring[i]->rq_info.rq_local = rte_calloc(NULL, data_tx_vring[i]->rq_info.rq_size, sizeof(struct toe_data_dpu_to_host_req), RTE_CACHE_LINE_SIZE);
        printf("data_tx_vring[%d]  RQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_tx_vring[i]->rq_info.rbc->queue_desc_h << 32)|data_tx_vring[i]->rq_info.rbc->queue_desc_lo, data_tx_vring[i]->rq_info.rbc->doorbell);
		if (data_tx_vring[i]->rq_info.rq_local == NULL)
			goto fail;

		data_tx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + toe_dev->data_queues + num + i);
		data_tx_vring[i]->cq_info.cq_size = TOE_CHANNEL3_MAX_QUEUE_SIZE;
		data_tx_vring[i]->cq_info.head = &data_tx_vring[i]->cq_info.cbc->doorbell;
		data_tx_vring[i]->cq_info.cq_local = rte_calloc(NULL, data_tx_vring[i]->cq_info.cq_size, sizeof(struct toe_data_dpu_to_host_res), RTE_CACHE_LINE_SIZE);
        printf("data_tx_vring[%d]  CQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_tx_vring[i]->cq_info.cbc->queue_desc_h << 32)|data_tx_vring[i]->cq_info.cbc->queue_desc_lo, data_tx_vring[i]->cq_info.cbc->doorbell);
		if (data_tx_vring[i]->cq_info.cq_local == NULL)
			goto fail;
		data_tx_vring[i]->cq_info.cq_compl = 1;

		snprintf(ring_name, sizeof(ring_name), "toe_data_st%d", i);
		data_tx_vring[i]->data_ring = rte_ring_create(ring_name, TOE_TX_DATA_RING_DESC, SOCKET_ID_ANY, 0);
		if (!data_tx_vring[i]->data_ring) {
			printf("%s-%d: data_tx_vring[%d]->data_ring create failed\n",__func__,__LINE__,i);
			goto fail;
		}
		
		data_tx_vring[i]->recovery_ring.size = TOE_RECOVERY_MBUF_RING_SIZE;
	}

	toe_eg->data_rx_vring = data_rx_vring;
	toe_eg->data_tx_vring = data_tx_vring;
	return 0;
fail:
	if (data_rx_vring && data_tx_vring) {
		for(i = 0; i < num; i ++) {
			if (data_rx_vring[i]->rq_info.rq_local)
				rte_free(data_rx_vring[i]->rq_info.rq_local);
			if (data_rx_vring[i]->cq_info.cq_local)
				rte_free(data_rx_vring[i]->cq_info.cq_local);
			if (data_rx_vring[i]->mbuf_save_pool)
				rte_mempool_free(data_rx_vring[i]->mbuf_save_pool);
			
			if (data_tx_vring[i]->rq_info.rq_local)
				rte_free(data_tx_vring[i]->rq_info.rq_local);
			if (data_tx_vring[i]->cq_info.cq_local)
				rte_free(data_tx_vring[i]->cq_info.cq_local);
			if (data_tx_vring[i]->data_ring)
				rte_ring_free(data_tx_vring[i]->data_ring);
		}
		if (data_rx_vring)
			rte_free(data_rx_vring);
		if (data_tx_vring)
			rte_free(data_tx_vring);
	}
	return -1;
}

struct io_module_func toe_module_func = {.get_wptr = toe_get_wptr, .get_wptr_datapkt = toe_get_wptr_datapkt};

int toe_tcpstack_init(struct toe_device *toe_dev)
{
	uint16_t lcore_id;
	struct mtcp_manager *mtcp;
	int idx = 0;
	
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		mtcp = InitializeMTCPManagerPerCore(lcore_id);
		if (!mtcp || !mtcp->ctx) {
				printf("tcpstack_ctx: alloc failed!\n");
				return -1;
		}

		mtcp->iom = &toe_module_func;
		idx ++;
	}

	return 0;
}

int toe_ctrl_thread_init(struct toe_device *toe_dev)
{
	int ret;
	cpu_set_t mask;
	int16_t lcoreid = -1;
	int cpu_cores ;
	char *core_id = NULL;
	char thread_name[16];
	cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
	core_id = getenv(TOE_CTRL_PROCESS);
	if (core_id != NULL) {
		lcoreid = strtol(core_id, NULL, 10);
		if (lcoreid > cpu_cores){
			RTE_LOG(ERR, PMD, TOE_CTRL_PROCESS " %d is vaild\n",lcoreid);
			return -1;
		}
	} else {
		RTE_LOG(ERR, PMD, TOE_CTRL_PROCESS " not set\n");
		return -1;
	}
	//toe_dev->toe_eg->ctrl_thread_lcore_id = lcoreid;

	ret = pthread_create(&ctrl_thread, NULL, toe_thread_sync_bar, (void *)toe_dev);
	if (ret){
		RTE_LOG(ERR, PMD, "toe: ctrl thread create error\n");
		return -1;
	}
	if (lcoreid < 0)
		return ret;
	snprintf(thread_name, sizeof(thread_name), "toe_sync-%02d", lcoreid);
	CPU_ZERO(&mask);
	CPU_SET(lcoreid, &mask);
	ret = pthread_setaffinity_np(ctrl_thread, sizeof(mask), &mask);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "toe: set ctrl thread cpu id fail: %d\n", ret);
	ret = pthread_setname_np(ctrl_thread, thread_name);
	if (ret)
		return ret;
	return 0;

}

int toe_engine_init(struct toe_device *toe_dev)
{
	struct toe_engine *toe_eg;
	struct toe_bar_base_cfg *base_cfg;
	struct timeval cur_ts = {0};
	int ret, i, j;

	printf("~~ %s-%d:111, lcore_id:%d\n",__func__,__LINE__,rte_lcore_id());
	toe_eg = rte_calloc(NULL, 1, sizeof(struct toe_engine), RTE_CACHE_LINE_SIZE);
	if (toe_eg == NULL) {
		printf("~~ %s-%d:toe_eg malloc failed! \n",__func__,__LINE__);
		goto fail;
	}
	toe_dev->toe_eg = toe_eg;
	
	toe_eg->pf = 0;
	toe_eg->vf = 0;
	toe_eg->bar = toe_pcie_bar_get(toe_eg->pf, toe_eg->vf);
	base_cfg = toe_base_bar_get(toe_eg->bar);
	base_cfg->vendor_queue_num = toe_dev->f_queues;
	base_cfg->fd_reserve_num = 1024;

	toe_eg->ep = agiep_get_ep();
	memset(toe_eg->irq_data, 0xFF, sizeof(toe_eg->irq_data));

	toe_eg->t_dev = toe_dev;

	if (toe_dma_init(toe_eg)){
		RTE_LOG(ERR, PMD, "toe: dma init failed\n");
		goto fail;
	}

	if (toe_sys_ctrl_ring_init(toe_dev))
		goto fail;
	
	if (toe_ctrl_ring_init(toe_dev))
		goto fail;

	if (toe_data_ring_init(toe_dev))
		goto fail;

	if (toe_tcpstack_init(toe_dev))
		goto fail;

	if (toe_ctrl_thread_init(toe_dev))
		goto fail;
	
	sys_absolute_time = TIMEVAL_TO_TS(&cur_ts);
	rte_initial_rdtsc = rte_rdtsc();
	return 0;
fail:
	if (toe_eg)
		rte_free(toe_eg);
	return -1;
}

static void toe_msi_free(struct toe_engine *toe_eg)
{
	uint64_t vector = 0;
	struct toe_device *toe_dev = toe_eg->t_dev;

	if (!toe_dev->active)
		return;
	
		while (toe_eg->vector_map){
			vector = __builtin_ffs(toe_eg->vector_map);
			if (vector)
				vector -= 1;
			else
				break;
			toe_eg->vector_map &= ~(1UL << vector);
			toe_eg->irq_addr[vector] = NULL;
			toe_eg->irq_data[vector] = UINT32_MAX;
			pci_ep_free_irq_addr(toe_eg->ep, toe_eg->pf,
				     toe_eg->vf, PCI_EP_IRQ_MSI, vector);
		}
	return;
}

static void toe_sys_ctrl_ring_free(struct toe_engine *toe_eg)
{
	struct toe_sys_ctl_vring *ctl_vring = toe_eg->sys_ctl_vring;
	int i;
	
	if (ctl_vring) {
			if (ctl_vring->rq_info.rq_local)
				rte_free(ctl_vring->rq_info.rq_local);
			if (ctl_vring->cq_info.cq_local)
				rte_free(ctl_vring->cq_info.cq_local);

		rte_free(ctl_vring);
	}

	return;
}

static void toe_ctrl_ring_free(struct toe_engine *toe_eg)
{
	struct toe_ctl_rx_vring **ctl_rx_vring = toe_eg->ctl_rx_vring;
	int i;
	
	if (ctl_rx_vring) {
		for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
			if (ctl_rx_vring[i]->rq_info.rq_local)
				rte_free(ctl_rx_vring[i]->rq_info.rq_local);
			if (ctl_rx_vring[i]->cq_info.cq_local)
				rte_free(ctl_rx_vring[i]->cq_info.cq_local);
		}
		rte_free(ctl_rx_vring);
	}

	return;
}

static void toe_data_ring_free(struct toe_device *toe_dev)
{
	struct toe_data_rx_vring **data_rx_vring = toe_dev->toe_eg->data_rx_vring;
	struct toe_data_tx_vring **data_tx_vring = toe_dev->toe_eg->data_tx_vring;
	int num = toe_dev->data_queues;
	int i;

	if (data_rx_vring && data_tx_vring) {
		for(i = 0; i < num; i ++) {
			if (data_rx_vring[i]->rq_info.rq_local)
				rte_free(data_rx_vring[i]->rq_info.rq_local);
			if (data_rx_vring[i]->cq_info.cq_local)
				rte_free(data_rx_vring[i]->cq_info.cq_local);
			if (data_rx_vring[i]->mbuf_save_pool)
				rte_mempool_free(data_rx_vring[i]->mbuf_save_pool);
			if (data_tx_vring[i]->rq_info.rq_local)
				rte_free(data_tx_vring[i]->rq_info.rq_local);
			if (data_tx_vring[i]->cq_info.cq_local)
				rte_free(data_tx_vring[i]->cq_info.cq_local);
			if (data_tx_vring[i]->data_ring)
				rte_ring_free(data_tx_vring[i]->data_ring);
		}
		if (data_rx_vring)
			rte_free(data_rx_vring);
		if (data_tx_vring)
			rte_free(data_tx_vring);
	}
	return;
}

void toe_engine_free(struct toe_device *toe_dev)
{
	struct toe_engine *toe_eg = toe_dev->toe_eg;
	
	if (!toe_dev->reset_done && toe_eg->t_dev->reset)	
		toe_reset_process(toe_eg);
	toe_msi_free(toe_eg);

	toe_dma_fini();
	toe_sys_ctrl_ring_free(toe_eg);
	toe_ctrl_ring_free(toe_eg);
	toe_data_ring_free(toe_dev);
	
	if (toe_eg)
		rte_free(toe_eg);

	return;
}

void toe_engine_reset(struct toe_engine *toe_eg)
{
	int i, j, ret, nb_pkts = MAX_PKT_BURST;
	struct rte_mbuf *rx_pkts[MAX_PKT_BURST];
	struct toe_tx_data_queue *node;
	struct toe_rx_queue *rxq = NULL;
	struct toe_rx_queue *data_rxq = NULL;

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		rxq = toe_eg->t_dev->data_rxq[i];
		do {
			ret = rte_ring_mc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
			rte_pktmbuf_free_bulk(rx_pkts, ret);
		}while(ret);
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		data_rxq = toe_eg->t_dev->data_rxq[i];
		do {
			ret = rte_ring_mc_dequeue_burst(data_rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
			rte_pktmbuf_free_bulk(rx_pkts, ret);
		}while(ret);
	}
	
	toe_msi_free(toe_eg);

	
	printf("@@%s-%d: engine rest done\n",__func__,__LINE__);
}

static void toe_reset_process(struct toe_engine *toe_eg)
{
	struct toe_bar_base_cfg *base_cfg;
	int i;
	
	base_cfg = (struct toe_bar_base_cfg *)toe_eg->bar;
	
	toe_dma_reset(toe_eg);
	toe_engine_reset(toe_eg);
	toe_eg->t_dev->reset = 0;
	toe_eg->t_dev->reset_done = 1;
	base_cfg->status &= ~TOE_CARD_RESET;
	
	toe_eg->t_dev->active = 0;
	return;
}

