
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
#include <rte_io_64.h>
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
		for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {
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

static uint64_t toe_irq_addr(struct toe_engine *toe_eg, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;
	printf("+++toe_irq_addr:vector:%d,toe_eg->irq_addr[vector]:%p\n",vector,toe_eg->irq_addr[vector]);

	if (toe_eg->irq_addr[vector] == NULL)
		toe_eg->irq_addr[vector] = (void *)pci_ep_get_irq_addr(toe_eg->ep,
				toe_eg->pf, toe_eg->vf, irq_type, vector);
	return (uint64_t)toe_eg->irq_addr[vector];
}

static uint32_t toe_irq_data(struct toe_engine *toe_eg, uint16_t vector)
{
	enum pci_ep_irq_type irq_type = PCI_EP_IRQ_MSI;
	printf("__toe_irq_data:vector:%d,toe_eg->irq_data[vector]:0x%x\n",vector,toe_eg->irq_data[vector]);
	if (toe_eg->irq_data[vector] == 0xFFFFFFFF) {
		toe_eg->irq_data[vector] = pci_ep_get_irq_data(toe_eg->ep, 
				toe_eg->pf, toe_eg->vf, irq_type, vector);
		printf("__toe_irq_data222:toe_eg->vf:%d,vector:%d,toe_eg->irq_data[vector]:0x%x\n",toe_eg->vf,vector,toe_eg->irq_data[vector]);
	}
	return toe_eg->irq_data[vector];
}

//uint32_t data = 0;

void toe_irq_raise(struct toe_engine *toe_eg, uint16_t vector)
{
	uint64_t addr = toe_irq_addr(toe_eg, vector);
	uint32_t data = toe_irq_data(toe_eg, vector);
	//data ++;
	printf("toe_irq_raise:vector:%u addr:0x%lx,data:%u,  pf:%d vf:%d\n",vector,addr,data,toe_eg->pf,toe_eg->vf);
	if (addr == 0)
		return;
	rte_write32(data, (void *)addr);
}



#define toe_tcp_ctrl_pkt_organiza

#if 0
uint8_t *
ethernet_output(uint16_t h_proto, uint16_t iplen, struct rte_mbuf *m)
{
    uint8_t *buf;
    struct ethhdr *ethh;
    int i, eidx;

    ethh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    for (i = 0; i < ETH_ALEN; i++) {
        ethh->h_source[i] = CONFIG.eths[eidx].haddr[i];
        ethh->h_dest[i] = dst_haddr[i];
    }
    ethh->h_proto = htons(h_proto);

    return (uint8_t *)(ethh + 1);
}

uint8_t *
ip_output(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen, struct rte_mbuf *m)
{
    struct iphdr *iph;
    int nif;
    unsigned char *haddr, is_external = 0;
    int rc = -1;

    if (stream->sndvar->nif_out >= 0) {
        nif = stream->sndvar->nif_out;
    } else {
        nif = GetOutputInterface(stream->daddr, &is_external);
        stream->sndvar->nif_out = nif;
        stream->is_external = is_external;
    }

    haddr = NULL;//GetDestinationHWaddr(stream->daddr, stream->is_external);
    if (!haddr) {
#if 0
        uint8_t *da = (uint8_t *)&stream->daddr;
        TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
                "is not in ARP table!\n",
                da[0], da[1], da[2], da[3]);
#endif
        /* if not found in the arp table, send arp request and return NULL */
        /* tcp will retry sending the packet later */
        //RequestARP(mtcp, (stream->is_external) ? (CONFIG.gateway)->daddr : stream->daddr,
        //       stream->sndvar->nif_out, mtcp->cur_ts);
        return NULL;
    }
    
    iph = (struct iphdr *)EthernetOutput(mtcp, ETH_P_IP, 
            stream->sndvar->nif_out, haddr, tcplen + IP_HEADER_LEN);
    if (!iph) {
        return NULL;
    }

    iph->ihl = IP_HEADER_LEN >> 2;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(IP_HEADER_LEN + tcplen);
    iph->id = htons(stream->sndvar->ip_id++);
    iph->frag_off = htons(0x4000);  // no fragmentation
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = stream->saddr;
    iph->daddr = stream->daddr;
    iph->check = 0;

#ifndef DISABLE_HWCSUM
    /* offload IP checkum if possible */
        if (mtcp->iom->dev_ioctl != NULL) {
        switch (iph->protocol) {
        case IPPROTO_TCP:
            rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_TCPIP_CSUM_PEEK, iph);
            break;
//        case IPPROTO_ICMP:
//            rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_IP_CSUM, iph);
//            break;
        }
    }
    /* otherwise calculate IP checksum in S/W */
    if (rc == -1)
        iph->check = ip_fast_csum(iph, iph->ihl);
#else
    UNUSED(rc);
    iph->check = ip_fast_csum(iph, iph->ihl);
#endif
    return (uint8_t *)(iph + 1);
}


int
send_tcp_packet(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen, struct rte_mbuf *m)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
	}
		
	return payloadlen;
}
#endif
/*
struct rte_mbuf *toe_tcp_ctrl_pkt_organiza(int flag, tcp_stream *tcp_s, struct rte_mempool *mbuf_pool)
{
		struct rte_mbuf *mbuf;
		struct rte_ether_hdr *ethh;
		struct rte_ipv4_hdr *iphdr;
		struct rte_tcp_hdr *tcphdr;

		mbuf = rte_pktmbuf_alloc(mbuf_pool);
		if (unlikely(mbuf == NULL)) {
			return NULL;
		}

		ethh = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		ethh->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		rte_memcpy(ethh->s_addr, tcp_s->src_mac, sizeof(ethh->s_addr));
		rte_memcpy(ethh->d_addr, tcp_s->dst_mac, sizeof(ethh->d_addr));
		
		iphdr = ethh + 1;
		iphdr->
		
		tcphdr = iphdr + 1;

		return mbuf;
}
*/
void toe_destory_stream_check(tcp_stream *tcp_s)
{
	if (tcp_s->ref_count > 0)
		return;
	if (tcp_s->connect_state == TOE_CLOSED) {
		TOE_DestroyTCPStream(tcp_s);
	}
	return;
}
int toe_send_tcppkt_to_ring(tcp_stream *tcp_s, uint8_t tcpflag, void *data, int data_len)
{
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	struct timeval cur_ts = {0};
	uint32_t ts;
	int ret;
	
	gettimeofday(&cur_ts, NULL);
	ts = TIMEVAL_TO_TS(&cur_ts);
	
	ret = SendTCPPacket(mtcp, tcp_s, ts, tcpflag, data, data_len, 0);

	return ret;
}

#define toe_ctrl_opcode_deal

typedef int (*toe_ctl_opt_cb)(struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	int idx);

static void toe_cq_common_msg( struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	tcp_stream *tcp_s,
																	int idx)
{
	cq_msg->opcode = rq_msg->opcode;
	cq_msg->rq_head = toe_eg->ctl_rx_vring[idx]->rq_info.pre_head;
	cq_msg->qid = idx;
	cq_msg->identification.card_stream_addr = (uint64_t)tcp_s;
	cq_msg->identification.host_dataptr = rq_msg->id.host_dataptr;

}


int toe_get_ipmac(struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	int idx)
{
	struct toe_h2d_msg_ipmac_notification_hdr *ipmac_nf = &rq_msg->ipmac_notification;	
	uint8_t a, b, c, d;

	ip_uint32_t_to_char(ipmac_nf->ip, &a, &b, &c, &d);

	rte_memcpy(toe_eg->t_dev->ip, &ipmac_nf->ip, sizeof(ipmac_nf->ip));
	
	rte_memcpy(toe_eg->t_dev->mac, ipmac_nf->mac, sizeof(ipmac_nf->mac));

    printf("%s:%d  InterfaceIndex:%u  IP:%hhu.%hhu.%hhu.%hhu  MAC:%02X-%02X-%02X-%02X-%02X-%02X\n", __func__, __LINE__, ipmac_nf->ifindex, a, b, c, d, toe_eg->t_dev->mac[0], toe_eg->t_dev->mac[1], toe_eg->t_dev->mac[2], toe_eg->t_dev->mac[3], toe_eg->t_dev->mac[4], toe_eg->t_dev->mac[5]);

	toe_cq_common_msg(rq_msg, cq_msg, toe_eg, NULL, idx);
	return 0;
}

int toe_h2d_ctrl_msg(struct toe_ctrl_host_to_dpu_req *rq_msg, 
																	struct toe_ctrl_host_to_dpu_res *cq_msg, 
																	struct toe_engine *toe_eg,
																	int idx)
{
	struct toe_h2d_ctrl_packet_msg *ctrl_msg = &rq_msg->ctrl_pkt_msg;
	uint8_t flags = ctrl_msg->tcp_params.tcp_flags;
	uint8_t send_ctlpkt = 1;
	tcp_stream *tcp_s;
	tcp_stream s_stream;
	int ret;

	printf("%s-%d: tcp ctrl flags:0x%x!\n",__func__,__LINE__,flags);	
	tcp_s = (tcp_stream *)rq_msg->id.card_stream_addr;
	if (!tcp_s && flags != TCP_FLAG_SYN) {
		printf("%s-%d: tcp stream is null!\n",__func__,__LINE__);
		return -1;
	}

	switch (flags) {
		case TCP_FLAG_SYN:
			s_stream.saddr = ctrl_msg->tcp_params.local_ip;
			s_stream.daddr = ctrl_msg->tcp_params.remote_ip;
			s_stream.sport = ctrl_msg->tcp_params.local_port;
			s_stream.dport = ctrl_msg->tcp_params.remote_port;
			tcp_s = StreamHTSearch_by_stream(&s_stream);
			if (!tcp_s) {
				tcp_s = CreateTCPStream_by_port(0, ctrl_msg->tcp_params.sequence, ctrl_msg->tcp_params.local_ip, ctrl_msg->tcp_params.local_port, ctrl_msg->tcp_params.remote_ip, ctrl_msg->tcp_params.remote_port);
				if (!tcp_s) {
					printf("%s-%d: tcp stream create failed!\n",__func__,__LINE__);
					return -1;
				}
				tcp_s->daddr = ctrl_msg->tcp_params.remote_ip;
				tcp_s->saddr = ctrl_msg->tcp_params.local_ip;
				rte_memcpy(tcp_s->dst_mac, ctrl_msg->tcp_params.remote_mac, sizeof(tcp_s->dst_mac));
				rte_memcpy(tcp_s->src_mac, ctrl_msg->tcp_params.local_mac, sizeof(tcp_s->src_mac));		
				tcp_s->host_dataptr = rq_msg->id.host_dataptr;
			}
			
			tcp_s->sndvar->mss = ctrl_msg->tcp_params.mss;
			tcp_s->snd_nxt = ctrl_msg->tcp_params.sequence;
			tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_params.window;
			tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_params.window_scale;
			
			printf("%s-%d,tcp_s:%p,tcp_s->state:%d,tcp_s->host_dataptr:%llx,acr->tcp_params.sequence:%u,tcp_s->rcvvar->rcv_wnd:%u,tcp_s->sndvar->wscale_mine:%u \n", __func__, __LINE__,tcp_s,tcp_s->state,tcp_s->host_dataptr,ctrl_msg->tcp_params.sequence,tcp_s->rcvvar->rcv_wnd,tcp_s->sndvar->wscale_mine);
			break;
		case (TCP_FLAG_SYN | TCP_FLAG_ACK):
			tcp_s->sndvar->iss = ctrl_msg->tcp_params.sequence;
			tcp_s->host_dataptr = rq_msg->id.host_dataptr;
		case TCP_FLAG_RST:
			
			tcp_s->connect_state = TOE_CLOSED;

			printf("%s-%d: tcp_s->connect_state:%d,tcp_s->sndvar->iss:%u\n",__func__,__LINE__,tcp_s->connect_state,tcp_s->sndvar->iss);			
			tcp_s->snd_nxt = ctrl_msg->tcp_params.sequence;
			tcp_s->rcv_nxt = ctrl_msg->tcp_params.acknowledge;
			tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_params.window;
			tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_params.window_scale;
			break;
		case TCP_FLAG_ACK:
			if (ctrl_msg->status != 0)
				tcp_s->connect_state = ctrl_msg->status;
			printf("%s-%d: tcp_s->connect_state:%d\n",__func__,__LINE__,tcp_s->connect_state);			
			tcp_s->snd_nxt = ctrl_msg->tcp_params.sequence;
			tcp_s->rcv_nxt = ctrl_msg->tcp_params.acknowledge;
			if (tcp_s->connect_state == TOE_ESTABLISHED) {
				printf("%s-%d: ctrl_msg->tcp_params.window:%u\n",__func__,__LINE__,ctrl_msg->tcp_params.window);
				if (ctrl_msg->tcp_params.window) {
					tcp_s->rcvvar->rcv_wnd = ctrl_msg->tcp_params.window << tcp_s->sndvar->wscale_mine;
					//tcp_s->sndvar->wscale_mine = ctrl_msg->tcp_params.window_scale;
				}
				tcp_s->state = TCP_ST_ESTABLISHED;
			}
			break;
		case (TCP_FLAG_FIN | TCP_FLAG_ACK):

			if (tcp_s->sndvar->tcp_data_ring.free_num < TCP_SEND_DATA_BUFFER_MAX_NUM) {
				send_ctlpkt = 0;
				break;
			}
			
			if (ctrl_msg->status != 0)
				tcp_s->connect_state = ctrl_msg->status;

			if (tcp_s->connect_state == TOE_CLOSING) {
				tcp_s->snd_nxt = ctrl_msg->tcp_params.sequence;
				tcp_s->rcv_nxt = ctrl_msg->tcp_params.acknowledge;
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

		if (ret >= 0) {
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

toe_ctl_opt_cb ctl_opt_cb[TOE_MSG_OPCODE_END] = {
	toe_get_ipmac,
	toe_h2d_ctrl_msg,
};

struct toe_ctrl_host_to_dpu_res * toe_avail_cq_msg(struct toe_ctl_cq_info *cq_info)
{
	struct toe_ctrl_host_to_dpu_res *cq_msg;
	/*cq full*/
	cq_info->head = cq_info->cbc->doorbell;
	printf("%s-%d:cq_info->pre_tail:%d,cq_info->cq_size:%d,cq_info->head:%d\n",__func__,__LINE__,cq_info->pre_tail,cq_info->cq_size,cq_info->head);

	if ((cq_info->tail + 1) % cq_info->cq_size == cq_info->head) {
		printf("%s-%d: ctl rx cq is full!\n", __func__, __LINE__);
		return NULL;
	}
	cq_msg = cq_info->cq_local + cq_info->tail;
	cq_msg->compl = cq_info->cq_compl;
	return cq_msg;
}

int toe_ctl_recv(void *vaddr, struct toe_engine *toe_eg, int idx)
{
	struct toe_ctrl_host_to_dpu_req *rq_msg = vaddr;
	unsigned char opcode = rq_msg->opcode;
	struct toe_ctrl_host_to_dpu_res *cq_msg = NULL;
	struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[idx]->cq_info;
	int ret = 0;

	if (opcode >= TOE_MSG_OPCODE_END) {
		printf("%s-%d:opcode:%d is illegal!\n", __func__, __LINE__, opcode);
		return -1;
	}

	cq_msg = toe_avail_cq_msg(cq_info);
	if (!cq_msg) {
		printf("%s-%d:cq is full!\n", __func__, __LINE__);
		return 0;
	}

    printf("\n%s-%d:Receive Message OpCode : %u\n", __func__, __LINE__, opcode);
    
	if (!ctl_opt_cb[opcode]) {
		printf("%s-%d:ERROR Invalid Opcode : %u\n", __func__, __LINE__, opcode);
		return -1;
	}
    
	ret = ctl_opt_cb[opcode](rq_msg, cq_msg, toe_eg, idx);

	if (ret != 0)
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

	printf("%s-%d:mbuf:%p, data_q->rxq:%p,len:%d\n",__func__,__LINE__, mbuf,data_q->rxq,len);
	if (!rte_ring_mp_enqueue_burst(data_q->rxq, (void *const *)&mbuf, 1, NULL)) {
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

	mbuf = stream->sndvar->tcp_data_ring.m[data_posit];
	if (unlikely(mbuf == NULL)) {
		return NULL;
	}

	m_data = rte_pktmbuf_prepend(mbuf, len - mbuf->data_len);

	printf("%s-%d:mbuf:%p,mbuf->data:%p,m_data:%p,len:%d,mbuf->data_len:%d\n",__func__,__LINE__,mbuf,mbuf->buf_addr+mbuf->data_off,m_data,len,mbuf->data_len);	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	rte_ring_mp_enqueue_burst(data_q->rxq, (void *const *)&mbuf, 1, NULL);

	return m_data;

}

int toe_sendbuf_update(tcp_stream *stream, int data_len)
{
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	struct tcp_send_buffer *buf;

	if (!stream->sndvar->sndbuf) {
		stream->sndvar->sndbuf = SBInit(mtcp->rbm_snd, stream->sndvar->iss + 1);
		if (!stream->sndvar->sndbuf) {
			stream->close_reason = TCP_NO_MEM;
			printf("%s-%d:stream->sndvar->sndbuf malloc failed\n ",__func__,__LINE__);
			return -1;
		}
	}
	buf = stream->sndvar->sndbuf;

	buf->len += data_len;
	buf->cum_len += data_len;
	return 0;
}

int toe_tcp_datapkt_send(tcp_stream *stream, struct toe_engine *toe_eg,
																		int idx)
{
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		struct timeval cur_ts = {0};
		uint32_t ts;
	
		gettimeofday(&cur_ts, NULL);
		ts = TIMEVAL_TO_TS(&cur_ts);
        printf("%s-%d  stream->sndvar->sndbuf=%p\n",__func__,__LINE__, stream->sndvar->sndbuf);
		
		return FlushTCPSendingBuffer(mtcp, stream, ts);

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

	for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {
		cbc = &toe_eg->ctl_rx_vring[i]->cq_info.cbc;
		toe_eg->vector_map |= (1UL << cbc->msi_vector);

		addr = toe_irq_addr(toe_eg, cbc->msi_vector);
		toe_irq_data(toe_eg, cbc->msi_vector);
		if (addr == 0)
			printf("%s toe ctrl irq_addr failed", __func__);
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
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

	toe_dev->active = (base_cfg->status & TOE_DRIVER_ACTIVE);

	if (toe_dev->active) {
	printf("%s-%d: active now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());

		toe_msi_init(toe_eg);
		return 1;
	}

	return 0;
}

int toe_dma_data_to_host(tcp_stream *stream, struct toe_engine *toe_eg, int qid, int timeout_send)
{
		struct tcp_recv_vars *rcvvar = stream->rcvvar;
		struct toe_data_tx_rq_info *data_rq = &toe_eg->data_tx_vring[qid]->rq_info;
		struct toe_data_dpu_to_host_req *rq = data_rq->rq_local + data_rq->pre_head;
		struct rte_qdma_job *jobs[TOE_JOB_DATABUF_NUM];
		uint16_t jobs_num = 0;
		struct rte_mbuf *m;
		mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
		int head, merged_len = -1, free_len, en_len = 0, en_len_total = 0, dma_final_len = 0;
		uint64_t h_buffer_addr;
		uint64_t host_list_addr = 0;

		if (data_rq->pre_head == data_rq->real_tail) {
			printf("%s-%d: no buffer!\n",__func__,__LINE__);
			goto done;
		}
		printf("%s-%d: timeout_send:%d,loop_count:%llu\n",__func__,__LINE__,timeout_send,loop_count);	
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		merged_len = rcvvar->rcvbuf->merged_len;
		printf("%s-%d: merged_len:%d, rcvvar->rcvbuf->data_buf.prev_head:%d,rcvvar->rcvbuf->data_buf.tail:%d, rq->recv_buffer[rq->use_idx].recv_buffer_len:%d,data_rq:%p data_rq->pre_head:%d,data_rq->real_tail:%d,rq:%p\n",__func__,__LINE__,merged_len, rcvvar->rcvbuf->data_buf.prev_head,rcvvar->rcvbuf->data_buf.tail,rq->recv_buffer[rq->use_idx].recv_buffer_len,data_rq,data_rq->pre_head,data_rq->real_tail,rq);
		while (merged_len && (merged_len > rq->recv_buffer[rq->use_idx].recv_buffer_len || timeout_send)) {
			head = rcvvar->rcvbuf->data_buf.prev_head;
			dma_final_len = 0;
			en_len_total = 0;
			host_list_addr = 0;
			do { 
				h_buffer_addr = rq->recv_buffer[rq->use_idx].recv_buffer_phyaddr + en_len_total;
				m = rcvvar->rcvbuf->data_buf.m_data[head];
				printf("%s-%d,m:%p,en_len:%d,dma_final_len:%d,en_len_total:%d,merged_len:%d,head:%d,h_buffer_addr:0x%llx,rq->use_idx:%d\n",__func__,__LINE__,m,m?m->data_len:0,dma_final_len,en_len_total,merged_len,head,h_buffer_addr,rq->use_idx);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				en_len = m->data_len;
				if (en_len_total + m->data_len >= rq->recv_buffer[rq->use_idx].recv_buffer_len) {
					en_len = rq->recv_buffer[rq->use_idx].recv_buffer_len - en_len_total;
					dma_final_len = en_len_total + en_len;

					host_list_addr = rq->recv_buffer[rq->use_idx].host_list_virtaddr;
					printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				} else if (timeout_send && (merged_len - en_len == 0)) {
					dma_final_len = en_len_total + en_len;
					host_list_addr = rq->recv_buffer[rq->use_idx].host_list_virtaddr;
					printf("%s-%d: dma_final_len:%d,host_list_addr:0x%llx\n",__func__,__LINE__,dma_final_len,host_list_addr);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				}
				
				if (dma_final_len > 0) { //写完一个buffer
					if (en_len == m->data_len)
						head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
					printf("%s-%d: en_len:%d,m->data_len:%d,head:%d\n",__func__,__LINE__,en_len,m->data_len,head);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
					rcvvar->rcvbuf->data_buf.prev_head = head;
					stream->ref_count ++;
				} else {
					head = (head + 1) % rcvvar->rcvbuf->data_buf.size;
				}
				
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				jobs[jobs_num] = toe_tx_databuf_to_job(m, h_buffer_addr, en_len, dma_final_len, stream->host_dataptr, host_list_addr,toe_eg,qid, stream, head);
				if (!jobs[jobs_num]) {
					goto done;
				}
	printf("%s-%d:loop_count:%llu,now:%llu \n",__func__,__LINE__,loop_count,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				jobs_num ++;
				if (jobs_num == TOE_JOB_DATABUF_NUM) {
						toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
						jobs_num = 0;
				}
				en_len_total += en_len;
				merged_len -= en_len;
				if (dma_final_len > 0) {
					if (en_len < m->data_len) {
						m->data_off += en_len;
						m->data_len -= en_len;
					}
					break;
				}
			}while(1);

			if (rq->use_idx + 1 == rq->buffer_num) { //rq中所有buffer写完，换下一个rq
				data_rq->pre_head = (data_rq->pre_head + 1) % data_rq->rq_size;
				printf("%s-%d: data_rq->pre_head:%d",__func__,__LINE__,data_rq->pre_head);
				printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
				if (data_rq->pre_head == data_rq->real_tail) { //没有可用的rq
					printf("%s-%d: no host buffer\n",__func__,__LINE__);
					break;
				}
				rq = data_rq->rq_local + data_rq->pre_head;
			} else {
				rq->use_idx += 1;
			}
			
		}

		if (jobs_num > 0) {
				toe_tx_data_job_enq(jobs, jobs_num, toe_eg);
				jobs_num = 0;
		}

		free_len = rcvvar->rcvbuf->merged_len - merged_len;
		if (free_len > 0) {
			RBRemove_no_copy(mtcp->rbm_rcv, rcvvar->rcvbuf, free_len, AT_MTCP);
			rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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
			prev_tsc = rte_rdtsc();
		}

done:
	return merged_len;
}

int toe_process_tcp_payload(tcp_stream *stream, struct rte_tcp_hdr *tcph, uint8_t *payload, int payloadlen, struct rte_mbuf *m, struct toe_engine *toe_eg)
{
	uint32_t seq = ntohl(tcph->sent_seq);
//	uint32_t rcv_ack = ntohl(tcph->recv_ack);
//	uint16_t window = ntohs(tcph->rx_win);
	struct tcp_recv_vars *rcvvar = stream->rcvvar;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	uint32_t prev_rcv_nxt;
	int ret;

	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	rte_pktmbuf_adj(m, m->data_len - payloadlen);
	
	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(seq + payloadlen, stream->rcv_nxt)) {
		printf("%s-%d: seq:%d and segment:%d length is lower than rcv_nxt:%d\n",__func__,__LINE__,seq, payloadlen, stream->rcv_nxt);

		return FALSE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	/* more than recv wnd */
	if (TCP_SEQ_GT(seq + payloadlen, stream->rcv_nxt + stream->rcvvar->rcv_wnd)) {
		printf("%s-%d: seq:%d and segment:%d length is more than recv wnd:(rcv_nxt:%d + rcv_wnd:%d)\n",__func__,__LINE__,seq, payloadlen, stream->rcv_nxt,stream->rcvvar->rcv_wnd);
		return FALSE;
	}

	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit_no_copy(mtcp->rbm_rcv, rcvvar->irs + 1);
		if (!rcvvar->rcvbuf) {
			printf("Stream %d: Failed to allocate receive buffer.\n", 
					stream->id);
			//cur_stream->state = TCP_ST_CLOSED;
			//cur_stream->close_reason = TCP_NO_MEM;
			//RaiseErrorEvent(mtcp, cur_stream);
			//toe_close_to_host(stream, toe_eg);
			return ERROR;
		}
	}

	printf("%s-%d: payloadlen:%d,m:%p\n",__func__,__LINE__,payloadlen,m);	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	prev_rcv_nxt = stream->rcv_nxt;
	ret = RBPut_no_copy(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, payload, (uint32_t)payloadlen, seq, m);
	if (ret < 0) {
		printf("Cannot merge payload. reason: %d\n", ret);
		return FALSE;
	}

	
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	stream->rcv_nxt = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;
	printf("%s-%d: rcvvar->rcv_wnd:%u, rcvvar->rcvbuf->size:%u\n",__func__,__LINE__, rcvvar->rcv_wnd, rcvvar->rcvbuf->size);

	if (TCP_SEQ_LEQ(stream->rcv_nxt, prev_rcv_nxt)) {
		/* There are some lost packets */
		printf("%s-%d: There are some lost packets rcv_nxt:%u,prev_rcv_nxt:%u\n",__func__,__LINE__,stream->rcv_nxt,prev_rcv_nxt);
		return FALSE;
	}
	rcvvar->rcvbuf->data_buf.m_data[rcvvar->rcvbuf->data_buf.tail] = m;
	rcvvar->rcvbuf->data_buf.tail = (rcvvar->rcvbuf->data_buf.tail + 1) % rcvvar->rcvbuf->data_buf.size;

	return TRUE;
}

void toe_deal_data_per_stream(struct toe_engine *toe_eg, int qid)
{
	struct toe_data_tx_vring *tx_vring = toe_eg->data_tx_vring[qid];
	tcp_stream *stream[TOE_DATA_STREAM_DEQ_NUM];
	int num, i, ret;

	do {
		num = rte_ring_count(tx_vring->data_ring);
		if (!num)
			break;
		
		num = RTE_MIN(num, TOE_DATA_STREAM_DEQ_NUM);
		num = rte_ring_mc_dequeue_burst(tx_vring->data_ring, (void **)stream, num, NULL);

		for (i = 0; i < num; i++) {
			toe_dma_data_to_host(stream[i], toe_eg, qid, 1);
			stream[i]->in_data_ring = 0;
			stream[i]->ref_count --;
			toe_destory_stream_check(stream[i]);
		}
	}while(1);
		
	return;
}

int toe_data_stream_enq(tcp_stream *stream, struct toe_engine *toe_eg, int qid)
{
	struct toe_data_tx_vring *tx_vring = toe_eg->data_tx_vring[qid];
	int ret = 0;
	if (stream->in_data_ring) {
		return ret;
	}
//缺少引用计数和free标志
	stream->ref_count ++;
	ret = rte_ring_enqueue(tx_vring->data_ring, (void *)stream);
	if (ret == 0)
		stream->in_data_ring = 1;

	return ret;
}

int toe_tcp_ctlpkt_to_host(struct rte_mbuf *m, struct rte_tcp_hdr *tcph, tcp_stream *stream, struct toe_engine *toe_eg, int qid)
{
	struct toe_ctrl_host_to_dpu_res *cq_msg;
	uint8_t flag = tcph->tcp_flags;
	struct toe_ctl_cq_info *cq_info = &toe_eg->ctl_rx_vring[qid]->cq_info;

	cq_msg = toe_avail_cq_msg(cq_info);

	cq_msg->qid = qid;
	cq_msg->compl = toe_eg->ctl_rx_vring[qid]->cq_info.cq_compl;
	cq_msg->identification.card_stream_addr = (uint64_t)stream;
	cq_msg->identification.host_dataptr = stream->host_dataptr;
	cq_msg->opcode = TOE_MESSAGE_OPCODE_D2H_CTRL_PACKET;

	cq_msg->ctrl_pkt_msg.tcp_params.local_ip = stream->daddr;
	cq_msg->ctrl_pkt_msg.tcp_params.remote_ip = stream->saddr;
	cq_msg->ctrl_pkt_msg.tcp_params.local_port = stream->dport;
	cq_msg->ctrl_pkt_msg.tcp_params.remote_port = stream->sport;

	cq_msg->ctrl_pkt_msg.tcp_params.tcp_flags = tcph->tcp_flags;
	cq_msg->ctrl_pkt_msg.tcp_params.sequence = ntohl(tcph->sent_seq);
	cq_msg->ctrl_pkt_msg.tcp_params.window = ntohl(tcph->rx_win);
	cq_msg->ctrl_pkt_msg.tcp_params.acknowledge = ntohl(tcph->recv_ack);
	switch (flag) {
		case TCP_FLAG_SYN:
			break;
		case (TCP_FLAG_SYN | TCP_FLAG_ACK):
				//stream->sndvar->snd_una++;
				printf("%s-%d:stream->sndvar->snd_una:%d,\n",__func__,__LINE__,stream->sndvar->snd_una);
			break;
		case (TCP_FLAG_FIN | TCP_FLAG_ACK):
				stream->sndvar->snd_una++;
				printf("%s-%d:stream->sndvar->snd_una:%d,\n",__func__,__LINE__,stream->sndvar->snd_una);
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

int toe_pkt_parse_tcp(struct rte_mbuf *mbuf, struct toe_engine *toe_eg, int qid)
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

	uint32_t cur_ts = mbuf->timestamp;
	uint32_t seq = ntohl(tcph->sent_seq);
        uint32_t ack_seq = ntohl(tcph->recv_ack);
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	int to_host = 0;
	int ret;
	
	s_stream.saddr = iph->dst_addr;
	s_stream.daddr = iph->src_addr;
	s_stream.sport = tcph->dst_port;
	s_stream.dport = tcph->src_port;
	printf("%s-%d: saddr:0x%x,daddr:0x%x,sport:%d,dport:%d,tcp_flag:0x%x,payloadlen:%d,iph->total_length:%d,payload:%p,iph:%p\n",__func__,__LINE__,ntohl(iph->src_addr), ntohl(iph->dst_addr), ntohs(tcph->src_port), ntohs(tcph->dst_port), tcp_flag,payloadlen,ntohs(iph->total_length),payload,(u_char *)iph);
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	stream = StreamHTSearch_by_stream(&s_stream);

	if (!stream) {
			if (tcp_flag == TCP_FLAG_SYN) {
				stream = CreateTCPStream_by_port(0, 0, iph->dst_addr, tcph->dst_port,iph->src_addr, tcph->src_port);
				if (!stream) {
					printf("%s-%d: stream create failed!\n",__func__,__LINE__);
					goto rst;
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
				//goto rst;
				return 0;
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
	if (!(tcp_flag == (TCP_FLAG_PSH | TCP_FLAG_ACK)) && !(tcp_flag == TCP_FLAG_ACK)) {
		to_host = 1;
		goto dma_to_host;
	}
	printf("%s-%d: stream->connect_state:%d\n",__func__,__LINE__,stream->connect_state);
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
	if (stream->connect_state != TOE_ESTABLISHED) {
		to_host = 1;
		goto dma_to_host;
	}

dma_to_host:
	if (stream->connect_state == TOE_ESTABLISHING && tcp_flag == TCP_FLAG_ACK) {
		printf("%s-%d: ack_seq:%u,stream->sndvar->iss:%u\n",__func__,__LINE__,ack_seq,stream->sndvar->iss);
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
		goto done;
	}

data_deal:

		ret = ValidateSequence(mtcp, stream, cur_ts, tcph, seq, ack_seq, payloadlen);
		if (!ret) {
			printf("%s-%d: ValidateSequence failed\n",__func__,__LINE__);
			return 0;
		}

	//stream->last_active_ts = mbuf->timestamp;
	//toe_update_timeout(stream, mbuf->timestamp, tcp_flag);

	if (payloadlen > 0) {
		if (toe_process_tcp_payload(stream, tcph, 
				payload, payloadlen, mbuf, toe_eg)) {
			/* if return is TRUE, send ACK */
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
			EnqueueACK(mtcp, stream, cur_ts, ACK_OPT_AGGREGATE);
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
			ret = 1;
		} else {
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
			EnqueueACK(mtcp, stream, cur_ts, ACK_OPT_NOW);
	printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
		}

		ret = toe_dma_data_to_host(stream, toe_eg, qid, 0);
		if (ret != 0) {
			toe_data_stream_enq(stream, toe_eg, qid);
		}
			
	}

	if (tcp_flag & TCP_FLAG_ACK) {
		if (stream->sndvar->sndbuf) {
			ProcessACK(mtcp, stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}
	}
	
	return ret;

	rst:
		//toe_send_tcppkt_to_ring(stream, TCP_FLAG_RST, NULL, 0);

done:
	toe_destory_stream_check(stream);
	return 0;
}

uint16_t toe_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct toe_rx_queue *txq = tx_queue;
	struct toe_engine *toe_eg = txq->toe_eg;
	int i,qid, ret;
	struct rte_mbuf *mbuf;

	if (!toe_eg->t_dev->active) {
		//rte_pktmbuf_free_bulk(tx_pkts, nb_pkts);
		return 0;
	}
	qid = txq->idx;

	for (i = 0; i < nb_pkts; i++) {
		mbuf = tx_pkts[i];
		ret = toe_pkt_parse_tcp(mbuf, toe_eg, qid);
		if (!ret)
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
	if (mtcp->g_sender->send_list_cnt)
		WriteTCPDataList(mtcp, mtcp->g_sender, cur_ts, thresh);
}

uint16_t toe_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	//struct toe_device *toe_dev = rx_queue;
	struct toe_rx_queue *rxq = (struct toe_rx_queue *)rx_queue;
	int idx = rxq->idx;
	struct toe_engine *toe_eg = rxq->toe_eg;
	struct toe_device *toe_dev = toe_eg->t_dev;
	mtcp_manager_t mtcp = g_mtcp[rte_lcore_id()];
	struct timeval cur_ts = {0};
	uint32_t ts;
	int ret;
	uint64_t now = rte_rdtsc();
//	uint64_t now_s = now/rte_get_tsc_hz();
	const uint64_t drain_tsc = (rte_get_tsc_hz() + TOE_US_PER_S - 1) /
		TOE_US_PER_S * TOE_BURST_TX_DRAIN_US;
/*	
	if (now_s - last > 10  && idx == 0) {
		last = now_s;
		toe_bar_printf(toe_eg, 1);

	//if(toe_eg->t_dev->active)
		//toe_irq_raise(toe_eg, toe_eg->ctl_rx_vring->cq_info.cbc->msi_vector);
	//toe_test(toe_eg);
	//printf("**&& toe_rx_pkt_burst: rxq:%p\n",rxq);
	//toe_test_creat(toe_eg);
	//toe_test_connect(toe_eg);
	}
*/

	if (!toe_eg->t_dev->enable)
		return 0;

	toe_bar_msg_sync(toe_eg);
/*
     if (toe_bar_msg_sync(toe_eg)) {
        ret = rte_ring_mc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
        printf("~~ %s:proc_id:%d, idx:%d set active, rx pkt num :%d\n",__func__,rte_lcore_id(),idx, ret);
        return ret;
    }
  */  
       	if (!toe_dev->reset_done && toe_eg->t_dev->reset) {
		toe_reset_process(toe_eg);
		ret = rte_ring_mc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
		return ret;
	}	
	if (!toe_eg->t_dev->active)
		return 0;

	//toe_dma_dequeue(toe_eg);

    // CHANNEL 1
	toe_rx_ctl_rq_dma_enqueue(toe_eg, rxq->idx);
	toe_rx_ctl_cq_dma_enqueue(toe_eg, rxq->idx);

    // CHANNEL 2
	toe_rx_data_dma_enqueue(toe_eg, rxq->idx);
	//toe_rx_databuf_dma_enqueue(toe_eg, data_rxq->idx);
	toe_rx_data_cq_dma_enqueue(toe_eg, rxq->idx);

	toe_dma_dequeue(toe_eg);
    // CHANNEL 3
	toe_tx_data_dma_enqueue(toe_eg, rxq->idx);
	if (unlikely(now - prev_tsc > drain_tsc)) {
		toe_deal_data_per_stream(toe_eg, rxq->idx);
		//prev_tsc = now;
	}
	
	toe_tx_data_cq_dma_enqueue(toe_eg, rxq->idx);
	
	toe_dma_dequeue(toe_eg);

	gettimeofday(&cur_ts, NULL);
	ts = TIMEVAL_TO_TS(&cur_ts);

	CheckRtmTimeout(mtcp, ts, 1000);	 
	WritePacketsToChunks(mtcp, ts); //将TCPControlList,TCPACKList,TCPDataList中待发送流组包放到接口待发送缓存
	ret = rte_ring_mc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
	if (ret > 0) {
		printf("%s-%d: rxq->rxq:%p, ret:%d\n",__func__,__LINE__,rxq->rxq,ret);	
		printf("%s-%d:  now:%llu\n",__func__,__LINE__,(rte_rdtsc()*1000000)/rte_get_tsc_hz());
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

//#define toe_engine_init

static int toe_ctrl_ring_init(struct toe_device *toe_dev)
{
	struct toe_ctl_rx_vring **ctl_rx_vring;
	struct toe_engine *toe_eg = toe_dev->toe_eg; 
	int i;
	
	ctl_rx_vring = rte_calloc(NULL, toe_dev->ctrl_queues, sizeof(struct toe_ctl_rx_vring *), RTE_CACHE_LINE_SIZE);
	if (ctl_rx_vring == NULL)
		goto fail;

/*ctl_rx_vring->rq_info*/
	for (i = 0; i < toe_dev->ctrl_queues; i++) {
		ctl_rx_vring[i] = rte_calloc(NULL, 1, sizeof(struct toe_ctl_rx_vring), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i] == NULL)
			goto fail;
		
		ctl_rx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, i);
		ctl_rx_vring[i]->rq_info.rq_size = TOE_MAX_RQ_SIZE;
		ctl_rx_vring[i]->rq_info.rq_local = rte_calloc(NULL, ctl_rx_vring[i]->rq_info.rq_size, sizeof(struct toe_ctrl_host_to_dpu_req), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i]->rq_info.rq_local == NULL)
			goto fail;
		//rte_atomic16_init(&ctl_rx_vring[i]->rq_info.wait_head_num);
		
	/*ctl_rx_vring->cq_info*/
		ctl_rx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, i);
		ctl_rx_vring[i]->cq_info.cq_size = TOE_MAX_CQ_SIZE;
		ctl_rx_vring[i]->cq_info.cq_local = rte_calloc(NULL, ctl_rx_vring[i]->cq_info.cq_size, sizeof(struct toe_ctrl_host_to_dpu_res), RTE_CACHE_LINE_SIZE);
		if (ctl_rx_vring[i]->cq_info.cq_local == NULL)
			goto fail;
		ctl_rx_vring[i]->cq_info.cq_compl = 1;
		//rte_atomic16_init(&ctl_rx_vring[i]->cq_info.wait_tail_num);
	}

	toe_eg->ctl_rx_vring = ctl_rx_vring;
	//toe_eg->ctl_tx_vring = ctl_tx_vring;
	return 0;
	
	fail:
	if (ctl_rx_vring) {
		for (i = 0; i < toe_dev->ctrl_queues; i++) {
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
		data_rx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + i);
		data_rx_vring[i]->rq_info.rq_size = TOE_MAX_RQ_SIZE;
		data_rx_vring[i]->rq_info.rq_local = rte_calloc(NULL, data_rx_vring[i]->rq_info.rq_size, sizeof(struct toe_data_host_to_dpu_req), RTE_CACHE_LINE_SIZE);
        printf("data_rx_vring[%d]  RQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_rx_vring[i]->rq_info.rbc->queue_desc_h << 32)|data_rx_vring[i]->rq_info.rbc->queue_desc_lo, data_rx_vring[i]->rq_info.rbc->doorbell);
		if (data_rx_vring[i]->rq_info.rq_local == NULL)
			goto fail;

		data_rx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + i);
		data_rx_vring[i]->cq_info.cq_size = TOE_MAX_CQ_SIZE;
		data_rx_vring[i]->cq_info.cq_local = rte_calloc(NULL, data_rx_vring[i]->cq_info.cq_size, sizeof(struct toe_data_host_to_dpu_res), RTE_CACHE_LINE_SIZE);
        printf("data_rx_vring[%d]  CQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_rx_vring[i]->cq_info.cbc->queue_desc_h << 32)|data_rx_vring[i]->cq_info.cbc->queue_desc_lo, data_rx_vring[i]->cq_info.cbc->doorbell);
		if (data_rx_vring[i]->cq_info.cq_local == NULL)
			goto fail;
		data_rx_vring[i]->cq_info.cq_compl = 1;

		data_tx_vring[i] = rte_calloc(NULL, 1, sizeof(struct toe_data_tx_vring), RTE_CACHE_LINE_SIZE);
		if (data_tx_vring[i] == NULL)
			goto fail;
		data_tx_vring[i]->idx = i;
		data_tx_vring[i]->toe_dev = toe_dev->toe_eg;
		data_tx_vring[i]->rq_info.rbc = toe_rq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + num + i);
		data_tx_vring[i]->rq_info.rq_size = TOE_MAX_TX_DATA_RQ_SIZE;
		data_tx_vring[i]->rq_info.rq_local = rte_calloc(NULL, data_tx_vring[i]->rq_info.rq_size, sizeof(struct toe_data_dpu_to_host_req), RTE_CACHE_LINE_SIZE);
        printf("data_tx_vring[%d]  RQ  PhyAddr:%llx  Doorbell:%u\n", i, (data_tx_vring[i]->rq_info.rbc->queue_desc_h << 32)|data_tx_vring[i]->rq_info.rbc->queue_desc_lo, data_tx_vring[i]->rq_info.rbc->doorbell);
		if (data_tx_vring[i]->rq_info.rq_local == NULL)
			goto fail;

		data_tx_vring[i]->cq_info.cbc = toe_cq_bar_get(toe_eg->bar, toe_dev->ctrl_queues + num + i);
		data_tx_vring[i]->cq_info.cq_size = TOE_MAX_TX_DATA_CQ_SIZE;
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
	
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		
			mtcp = InitializeMTCPManagerPerCore(lcore_id);
			if (!mtcp || !mtcp->ctx) {
					printf("tcpstack_ctx: alloc failed!\n");
					return -1;
			}

	//		mtcp->ctx->io_private_context = toe_dev->data_rxq[idx];
			mtcp->iom = &toe_module_func;
			idx ++;
	}

	return 0;
}

int toe_engine_init(struct toe_device *toe_dev)
{
	struct toe_engine *toe_eg;
	struct toe_bar_base_cfg *base_cfg;
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

		printf("~~ %s-%d:222 toe_dev->toe_eg:%p,toe_eg->bar:%p\n",__func__,__LINE__,toe_dev->toe_eg,toe_eg->bar);
	if (toe_dma_init(toe_eg)){
		RTE_LOG(ERR, PMD, "toe: dma init failed\n");
		goto fail;
	}

	if (toe_ctrl_ring_init(toe_dev))
		goto fail;

	if (toe_data_ring_init(toe_dev))
		goto fail;

	if (toe_tcpstack_init(toe_dev))
		goto fail;
	printf("~~ %s-%d:33\n",__func__,__LINE__);
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

static void toe_ctrl_ring_free(struct toe_engine *toe_eg)
{
	struct toe_ctl_rx_vring **ctl_rx_vring = toe_eg->ctl_rx_vring;
	int i;
	
	if (ctl_rx_vring) {
		for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {
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

	toe_msi_free(toe_eg);

	toe_dma_fini();
	
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

	for (i = 0; i < TOE_MAX_SOCKET_NUM; i++) {
		toe_eg->fd_save_kernel[i] = 0;
	}

	for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {
		rxq = toe_eg->t_dev->ctl_rxq[i];
		do {
			ret = rte_ring_mc_dequeue_burst(rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
			rte_pktmbuf_free_bulk(rx_pkts, ret);
		}while(ret);
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
	/*
		for (j = 0; j < TOE_HASH_SIZE; j++) {
			TAILQ_FOREACH(node, &toe_tx_data_list[i][j], next) {
				TAILQ_REMOVE(&toe_tx_data_list[i][j], node, next);
				toe_tx_data_node_remove(node->fd, node, i);
			}
		}
	*/
		data_rxq = toe_eg->t_dev->data_rxq[i];
		do {
			ret = rte_ring_mc_dequeue_burst(data_rxq->rxq, (void **)rx_pkts, nb_pkts, NULL);
			rte_pktmbuf_free_bulk(rx_pkts, ret);
		}while(ret);
	}
	
	toe_msi_free(toe_eg);

	
	printf("@@%s-%d: engine rest done\n",__func__,__LINE__);
}

#if 0
static int toe_reset_notify_ctl(struct toe_engine *toe_eg)
{
		struct rte_mbuf *mbuf;
		struct toe_rx_ctl_queue *ctl_q;
		u_char *data;
		
		ctl_q = toe_eg->t_dev->ctl_rxq[0];
		mbuf = rte_pktmbuf_alloc(ctl_q->pkt_pool);
		
		if (unlikely(mbuf == NULL)) {
			return -1;
		}
		
		mbuf->ol_flags |= TOE_CTL_FLAG;
		data = rte_pktmbuf_mtod(mbuf, u_char*);
		*data = TOE_MSG_RESET;
		
		return rte_ring_mp_enqueue_burst(ctl_q->rxq, (void *const *) &mbuf, 1, NULL);
}
#endif
static void toe_reset_process(struct toe_engine *toe_eg)
{
	struct toe_bar_base_cfg *base_cfg;
	int i;
	
	base_cfg = (struct toe_bar_base_cfg *)toe_eg->bar;
	
	toe_dma_reset(toe_eg);
	toe_engine_reset(toe_eg);
	//toe_reset_notify_ctl(toe_eg);
/*
	for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++)
		toe_ctl_notify_to_ff(toe_eg, TOE_CTL_FLAG, TOE_MSG_RESET, 0, i);
*/
	toe_eg->t_dev->reset = 0;
	toe_eg->t_dev->reset_done = 1;
	base_cfg->status &= ~TOE_CARD_RESET;
	
	//base_cfg->status &= ~TOE_DRIVER_ACTIVE;
	//toe_eg->t_dev->activ	toe_eg->t_dev->reset_done = 1;
	base_cfg->status &= ~TOE_CARD_RESET;
	
	//base_cfg->status &= ~TOE_DRIVER_ACTIVE;
	//toe_eg->t_dev->active = 0;
	return;
}

