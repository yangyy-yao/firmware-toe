#include <assert.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_io.h>
#include <agiep_pci.h>

#include "agiep_vring.h"
#include "agiep_frep.h"
#include "agiep_virtio_rxtx.h"
#include "agiep_virtio_net.h"
#include "agiep_mbuf_iov.h"

#include "agiep_ctrl.h"


int agiep_virtio_rx_pkts(struct virtnet_rx *rx);
void agiep_virtio_rx_batch_cb(struct agiep_async_dma_batch *batch);
void agiep_virtio_tx_batch_cb(struct agiep_async_dma_batch *batch);

void agiep_virtio_tx_flush(struct agiep_virtio_port *port, int queue_idx);

__rte_always_inline void
agiep_virtio_rx_synchronize(struct virtnet_rx *rx)
{
	while (rx->seq & 1) {
		cpu_relax();
	}
}

__rte_always_inline void
agiep_virtio_tx_synchronize(struct virtnet_tx *tx)
{
	while (tx->flush_seq & 1)
		cpu_relax();
}

__rte_always_inline void
agile_update_packet_stats(struct virtnet_stats *stats, struct rte_mbuf *mbuf)
{
	stats->bytes += mbuf->pkt_len;
	stats->packets++;
}
static void agiep_virtio_vq_dma_process(struct virtqueue *vq)
{
	struct agiep_async_dma_job *jobs[4096];
	struct agiep_async_dma_job *job;
	int ret;
	int i;
	if (unlikely(!vq->dma))
		return;
	do {
		ret = agiep_dma_dequeue_buffers(vq->dma, jobs, 4096);
		for (i = 0; i < ret; i++) {
			job = jobs[i];
			if (job->cb)
				job->cb(job);
		}
	} while(ret);
}

void agiep_virtio_vring_cache(struct virtqueue *vq)
{
	uint16_t notify;
	int canbe;

	virtqueue_indir_cache(vq);
	virtqueue_dma_rejob(vq);

	canbe = virtqueu_canbe_cache(vq);

	notify = vq->notify_cb(vq);
	if (virtqueue_cache(vq, notify | canbe) < 0)
		vq->notify = 1;
}

static void agiep_virtio_vring_interrupt(struct agiep_virtio_port *port,
	struct virtqueue *vq, struct virnet_notify *notify, int irq_thre_num, uint64_t irq_thre_tsc)
{
	uint64_t cur_tsc = rte_rdtsc();
	uint32_t flush_idx = virtqueue_flush_idx(vq);
	uint16_t avail;
	int desc_num;
	int diff;
	int interrupt_status = virtqueue_get_interrupt(vq);
	if (interrupt_status == INTERRUPT_RAISE && virtqueue_interruptable(vq)) {
		agiep_virtio_port_msix_raise(port, vq->msi_vector);
		notify->notified_used_idx = flush_idx;
		notify->irq_tsc = cur_tsc;
		virtqueue_set_interrupt(vq, INTERRUPT_NO);
		return;
	}
	if (interrupt_status == INTERRUPT_PRE)
		return;
	avail = virtqueue_avail_idx(vq);
	desc_num = virtqueue_desc_num(vq);
	diff = avail - notify->notified_used_idx;
	//当avail_idx已经超过了notified_used_idx，说明host驱动已经在轮询中处理dma写上去的新used_idx，
	//并且根据新的used_idx更新了avail_idx，
	//那么这次就不需要中断来通知host有used更新了
	if (diff > desc_num || (diff < 0 && (diff + 65535) > desc_num)) {
		notify->notified_used_idx = avail - desc_num;
		return;
	}
	int gap = (int)(flush_idx - notify->notified_used_idx);

	if (gap == 0)
		return;
	if (gap < 0)
		gap += virtqueue_desc_num(vq);

	if ((gap > irq_thre_num) || (cur_tsc - notify->irq_tsc > irq_thre_tsc)) {
		virtqueue_set_interrupt(vq, INTERRUPT_PRE);
		return ;
	}
}

static void agiep_virtio_vring_interrupt_rx(struct agiep_virtio_port *port,
	struct virtqueue *vq, struct virnet_notify *notify, uint64_t irq_thre_tsc)
{
	uint64_t cur_tsc = rte_rdtsc();
	uint32_t flush_idx = virtqueue_flush_idx(vq);
	int gap = (int)(flush_idx - notify->notified_used_idx);

	if (gap == 0)
		return;
	if (cur_tsc - notify->irq_tsc > irq_thre_tsc) {
		goto do_int;
	}
	return;
do_int:
	agiep_virtio_port_msix_raise(port, vq->msi_vector);
	notify->notified_used_idx = flush_idx;
	notify->irq_tsc = cur_tsc;
}

uint16_t agiep_virtio_tx_xmit(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct virtnet_tx *tx = tx_queue;
	struct virtqueue *vq;
	struct agiep_virtio_port *port;
	struct agiep_frep_device *fdev;

	if (unlikely(!tx_queue))
		return 0;

	port = tx->priv;
	if (!(agiep_virtio_port_enabled(port)))
		return 0;
	fdev = port->fdev;
	// TODO: 分发到其他所有可用队列
	tx = fdev->eth_dev->data->tx_queues[tx->id % fdev->used_queues];
	if (unlikely(!tx)) {
		return 0;
	}

	vq = tx->vq;
	if (unlikely(!vq)) {
		return 0;
	}

	return rte_ring_mp_enqueue_burst(tx->tx_ring, (void *const *) tx_pkts,
					nb_pkts, NULL);
}

void agiep_virtio_tx_batch_cb(struct agiep_async_dma_batch *batch)
{
	struct virtnet_tx_ctx *ctx = batch->priv;
	struct virtnet_tx *tx = ctx->tx;
	struct virtqueue *vq = ctx->tx->vq;
	if (unlikely(!vq))
		return;
	virtqueue_idx_push(vq, ctx->used_idx, ctx->nb_elems);
	rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	tx->ctx_map[ctx->idx] = NULL;
	rte_mempool_put(tx->ctx_pool, ctx);
	rte_mempool_put(batch->dma->bpool, batch);
}

uint16_t agiep_virtio_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct virtnet_tx *tx;
	struct virtqueue *vq;
	struct rte_mbuf *pkt;
	struct virtnet_tx_ctx *ctx;
	struct agiep_async_dma_batch *batch;
	struct rte_qdma_job *jobs;
	struct agiep_dma *dma;
	struct virtio_net_hdr_mrg_rxbuf *hdrmrg;
	int i, j;
	int nb_elems;
	int vq_num;
	int total_jobs;
	int nb_jobs;
	uint16_t nb_mbuf;
	int batch_nb_jobs;
	uint16_t ctx_nb_elems;
	uint16_t last_avail_idx;

	tx = tx_queue;

	vq = tx->vq;
	if (unlikely(!vq))
		return 0;
	if (unlikely(!virtqueue_enabled(vq)))
		return 0;

	const uint16_t mask = tx->nb_desc - 1;

	dma = vq->dma;

	const int header_size = tx->mergeable;

	vq_num = (int)virtqueue_num(vq);
	if (!vq_num)
		return 0;
	virtqueue_elems(vq, &last_avail_idx, NULL);

	if (unlikely(rte_mempool_get(tx->ctx_pool, (void **) &ctx))){
		return 0;
	}
	ctx->tx = tx;
	ctx->used_idx = last_avail_idx;
	ctx->nb_mbuf = 0;
	ctx->nb_elems = 0;
	ctx_nb_elems = 0;

	if (unlikely(rte_mempool_get(dma->bpool, (void **) &batch))) {
		rte_mempool_put(tx->ctx_pool, ctx);
		return 0;
	}

	batch->cb = agiep_virtio_tx_batch_cb;
	batch->priv = ctx;
	batch->nb_jobs = 0;
	total_jobs = batch->total_jobs;
	nb_mbuf = 0;
	batch_nb_jobs = 0;

	tx->ctx_map[ctx->idx] = ctx;

	for (i = 0; i < nb_pkts; i++) {
		pkt = tx_pkts[i];
#ifdef RTE_LIBRTE_AGILE_EP_PMD_VIRTIO_DEBUG
		assert(pkt->nb_segs <= RTE_PMD_AGIEP_MAX_SEGS);
#endif

		// FIXME: single mbuf data_len must less than the buffer len which
		// host allocaed.
		nb_elems = 0;
		nb_jobs = agiep_pkt_to_iov_jobcnt(vq, mask, pkt, header_size, &nb_elems, last_avail_idx);

		if (nb_jobs < 0 ) {
			tx->stats.errors ++;
			/*失败的场景，agiep_pkt_to_iov_jobcnt里面会释放mbuf，需要continue让i++
			否则会导致本函数执行完后在agiep_virtio_tx_flush中重复释放失败的mbuf*/
			continue;
		}
		if (unlikely(!IS_MERGEABLE(header_size))) {
			nb_elems = 1;
		}

		if (nb_elems > vq_num ) {
			goto enqueue_jobs;
		}
		agile_update_packet_stats(&tx->stats, pkt);
		// alloc new.
		if (unlikely(nb_jobs + batch_nb_jobs > total_jobs
			|| ctx_nb_elems + nb_elems > RTE_PMD_AGIEP_TX_MAX_BURST)) {
			ctx->nb_mbuf = nb_mbuf;
			ctx->nb_elems = ctx_nb_elems;
			batch->nb_jobs = batch_nb_jobs;
			batch_nb_jobs = agiep_dma_batch_enqueue(dma, batch, batch->pjobs, batch->nb_jobs);
			if (unlikely(batch_nb_jobs != batch->nb_jobs))
				goto failed_jobs;
			virtqueue_idx_pop(vq, ctx_nb_elems);
			if (unlikely(vq->dlog && vq->dlog->loging)) {
				for (j = 0; j < batch_nb_jobs; j++) {
					agiep_dirty_log_add(vq->dlog, batch->pjobs[j]->job->dest, batch->pjobs[j]->job->len);
				}
			}
			if (unlikely(rte_mempool_get(tx->ctx_pool, (void **) &ctx)))
				goto out;
			ctx->tx = tx;
			ctx->used_idx = last_avail_idx;
			nb_mbuf = 0;
			ctx_nb_elems = 0;
			if (unlikely(rte_mempool_get(dma->bpool, (void **) &batch))) {
				rte_mempool_put(tx->ctx_pool, ctx);
				goto out;
			}
			batch->cb = agiep_virtio_tx_batch_cb;
			batch->priv = ctx;
			total_jobs = batch->total_jobs;
			batch_nb_jobs = 0;

			tx->ctx_map[ctx->idx] = ctx;
		}
		jobs = &batch->qjobs[batch_nb_jobs];
		// must has enough head rom to store virtio_net_hdr_mrg_rxbuf header.
		hdrmrg = rte_pktmbuf_mtod_offset(pkt, struct virtio_net_hdr_mrg_rxbuf *, -header_size);
		memset(hdrmrg, 0, header_size);
		vq_num -= nb_elems;

		if (pkt->ol_flags & PKT_RX_L4_CKSUM_GOOD)
			hdrmrg->hdr.flags |= VIRTIO_NET_HDR_F_DATA_VALID;
		
		if (likely(IS_MERGEABLE(header_size)))
			hdrmrg->num_buffers = nb_elems;
		agiep_pkt_to_iov(vq, mask, pkt, jobs, header_size, &last_avail_idx);
		ctx->mbuf[nb_mbuf] = pkt;
		nb_mbuf ++;
		batch_nb_jobs += nb_jobs;
		ctx_nb_elems += nb_elems;
	}
enqueue_jobs:
	ctx->nb_mbuf = nb_mbuf;
	ctx->nb_elems = ctx_nb_elems;
	batch->nb_jobs = batch_nb_jobs;
	if (nb_mbuf == 0 || ctx_nb_elems == 0 || batch_nb_jobs == 0)
		goto failed_jobs;
	batch_nb_jobs = agiep_dma_batch_enqueue(dma, batch, batch->pjobs, batch->nb_jobs);
	if (unlikely(batch_nb_jobs != batch->nb_jobs))
		goto failed_jobs;
	virtqueue_idx_pop(vq, ctx_nb_elems);
	if (unlikely(vq->dlog && vq->dlog->loging)) {
		for (j = 0; j < batch->nb_jobs; j++) {
			agiep_dirty_log_add(vq->dlog, batch->pjobs[j]->job->dest, batch->pjobs[j]->job->len);
		}
	}
	return i;
failed_jobs:
	// roll back failed jobs
	rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	tx->ctx_map[ctx->idx] = NULL;
	rte_mempool_put(tx->ctx_pool, ctx);
	rte_mempool_put(dma->bpool, batch);
out:
	return i;
}

void agiep_virtio_tx_flush(struct agiep_virtio_port *port, int queue_idx)
{
	// 2 for prefetch
	struct rte_mbuf *pkts[RTE_PMD_AGIEP_TX_MAX_BURST * VIRTIO_NET_TX_RATIO];
	uint16_t nb_pkts;
	uint16_t send;
	struct virtqueue *vq;
	struct virtnet_tx *tx;

	tx = port->fdev->eth_dev->data->tx_queues[queue_idx];

	if (unlikely(tx == NULL))
		return;

	tx->flush_seq++;
	rte_mb();
	vq = tx->vq;
	if (unlikely(!vq)) {
		goto out;
	}
	if (unlikely(!virtqueue_enabled(vq)))
		goto out;
	agiep_virtio_vq_dma_process(vq);
	agiep_virtio_vring_interrupt(port, vq, &tx->notify, tx->notify.irq_num_threshold, tx->notify.irq_threshold);
	agiep_virtio_vring_cache(vq);
	virtqueue_flush(vq);
	virtqueue_scan_avail(vq);
	if (rte_ring_count(tx->tx_ring) == 0)
		goto out;

	nb_pkts = rte_ring_sc_dequeue_burst(tx->tx_ring, (void **) pkts,
		RTE_PMD_AGIEP_TX_MAX_BURST * VIRTIO_NET_TX_RATIO, NULL);

	send = agiep_virtio_tx_pkt_burst(tx, pkts, nb_pkts);
	if (send != nb_pkts){
		rte_pktmbuf_free_bulk(&pkts[send], nb_pkts - send);
		tx->stats.errors += nb_pkts - send;
	}
out:
	tx->flush_seq++;
}

__rte_always_inline static void
agiep_virtio_rx_checksum_set(struct rte_mbuf *pkt, struct virtnet_rx_ctx *ctx)
{
	struct virtio_net_hdr_mrg_rxbuf *hdrmrg;
	struct agiep_frep_device *fdev;

	hdrmrg = rte_pktmbuf_mtod_offset(pkt, struct virtio_net_hdr_mrg_rxbuf *, 0);

	if (hdrmrg->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
		pkt->ol_flags |= (PKT_TX_TCP_CKSUM | PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM);

	fdev = ctx->rx->priv->fdev;
	if (fdev->hw_checksum && (pkt->ol_flags & PKT_RX_L4_CKSUM_MASK) == PKT_RX_L4_CKSUM_UNKNOWN)
		pkt->ol_flags |= PKT_RX_L4_CKSUM_GOOD;

}

void agiep_virtio_rx_batch_cb(struct agiep_async_dma_batch *batch)
{
	struct virtnet_rx_ctx *ctx;
	struct virtqueue *vq;
	uint16_t i;
	struct rte_mbuf *mbuf;
	struct rte_mbuf *head;
	int header_size;

	ctx = batch->priv;
	vq = ctx->rx->vq;
	if (unlikely(!vq))
		return;

	header_size = ctx->rx->mergeable;

	rte_prefetch1(ctx->mbuf[0]);

	for (i = 0; i < ctx->nb_mbuf; i++) {
		if (i + 1 < ctx->nb_mbuf)
			rte_prefetch1(ctx->mbuf[i + 1]);
		mbuf = ctx->mbuf[i];
		agiep_virtio_rx_checksum_set(mbuf, ctx);
		if (mbuf->nb_segs > 1 && mbuf->data_len == header_size) {
			head = mbuf;
			mbuf = head->next;
			mbuf->pkt_len = head->pkt_len - head->data_len;
			head->next = NULL;
			mbuf->nb_segs = head->nb_segs - 1;
			mbuf->ol_flags = head->ol_flags;
			head->nb_segs = 1;
			rte_pktmbuf_free(head);
		} else {
			mbuf->data_len = mbuf->data_len - header_size;
			mbuf->pkt_len = mbuf->pkt_len - header_size;
			mbuf->data_off = mbuf->data_off + header_size;
		}
		ctx->rx->mbuf_list[(ctx->used_idx + i) % ctx->rx->nb_desc] = mbuf;
	}
	//TODO: generate mbuf flags from virtio net hdr
	virtqueue_idx_push(vq, ctx->used_idx, ctx->nb_elems);
	TAILQ_REMOVE(&ctx->rx->ctx_list, ctx, entry);
	rte_mempool_put(ctx->rx->ctx_pool, ctx);
	rte_mempool_put(batch->dma->bpool, batch);
}

int agiep_virtio_rx_pkts(struct virtnet_rx *rx)
{
	struct rte_mbuf *segs[RTE_PMD_AGIEP_MAX_SEGS];
	struct virtqueue *vq;
	struct vring_queue_elem *elem;
	struct vring_queue_elem *elems;
	struct rte_qdma_job *jobs;
	struct rte_qdma_rbp *rbp;

	struct virtnet_rx_ctx *ctx;
	struct agiep_async_dma_batch *batch;
	struct agiep_dma *dma;
	int avail_mbuf;
	uint16_t nb_elems;
	uint16_t buf_size;
	uint16_t nb_jobs;
	uint16_t nb_segs;
	uint16_t vq_num;
	uint16_t max_elems;
	uint16_t avail_idx;
	uint16_t last_avail_idx;
	uint16_t batch_nb_jobs;
	uint16_t ctx_nb_mbuf;
	uint16_t ctx_nb_elems;
	uint16_t header_size;

	vq = rx->vq;

	if (unlikely(vq == NULL))
		return 0;

	vq_num = virtqueue_num(vq);
	if (!vq_num)
		return 0;

	dma = vq->dma;
	avail_mbuf = (int)(rx->nb_desc - rx->nb_mbuf);
	buf_size = rte_pktmbuf_data_room_size(rx->mpool) - RTE_PKTMBUF_HEADROOM;
	max_elems = RTE_MIN(vq_num, RTE_PMD_AGIEP_RX_MAX_BURST);
	max_elems = RTE_MIN(avail_mbuf, max_elems);
	if (unlikely(max_elems == 0))
		return 0;

	rbp = agiep_dma_rbp(dma, DMA_JOB_F_FROM_PCI);

	elems = virtqueue_elems(vq, &last_avail_idx, &avail_idx);

	if (unlikely(rte_mempool_get(rx->ctx_pool, (void **) &ctx))) {
		return 0;
	}
	ctx->rx = rx;
	ctx->used_idx = last_avail_idx;
	ctx->nb_mbuf = 0;
	ctx->nb_elems = 0;
	ctx_nb_elems = 0;
	ctx_nb_mbuf = 0;
	header_size = rx->mergeable;

	if (unlikely(rte_mempool_get(dma->bpool, (void **) &batch))) {
		rte_mempool_put(rx->ctx_pool, ctx);
		return 0;
	}
	batch->cb = agiep_virtio_rx_batch_cb;
	batch->priv = ctx;
	batch->nb_jobs = 0;
	batch_nb_jobs = 0;
	TAILQ_INSERT_HEAD(&rx->ctx_list, ctx, entry);

	for (nb_elems = 0; nb_elems < max_elems; nb_elems++) {
		elem = &elems[last_avail_idx % rx->nb_desc];
		agiep_iov_to_mbuf_jobcnt(vq, elem, buf_size, &nb_jobs, &nb_segs, header_size);
		// one elem length must be less than buf_size * RTE_PMD_AGIEP_RX_MAX_BURST * 2
		if ((ctx_nb_mbuf + nb_segs > RTE_PMD_AGIEP_RX_MAX_BURST * 2) ||
				(batch_nb_jobs + nb_jobs > batch->total_jobs)) {
			batch->nb_jobs = batch_nb_jobs;
			ctx->nb_elems = ctx_nb_elems;
			ctx->nb_mbuf = ctx_nb_mbuf;
			if (unlikely(!agiep_dma_batch_enqueue(dma, batch, batch->pjobs, batch->nb_jobs))) {
				goto failed_jobs;
			}
			rx->nb_mbuf += ctx->nb_mbuf;
			virtqueue_idx_pop(vq, ctx->nb_elems);
			if (unlikely(rte_mempool_get(rx->ctx_pool, (void **) &ctx))) {
				return nb_elems;
			}
			ctx->rx = rx;
			ctx->used_idx = last_avail_idx;
			ctx->nb_mbuf = 0;
			ctx->nb_elems = 0;
			ctx_nb_elems = 0;
			ctx_nb_mbuf = 0;
			if (unlikely(rte_mempool_get(dma->bpool, (void **) &batch))) {
				rte_mempool_put(rx->ctx_pool, ctx);
				return nb_elems;
			}
			batch->nb_jobs = 0;
			batch->cb = agiep_virtio_rx_batch_cb;
			batch->priv = ctx;
			batch_nb_jobs = 0;
			TAILQ_INSERT_HEAD(&rx->ctx_list, ctx, entry);
		}

		jobs = &batch->qjobs[batch_nb_jobs];

		if (unlikely(rte_pktmbuf_alloc_bulk(rx->mpool, segs, nb_segs))) {
			goto enqueue_jobs;
		}
		ctx->mbuf[ctx_nb_mbuf] = segs[0];
		ctx_nb_mbuf += 1;
		ctx_nb_elems += 1;
		batch_nb_jobs += nb_jobs;
		elem->len = elem->in_len;

		agiep_iov_to_mbuf(vq, elem, jobs, rbp, segs, header_size);
		last_avail_idx++;
	}
enqueue_jobs:
	ctx->nb_mbuf = ctx_nb_mbuf;
	ctx->nb_elems = ctx_nb_elems;
	batch->nb_jobs = batch_nb_jobs;
	if (unlikely(agiep_dma_batch_enqueue(dma, batch, batch->pjobs, batch->nb_jobs) != batch_nb_jobs)) {
		goto failed_jobs;
	}
	rx->nb_mbuf += ctx->nb_mbuf;
	virtqueue_idx_pop(vq, ctx->nb_elems);
	return nb_elems;
failed_jobs:
	rte_pktmbuf_free_bulk(ctx->mbuf, ctx->nb_mbuf);
	TAILQ_REMOVE(&rx->ctx_list, ctx, entry);
	rte_mempool_put(rx->ctx_pool, ctx);
	rte_mempool_put(dma->bpool, batch);
	return (int)(nb_elems - ctx->nb_elems);
}

static int agiep_virtio_rx_mbuf_dequeue(struct virtnet_rx *rx, struct rte_mbuf **pkts, int nb_pkts)
{
	int i;
	const uint16_t nb_desc = rx->nb_desc;
	if (rx->mbuf_list[rx->elem_id] == NULL)
		return 0;
	i = 0;
	do {
		pkts[i] = rx->mbuf_list[rx->elem_id];
		rx->mbuf_list[rx->elem_id] = NULL;
		rx->elem_id ++;
		rx->elem_id &= (nb_desc - 1);
		agile_update_packet_stats(&rx->stats, pkts[i]);
		i++;
		rte_prefetch1(pkts[i]);
	}while (rx->mbuf_list[rx->elem_id] != NULL && i < nb_pkts);
	rx->nb_mbuf -= i;
	return i;
}

static int agiep_virtio_vq_finalize(struct virtnet_rx *rx)
{
	struct virtqueue *rx_vq;
	struct virtqueue *tx_vq;
	struct virtnet_tx *tx;
	struct virtqueue *cvq;
	struct agiep_virtio_port *port;
	struct agiep_net_ctrl *ctrl;
	int ret = 0;

	port = rx->priv;
	rx_vq = rx->vq;
	if (likely(rx_vq)) {
		if (rx_vq->dlog && rx->id == 0 && unlikely(rx_vq->dlog->log_flushing != DIRTYLOG_FLUSH_STOP))
			agiep_dirty_log_process(rx_vq->dlog);
		if (virtqueue_enabled(rx_vq)) {
			/*
			* virtqueue_flush_synchronize 在 vendor_dev_softreset 之前 vendor_dev_disable 里面调用；
			* queue 不会被释放了，此处肯定会调用，保证 virtqueue_flush_synchronize 不会死循环。
			* 如果要支持firmware driver stop和reset并发的话，这个地方需要重新考虑一下。
			*/
			agiep_virtio_vq_dma_process(rx_vq);
		}
	}
	
	ctrl = port->ctrl;
	if (ctrl && rx->id == 0) {
		ctrl->seq++;
		rte_mb();
		cvq = ctrl->cvq;
		if (likely(cvq) && virtqueue_enabled(cvq)) {
			agiep_virtio_vq_dma_process(cvq);
		}
		ctrl->seq++;
	}

	tx = port->fdev->eth_dev->data->tx_queues[rx->id];

	if (unlikely(tx == NULL))
		return ret;

	tx->flush_seq++;
	rte_mb();
	tx_vq = tx->vq;
	if (tx_vq && virtqueue_enabled(tx_vq)) {
		agiep_virtio_vq_dma_process(tx_vq);
	}
	tx->flush_seq++;
	return ret;
}

uint16_t
agiep_virtio_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct virtnet_rx *rx;
	struct virtqueue *vq;
	struct virtqueue *cvq;
	struct agiep_virtio_port *port;
	struct agiep_net_ctrl *ctrl;
	uint ret = 0;
	int can_ctrl;

	if (unlikely(!rx_queue))
		return 0;

	rx = rx_queue;
	rx->seq++;
	rte_mb();
	port = rx->priv;
	if (!(agiep_virtio_port_enabled(port)))
		goto out;
	vq = rx->vq;
	if (unlikely(!vq))
		goto out;
	if (!virtqueue_enabled(vq))
		goto out;
	/** tx transmission is slower than rx,
	 * adjust the ratio of tx and rx to ensure the same cycle as possible */
	if ((rx->seq + 1) % (VIRTIO_NET_TX_RATIO * 2) == 0 && rx->id < port->fdev->used_queues)
		agiep_virtio_tx_flush(port, rx->id);

	agiep_virtio_vq_dma_process(vq);

	ctrl = port->ctrl;
	can_ctrl = ((rx->seq + 1) % (VIRTIO_NET_CTRL_FREQ * 2)) == 0;
	if (rx->id == 0 && ctrl != NULL && can_ctrl) {
		ctrl->seq++;
		rte_mb();
		cvq = ctrl->cvq;

		if (likely(cvq) && virtqueue_enabled(cvq)) {
			agiep_virtio_vq_dma_process(cvq);
			agiep_rq_process(port);
			agiep_cq_process(port);
		}
		ctrl->seq++;
	}

	//only use irq_threshold
	agiep_virtio_vring_interrupt_rx(port, vq, &rx->notify, rx->notify.irq_threshold);
	agiep_virtio_vring_cache(vq);
	virtqueue_flush(vq);
	agiep_virtio_rx_pkts(rx);
	ret = agiep_virtio_rx_mbuf_dequeue(rx, rx_pkts, nb_pkts);
out:
	agiep_virtio_vq_finalize(rx);
	rx->seq++;
	return ret;
}
