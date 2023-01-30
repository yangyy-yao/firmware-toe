#include <agiep_vring.h>
#include <assert.h>
#include "agiep_mbuf_iov.h"

#define IS_MERGEABLE(size) (((size) == 12))

__rte_always_inline int
agiep_pkt_to_iov_jobcnt(struct virtqueue *vq, uint16_t mask, struct rte_mbuf *pkt, 
		uint16_t header_size, int *nb_elems, uint16_t last_avail_idx)
{
	struct vring_queue_elem *elem;
	struct vring_queue_elem *elems;
	uint16_t tmp;
	uint16_t out_len;
	int iov_cnt = 0;
	struct iovec *iov;
	struct rte_mbuf *mbuf = pkt;
	int bytes;
	int j = 0;
	int i = 0;
	uint32_t iv_offset = 0;
	uint16_t mb_offset = 0;
	int elems_count = *nb_elems;

	elems = virtqueue_elems(vq, &tmp, NULL);
	elem = &elems[last_avail_idx & mask];
	out_len = elems[last_avail_idx & mask].out_len;


	/*本函数中所有返回小于0的点必须释放mbuf，否则会导致内存泄漏！！！*/

	//out_len == 0(no cache)
	if (unlikely(!IS_MERGEABLE(header_size) && (mbuf->pkt_len + header_size > out_len))){
		rte_pktmbuf_free(mbuf);
		return -1;;
	}

	while(mbuf) {
		if (i >= iov_cnt) {
			elem = &elems[last_avail_idx & mask];
			iov_cnt = elem->out_num;
			last_avail_idx ++;
			i = 0;
			elems_count ++;
		}
		iov = virtqueue_outv(vq, elem->id, i);
		if ((uint16_t)(iov->iov_len - iv_offset) >= (uint16_t)(mbuf->data_len + header_size - mb_offset)) {
			bytes = mbuf->data_len + header_size - mb_offset;
		} else {
			bytes = iov->iov_len - iv_offset;
		}

		iv_offset += bytes;
		mb_offset += bytes - header_size;

		if (mb_offset == mbuf->data_len) {
			mbuf = mbuf->next;
			mb_offset = 0;
			header_size = 0;
		}

		if (iv_offset == iov->iov_len) {
			i++;
			iv_offset = 0;
			header_size = 0;
		}
		j++;
	}
	*nb_elems = elems_count;
	return j;
}

__rte_always_inline int
agiep_pkt_to_iov(struct virtqueue *vq, uint16_t mask, struct rte_mbuf *pkt,
	struct rte_qdma_job *jobs, uint16_t header_size, uint16_t *plast_avail_idx)
{	
	struct vring_queue_elem *elem = NULL;
	struct vring_queue_elem *elems = NULL;
	uint16_t tmp;
	struct rte_mbuf *mbuf = pkt;
	int iov_cnt = 0;
	struct iovec *iov;
	struct rte_qdma_job *job = jobs;
	int bytes;
	int i = 0;
	uint32_t iv_offset = 0;
	uint16_t mb_offset = 0;
	int total = 0;
	struct agiep_dma *dma;
	struct rte_qdma_rbp *rbp;
	uint16_t last_avail_idx = *plast_avail_idx;

	elems = virtqueue_elems(vq, &tmp, NULL);

	dma = vq->dma;
	rbp = agiep_dma_rbp(dma, DMA_JOB_F_TO_PCI);
	while(mbuf) {
		if (i >= iov_cnt) {
			elem = &elems[last_avail_idx & mask];
			iov_cnt = elem->out_num;
			last_avail_idx ++;
			i = 0;
			total = 0;
		}
		iov = virtqueue_outv(vq, elem->id, i);
		if ((uint16_t)(iov->iov_len - iv_offset) >= (uint16_t)(mbuf->data_len + header_size - mb_offset)) {
			bytes = mbuf->data_len + header_size - mb_offset;
		} else {
			bytes = iov->iov_len - iv_offset;
		}
		job->src = rte_pktmbuf_iova_offset(mbuf, -header_size) + mb_offset;
		job->dest = (uint64_t)iov->iov_base + iv_offset;
		job->len = bytes;
		job->rbp = rbp;

		iv_offset += bytes;
		mb_offset += bytes - header_size;

		if (mb_offset == mbuf->data_len) {
			mbuf = mbuf->next;
			mb_offset = 0;
			header_size = 0;
		}

		if (iv_offset == iov->iov_len) {
			i++;
			iv_offset = 0;
			header_size = 0;
		}

		total += bytes;
		elem->len = total;
		job++;
	}
	*plast_avail_idx = last_avail_idx;
	return total;
}

__rte_always_inline void
agiep_iov_to_mbuf_jobcnt(struct virtqueue *vq, struct vring_queue_elem *elem,
	uint16_t buf_len, uint16_t *job_cnt, uint16_t *mbuf_cnt, uint16_t header_size)
{
	struct iovec *iov;
	uint32_t i;
	int iov_len;
	int mbuf_len;

	*job_cnt = 0;
	*mbuf_cnt = 0;

	for (i = 0; i < elem->in_num; i++) {
		if (i == 0) 
			mbuf_len = buf_len + header_size;
		else
			mbuf_len = buf_len;
		iov = virtqueue_inv(vq, elem->id, i);
		iov_len = iov->iov_len;
		*job_cnt += iov_len / mbuf_len + (iov_len % mbuf_len != 0);
		*mbuf_cnt = *job_cnt;
	}
}

__rte_always_inline int
agiep_iov_to_mbuf(struct virtqueue *vq, struct vring_queue_elem *elem,
	struct rte_qdma_job *jobs, struct rte_qdma_rbp *rbp,
	struct rte_mbuf **segs, uint16_t header_size)
{
	struct iovec *iov;
	struct rte_qdma_job *job;
	struct rte_mbuf *head;
	struct rte_mbuf *prev;
	struct rte_mbuf *pkt;
	int iov_len;
	int copy_len;
	uint32_t i;
	int j;
	int seg;
	uint16_t iov_offset;
	uint16_t buf_len;
	uint16_t dma_offset;
	j = 0;
	seg = 0;
	prev = NULL;
	head = segs[0];
	pkt = NULL;
	head->pkt_len = 0;
	head->data_off -= header_size;

	for (i = 0; i < elem->in_num; i++) {
		iov = virtqueue_inv(vq, elem->id, i);
		iov_len = iov->iov_len;
		iov_offset = 0;
		do {
			prev = pkt;
			pkt = segs[seg++];
			buf_len = rte_pktmbuf_tailroom(pkt);
			if (prev){
				prev->next = pkt;
				head->nb_segs ++;
			}
			copy_len = iov_len > buf_len ? buf_len : iov_len;
			job = &jobs[j++];
			dma_offset = ALIGN_DMA_CALC_OFFSET((uint64_t)iov->iov_base + iov_offset);
			job->src = (uint64_t)iov->iov_base + iov_offset - dma_offset;
			job->dest = rte_pktmbuf_iova(pkt) - dma_offset;
			job->len = copy_len + dma_offset;
			job->rbp = rbp;
			pkt->data_len = copy_len;
			pkt->pkt_len = copy_len;
			if (seg > 1)
				head->pkt_len += copy_len;
			iov_offset += copy_len;
			iov_len -= copy_len;
			if (likely(!iov_len))
				break;
		} while(1);
	}
	return 0;
}