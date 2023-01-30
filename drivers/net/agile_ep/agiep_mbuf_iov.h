#ifndef RTE_AGIEP_MBUF_IOV_H_
#define RTE_AGIEP_MBUF_IOV_H_
#include <rte_mbuf.h>
#include <agiep_vring.h>
struct iovec_offset {
	int id;
	int offset;
};
int agiep_pkt_to_iov_jobcnt(struct virtqueue *vq, uint16_t mask, struct rte_mbuf *pkt,
	uint16_t header_size, int *elems_count, uint16_t last_avail_idx);

int
agiep_pkt_to_iov(struct virtqueue *vq, uint16_t mask, struct rte_mbuf *pkt,
	struct rte_qdma_job *jobs, uint16_t header_size, uint16_t *plast_avail_idx);

void agiep_iov_to_mbuf_jobcnt(struct virtqueue *vq, struct vring_queue_elem *elem,
	uint16_t buf_len, uint16_t *job_cnt, uint16_t *mbuf_cnt, uint16_t header_size);

int agiep_iov_to_mbuf(struct virtqueue *vq, struct vring_queue_elem *elem,
	struct rte_qdma_job *jobs, struct rte_qdma_rbp *rbp,
	struct rte_mbuf **segs, uint16_t header_size);
#endif
