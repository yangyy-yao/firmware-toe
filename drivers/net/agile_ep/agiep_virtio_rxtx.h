#ifndef RTE_AGIEP_VIRTIO_RXTX_H_
#define RTE_AGIEP_VIRTIO_RXTX_H_
#include <stdint.h>
#include <agiep_vring.h>
#include <agiep_lib.h>
#include "agiep_virtio_port.h"
#define INTERRUPT_THRESHOLD 32
#define US_PER_S 1000000
#define MS_PER_S 1000
#define INTERRUPT_TSC_THRESHOLD 10  /* TX drain every ~10us */
#define VIRTIO_NET_TX_MAX_ELEM 16
#define VIRTIO_NET_CTRL_FREQ   (32)

#define VIRTIO_NET_TX_RATIO    5 	/** best ratio in test */
#define IS_MERGEABLE(size) (((size) == sizeof(struct virtio_net_hdr_mrg_rxbuf)))

struct virtnet_tx;
struct virtnet_rx;

struct virtnet_stats {
	uint64_t	packets;
	uint64_t	bytes;
	uint64_t	errors;
} __rte_packed;

struct virtnet_tx_ctx {
	struct virtnet_tx *tx;
	uint16_t nb_mbuf;
	uint16_t idx;
	uint16_t nb_elems;
	uint16_t used_idx;
	TAILQ_ENTRY(virtnet_tx_ctx) entry;
	uint64_t reserved1[3];
	struct rte_mbuf *mbuf[RTE_PMD_AGIEP_TX_MAX_BURST];
	struct vring_queue_elem *elems[RTE_PMD_AGIEP_TX_MAX_BURST];
} __rte_cache_aligned;

struct virtnet_rx_ctx {
	struct virtnet_rx *rx;
	uint16_t nb_mbuf;
	uint16_t used_idx;
	uint16_t nb_elems;
	uint16_t reserved;
	TAILQ_ENTRY(virtnet_rx_ctx) entry;
	uint64_t reserved1[4];
	struct rte_mbuf *mbuf[RTE_PMD_AGIEP_RX_MAX_BURST * 2];
} __rte_cache_aligned;

struct virnet_notify {
	uint32_t notified_used_idx;
	uint32_t irq_num_threshold;
	uint64_t irq_tsc;
	uint64_t irq_threshold;
} __rte_packed;

struct virtnet_rx {
	struct agiep_frep_queue fq;
	uint16_t id;
	uint16_t elem_id;
	uint16_t nb_desc;
	uint16_t nb_mbuf;
	uint32_t mergeable;
	volatile uint64_t seq;
	struct rte_mempool *mpool;
	struct rte_mempool *ctx_pool;
	struct virtqueue *vq;
	struct rte_mbuf **mbuf_list;
	// --cache line --
	struct virnet_notify notify;
	struct virtnet_stats stats;
	struct virtqueue *bvq;
	struct agiep_virtio_port *priv;
	TAILQ_HEAD(rx_ctx_list, virtnet_rx_ctx) ctx_list;
} __rte_cache_aligned;

struct virtnet_tx {
	struct agiep_frep_queue fq;
	uint16_t id;
	uint16_t nb_desc;
	uint16_t reserved1;
	uint16_t mergeable;
	volatile uint64_t flush_seq;
	struct rte_ring *tx_ring;
	struct rte_mempool *ctx_pool;
	struct virtqueue *vq;
	struct virnet_notify notify;
	// -- cache line --
	// cache line
	struct virtnet_tx_ctx **ctx_map;
	uint32_t reserved;
	struct virtqueue *bvq;
	struct agiep_virtio_port *priv;
	struct virtnet_stats stats;
} __rte_cache_aligned;

uint16_t agiep_virtio_rx_pkt_burst(void *rx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t agiep_virtio_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t agiep_virtio_tx_xmit(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void agiep_virtio_vring_cache(struct virtqueue *vq);
void
virtio_update_packets_stats(struct virtnet_stats *stats, struct rte_mbuf **pkts,
	uint16_t nb_pkt);
void
agile_update_packet_stats(struct virtnet_stats *stats, struct rte_mbuf *mbuf);

void agiep_virtio_rx_synchronize(struct virtnet_rx *rx);
void agiep_virtio_tx_synchronize(struct virtnet_tx *tx);


#endif
