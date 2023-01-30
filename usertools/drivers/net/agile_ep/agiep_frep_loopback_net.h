#ifndef AGIEP_FREP_LOOPBACK_NET_H_
#define AGIEP_FREP_LOOPBACK_NET_H_
#include "agiep_frep.h"

#define AGIEP_FREP_LO_QUEUE_SIZE  (4 * 1024)

struct frep_loopback_queue {
	struct agiep_frep_queue fq;
	struct rte_ring *lo_ring;
};

struct agiep_frep_loopback_device {
	uint16_t queue_num;
	struct frep_loopback_queue **lo_q;
};

uint16_t agiep_frep_loopback_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t agiep_frep_loopback_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

#endif
