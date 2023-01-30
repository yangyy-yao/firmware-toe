#include <rte_mbuf.h>
#include <rte_ring.h>
#include "agiep_frep_loopback_net.h"

uint16_t agiep_frep_loopback_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t ret;
	struct frep_loopback_queue *q = tx_queue;
	
	if (!q) {
		RTE_LOG(ERR, PMD, "%s-%d:,queue is null!\n", __func__, __LINE__);
		return 0;
	}
	ret = rte_ring_mp_enqueue_burst(q->lo_ring, (void *const *) tx_pkts, nb_pkts, NULL);
	return ret;
}


uint16_t agiep_frep_loopback_rx_pkt_burst(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint16_t ret;
	struct frep_loopback_queue *q = rx_queue;
	
	if (!q) {
		RTE_LOG(ERR, PMD, "%s-%d:,queue is null!\n", __func__, __LINE__);
		return 0;
	}

	ret = rte_ring_mc_dequeue_burst(q->lo_ring, (void **)rx_pkts, nb_pkts, NULL);
	return ret;
}

