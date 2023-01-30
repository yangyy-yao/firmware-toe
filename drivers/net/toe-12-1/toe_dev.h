#ifndef RTE_PMD_TOE_DEV_H_
#define RTE_PMD_TOE_DEV_H_

#include "toe_engine.h"
#include "toe_dma.h"

//#define RTE_PMD_TOE_MAX_QUEUES 16


//#define TOE_RQ_WAIT_HEAD_BIT_SIZE ((TOE_MAX_RQ_SIZE / 16) + (!(TOE_MAX_RQ_SIZE % 16) ? 0 : 1))
#define ETH_TOE_PF "pf"
#define ETH_TOE_VF "vf"

#define ETH_TOE_QUEUES "queues"
#define ETH_TOE_CTRL_QUEUES "ctrl_queues"
#define ETH_TOE_MAC "vmac"
#define FREP_QUEUES "frep_queues"

#define CTRL_PKT_MAX_DESC  2048
#define CTRL_PKT_CACHE_DESC  64

#define MAX_PF 2
#define MAX_VF 64

struct toe_rx_queue {
	int idx;
	struct toe_engine *toe_eg;
	struct rte_ring *rxq;
	struct rte_mempool *pkt_pool;
	uint16_t nb_rx_desc;
};
/*
struct toe_rx_ctl_queue {
	int idx;
	struct toe_engine *toe_eg;
	struct rte_ring *rxq;
	struct rte_mempool *pkt_pool;
	uint16_t nb_rx_desc;
};

struct toe_tx_ctl_queue {
	int idx;
	int data_idx;
	struct toe_engine *toe_eg;
	struct rte_ring *txq;
	uint16_t nb_tx_desc;
};

struct toe_rx_data_queue {
	int idx;
	struct toe_engine *toe_eg;
	struct rte_ring *rxq;
	struct rte_mempool *pkt_pool;
	uint16_t nb_rx_desc;
};


struct toe_rx_queue {
	struct toe_rx_ctl_queue **ctl_rxq;
	struct toe_rx_data_queue **data_rxq;

};
*/

struct toe_device {
	struct rte_eth_dev *eth_dev;
	struct rte_ether_addr *addr;
	uint32_t ip[4];
	uint8_t mac[6];
	uint16_t queues;
	uint16_t ctrl_queues;
	uint16_t data_queues;
	uint16_t f_queues;
	int pf;
	int vf;
	struct rte_kvargs *kvlist;
	struct toe_engine *toe_eg;
	struct toe_rx_queue **data_rxq;
	struct toe_rx_queue **ctl_rxq;
	//struct toe_tx_ctl_queue **ctl_txq;
	uint8_t enable;
	uint8_t active;
	uint8_t reset;
	uint8_t reset_done;
};

#endif

